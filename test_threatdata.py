import datetime
import gzip
import json
import os
import shutil
import ssl
import stat
import subprocess  # nosec B404 - used only to create a throwaway test certificate
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import threatdata as td
from prioritizer import Asset, Exposure, Threat, prioritize
from settings import DEFAULT_SETTINGS, Settings


def kev_entry(cve="CVE-2024-0001", **changes):
    entry = {"cveID": cve, "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Widget flaw",
             "dateAdded": "2024-01-02", "shortDescription": "text", "requiredAction": "Apply updates.",
             "dueDate": "2024-01-23", "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": ["CWE-79"],
             "forensicTriage": "future field"}
    entry.update(changes)
    return entry


def kev_doc(entries=None, **changes):
    entries = [kev_entry()] if entries is None else entries
    doc = {"title": "KEV", "catalogVersion": "2026.10.04", "dateReleased": "2026-10-04T18:52:56.0635Z",
           "count": len(entries), "vulnerabilities": entries}
    doc.update(changes)
    return doc


def kev_bytes(entries=None, **changes):
    return json.dumps(kev_doc(entries, **changes)).encode()


def epss_text(rows=None, first="#model_version:v2026.06.15,score_date:2026-10-07T12:00:27Z",
              header="cve,epss,percentile"):
    rows = ["CVE-2024-0001,0.50000,0.97000", "CVE-2024-0002,0.00100,0.20000"] if rows is None else rows
    return "\n".join([first, header, *rows]) + "\n"


def epss_bytes(text=None, compressed=True):
    raw = (epss_text() if text is None else text).encode()
    return gzip.compress(raw) if compressed else raw


class KevParserTests(unittest.TestCase):
    def test_valid_file_with_extra_fields(self):
        data = td.parse_kev(kev_bytes([kev_entry(), kev_entry("CVE-2024-0002", knownRansomwareCampaignUse="Known")]))
        self.assertEqual((data.catalog_version, data.date_released), ("2026.10.04", "2026-10-04"))
        self.assertEqual(set(data.entries), {"CVE-2024-0001", "CVE-2024-0002"})
        self.assertFalse(data.entries["CVE-2024-0001"].ransomware)
        self.assertTrue(data.entries["CVE-2024-0002"].ransomware)
        self.assertEqual(data.entries["CVE-2024-0001"].due_date, "2024-01-23")

    def test_empty_due_date_is_allowed(self):
        self.assertEqual(td.parse_kev(kev_bytes([kev_entry(dueDate="")])).entries["CVE-2024-0001"].due_date, "")

    def test_control_characters_are_replaced(self):
        data = td.parse_kev(kev_bytes([kev_entry(requiredAction="Apply\x00 \x1b[31mupdates\r\n")]))
        self.assertEqual(data.entries["CVE-2024-0001"].required_action, "Apply   [31mupdates")

    def test_malformed_files_are_rejected_with_a_clear_error(self):
        good = kev_doc()
        no_count = {k: v for k, v in good.items() if k != "count"}
        cases = {
            "empty": b"", "not json": b"not json", "truncated": kev_bytes()[:50], "array": b"[]", "null": b"null",
            "utf-16": json.dumps(good).encode("utf-16"), "invalid utf-8": b"\xff\xfe\xfd",
            "nan": kev_bytes().replace(b'"count": 1', b'"count": NaN'),
            "duplicate keys": b'{"catalogVersion": "1", "catalogVersion": "2"}',
            "deep nesting": b"[" * 100_000 + b"]" * 100_000,
            "no version": json.dumps({k: v for k, v in good.items() if k != "catalogVersion"}).encode(),
            "bad version": kev_bytes(catalogVersion="a b/c"), "version number": kev_bytes(catalogVersion=5),
            "bad release date": kev_bytes(dateReleased="yesterday"), "no list": kev_bytes(vulnerabilities={}),
            "no count": json.dumps(no_count).encode(), "count mismatch": kev_bytes(count=5),
            "count bool": kev_bytes(count=True),
            "entry not object": kev_bytes(["x"], count=1),
            "bad cve": kev_bytes([kev_entry("CVE-24-1")]), "cve not text": kev_bytes([kev_entry(5)]),
            "duplicate cve": kev_bytes([kev_entry(), kev_entry()]),
            "bad added date": kev_bytes([kev_entry(dateAdded="2024-13-45")]),
            "bad due date": kev_bytes([kev_entry(dueDate="soon")]),
            "due date number": kev_bytes([kev_entry(dueDate=5)]),
            "bad ransomware": kev_bytes([kev_entry(knownRansomwareCampaignUse="Maybe")]),
            "action number": kev_bytes([kev_entry(requiredAction=5)]),
            "action missing": kev_bytes([{k: v for k, v in kev_entry().items() if k != "requiredAction"}]),
            "huge field": kev_bytes([kev_entry(requiredAction="A" * (td.MAX_FIELD_CHARS + 1))]),
        }
        for label, data in cases.items():
            with self.subTest(case=label), self.assertRaises(td.ThreatDataError):
                td.parse_kev(data)

    def test_size_and_entry_limits(self):
        with mock.patch.object(td, "KEV_MAX_BYTES", 100), self.assertRaisesRegex(td.ThreatDataError, "larger than"):
            td.parse_kev(kev_bytes())
        with mock.patch.object(td, "KEV_MAX_ENTRIES", 1), self.assertRaisesRegex(td.ThreatDataError, "more than"):
            td.parse_kev(kev_bytes([kev_entry(), kev_entry("CVE-2024-0002")]))


class EpssParserTests(unittest.TestCase):
    def test_valid_gzip_and_plain(self):
        for compressed in (True, False):
            with self.subTest(compressed=compressed):
                data = td.parse_epss(epss_bytes(compressed=compressed))
                self.assertEqual((data.model_version, data.score_date), ("v2026.06.15", "2026-10-07"))
                self.assertEqual(data.scores["CVE-2024-0001"], (0.5, 0.97))

    def test_header_without_time_and_crlf_lines(self):
        text = epss_text(first="#model_version:v2025.03.14,score_date:2026-10-07").replace("\n", "\r\n")
        self.assertEqual(td.parse_epss(text.encode()).score_date, "2026-10-07")

    def test_malformed_files_are_rejected_with_a_clear_error(self):
        compressed = epss_bytes()
        cases = {
            "empty": b"", "empty after header": epss_text([]).encode(),
            "no header line": epss_text(first="cve,epss,percentile", header="CVE-2024-0001,0.5,0.9").encode(),
            "bad header line": epss_text(first="#model_version:x y,score_date:2026-10-07").encode(),
            "bad score date": epss_text(first="#model_version:v1,score_date:2026-99-99").encode(),
            "wrong columns": epss_text(header="cve,score,rank").encode(),
            "extra column": epss_text(header="cve,epss,percentile,x").encode(),
            "bad cve": epss_text(["BAD,0.1,0.1"]).encode(), "short row": epss_text(["CVE-2024-0001,0.1"]).encode(),
            "long row": epss_text(["CVE-2024-0001,0.1,0.1,0.1"]).encode(),
            "text score": epss_text(["CVE-2024-0001,high,0.1"]).encode(),
            "nan": epss_text(["CVE-2024-0001,nan,0.1"]).encode(), "inf": epss_text(["CVE-2024-0001,0.1,inf"]).encode(),
            "negative": epss_text(["CVE-2024-0001,-0.1,0.1"]).encode(),
            "over one": epss_text(["CVE-2024-0001,0.1,1.5"]).encode(),
            "duplicate": epss_text(["CVE-2024-0001,0.1,0.1", "CVE-2024-0001,0.2,0.2"]).encode(),
            "invalid utf-8": b"\xff\xfe\xfd", "utf-16": epss_text().encode("utf-16"),
            "truncated gzip": compressed[: len(compressed) // 2], "corrupt gzip": compressed[:10] + b"\x00" * 20,
            "gzip magic only": b"\x1f\x8b",
        }
        for label, data in cases.items():
            with self.subTest(case=label), self.assertRaises(td.ThreatDataError):
                td.parse_epss(data)

    def test_decompression_bomb_is_stopped(self):
        bomb = gzip.compress(b"#model_version:v1,score_date:2026-10-07\ncve,epss,percentile\n" + b"0" * 5_000_000)
        with mock.patch.object(td, "EPSS_MAX_DECOMPRESSED", 200_000):
            self.assertLess(len(bomb), 20_000)
            with self.assertRaisesRegex(td.ThreatDataError, "expands to more than"):
                td.parse_epss(bomb)

    def test_size_and_row_limits(self):
        with mock.patch.object(td, "EPSS_MAX_COMPRESSED", 10), self.assertRaisesRegex(td.ThreatDataError, "larger"):
            td.parse_epss(epss_bytes())
        with mock.patch.object(td, "EPSS_MAX_DECOMPRESSED", 10), self.assertRaisesRegex(td.ThreatDataError, "larger"):
            td.parse_epss(epss_bytes(compressed=False))
        with mock.patch.object(td, "EPSS_MAX_ROWS", 1), self.assertRaisesRegex(td.ThreatDataError, "more than"):
            td.parse_epss(epss_bytes())

    def test_normalize_cve(self):
        self.assertEqual(td.normalize_cve("  cve-2024-12345 "), "CVE-2024-12345")
        for bad in ("", "CVE-24-1", "CVE-2024-123", "x", "CVE-2024-1234; DROP", "CVE-2024-1234\n=1"):
            with self.subTest(text=bad), self.assertRaises(ValueError):
                td.normalize_cve(bad)


class StorageTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name) / "data"
        self.now = datetime.datetime(2026, 10, 7, 12, 0, tzinfo=datetime.timezone.utc)

    def fetcher(self, kev=None, epss=None):
        def fetch(url, max_bytes, allowed_hosts):
            result = kev if url == td.KEV_URL else epss
            if isinstance(result, Exception):
                raise result
            return result
        return fetch

    def update(self, kev=None, epss=None, now=None):
        return td.update_from_network(self.dir, self.fetcher(kev or kev_bytes(), epss or epss_bytes()), now or self.now)

    def test_successful_update_stores_validated_files_with_user_only_permissions(self):
        results = self.update()
        self.assertTrue(all(r.ok for r in results), results)
        self.assertEqual(sorted(os.listdir(self.dir)), ["epss.csv.gz", "kev.json", "meta.json"])
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
            for name in os.listdir(self.dir):
                self.assertEqual(stat.S_IMODE(os.stat(self.dir / name).st_mode), 0o600, name)
        data = td.ThreatData.load(self.dir)
        self.assertEqual(data.warnings, [])
        self.assertEqual(data.versions(), "KEV 2026.10.04 (2026-10-04); EPSS v2026.06.15 (2026-10-07)")
        self.assertEqual(data.meta["kev"]["source"], td.KEV_URL)
        self.assertEqual(data.meta["kev"]["retrieved_at"], "2026-10-07T12:00:00Z")
        self.assertEqual(len(data.meta["epss"]["sha256"]), 64)

    def test_failed_download_keeps_the_previous_copy(self):
        self.update()
        before = {n: (self.dir / n).read_bytes() for n in os.listdir(self.dir)}
        results = self.update(kev=td.FetchError("the connection timed out"), epss=td.FetchError("HTTP 500"))
        self.assertEqual([r.ok for r in results], [False, False])
        self.assertIn("previous copy was kept", results[0].message)
        self.assertIn("timed out", results[0].message)
        self.assertEqual({n: (self.dir / n).read_bytes() for n in os.listdir(self.dir)}, before)

    def test_invalid_data_never_replaces_good_data(self):
        self.update()
        before = {n: (self.dir / n).read_bytes() for n in os.listdir(self.dir)}
        results = self.update(kev=b"{not json", epss=epss_bytes(epss_text(["BAD,1,1"])))
        self.assertEqual([r.ok for r in results], [False, False])
        self.assertEqual({n: (self.dir / n).read_bytes() for n in os.listdir(self.dir)}, before)
        self.assertEqual([n for n in os.listdir(self.dir) if n.startswith(".tmp")], [])

    def test_one_source_failing_does_not_block_the_other(self):
        results = self.update(kev=td.FetchError("down"))
        self.assertEqual([r.ok for r in results], [False, True])
        data = td.ThreatData.load(self.dir)
        self.assertIsNone(data.kev)
        self.assertIsNotNone(data.epss)
        self.assertEqual(data.warnings, [])

    def test_cancel_and_progress_in_update(self):
        cancel, seen = threading.Event(), []
        results = td.update_from_network(self.dir, self.fetcher(kev_bytes(), epss_bytes()), self.now, cancel,
                                         seen.append)
        self.assertEqual((seen, [r.ok for r in results]), (["Downloading KEV...", "Downloading EPSS..."], [True, True]))
        cancel.set()
        before = {n: (self.dir / n).read_bytes() for n in os.listdir(self.dir)}
        results = td.update_from_network(self.dir, self.fetcher(kev_bytes([kev_entry("CVE-2024-0009")]), None),
                                         self.now, cancel)
        self.assertEqual([r.ok for r in results], [False, False])
        self.assertIn("cancelled", results[0].message)
        self.assertEqual({n: (self.dir / n).read_bytes() for n in os.listdir(self.dir)}, before)

    def test_failed_write_leaves_previous_data_and_no_temp_files(self):
        self.update()
        before = {n: (self.dir / n).read_bytes() for n in os.listdir(self.dir)}
        with mock.patch("threatdata.os.replace", side_effect=OSError(28, "No space left on device")):
            results = self.update(kev=kev_bytes([kev_entry("CVE-2024-0009")]))
        self.assertFalse(results[0].ok)
        self.assertIn("previous copy was kept", results[0].message)
        self.assertEqual({n: (self.dir / n).read_bytes() for n in os.listdir(self.dir)}, before)

    def test_import_from_files_validates_like_a_download(self):
        src = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, src)
        (src / "kev.json").write_bytes(kev_bytes())
        (src / "epss.csv").write_bytes(epss_bytes(compressed=False))
        results = td.import_from_files(src / "kev.json", src / "epss.csv", self.dir, self.now)
        self.assertEqual([r.ok for r in results], [True, True])
        self.assertEqual((self.dir / td.EPSS_FILE).read_bytes()[:2], b"\x1f\x8b")
        data = td.ThreatData.load(self.dir)
        self.assertEqual(data.meta["epss"]["source"], "file import: epss.csv")
        (src / "bad.json").write_bytes(b"nope")
        results = td.import_from_files(src / "bad.json", None, self.dir, self.now)
        self.assertEqual([r.ok for r in results], [False])
        self.assertEqual(td.import_from_files(None, None, self.dir), [])

    def test_import_handles_missing_directory_and_oversized_files(self):
        src = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, src)
        results = td.import_from_files(src / "missing.json", src, self.dir, self.now)
        self.assertEqual([r.ok for r in results], [False, False])
        big = src / "big.json"
        big.write_bytes(b" " * 200)
        with mock.patch.object(td, "KEV_MAX_BYTES", 100):
            self.assertFalse(td.import_from_files(big, None, self.dir, self.now)[0].ok)

    def test_import_source_labels_are_sanitized(self):
        src = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, src)
        name = "k\x1b[31mev\n.json"
        (src / name).write_bytes(kev_bytes())
        td.import_from_files(src / name, None, self.dir, self.now)
        source = td.ThreatData.load(self.dir).meta["kev"]["source"]
        self.assertNotRegex(source, r"[\x00-\x1f\x7f]")

    def test_corrupt_stored_files_become_warnings_not_crashes(self):
        self.update()
        (self.dir / td.KEV_FILE).write_bytes(b"corrupted")
        (self.dir / td.META_FILE).write_bytes(b"\xff not json")
        data = td.ThreatData.load(self.dir)
        self.assertIsNone(data.kev)
        self.assertIsNotNone(data.epss)
        self.assertEqual(len(data.warnings), 1)
        self.assertEqual(data.meta, {})

    def test_load_with_nothing_stored(self):
        data = td.ThreatData.load(self.dir)
        self.assertEqual((data.kev, data.epss, data.warnings), (None, None, []))
        self.assertEqual(data.versions(), "KEV not loaded; EPSS not loaded")
        info = data.lookup("CVE-2024-0001")
        self.assertEqual((info.kev_loaded, info.epss_loaded, info.kev, info.epss), (False, False, None, None))

    def test_directory_in_place_of_a_stored_file(self):
        (self.dir / td.KEV_FILE).mkdir(parents=True)
        data = td.ThreatData.load(self.dir)
        self.assertIsNone(data.kev)
        self.assertEqual(len(data.warnings), 1)

    def test_lookup(self):
        self.update(kev=kev_bytes([kev_entry("CVE-2024-0001", knownRansomwareCampaignUse="Known")]))
        data = td.ThreatData.load(self.dir)
        info = data.lookup(" cve-2024-0001")
        self.assertTrue(info.kev.ransomware)
        self.assertEqual((info.epss, info.percentile), (0.5, 0.97))
        other = data.lookup("CVE-2024-0002")
        self.assertIsNone(other.kev)
        self.assertEqual(other.percentile, 0.2)
        self.assertEqual(data.lookup("CVE-2030-9999").epss, None)
        with self.assertRaises(ValueError):
            data.lookup("not a cve")

    def test_freshness(self):
        self.update()
        data = td.ThreatData.load(self.dir)
        fresh = data.freshness(7, self.now + datetime.timedelta(days=1, hours=1))
        self.assertEqual([f.stale for f in fresh], [False, False])
        self.assertIn("retrieved 1 day ago", fresh[0].text)
        self.assertIn("2026.10.04", fresh[0].text)
        self.assertIn("v2026.06.15", fresh[1].text)
        stale = data.freshness(7, self.now + datetime.timedelta(days=8))
        self.assertEqual([f.stale for f in stale], [True, True])
        exactly = data.freshness(7, self.now + datetime.timedelta(days=7))
        self.assertEqual([f.stale for f in exactly], [False, False])
        custom = data.freshness(1, self.now + datetime.timedelta(days=2))
        self.assertTrue(custom[0].stale)
        (self.dir / td.META_FILE).unlink()
        unknown = td.ThreatData.load(self.dir).freshness(7, self.now)
        self.assertTrue(all(f.stale and not f.missing for f in unknown))
        self.assertIn("unknown", unknown[0].text)
        empty = td.ThreatData().freshness(7, self.now)
        self.assertTrue(all(f.stale and f.missing for f in empty))

    def test_default_data_dir_uses_an_absolute_xdg_folder_only(self):
        if sys.platform in ("win32", "darwin"):
            self.skipTest("XDG applies to Linux")
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": str(self.dir)}):
            self.assertEqual(td.default_data_dir(), self.dir / "vuln-prioritizer" / "data")
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": "relative"}):
            self.assertEqual(td.default_data_dir(), Path.home() / ".local" / "share" / "vuln-prioritizer" / "data")


def info_for(kev=False, epss=None, percentile=None, kev_loaded=True, epss_loaded=True, ransomware=False):
    entry = td.KevEntry("CVE-2024-0001", "Acme", "Widget", "Flaw", "2024-01-02", "Apply updates.", "2024-01-23",
                        ransomware) if kev else None
    return td.CveInfo("CVE-2024-0001", entry, epss, percentile, kev_loaded, epss_loaded)


class ThreatDerivationTests(unittest.TestCase):
    def derive(self, info, **kwargs):
        return td.derive_threat(info, kwargs.pop("settings", DEFAULT_SETTINGS), **kwargs)

    def test_kev_means_active(self):
        decision = self.derive(info_for(kev=True))
        self.assertEqual(decision.level, Threat.ACTIVE)
        self.assertEqual(decision.sources, ("In CISA KEV",))

    def test_kev_wins_over_epss(self):
        self.assertEqual(self.derive(info_for(kev=True, epss=0.9, percentile=0.99)).sources, ("In CISA KEV",))

    def test_epss_percentile_at_or_above_cutoff_means_public(self):
        for percentile, expected in ((0.949, Threat.NONE), (0.95, Threat.PUBLIC), (0.999, Threat.PUBLIC)):
            with self.subTest(percentile=percentile):
                self.assertEqual(self.derive(info_for(epss=0.1, percentile=percentile)).level, expected)
        decision = self.derive(info_for(epss=0.1, percentile=0.96))
        self.assertTrue(decision.sources[0].startswith("Elevated EPSS"))
        self.assertNotIn("exploit available", " ".join(decision.sources))

    def test_epss_cutoff_follows_settings(self):
        info = info_for(epss=0.1, percentile=0.9)
        self.assertEqual(self.derive(info).level, Threat.NONE)
        self.assertEqual(self.derive(info, settings=Settings(epss_percentile_cutoff=0.85)).level, Threat.PUBLIC)

    def test_manual_flags_only_raise(self):
        none = info_for()
        self.assertEqual(self.derive(none, analyst_confirmed=True).level, Threat.ACTIVE)
        self.assertEqual(self.derive(none, public_exploit=True).level, Threat.PUBLIC)
        self.assertEqual(self.derive(info_for(kev=True), public_exploit=True).level, Threat.ACTIVE)
        both = self.derive(none, analyst_confirmed=True, public_exploit=True)
        self.assertEqual(both.level, Threat.ACTIVE)
        epss = self.derive(info_for(epss=0.1, percentile=0.99), analyst_confirmed=True)
        self.assertEqual(epss.level, Threat.ACTIVE)

    def test_missing_data_never_lowers_the_level(self):
        decision = self.derive(info_for(kev_loaded=False, epss_loaded=False), public_exploit=True)
        self.assertEqual(decision.level, Threat.PUBLIC)
        self.assertEqual(len(decision.notes), 2)
        self.assertEqual(self.derive(None, analyst_confirmed=True).level, Threat.ACTIVE)
        self.assertEqual(self.derive(None).level, Threat.NONE)

    def test_not_in_kev_or_low_epss_is_none_not_a_claim_of_safety(self):
        decision = self.derive(info_for(epss=0.001, percentile=0.1))
        self.assertEqual((decision.level, decision.sources), (Threat.NONE, ("No KEV or elevated EPSS signal",)))

    def test_override_needs_a_reason_and_is_recorded(self):
        with self.assertRaises(ValueError):
            self.derive(info_for(kev=True), override=Threat.NONE)
        with self.assertRaises(ValueError):
            self.derive(info_for(kev=True), override=Threat.NONE, override_reason="   ")
        decision = self.derive(info_for(kev=True), override=Threat.PUBLIC, override_reason="Patched by vendor hotfix\n")
        self.assertEqual(decision.level, Threat.PUBLIC)
        self.assertIn("Manual override (Patched by vendor hotfix)", decision.sources)
        self.assertIn("from ACTIVE to PUBLIC", decision.notes[0])

    def test_apply_context_adds_kev_details_without_changing_the_bucket(self):
        info = info_for(kev=True)
        decision = self.derive(info)
        plain = prioritize(8.0, decision.level, Asset.STANDARD, Exposure.HIGH)
        result = td.apply_threat_context(plain, decision, info)
        self.assertEqual((result.priority, result.score), (plain.priority, plain.score))
        self.assertIn("CISA required action: Apply updates.", result.action)
        self.assertTrue(result.action.startswith(plain.action))
        self.assertTrue(any("remediation due 2024-01-23" in r and "context only" in r for r in result.reasons))
        self.assertTrue(any(r.startswith("Threat level from: In CISA KEV") for r in result.reasons))
        self.assertFalse(any("ransomware" in r for r in result.reasons))

    def test_ransomware_ranks_higher_within_the_bucket_only(self):
        info = info_for(kev=True, ransomware=True)
        decision = self.derive(info)
        plain = prioritize(8.0, decision.level, Asset.STANDARD, Exposure.HIGH)
        result = td.apply_threat_context(plain, decision, info)
        self.assertEqual(result.priority, plain.priority)
        self.assertAlmostEqual(result.score - plain.score, td.RANSOMWARE_SCORE_BONUS, places=6)
        top = prioritize(10.0, Threat.ACTIVE, Asset.CROWN, Exposure.HIGH)
        self.assertEqual(td.apply_threat_context(top, decision, info).score, 10.0)

    def test_no_kev_context_leaves_the_result_alone(self):
        decision = self.derive(info_for())
        plain = prioritize(8.0, decision.level, Asset.STANDARD, Exposure.HIGH)
        result = td.apply_threat_context(plain, decision, info_for())
        self.assertEqual((result.action, result.score), (plain.action, plain.score))


# ---- download tests against a local TLS server ------------------------------

class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send(self, body=b"ok", status=200, headers=()):
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        try:
            self.route()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def route(self):
        path = self.path
        if path == "/ok":
            self.send(b"hello")
        elif path == "/redirect-relative":
            self.send(b"", 302, [("Location", "ok")])
        elif path == "/redirect-other-host":
            self.send(b"", 302, [("Location", "https://evil.invalid/ok")])
        elif path == "/redirect-http":
            self.send(b"", 302, [("Location", "http://localhost/ok")])
        elif path == "/redirect-userinfo":
            self.send(b"", 302, [("Location", "https://user:pw@localhost/ok")])
        elif path == "/redirect-file":
            self.send(b"", 302, [("Location", "file:///etc/passwd")])
        elif path == "/loop":
            self.send(b"", 302, [("Location", "/loop")])
        elif path == "/chain":
            self.send(b"", 302, [("Location", "/chain2")])
        elif path == "/chain2":
            self.send(b"", 302, [("Location", "/chain3")])
        elif path == "/chain3":
            self.send(b"", 302, [("Location", "/chain4")])
        elif path == "/chain4":
            self.send(b"", 302, [("Location", "/ok")])
        elif path == "/big":
            self.send(b"x" * 3_000_000)
        elif path == "/big-chunked":
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            for _ in range(60):
                self.wfile.write(b"x" * 50_000)
        elif path == "/drip":
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            for _ in range(100):
                self.wfile.write(b"x")
                self.wfile.flush()
                time.sleep(0.1)
        elif path == "/hang":
            time.sleep(4)
            self.send(b"late")
        elif path == "/truncated":
            self.send_response(200)
            self.send_header("Content-Length", "100000")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"x" * 500)
            self.wfile.flush()
            self.close_connection = True
        elif path == "/500":
            self.send(b"error", 500)
        elif path == "/404":
            self.send(b"missing", 404)
        else:
            self.send(b"?", 404)


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed to create a test certificate")
class FetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cert, key = Path(cls.tmp.name) / "cert.pem", Path(cls.tmp.name) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),  # noqa: S603, S607  # nosec B603 B607
                        "-out", str(cert), "-days", "2", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost",
                        "-addext", "basicConstraints=critical,CA:TRUE",
                        "-addext", "keyUsage=critical,digitalSignature,keyCertSign"],
                       check=True, capture_output=True)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert, key)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.daemon_threads = True
        cls.server.socket = server_ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.trusting = ssl.create_default_context(cafile=str(cert))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def get(self, path, max_bytes=1_000_000, hosts=("localhost",), context=None, **kwargs):
        return td.fetch(f"https://localhost:{self.port}{path}", max_bytes, frozenset(hosts),
                        context=context or self.trusting, **kwargs)

    def test_downloads_over_https(self):
        self.assertEqual(self.get("/ok"), b"hello")

    def test_follows_a_relative_redirect_on_the_same_host(self):
        self.assertEqual(self.get("/redirect-relative"), b"hello")

    def test_refuses_redirects_to_other_hosts_schemes_and_userinfo(self):
        for path in ("/redirect-other-host", "/redirect-http", "/redirect-userinfo", "/redirect-file"):
            with self.subTest(path=path), self.assertRaisesRegex(td.FetchError, "redirect"):
                self.get(path)

    def test_limits_redirects(self):
        for path in ("/loop", "/chain"):
            with self.subTest(path=path), self.assertRaisesRegex(td.FetchError, "refused or repeated"):
                self.get(path)

    def test_enforces_the_size_cap(self):
        with self.assertRaisesRegex(td.FetchError, "larger than"):
            self.get("/big", max_bytes=1_000_000)
        with self.assertRaisesRegex(td.FetchError, "larger than"):
            self.get("/big-chunked", max_bytes=1_000_000)

    def test_enforces_the_overall_deadline_against_a_slow_drip(self):
        started = time.monotonic()
        with self.assertRaisesRegex(td.FetchError, "took too long"):
            self.get("/drip", deadline=1)
        self.assertLess(time.monotonic() - started, 5)

    def test_times_out_when_the_server_does_not_answer(self):
        started = time.monotonic()
        with self.assertRaisesRegex(td.FetchError, "timed out"):
            self.get("/hang", timeout=1)
        self.assertLess(time.monotonic() - started, 3.5)

    def test_a_download_can_be_cancelled_mid_stream(self):
        cancel = threading.Event()
        threading.Timer(0.4, cancel.set).start()
        started = time.monotonic()
        with self.assertRaisesRegex(td.FetchError, "cancelled"):
            self.get("/drip", cancel=cancel, deadline=30)
        self.assertLess(time.monotonic() - started, 3)

    def test_a_connection_cut_mid_download_is_a_clear_error(self):
        with self.assertRaisesRegex(td.FetchError, "cut off"):
            self.get("/truncated")

    def test_the_system_proxy_setting_is_honored(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:1", "https_proxy": "http://127.0.0.1:1"}):
            with self.assertRaisesRegex(td.FetchError, "could not connect"):
                self.get("/ok")
        self.assertEqual(self.get("/ok"), b"hello")

    def test_http_errors_are_reported_plainly(self):
        for path, code in (("/500", "500"), ("/404", "404")):
            with self.subTest(path=path), self.assertRaisesRegex(td.FetchError, f"HTTP {code}"):
                self.get(path)

    def test_untrusted_certificate_is_refused(self):
        with self.assertRaisesRegex(td.FetchError, "could not be verified"):
            self.get("/ok", context=ssl.create_default_context())

    def test_default_context_verifies_certificates(self):
        with self.assertRaisesRegex(td.FetchError, "could not be verified"):
            td.fetch(f"https://localhost:{self.port}/ok", 1000, frozenset({"localhost"}))

    def test_wrong_hostname_is_refused(self):
        with self.assertRaisesRegex(td.FetchError, "could not be verified"):
            td.fetch(f"https://127.0.0.1:{self.port}/ok", 1000, frozenset({"127.0.0.1"}), context=self.trusting)

    def test_refuses_plain_http_other_hosts_and_userinfo_before_connecting(self):
        for url in (f"http://localhost:{self.port}/ok", f"https://evil.invalid:{self.port}/ok",
                    f"https://user:pw@localhost:{self.port}/ok", "file:///etc/passwd", "ftp://localhost/ok", ""):
            with self.subTest(url=url), self.assertRaisesRegex(td.FetchError, "only HTTPS"):
                td.fetch(url, 1000, frozenset({"localhost"}), context=self.trusting)

    def test_closed_port_is_a_clear_error(self):
        with self.assertRaisesRegex(td.FetchError, "could not connect"):
            td.fetch("https://localhost:1/ok", 1000, frozenset({"localhost"}), context=self.trusting)

    def test_production_urls_are_https_on_the_expected_hosts(self):
        for url, hosts in ((td.KEV_URL, td.KEV_HOSTS), (td.EPSS_URL, td.EPSS_HOSTS)):
            parts = td.urllib.parse.urlsplit(url)
            self.assertEqual(parts.scheme, "https")
            self.assertIn(parts.hostname, hosts)

    def test_update_reports_a_tls_failure_and_keeps_data(self):
        data_dir = Path(self.tmp.name) / "data"
        results = td.update_from_network(
            data_dir, lambda url, cap, hosts: td.fetch(f"https://localhost:{self.port}/ok", cap, {"localhost"},
                                                       context=ssl.create_default_context()))
        self.assertEqual([r.ok for r in results], [False, False])
        self.assertIn("could not be verified", results[0].message)
        self.assertFalse(data_dir.exists() and any(data_dir.iterdir()))


if __name__ == "__main__":
    unittest.main()
