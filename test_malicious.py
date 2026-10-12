import csv
import gzip
import io
import json
import os
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import batch
import icsadvisories
import inventory
import malicious_cases
import settings
import threatdata
from test_icsadvisories import ROOT, advisory, good, member_path

ALLOWED_ERRORS = (ValueError, OSError, UnicodeDecodeError, csv.Error)
TIME_LIMIT_SECONDS = 30


class MaliciousFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.cases = malicious_cases.build(cls.dir.name)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def load(self, name):
        start = time.monotonic()
        try:
            return batch.process_file(self.cases[name]), None
        except ALLOWED_ERRORS as error:
            return None, error
        finally:
            self.assertLess(time.monotonic() - start, TIME_LIMIT_SECONDS, name)

    def test_every_case_fails_safely_or_parses(self):
        for name in self.cases:
            with self.subTest(case=name):
                items, error = self.load(name)
                self.assertTrue(items is not None or error is not None)

    def test_unreadable_files_are_rejected(self):
        for name in ("many_rows", "one_huge_line", "long_field", "empty", "utf16", "latin1",
                     "missing_column", "duplicate_column"):
            with self.subTest(case=name):
                items, error = self.load(name)
                self.assertIsNone(items)
                self.assertIsInstance(error, ALLOWED_ERRORS)

    def test_header_only_has_no_rows(self):
        self.assertEqual(self.load("header_only")[0], [])

    def test_bad_cvss_values_become_error_rows(self):
        for label in ("nan", "inf", "negative", "over_ten", "huge", "blank", "text"):
            with self.subTest(cvss=label):
                items, error = self.load("cvss_" + label)
                self.assertIsNone(error)
                self.assertEqual([i.priority for i in items], ["ERROR"])

    def test_formula_payloads_are_neutralized_on_export(self):
        items, _ = self.load("formula_payloads")
        out = os.path.join(self.dir.name, "export.csv")
        batch.write_results(out, items)
        with open(out, newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                for key in ("id", "name", "error", "cvss"):
                    self.assertFalse(row[key].startswith(tuple("=+-@\t\r")), (key, row[key]))

    def test_column_layout_cases(self):
        self.assertEqual([i.priority for i in self.load("extra_columns")[0]], ["NOW"])
        self.assertEqual([i.priority for i in self.load("reordered_columns")[0]], ["NOW"])
        self.assertEqual(self.load("bom_utf8")[0][0].priority, "NOW")

    def test_hostile_cvss_vectors_become_error_rows_and_never_a_score(self):
        for name in ("vector_invalid", "vector_mismatch", "vector_v2", "vector_formula", "vector_unicode",
                     "vector_null_byte"):
            with self.subTest(case=name):
                items, error = self.load(name)
                self.assertIsNone(error, name)
                self.assertEqual([i.priority for i in items], ["ERROR"], name)
                self.assertIn("cvss", items[0].error)
                self.assertLess(len(items[0].error), 300)
                self.assertLessEqual(len(items[0].cvss_vector), batch.MAX_ERROR_VECTOR_CHARS)
        items, error = self.load("vector_only")
        self.assertEqual((error, [i.priority for i in items], items[0].cvss), (None, ["NOW"], 9.8))
        items, error = self.load("vector_duplicate_header")
        self.assertIsNone(items)
        self.assertIn("Duplicate column", str(error))

    def test_a_giant_vector_cell_is_refused_by_the_csv_layer_before_any_parsing(self):
        items, error = self.load("vector_huge")
        self.assertIsNone(items)
        self.assertIn("field larger than field limit", str(error))
        long_cell = batch.score_row(2, {"cvss_vector": "CVSS:3.1/" + "A" * 100_000, "threat": "none",
                                        "asset": "standard", "exposure": "low"})
        self.assertEqual(long_cell.priority, "ERROR")
        self.assertIn("longer than 400", long_cell.error)

    def test_a_hostile_vector_cell_does_not_survive_into_an_unsafe_export(self):
        items, _ = self.load("vector_formula")
        out = os.path.join(self.dir.name, "vectors.csv")
        batch.write_results(out, items)
        with open(out, newline="", encoding="utf-8-sig") as fh:
            row = next(csv.DictReader(fh))
        self.assertTrue(row["cvss_vector"].startswith("'="))
        self.assertFalse(row["error"].startswith(tuple("=+-@\t\r")))

    def test_row_and_size_caps(self):
        path = os.path.join(self.dir.name, "cap.csv")
        with open(path, "wb") as fh:
            fh.write(malicious_cases.HEADER + malicious_cases.GOOD_ROW * (batch.MAX_ROWS + 1))
        with self.assertRaisesRegex(ValueError, "data rows"):
            batch.process_file(path)
        with open(path, "wb") as fh:
            fh.write(malicious_cases.HEADER)
            fh.truncate(batch.MAX_FILE_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "larger than"):
            batch.process_file(path)


class MaliciousSettingsTests(unittest.TestCase):
    def test_every_hostile_settings_file_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            cases = malicious_cases.build_settings(directory)
            before = sorted(os.listdir(directory))
            for name, path in cases.items():
                with self.subTest(case=name):
                    start = time.monotonic()
                    result = settings.load(path)
                    self.assertLess(time.monotonic() - start, TIME_LIMIT_SECONDS)
                    self.assertEqual(result.settings, settings.DEFAULT_SETTINGS)
                    self.assertEqual(len(result.warnings), 1)
                    self.assertLess(len(result.warnings[0]), 600)
            self.assertEqual(sorted(os.listdir(directory)), before)


class MaliciousThreatDataTests(unittest.TestCase):
    GOOD_KEV = '{"catalogVersion": "1", "dateReleased": "2024-01-02", "count": 0, "vulnerabilities": []}'
    SANITIZED = ("kev_formula_text", "kev_control_characters")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        (self.work / "cases").mkdir()
        self.store = self.work / "store"

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.store.iterdir()}

    def test_hostile_files_are_rejected_without_touching_stored_data(self):
        cases = malicious_cases.build_threat_data(str(self.work / "cases"))
        good = self.work / "good.json"
        good.write_text(self.GOOD_KEV, encoding="utf-8")
        self.assertTrue(threatdata.import_from_files(good, None, self.store)[0].ok)
        before = self.snapshot()
        for name, (kind, path) in cases.items():
            if name in self.SANITIZED:
                continue
            with self.subTest(case=name):
                start = time.monotonic()
                args = (path, None) if kind == "kev" else (None, path)
                results = threatdata.import_from_files(*args, self.store)
                self.assertLess(time.monotonic() - start, TIME_LIMIT_SECONDS)
                self.assertEqual(len(results), 1)
                self.assertFalse(results[0].ok, results[0].message)
                self.assertIn("previous copy was kept", results[0].message)
                self.assertLess(len(results[0].message), 400)
        self.assertEqual(self.snapshot(), before)

    def test_text_fields_with_formulas_or_control_characters_are_stored_cleaned(self):
        cases = malicious_cases.build_threat_data(str(self.work / "cases"))
        results = threatdata.import_from_files(cases["kev_control_characters"][1], None, self.store)
        self.assertTrue(results[0].ok)
        entry = threatdata.ThreatData.load(self.store).kev.entries["CVE-2024-0001"]
        self.assertNotRegex(entry.product, r"[\x00-\x1f\x7f]")
        results = threatdata.import_from_files(cases["kev_formula_text"][1], None, self.store)
        entry = threatdata.ThreatData.load(self.store).kev.entries["CVE-2024-0001"]
        self.assertEqual(entry.required_action, "=1+1")


class MaliciousInventoryTests(unittest.TestCase):
    """Every hostile asset inventory is either loaded safely (bad rows skipped) or refused with a ValueError."""

    HEAD = b"asset_id,name,criticality,exposure,controls\n"

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dir = folder.name

    def path(self, name, data):
        return malicious_cases._write(self.dir, name + ".csv", data)

    def cases(self):
        row = b"A-%d,Pump,crown,high,none\n"
        return {
            "empty": b"",
            "header_only": self.HEAD,
            "utf16": (self.HEAD + b"A-1,Pump,crown,high,none\n").decode().encode("utf-16"),
            "latin1": self.HEAD + b"A-1,Caf\xe9,crown,high,none\n",
            "binary_garbage": bytes(range(256)) * 40,
            "nul_bytes": self.HEAD + b"A-1\x00,Pump,crown,high,none\n",
            "unterminated_quote": self.HEAD + b'A-1,"never closed,crown,high,none\n',
            "old_mac_line_endings": self.HEAD.replace(b"\n", b"\r") + b"A-1,Pump,crown,high,none\r",
            "huge_cell": self.HEAD + b"A-1," + b"x" * 300_000 + b",crown,high,none\n",
            "huge_id": self.HEAD + b"x" * 300_000 + b",Pump,crown,high,none\n",
            "formula_cells": self.HEAD + b'"=HYPERLINK(""http://x"")",=cmd|x,crown,high,none\n',
            "control_characters": self.HEAD + b"A\x1b[2J-1,Pu\x07mp,crown,high,none\n",
            "bidi_and_invisible": self.HEAD + "A-\u202e1,Pu\u200bmp,crown,high,none\n".encode(),
            "one_asset_a_thousand_times": self.HEAD + b"A-1,Pump,crown,high,none\n" * 1000,
            "thousands_of_duplicate_pairs": self.HEAD + b"".join(row % (i // 2) for i in range(4000)),
            "thousands_of_bad_rows": self.HEAD + b"A-1,Pump,nonsense,high,none\n" * 5000,
            "ragged_rows": self.HEAD + b"A\nB,x\nC,x,crown,high,none,extra,extra\n",
            "requirement_values_hostile": b"asset_id,confidentiality,integrity,availability\n"
                                          b"A,=cmd|x,\x1b[2J,\xe2\x80\xaehigh\nB," + b"x" * 300_000 + b",low,low\n",
            "requirement_values_valid_and_odd": (b"asset_id,CR,IR,AR\nA,HIGH,low,M\nB,not defined,x,\n"
                                                 b"C,Low ,\tmedium,H\n"),
            "requirement_columns_only": b"asset_id,availability\n" + b"A-1,high\n" * 500,
        }

    def test_every_hostile_inventory_is_loaded_safely_or_refused_cleanly(self):
        for name, data in self.cases().items():
            with self.subTest(case=name):
                try:
                    inv = inventory.load(self.path(name, data))
                except ValueError:
                    continue
                self.assertLessEqual(len(inv.problems), inventory.MAX_PROBLEMS)
                for record in inv.records.values():
                    self.assertTrue(record.asset_id.isprintable() and record.name.isprintable())
                    self.assertLessEqual(len(record.asset_id), inventory.MAX_KEY_CHARS)
                inv.summary()

    def test_a_file_over_the_size_limit_is_refused_without_being_read(self):
        path = self.path("toobig", self.HEAD + b"A,B,crown,high,none\n" * 300_000)
        with mock.patch.object(inventory, "MAX_FILE_BYTES", 1024 * 1024), mock.patch("builtins.open") as opened, \
                self.assertRaisesRegex(ValueError, "larger than"):
            inventory.load(path)
        opened.assert_not_called()

    def test_a_hostile_inventory_cannot_inject_into_the_exported_results(self):
        inv = inventory.load(self.path("f", self.cases()["formula_cells"]))
        findings = self.path("find", b"id,asset_id,cvss,threat\nF1,=cmd|x,5,none\n")
        items = batch.process_file(findings, inventory=inv)
        out = os.path.join(self.dir, "out.csv")
        batch.write_results(out, items)
        with open(out, newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                for value in row.values():
                    self.assertFalse(value[:1] in ("=", "+", "-", "@"), value)


class MaliciousAdvisoryArchiveTests(unittest.TestCase):
    """Hostile CISA advisory archives, at their real limits: each is refused or read safely, quickly, and a refused
    file never replaces the advisories already stored."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.base = Path(cls.dir.name)

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def setUp(self):
        self.store = self.base / "store"
        self.good = self.base / "good.tar.gz"
        self.good.write_bytes(good(advisory()))
        self.assertTrue(icsadvisories.import_from_file(self.good, self.store).ok)
        self.before = (self.store / icsadvisories.ICS_FILE).read_bytes()

    def tar_gz_file(self, name, write):
        path = self.base / name
        with gzip.open(path, "wb", compresslevel=9) as raw, tarfile.open(fileobj=raw, mode="w|") as tar:
            write(tar)
        return path

    def run_case(self, path):
        start = time.monotonic()
        result = icsadvisories.import_from_file(path, self.store)
        self.assertLess(time.monotonic() - start, TIME_LIMIT_SECONDS, path.name)
        return result

    def assert_refused_and_kept(self, path):
        result = self.run_case(path)
        self.assertFalse(result.ok, result.message)
        self.assertEqual((self.store / icsadvisories.ICS_FILE).read_bytes(), self.before)
        return result

    def test_a_gzip_bomb_that_expands_past_the_limit_is_stopped_while_reading(self):
        def write(tar):
            info = tarfile.TarInfo(f"{ROOT}/../padding.bin")
            info.size = icsadvisories.ICS_MAX_STREAM + 50 * 1024 * 1024
            tar.addfile(info, _Zeros(info.size))
        path = self.tar_gz_file("bomb.tar.gz", write)
        self.assertLess(path.stat().st_size, 20 * 1024 * 1024, "the bomb should be small on disk")
        self.assertIn("expands to more than", self.assert_refused_and_kept(path).message)

    def test_a_flood_of_empty_entries_is_stopped(self):
        def write(tar):
            for n in range(icsadvisories.ICS_MAX_MEMBERS + 100):
                tar.addfile(tarfile.TarInfo(f"CSAF-develop/e{n}"))
        self.assertIn("entries", self.assert_refused_and_kept(self.tar_gz_file("flood.tar.gz", write)).message)

    def test_hostile_entry_names_and_types_are_never_used(self):
        evil = advisory("ICSA-26-099-01", cves=("CVE-2026-9999",))
        raw = json.dumps(evil).encode()

        def write(tar):
            good_info = tarfile.TarInfo(member_path("ICSA-26-006-01"))
            body = json.dumps(advisory()).encode()
            good_info.size = len(body)
            tar.addfile(good_info, io.BytesIO(body))
            names = ["../../../../tmp/icsa-26-099-01.json", "/etc/icsa-26-099-01.json",
                     f"{ROOT}/2026/../../../../x/icsa-26-099-01.json", f"{ROOT}\\2026\\icsa-26-099-01.json",
                     "CSAF-develop/csaf_files/IT/white/2026/icsa-26-099-01.json",
                     f"{ROOT}/2026/icsa-26-099-01.json.asc",
                     f"{ROOT}/2026/ICSA-26-099-01.json", f"{ROOT}/2026/icsa-26-099-01.json\n",
                     f"{ROOT}/2026/icsa-26-099-01.json.png"]
            for name in names:
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
            for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
                info = tarfile.TarInfo(member_path("ICSA-26-098-01"))
                info.type, info.linkname = kind, "/etc/passwd"
                tar.addfile(info)
        path = self.tar_gz_file("names.tar.gz", write)
        self.assertTrue(self.run_case(path).ok)
        data, _warnings = icsadvisories.load(self.store)
        self.assertEqual(set(data.advisories), {"ICSA-26-006-01"})
        self.assertEqual(data.lookup("CVE-2026-9999"), ((), 0))
        self.assertFalse((Path(tempfile.gettempdir()) / "icsa-26-099-01.json").exists())

    def test_a_header_that_claims_a_huge_file_is_refused_without_reading_it(self):
        def write(tar):
            info = tarfile.TarInfo(member_path("ICSA-26-006-01"))
            info.size = 3 * 1024 ** 3
            tar.addfile(info, _Zeros(info.size))
        self.assert_refused_and_kept(self.tar_gz_file("claims.tar.gz", write))

    def test_hostile_advisory_content_is_neutralised(self):
        title = "=HYPERLINK(\"http://evil.example\") \x1b[31m\u202e\u200b"
        hostile = advisory("ICSA-26-006-01", title, ("CVE-2025-61939",), "<script>alert(1)</script>\x00")
        hostile["document"]["references"] = [{"category": "self", "url": "javascript:alert(1)"}]
        path = self.base / "hostile.tar.gz"
        path.write_bytes(good(hostile))
        self.assertTrue(self.run_case(path).ok)
        data, _warnings = icsadvisories.load(self.store)
        found = data.lookup("CVE-2025-61939")[0][0]
        for text in (found.title, *found.vendors):
            self.assertTrue(text.isprintable(), repr(text))
            self.assertNotIn("\u202e", text)
        self.assertEqual(found.url, "https://www.cisa.gov/news-events/ics-advisories/icsa-26-006-01")

    def test_random_garbage_wrapped_in_gzip_and_tar_framing_is_refused(self):
        for name, payload in (("g1", b"\0" * 512 * 3), ("g2", os.urandom(4096)), ("g3", b"ustar" * 200)):
            with self.subTest(name):
                path = self.base / f"{name}.tar.gz"
                path.write_bytes(gzip.compress(payload))
                self.assert_refused_and_kept(path)


class _Zeros(io.RawIOBase):
    """A file-like object of a given size that is all zeros, produced as it is read (no memory used)."""

    def __init__(self, size):
        self.left = size

    def readable(self):
        return True

    def readinto(self, buffer):
        count = min(len(buffer), self.left)
        buffer[:count] = bytes(count)
        self.left -= count
        return count


if __name__ == "__main__":
    unittest.main()
