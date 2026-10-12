"""Tests for the CISA ICS advisories index: parsing hostile archives, storage, update and import."""
import gzip
import io
import json
import sys
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

try:
    from hypothesis import given
    from hypothesis import settings as hyp_settings
    from hypothesis import strategies as st
except ImportError:  # hypothesis is an optional test dependency
    st = None

import icsadvisories as ics
import threatdata as td

ROOT = "CSAF-develop/csaf_files/OT/white"


def advisory(ident="ICSA-26-006-01", title="Columbia Weather Systems MicroServer", cves=("CVE-2025-61939",),
             vendor="Columbia Weather Systems", published="2026-01-06T06:00:00.000000Z",
             updated="2026-01-06T06:00:00.000000Z"):
    return {
        "document": {"title": title, "tracking": {"id": ident, "initial_release_date": published,
                                                    "current_release_date": updated}},
        "product_tree": {"branches": [{"category": "vendor", "name": vendor, "branches": []}]},
        "vulnerabilities": [{"cve": c} for c in cves],
    }


def member_path(ident):
    year = ident.split("-")[1]
    return f"{ROOT}/20{year}/{ident.lower()}.json"


def archive(files, extra=()):
    """Build a tar.gz from (path, bytes-or-dict) pairs; extra holds ready-made TarInfo, bytes pairs."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path, content in files:
            raw = content if isinstance(content, bytes) else json.dumps(content).encode("utf-8")
            info = tarfile.TarInfo(path)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
        for info, raw in extra:
            tar.addfile(info, io.BytesIO(raw))
    return buffer.getvalue()


def good(*docs):
    return archive([(member_path(d["document"]["tracking"]["id"]), d) for d in docs])


class ParseArchiveTests(unittest.TestCase):
    def test_reads_an_advisory_and_its_cves(self):
        data = ics.parse_archive(good(advisory()))
        found, count = data.lookup("cve-2025-61939")
        self.assertEqual(count, 1)
        self.assertEqual(found[0].id, "ICSA-26-006-01")
        self.assertEqual(found[0].title, "Columbia Weather Systems MicroServer")
        self.assertEqual(found[0].vendors, ("Columbia Weather Systems",))
        self.assertEqual((found[0].published, found[0].updated), ("2026-01-06", "2026-01-06"))
        self.assertEqual(data.feed_date, "2026-01-06")

    def test_unknown_cve_finds_nothing(self):
        found, count = ics.parse_archive(good(advisory())).lookup("CVE-2020-0001")
        self.assertEqual((found, count), ((), 0))

    def test_the_link_is_built_from_the_advisory_number_never_copied_from_the_file(self):
        doc = advisory()
        doc["document"]["references"] = [{"category": "self", "url": "https://evil.example/phish"}]
        found = ics.parse_archive(good(doc)).lookup("CVE-2025-61939")[0][0]
        self.assertEqual(found.url, "https://www.cisa.gov/news-events/ics-advisories/icsa-26-006-01")

    def test_a_medical_advisory_links_to_the_medical_section(self):
        found = ics.parse_archive(good(advisory("ICSMA-26-010-01", cves=("CVE-2026-0001",)))).lookup(
            "CVE-2026-0001")[0][0]
        self.assertEqual(found.url, "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-010-01")

    def test_a_revision_letter_is_part_of_the_advisory_number(self):
        found = ics.parse_archive(good(advisory("ICSA-10-316-01A", cves=("CVE-2010-0001",)))).lookup(
            "CVE-2010-0001")[0][0]
        self.assertEqual(found.url, "https://www.cisa.gov/news-events/ics-advisories/icsa-10-316-01a")

    def test_newest_advisory_first_and_the_count_is_the_real_total(self):
        docs = [advisory(f"ICSA-26-{n:03d}-01", cves=("CVE-2026-0001",), updated=f"2026-02-{n:02d}T00:00:00Z")
                for n in range(1, 9)]
        found, count = ics.parse_archive(good(*docs)).lookup("CVE-2026-0001")
        self.assertEqual(count, 8)
        self.assertEqual(len(found), ics.MAX_LISTED)
        self.assertEqual(found[0].id, "ICSA-26-008-01")
        self.assertEqual([a.updated for a in found], sorted((a.updated for a in found), reverse=True))

    def test_advisories_that_name_no_cve_are_left_out(self):
        data = ics.parse_archive(good(advisory(), advisory("ICSA-26-007-01", cves=())))
        self.assertEqual(set(data.advisories), {"ICSA-26-006-01"})

    def test_text_is_cleaned_and_limited(self):
        doc = advisory(title="Evil\x00\u202e Title\n" + "x" * 500, vendor="Ven\x07dor" + "y" * 200)
        found = ics.parse_archive(good(doc)).lookup("CVE-2025-61939")[0][0]
        self.assertLessEqual(len(found.title), ics.MAX_TITLE_CHARS)
        self.assertNotIn("\x00", found.title)
        self.assertNotIn("\u202e", found.title)
        self.assertNotIn("\n", found.title)
        self.assertLessEqual(len(found.vendors[0]), ics.MAX_VENDOR_CHARS)
        self.assertNotIn("\x07", found.vendors[0])

    def test_a_trailing_new_line_does_not_make_a_name_pass(self):
        evil = advisory("ICSA-26-099-01", cves=("CVE-2026-9999",))
        data = ics.parse_archive(archive([(member_path("ICSA-26-006-01"), advisory()),
                                          (member_path("ICSA-26-099-01") + "\n", evil)]))
        self.assertEqual(set(data.advisories), {"ICSA-26-006-01"})
        padded = ics.parse_archive(good(advisory(ident="ICSA-26-007-01", cves=("CVE-2026-0002\n", "CVE-2026-0003"))))
        self.assertEqual(padded.lookup("CVE-2026-0002")[1], 0)
        self.assertEqual(padded.lookup("CVE-2026-0003")[1], 1)

    def test_files_outside_the_ot_advisory_folder_are_ignored(self):
        evil = advisory("ICSA-26-099-01", cves=("CVE-2026-9999",))
        files = [(member_path("ICSA-26-006-01"), advisory()),
                 ("CSAF-develop/csaf_files/IT/white/2026/icsa-26-099-01.json", evil),
                 ("../../etc/icsa-26-099-01.json", evil),
                 ("/abs/csaf_files/OT/white/2026/../2026/icsa-26-099-01.json", evil),
                 (f"{ROOT}/2026/sub/icsa-26-099-01.json", evil)]
        data = ics.parse_archive(archive(files))
        self.assertEqual(set(data.advisories), {"ICSA-26-006-01"})
        self.assertEqual(data.lookup("CVE-2026-9999"), ((), 0))

    def test_links_and_devices_in_the_archive_are_not_read(self):
        link = tarfile.TarInfo(member_path("ICSA-26-099-01"))
        link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
        device = tarfile.TarInfo(member_path("ICSA-26-098-01"))
        device.type = tarfile.CHRTYPE
        data = ics.parse_archive(archive([(member_path("ICSA-26-006-01"), advisory())],
                                         extra=[(link, b""), (device, b"")]))
        self.assertEqual(set(data.advisories), {"ICSA-26-006-01"})


class SkippedAdvisoryTests(unittest.TestCase):
    def archive_with(self, bad, good_count=30):
        files = [(member_path(f"ICSA-26-{n:03d}-01"), advisory(f"ICSA-26-{n:03d}-01", cves=(f"CVE-2026-{n:04d}",)))
                 for n in range(1, good_count + 1)]
        return archive(files + bad)

    def test_one_unreadable_advisory_is_skipped_not_fatal(self):
        data = ics.parse_archive(self.archive_with([(member_path("ICSA-26-200-01"), b"{not json")]))
        self.assertEqual(len(data.advisories), 30)

    def test_each_kind_of_bad_advisory_is_skipped(self):
        bad_docs = {
            "id does not match the file": ("ICSA-26-201-01", advisory("ICSA-26-999-01")),
            "id is not an advisory number": ("ICSA-26-202-01", advisory("../../x")),
            "no title": ("ICSA-26-203-01", advisory(title="")),
            "bad date": ("ICSA-26-204-01", advisory(published="yesterday")),
            "title not text": ("ICSA-26-205-01", {**advisory("ICSA-26-205-01"), "document": {
                "title": 5, "tracking": advisory()["document"]["tracking"]}}),
            "no tracking": ("ICSA-26-206-01", {"document": {"title": "t"}}),
            "document not an object": ("ICSA-26-207-01", {"document": []}),
            "vulnerabilities not a list": ("ICSA-26-208-01", {**advisory("ICSA-26-208-01"), "vulnerabilities": {}}),
            "not an object": ("ICSA-26-209-01", []),
        }
        for label, (ident, doc) in bad_docs.items():
            with self.subTest(label):
                if label == "id does not match the file":
                    doc["document"]["tracking"]["id"] = "ICSA-26-999-01"
                data = ics.parse_archive(self.archive_with([(member_path(ident), doc)]))
                self.assertNotIn(ident, data.advisories)
                self.assertEqual(len(data.advisories), 30)

    def test_json_tricks_are_refused(self):
        tricks = {
            "duplicate keys": b'{"document": {}, "document": {}}',
            "NaN": b'{"document": {"title": NaN}}',
            "deep nesting": b"[" * 100000 + b"]" * 100000,
            "not utf-8": b"\xff\xfe\x00{",
            "empty": b"",
        }
        for label, raw in tricks.items():
            with self.subTest(label):
                data = ics.parse_archive(self.archive_with([(member_path("ICSA-26-210-01"), raw)]))
                self.assertEqual(len(data.advisories), 30)

    def test_a_product_tree_that_is_too_deep_or_too_big_is_skipped(self):
        deep = advisory("ICSA-26-211-01")
        node = {"category": "vendor", "name": "x"}
        for _ in range(ics.MAX_TREE_DEPTH + 5):
            node = {"branches": [node]}
        deep["product_tree"] = node
        wide = advisory("ICSA-26-212-01")
        wide["product_tree"] = {"branches": [{"name": str(i)} for i in range(ics.MAX_TREE_NODES + 5)]}
        data = ics.parse_archive(self.archive_with([(member_path("ICSA-26-211-01"), deep),
                                                    (member_path("ICSA-26-212-01"), wide)]))
        self.assertEqual(len(data.advisories), 30)

    def test_an_advisory_naming_too_many_cves_is_skipped(self):
        many = advisory("ICSA-26-213-01", cves=[f"CVE-2026-{n:05d}" for n in range(ics.ICS_MAX_CVES + 1)])
        data = ics.parse_archive(self.archive_with([(member_path("ICSA-26-213-01"), many)]))
        self.assertNotIn("ICSA-26-213-01", data.advisories)

    def test_an_oversized_advisory_file_is_skipped_without_being_read(self):
        # Valid JSON, so the only reason to skip it is its size
        big = json.dumps(advisory("ICSA-26-214-01", cves=("CVE-2026-9214",))).encode() + \
            b" " * ics.ICS_MAX_ADVISORY_BYTES
        data = ics.parse_archive(self.archive_with([(member_path("ICSA-26-214-01"), big)]))
        self.assertEqual(len(data.advisories), 30)
        self.assertNotIn("ICSA-26-214-01", data.advisories)
        small = json.dumps(advisory("ICSA-26-215-01", cves=("CVE-2026-9215",))).encode() + b" " * 1000
        self.assertIn("ICSA-26-215-01", ics.parse_archive(self.archive_with(
            [(member_path("ICSA-26-215-01"), small)])).advisories)

    def test_invalid_cve_ids_are_ignored_and_duplicates_collapse(self):
        doc = advisory("ICSA-26-215-01", cves=("CVE-2026-1111", "cve-2026-1111", "CVE-2026-1111", "nope", "CVE-1-2"))
        data = ics.parse_archive(self.archive_with([(member_path("ICSA-26-215-01"), doc)]))
        self.assertEqual(data.lookup("CVE-2026-1111")[1], 1)
        self.assertEqual(data.lookup("CVE-2026-1111")[0][0].id, "ICSA-26-215-01")

    def test_too_many_unreadable_advisories_means_the_format_has_changed(self):
        bad = [(member_path(f"ICSA-26-{n:03d}-02"), b"{") for n in range(1, 40)]
        with self.assertRaisesRegex(td.ThreatDataError, "format changed"):
            ics.parse_archive(self.archive_with(bad, good_count=30))

    def test_nothing_readable_is_an_error(self):
        with self.assertRaisesRegex(td.ThreatDataError, "no readable"):
            ics.parse_archive(archive([(member_path("ICSA-26-001-01"), b"{")]))
        with self.assertRaisesRegex(td.ThreatDataError, "no readable"):
            ics.parse_archive(archive([("README.md", b"hello")]))


class HostileArchiveTests(unittest.TestCase):
    def test_not_gzip_is_refused(self):
        for raw in (b"", b"hello", b"PK\x03\x04" + b"0" * 50, b"\x1f\x8b"):
            with self.subTest(raw=raw[:6]), self.assertRaises(td.ThreatDataError):
                ics.parse_archive(raw)

    def test_a_truncated_download_is_refused(self):
        raw = good(advisory())
        for cut in (len(raw) - 1, len(raw) // 2, 12):
            with self.subTest(cut=cut), self.assertRaises(td.ThreatDataError):
                ics.parse_archive(raw[:cut])

    def test_gzip_wrapping_something_that_is_not_a_tar_is_refused(self):
        with self.assertRaises(td.ThreatDataError):
            ics.parse_archive(gzip.compress(b"this is not a tar file" * 100))

    def test_a_decompression_bomb_is_stopped(self):
        old = ics.ICS_MAX_STREAM
        ics.ICS_MAX_STREAM = 2 * 1024 * 1024
        try:
            info = tarfile.TarInfo("CSAF-develop/README")
            info.size = 8 * 1024 * 1024
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
                tar.addfile(info, io.BytesIO(b"\0" * info.size))
            self.assertLess(len(buffer.getvalue()), 100_000)
            with self.assertRaisesRegex(td.ThreatDataError, "expands to more than"):
                ics.parse_archive(buffer.getvalue())
        finally:
            ics.ICS_MAX_STREAM = old

    def test_too_many_entries_are_refused(self):
        old = ics.ICS_MAX_MEMBERS
        ics.ICS_MAX_MEMBERS = 20
        try:
            files = [(f"CSAF-develop/f{n}", b"x") for n in range(30)]
            with self.assertRaisesRegex(td.ThreatDataError, "more than 20 entries"):
                ics.parse_archive(archive(files))
        finally:
            ics.ICS_MAX_MEMBERS = old

    def test_too_many_advisories_are_refused(self):
        old = ics.ICS_MAX_ADVISORIES
        ics.ICS_MAX_ADVISORIES = 5
        try:
            docs = [advisory(f"ICSA-26-{n:03d}-01", cves=(f"CVE-2026-{n:04d}",)) for n in range(1, 9)]
            with self.assertRaisesRegex(td.ThreatDataError, "more than 5 advisories"):
                ics.parse_archive(good(*docs))
        finally:
            ics.ICS_MAX_ADVISORIES = old

    def test_the_same_advisory_number_twice_is_refused(self):
        again = (f"{ROOT}/2027/icsa-26-006-01.json", advisory())
        raw = archive([(member_path("ICSA-26-006-01"), advisory()), again])
        with self.assertRaisesRegex(td.ThreatDataError, "listed twice"):
            ics.parse_archive(raw)

    def test_a_download_over_the_limit_is_refused_before_reading(self):
        with self.assertRaisesRegex(td.ThreatDataError, "larger than"):
            ics.parse_archive(b"\x1f\x8b" + b"\0" * (ics.ICS_MAX_COMPRESSED + 1))


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.data = ics.parse_archive(good(
            advisory(), advisory("ICSA-26-007-01", "Other Product", ("CVE-2025-61939", "CVE-2026-0002"), "Other Co")))
        self.index = json.loads(ics.to_index(self.data))

    def reload(self, doc):
        return ics.parse_index(json.dumps(doc).encode("utf-8"))

    def test_the_index_round_trips(self):
        again = ics.parse_index(ics.to_index(self.data))
        self.assertEqual(again.advisories, self.data.advisories)
        self.assertEqual(again.by_cve, self.data.by_cve)
        self.assertEqual(again.feed_date, self.data.feed_date)

    def test_the_index_is_the_same_each_time(self):
        self.assertEqual(ics.to_index(self.data), ics.to_index(ics.parse_index(ics.to_index(self.data))))

    def test_a_stored_index_is_checked_as_strictly_as_a_download(self):
        def mutate(change):
            doc = json.loads(json.dumps(self.index))
            change(doc)
            return doc

        cases = {
            "unknown version": mutate(lambda d: d.update(version=2)),
            "count mismatch": mutate(lambda d: d.update(count=99)),
            "no advisories": mutate(lambda d: d.update(advisories=[], count=0)),
            "extra field": mutate(lambda d: d["advisories"][0].update(url="https://evil.example")),
            "missing field": mutate(lambda d: d["advisories"][0].pop("title")),
            "bad id": mutate(lambda d: d["advisories"][0].update(id="../x")),
            "bad cve": mutate(lambda d: d["advisories"][0].update(cves=["nope"])),
            "cve with a trailing new line": mutate(lambda d: d["advisories"][0].update(cves=["CVE-2025-61939\n"])),
            "id with a trailing new line": mutate(lambda d: d["advisories"][0].update(id="ICSA-26-006-01\n")),
            "empty cve list": mutate(lambda d: d["advisories"][0].update(cves=[])),
            "repeated cve": mutate(lambda d: d["advisories"][0].update(cves=["CVE-2025-61939"] * 2)),
            "bad date": mutate(lambda d: d["advisories"][0].update(updated="soon")),
            "title with control characters": mutate(lambda d: d["advisories"][0].update(title="a\x00b")),
            "title not text": mutate(lambda d: d["advisories"][0].update(title=7)),
            "vendors not a list": mutate(lambda d: d["advisories"][0].update(vendors="Acme")),
            "too many vendors": mutate(lambda d: d["advisories"][0].update(vendors=["a"] * 9)),
            "same advisory twice": mutate(lambda d: d["advisories"].append(dict(d["advisories"][0])) or
                                          d.update(count=3)),
            "row not an object": mutate(lambda d: d["advisories"].__setitem__(0, 5)),
            "not an object": [],
        }
        for label, doc in cases.items():
            with self.subTest(label), self.assertRaises(td.ThreatDataError):
                self.reload(doc)

    def test_garbage_is_refused(self):
        for raw in (b"", b"{", b"\xff\xfe", b"null", b"[]", b'{"version": 1, "version": 1}', b"NaN"):
            with self.subTest(raw=raw), self.assertRaises(td.ThreatDataError):
                ics.parse_index(raw)

    def test_an_index_over_the_limit_is_refused(self):
        with self.assertRaisesRegex(td.ThreatDataError, "larger than"):
            ics.parse_index(b" " * (ics.ICS_MAX_INDEX_BYTES + 1))


@unittest.skipIf(st is None, "hypothesis is not installed")
class IcsFuzzTests(unittest.TestCase):
    if st is not None:
        @hyp_settings(max_examples=300, deadline=None)
        @given(st.binary(max_size=4000))
        def test_any_bytes_as_a_download_are_refused_cleanly(self, raw):
            try:
                ics.parse_archive(raw)
            except td.ThreatDataError:
                pass

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.binary(max_size=4000))
        def test_any_gzip_wrapped_bytes_are_refused_or_read_cleanly(self, raw):
            try:
                data = ics.parse_archive(gzip.compress(raw))
            except td.ThreatDataError:
                return
            self.assertTrue(data.advisories)

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.binary(max_size=4000))
        def test_any_bytes_as_a_stored_index_are_refused_cleanly(self, raw):
            try:
                ics.parse_index(raw)
            except td.ThreatDataError:
                pass

        json_values = st.recursive(
            st.none() | st.booleans() | st.integers() | st.text(max_size=40),
            lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children,
                                                                                max_size=5),
            max_leaves=20)

        @hyp_settings(max_examples=300, deadline=None)
        @given(json_values)
        def test_any_json_as_an_advisory_is_skipped_or_read_with_clean_text(self, doc):
            raw = json.dumps(doc).encode("utf-8")
            try:
                found, cves = ics._read_advisory(raw, "icsa-26-006-01")
            except ValueError:
                return
            self.assertTrue(found.title.isprintable())
            self.assertLessEqual(len(found.title), ics.MAX_TITLE_CHARS)
            self.assertTrue(all(td.CVE_RE.match(c) for c in cves))
            self.assertTrue(found.url.startswith("https://www.cisa.gov/news-events/ics"))

        @hyp_settings(max_examples=200, deadline=None)
        @given(st.text(max_size=300), st.text(max_size=100), st.lists(st.text(max_size=20), max_size=4))
        def test_any_text_in_an_advisory_is_stored_clean_and_reads_back_the_same(self, title, vendor, cves):
            doc = advisory(title=title, vendor=vendor, cves=[*cves, "CVE-2026-0001"])
            try:
                data = ics.parse_archive(good(doc))
            except td.ThreatDataError:
                return                          # a title that cleans to nothing is skipped, leaving no advisories
            again = ics.parse_index(ics.to_index(data))
            self.assertEqual((again.advisories, again.by_cve), (data.advisories, data.by_cve))
            for found in data.advisories.values():
                self.assertTrue(found.title.isprintable() and all(v.isprintable() for v in found.vendors))


class FakeFetcher:
    def __init__(self, body=None, error=None):
        self.body, self.error, self.calls = body, error, []

    def __call__(self, url, cap, hosts, **kwargs):
        self.calls.append((url, cap, hosts, kwargs))
        if self.error:
            raise self.error
        return self.body


class StorageTests(unittest.TestCase):
    NOW = td._now()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def update(self, body, **kwargs):
        return ics.update_from_network(self.dir, FakeFetcher(body), self.NOW, **kwargs)

    def test_update_downloads_validates_and_stores(self):
        fetcher = FakeFetcher(good(advisory()))
        result = ics.update_from_network(self.dir, fetcher, self.NOW)
        self.assertTrue(result.ok, result.message)
        self.assertIn("1 advisories naming 1 CVEs", result.message)
        self.assertEqual(fetcher.calls[0][0], ics.ICS_URL)
        self.assertEqual(fetcher.calls[0][2], ics.ICS_HOSTS)
        data, warnings = ics.load(self.dir)
        self.assertEqual(warnings, [])
        self.assertEqual(data.lookup("CVE-2025-61939")[1], 1)

    def test_only_the_expected_https_host_is_allowed(self):
        self.assertTrue(ics.ICS_URL.startswith("https://codeload.github.com/"))
        self.assertEqual(ics.ICS_HOSTS, frozenset({"codeload.github.com"}))
        with self.assertRaises(td.FetchError):
            td.fetch("http://codeload.github.com/cisagov/CSAF/tar.gz/refs/heads/develop", 1000, ics.ICS_HOSTS)
        with self.assertRaises(td.FetchError):
            td.fetch("https://evil.example/x.tar.gz", 1000, ics.ICS_HOSTS)

    def test_a_failed_download_keeps_the_previous_copy(self):
        self.assertTrue(self.update(good(advisory())).ok)
        before = (self.dir / ics.ICS_FILE).read_bytes()
        result = ics.update_from_network(self.dir, FakeFetcher(error=td.FetchError("the connection timed out")),
                                         self.NOW)
        self.assertFalse(result.ok)
        self.assertIn("previous copy was kept", result.message)
        self.assertEqual((self.dir / ics.ICS_FILE).read_bytes(), before)

    def test_an_index_that_does_not_read_back_is_never_stored(self):
        self.assertTrue(self.update(good(advisory())).ok)
        before = (self.dir / ics.ICS_FILE).read_bytes()
        with mock.patch.object(ics, "to_index", return_value=b'{"version": 1}'):
            result = self.update(good(advisory("ICSA-26-007-01", cves=("CVE-2026-0002",))))
        self.assertFalse(result.ok)
        self.assertEqual((self.dir / ics.ICS_FILE).read_bytes(), before)

    def test_invalid_data_keeps_the_previous_copy(self):
        self.assertTrue(self.update(good(advisory())).ok)
        before = (self.dir / ics.ICS_FILE).read_bytes()
        for body in (b"<html>blocked</html>", b"", good(), gzip.compress(b"nope")):
            with self.subTest(body=body[:8]):
                result = self.update(body)
                self.assertFalse(result.ok)
                self.assertEqual((self.dir / ics.ICS_FILE).read_bytes(), before)

    def test_cancelling_does_nothing(self):
        flag = threading.Event()
        flag.set()
        fetcher = FakeFetcher(good(advisory()))
        result = ics.update_from_network(self.dir, fetcher, self.NOW, cancel=flag)
        self.assertFalse(result.ok)
        self.assertEqual(fetcher.calls, [])
        self.assertFalse((self.dir / ics.ICS_FILE).exists())

    def test_progress_is_reported(self):
        messages = []
        self.update(good(advisory()), progress=messages.append)
        self.assertEqual(messages, ["Downloading ICS advisories..."])

    def test_import_reads_a_downloaded_archive(self):
        path = self.dir / "CSAF-develop.tar.gz"
        path.write_bytes(good(advisory()))
        result = ics.import_from_file(path, self.dir, self.NOW)
        self.assertTrue(result.ok, result.message)
        self.assertEqual(ics.load(self.dir)[0].lookup("CVE-2025-61939")[1], 1)
        self.assertIn("file import: CSAF-develop.tar.gz", (self.dir / ics.ICS_META_FILE).read_text())

    def test_import_refuses_bad_files_and_keeps_the_previous_copy(self):
        self.assertTrue(self.update(good(advisory())).ok)
        before = (self.dir / ics.ICS_FILE).read_bytes()
        for name, raw in (("a.tar.gz", b"hello"), ("b.tar.gz", good()), ("c.tar.gz", b"\x1f\x8b" + b"0" * 60)):
            with self.subTest(name):
                (self.dir / name).write_bytes(raw)
                self.assertFalse(ics.import_from_file(self.dir / name, self.dir, self.NOW).ok)
        self.assertFalse(ics.import_from_file(self.dir / "missing.tar.gz", self.dir, self.NOW).ok)
        self.assertFalse(ics.import_from_file(self.dir, self.dir, self.NOW).ok)
        self.assertEqual((self.dir / ics.ICS_FILE).read_bytes(), before)

    def test_import_refuses_a_file_over_the_limit_without_reading_it(self):
        old = ics.ICS_MAX_COMPRESSED
        ics.ICS_MAX_COMPRESSED = 1000
        try:
            (self.dir / "big.tar.gz").write_bytes(b"\x1f\x8b" + b"0" * 2000)
            result = ics.import_from_file(self.dir / "big.tar.gz", self.dir, self.NOW)
            self.assertFalse(result.ok)
            self.assertIn("larger than", result.message)
        finally:
            ics.ICS_MAX_COMPRESSED = old

    def test_a_corrupted_stored_index_becomes_a_warning(self):
        self.assertTrue(self.update(good(advisory())).ok)
        (self.dir / ics.ICS_FILE).write_bytes(b'{"version": 1')
        data, warnings = ics.load(self.dir)
        self.assertIsNone(data)
        self.assertIn("could not be used", warnings[0])
        self.assertTrue(ics.status(self.dir).problem)

    def test_nothing_stored_is_not_an_error(self):
        self.assertEqual(ics.load(self.dir), (None, []))
        status = ics.status(self.dir)
        self.assertFalse(status.loaded)
        self.assertEqual(status.problem, "")
        self.assertTrue(status.freshness(30).missing)

    def test_status_describes_what_is_stored(self):
        self.update(good(advisory(), advisory("ICSA-26-007-01", cves=("CVE-2026-0002",))))
        status = ics.status(self.dir)
        self.assertTrue(status.loaded)
        self.assertEqual((status.count, status.date), (2, "2026-01-06"))
        self.assertEqual(status.version_text, "updated 2026-01-06")
        fresh = status.freshness(30, self.NOW)
        self.assertFalse(fresh.stale)
        self.assertIn("retrieved 0 days ago", fresh.text)

    @unittest.skipIf(sys.platform == "win32", "Windows has no permission bits to check")
    def test_stored_files_are_not_world_writable(self):
        self.update(good(advisory()))
        for name in (ics.ICS_FILE, ics.ICS_META_FILE):
            self.assertFalse((self.dir / name).stat().st_mode & 0o022)

    def test_the_meta_file_records_where_the_data_came_from(self):
        self.update(good(advisory()))
        meta = json.loads((self.dir / ics.ICS_META_FILE).read_text())
        self.assertEqual((meta["version"], meta["source"], meta["count"]), (1, ics.ICS_URL, "1"))
        self.assertEqual(len(meta["sha256"]), 64)

    def test_versions_text(self):
        data = ics.parse_archive(good(advisory()))
        self.assertEqual(ics.versions(data), "ICS advisories 2026-01-06")
        self.assertEqual(ics.versions(None), "ICS advisories not loaded")


if __name__ == "__main__":
    unittest.main()
