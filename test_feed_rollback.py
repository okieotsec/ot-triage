"""A network update never replaces the stored threat data with an older or much smaller copy (CP23-02)."""
import datetime
import os
import tempfile
import unittest
from pathlib import Path

import icsadvisories as ics
import threatdata as td
from test_icsadvisories import advisory, good
from test_threatdata import epss_bytes, epss_text, kev_bytes, kev_entry

NOW = datetime.datetime(2026, 10, 7, 12, 0, tzinfo=datetime.UTC)


def kev(count, released="2026-10-04T18:52:56.0635Z"):
    return kev_bytes([kev_entry(f"CVE-2024-{n:04d}") for n in range(1, count + 1)], dateReleased=released)


def epss(count, day="2026-10-07"):
    rows = [f"CVE-2024-{n:04d},0.50000,0.97000" for n in range(1, count + 1)]
    return epss_bytes(epss_text(rows, first=f"#model_version:v2026.06.15,score_date:{day}T12:00:27Z"))


def archive(count, updated="2026-01-06T06:00:00.000000Z"):
    return good(*[advisory(f"ICSA-26-{n:03d}-01", cves=(f"CVE-2025-{n:05d}",), updated=updated)
                  for n in range(1, count + 1)])


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name) / "data"

    def fetcher(self, kev_body, epss_body):
        def fetch(url, max_bytes, allowed_hosts, **_kwargs):
            return kev_body if url == td.KEV_URL else epss_body
        return fetch

    def update(self, kev_body, epss_body):
        return td.update_from_network(self.dir, self.fetcher(kev_body, epss_body), NOW)

    def stored(self):
        return {name: (self.dir / name).read_bytes() for name in os.listdir(self.dir)}


class KevAndEpssTests(Case):
    def test_the_first_install_is_never_compared_with_anything(self):
        results = self.update(kev(3), epss(3))
        self.assertEqual([r.ok for r in results], [True, True])
        self.assertEqual([r.message for r in results], ["KEV updated.", "EPSS updated."])

    def test_an_older_download_is_refused_and_the_stored_copy_kept(self):
        self.update(kev(10), epss(10))
        before = self.stored()
        results = self.update(kev(10, "2026-10-01T00:00:00Z"), epss(10, "2026-10-05"))
        self.assertEqual([r.ok for r in results], [False, False])
        for result, word in zip(results, ("KEV", "EPSS"), strict=True):
            self.assertIn(f"{word} not updated: the download is older than the previous copy", result.message)
            self.assertIn("import a file if you are sure", result.message)
            self.assertIn("The previous copy was kept.", result.message)
        self.assertIn("(dated 2026-10-01, previous 2026-10-04)", results[0].message)
        self.assertIn("(dated 2026-10-05, previous 2026-10-07)", results[1].message)
        self.assertEqual(self.stored(), before)

    def test_the_same_or_a_newer_date_is_accepted(self):
        self.update(kev(10), epss(10))
        same = self.update(kev(10), epss(10))
        newer = self.update(kev(10, "2026-10-09T00:00:00Z"), epss(10, "2026-10-09"))
        self.assertEqual([r.ok for r in same + newer], [True] * 4)

    def test_a_much_smaller_download_is_refused_but_a_fall_of_exactly_the_limit_is_not(self):
        self.update(kev(100), epss(100))
        before = self.stored()
        refused = self.update(kev(79), epss(79))
        self.assertEqual([r.ok for r in refused], [False, False])
        self.assertIn("much smaller than the previous copy (79 entries against 100, a fall of 21%)",
                      refused[0].message)
        self.assertEqual(self.stored(), before)
        allowed = self.update(kev(80), epss(80))
        self.assertEqual([r.ok for r in allowed], [True, True])
        self.assertEqual(td.MAX_SHRINK_PERCENT, 20)

    def test_a_bigger_download_is_fine(self):
        self.update(kev(10), epss(10))
        self.assertEqual([r.ok for r in self.update(kev(500), epss(500))], [True, True])

    def test_both_reasons_are_given_together(self):
        self.update(kev(100), epss(100))
        message = self.update(kev(10, "2026-10-01T00:00:00Z"), epss(10, "2026-10-01"))[0].message
        self.assertIn("older than the previous copy", message)
        self.assertIn("much smaller than the previous copy", message)

    def test_one_refused_source_does_not_block_the_other(self):
        self.update(kev(10), epss(10))
        results = self.update(kev(10, "2026-10-01T00:00:00Z"), epss(10, "2026-10-09"))
        self.assertEqual([r.ok for r in results], [False, True])

    def test_a_damaged_stored_copy_can_always_be_replaced(self):
        self.update(kev(10), epss(10))
        (self.dir / td.KEV_FILE).write_bytes(b"not json")
        (self.dir / td.EPSS_FILE).write_bytes(b"not gzip")
        results = self.update(kev(2, "2026-09-01T00:00:00Z"), epss(2, "2026-09-01"))
        self.assertEqual([r.ok for r in results], [True, True])
        self.assertEqual(td.ThreatData.load(self.dir).warnings, [])

    def test_a_file_you_chose_is_allowed_with_a_note(self):
        self.update(kev(100), epss(100))
        old_kev, old_epss = self.dir.parent / "kev.json", self.dir.parent / "epss.csv"
        old_kev.write_bytes(kev(10, "2026-10-01T00:00:00Z"))
        old_epss.write_bytes(epss_text([f"CVE-2024-{n:04d},0.5,0.9" for n in range(1, 11)],
                                       first="#model_version:v2026.06.15,score_date:2026-10-01T12:00:27Z").encode())
        results = td.import_from_files(old_kev, old_epss, self.dir, NOW)
        self.assertEqual([r.ok for r in results], [True, True])
        for result in results:
            self.assertIn("Note: this file is older than the previous copy", result.message)
            self.assertIn("much smaller than the previous copy (10 entries against 100, a fall of 90%)",
                          result.message)
        self.assertEqual(len(td.ThreatData.load(self.dir).kev.entries), 10)

    def test_an_ordinary_file_import_has_no_note(self):
        self.update(kev(10), epss(10))
        path = self.dir.parent / "kev.json"
        path.write_bytes(kev(10, "2026-10-09T00:00:00Z"))
        self.assertEqual(td.import_from_files(path, None, self.dir, NOW)[0].message, "KEV updated.")


class IcsTests(Case):
    def update(self, body):
        return ics.update_from_network(self.dir, lambda url, cap, hosts, **kw: body, NOW)

    def test_an_older_or_much_smaller_archive_is_refused_and_the_stored_index_kept(self):
        self.assertTrue(self.update(archive(10)).ok)
        before = (self.dir / ics.ICS_FILE).read_bytes()
        older = self.update(archive(10, "2025-12-01T06:00:00.000000Z"))
        smaller = self.update(archive(7))
        self.assertFalse(older.ok)
        self.assertIn("older than the previous copy (dated 2025-12-01, previous 2026-01-06)", older.message)
        self.assertFalse(smaller.ok)
        self.assertIn("much smaller than the previous copy (7 entries against 10, a fall of 30%)", smaller.message)
        for result in (older, smaller):
            self.assertIn("The previous copy was kept.", result.message)
            self.assertIn("import a file if you are sure", result.message)
        self.assertEqual((self.dir / ics.ICS_FILE).read_bytes(), before)

    def test_the_same_newer_or_slightly_smaller_archive_is_accepted(self):
        self.assertTrue(self.update(archive(10)).ok)
        self.assertTrue(self.update(archive(10)).ok)
        self.assertTrue(self.update(archive(10, "2026-02-01T06:00:00.000000Z")).ok)
        self.assertTrue(self.update(archive(8, "2026-02-01T06:00:00.000000Z")).ok)

    def test_the_first_install_and_a_damaged_stored_index_are_not_compared(self):
        self.assertTrue(self.update(archive(3)).ok)
        (self.dir / ics.ICS_FILE).write_bytes(b"damaged")
        self.assertTrue(self.update(archive(2, "2025-01-01T06:00:00.000000Z")).ok)

    def test_a_file_you_chose_is_allowed_with_a_note(self):
        self.assertTrue(self.update(archive(10)).ok)
        path = self.dir.parent / "old.tar.gz"
        path.write_bytes(archive(3, "2025-06-01T06:00:00.000000Z"))
        result = ics.import_from_file(path, self.dir, NOW)
        self.assertTrue(result.ok, result.message)
        self.assertIn("Note: this file is older than the previous copy", result.message)
        self.assertIn("much smaller than the previous copy (3 entries against 10", result.message)
        self.assertEqual(len(ics.load(self.dir)[0].advisories), 3)


if __name__ == "__main__":
    unittest.main()
