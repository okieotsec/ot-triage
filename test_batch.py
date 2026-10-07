import csv
import os
import tempfile
import unittest

import batch
import threatdata as td
from prioritizer import Asset, Controls, Exposure, Patch, Threat

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLE = os.path.join(HERE, "sample_vulns.csv")


def write_csv(text):
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as fh:
        fh.write(text)
    return path


class SampleFileTests(unittest.TestCase):
    """The sample file carries a hand-derived `expected` column that the tool must reproduce."""

    @classmethod
    def setUpClass(cls):
        cls.expected = {line: row["expected"] for line, row in batch.read_rows(SAMPLE)}
        cls.items = batch.process_file(SAMPLE)

    def test_every_row_matches_expected(self):
        self.assertEqual(len(self.items), len(self.expected))
        for item in self.items:
            self.assertEqual(item.priority, self.expected[item.line],
                             f"line {item.line} ({item.id}): {item.error or item.result.reasons}")

    def test_blank_row_skipped(self):
        self.assertEqual(len(self.items), 33)

    def test_sorted_by_bucket_then_score_errors_last(self):
        order = {"NOW": 0, "NEXT": 1, "NEVER": 2, "ERROR": 3}
        buckets = [order[i.priority] for i in self.items]
        self.assertEqual(buckets, sorted(buckets))
        for bucket in ("NOW", "NEXT", "NEVER"):
            scores = [i.result.score for i in self.items if i.priority == bucket]
            self.assertEqual(scores, sorted(scores, reverse=True))

    def test_error_messages_name_the_problem(self):
        by_id = {i.id: i for i in self.items}
        self.assertIn("cvss", by_id["BAD-26"].error)
        self.assertIn("cvss", by_id["BAD-27"].error)
        self.assertIn("threat: value is required", by_id["BAD-28"].error)
        self.assertIn("asset", by_id["BAD-29"].error)
        multi = by_id["BAD-31"].error
        for name in ("cvss", "threat", "exposure"):
            self.assertIn(name, multi)

    def test_summary_counts(self):
        counts = batch.summarize(self.items)
        self.assertEqual(sum(counts.values()), 33)
        self.assertEqual(counts["ERROR"], 6)


class ParsingTests(unittest.TestCase):
    def test_aliases_and_labels(self):
        item = batch.score_row(2, {"cvss": "8", "threat": "Public exploit available", "asset": "crown jewel",
                                   "exposure": "Internet", "patch": "End-of-life", "controls": "PARTIAL"})
        self.assertEqual(item.inputs["threat"], Threat.PUBLIC)
        self.assertEqual(item.inputs["asset"], Asset.CROWN)
        self.assertEqual(item.inputs["exposure"], Exposure.HIGH)
        self.assertEqual(item.inputs["patch"], Patch.EOL)
        self.assertEqual(item.inputs["controls"], Controls.PARTIAL)

    def test_optional_defaults(self):
        item = batch.score_row(2, {"cvss": "5", "threat": "none", "asset": "standard", "exposure": "low"})
        self.assertEqual(item.inputs["patch"], Patch.AVAILABLE)
        self.assertEqual(item.inputs["controls"], Controls.NONE)

    def test_header_aliases_and_bom(self):
        path = write_csv("﻿CVSS Score,Threat Status,Asset Criticality,Network Exposure\n9.8,active,crown,high\n")
        self.addCleanup(os.remove, path)
        items = batch.process_file(path)
        self.assertEqual([i.priority for i in items], ["NOW"])

    def test_missing_required_column(self):
        path = write_csv("cvss,threat,asset\n9.8,active,crown\n")
        self.addCleanup(os.remove, path)
        with self.assertRaisesRegex(ValueError, "exposure"):
            batch.process_file(path)

    def test_empty_file(self):
        path = write_csv("")
        self.addCleanup(os.remove, path)
        with self.assertRaises(ValueError):
            batch.process_file(path)

    def test_short_row_does_not_crash(self):
        path = write_csv("cvss,threat,asset,exposure\n9.8,active\n")
        self.addCleanup(os.remove, path)
        item = batch.process_file(path)[0]
        self.assertEqual(item.priority, "ERROR")


class ExportTests(unittest.TestCase):
    def test_export_roundtrip_and_formula_safety(self):
        items = batch.process_file(SAMPLE)
        fd, out = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.remove, out)
        batch.write_results(out, items)
        with open(out, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), len(items))
        self.assertEqual(rows[0]["rank"], "1")
        self.assertEqual(rows[0]["priority"], "NOW")
        ranks = [int(r["rank"]) for r in rows if r["rank"]]
        self.assertEqual(ranks, list(range(1, len(ranks) + 1)))
        self.assertEqual([r["priority"] for r in rows if not r["rank"]], ["ERROR"] * 6)
        for r in rows:
            for key in ("id", "name", "error", "cvss"):
                self.assertNotRegex(r[key], r"^[=+\-@]", f"unsafe cell in {key}: {r[key]!r}")
        self.assertTrue(any(r["id"].startswith("'=HYPERLINK") for r in rows))


class FormulaSafetyTests(unittest.TestCase):
    PAYLOADS = ["=HYPERLINK(\"http://example.com\")", "+cmd", "-1+1", "@SUM(A1)", "\t=1", "\r=1"]

    def test_safe_prefixes_formula_characters(self):
        for payload in self.PAYLOADS:
            self.assertEqual(batch._safe(payload), "'" + payload)
        for text in ("", "plain", "a=b", "1+1"):
            self.assertEqual(batch._safe(text), text)

    def test_export_neutralizes_every_text_cell(self):
        good = batch.score_row(2, {"id": "=ID", "name": "+name", "cvss": "9.8", "threat": "active",
                                   "asset": "crown", "exposure": "high"})
        bad = batch.score_row(3, {"id": "-id", "name": "@name", "cvss": "=BAD", "threat": "active",
                                  "asset": "crown", "exposure": "high"})
        fd, out = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.remove, out)
        batch.write_results(out, [good, bad])
        with open(out, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(rows[0]["id"], "'=ID")
        self.assertEqual(rows[0]["name"], "'+name")
        self.assertEqual(rows[1]["id"], "'-id")
        self.assertEqual(rows[1]["name"], "'@name")
        self.assertEqual(rows[1]["cvss"], "'=BAD")
        for row in rows:
            for value in row.values():
                self.assertFalse(value.startswith(tuple("=+-@\t\r")), value)


class RankingTests(unittest.TestCase):
    @staticmethod
    def item(line, cvss, threat, asset, exposure):
        return batch.score_row(line, {"cvss": cvss, "threat": threat, "asset": asset, "exposure": exposure})

    def test_bucket_outranks_a_higher_score(self):
        now = self.item(2, "8.0", "public", "standard", "high")
        next_ = self.item(3, "8.0", "none", "crown", "medium")
        self.assertEqual((now.priority, next_.priority), ("NOW", "NEXT"))
        self.assertGreater(next_.result.score, now.result.score)
        self.assertEqual(batch.sort_items([next_, now]), [now, next_])

    def test_ties_keep_source_order(self):
        first = self.item(2, "8.0", "public", "standard", "high")
        second = self.item(3, "8.0", "public", "standard", "high")
        self.assertEqual(batch.sort_items([second, first]), [first, second])

    def test_errors_sort_last_by_line(self):
        bad_late = self.item(9, "abc", "none", "standard", "low")
        bad_early = self.item(4, "abc", "none", "standard", "low")
        never = self.item(5, "1.0", "none", "standard", "low")
        self.assertEqual(batch.sort_items([bad_late, bad_early, never]), [never, bad_early, bad_late])


def make_threatdata(kev=None, epss=None, kev_loaded=True, epss_loaded=True):
    entries = {c: td.KevEntry(c, "Acme", "Widget", "Flaw", "2024-01-02", action, "2024-01-23", ransomware)
               for c, action, ransomware in (kev or [])}
    return td.ThreatData(td.KevData("2026.10.04", "2026-10-04", entries) if kev_loaded else None,
                         td.EpssData("v2026.06.15", "2026-10-07", dict(epss or {})) if epss_loaded else None)


class CveColumnTests(unittest.TestCase):
    BASE = {"cvss": "8.0", "asset": "standard", "exposure": "high"}

    def row(self, **changes):
        return {**self.BASE, **changes}

    def test_kev_derives_active_when_the_threat_cell_is_blank(self):
        data = make_threatdata(kev=[("CVE-2024-0001", "Apply updates.", False)])
        item = batch.score_row(2, self.row(cve="cve-2024-0001"), threatdata=data)
        self.assertEqual((item.priority, item.inputs["threat"], item.cve), ("NOW", Threat.ACTIVE, "CVE-2024-0001"))
        self.assertEqual(item.threat_sources, "In CISA KEV")
        self.assertIn("CISA required action: Apply updates.", item.result.action)

    def test_cve_without_signals_is_none_and_elevated_epss_is_public(self):
        data = make_threatdata(epss={"CVE-2024-0002": (0.4, 0.99), "CVE-2024-0003": (0.001, 0.2)})
        elevated = batch.score_row(2, self.row(cve="CVE-2024-0002"), threatdata=data)
        quiet = batch.score_row(3, self.row(cve="CVE-2024-0003"), threatdata=data)
        unknown = batch.score_row(4, self.row(cve="CVE-2030-9999"), threatdata=data)
        self.assertEqual([i.inputs["threat"] for i in (elevated, quiet, unknown)],
                         [Threat.PUBLIC, Threat.NONE, Threat.NONE])
        self.assertTrue(elevated.threat_sources.startswith("Elevated EPSS"))

    def test_the_threat_column_can_raise_but_never_lower_the_derived_level(self):
        data = make_threatdata(kev=[("CVE-2024-0001", "", False)])
        lowered = batch.score_row(2, self.row(cve="CVE-2024-0001", threat="none"), threatdata=data)
        raised = batch.score_row(3, self.row(cve="CVE-2024-0009", threat="active"), threatdata=data)
        self.assertEqual(lowered.inputs["threat"], Threat.ACTIVE)
        self.assertEqual(raised.inputs["threat"], Threat.ACTIVE)
        self.assertIn("Analyst-confirmed", raised.threat_sources)

    def test_missing_data_is_never_treated_as_safe(self):
        empty = make_threatdata(kev_loaded=False, epss_loaded=False)
        for data in (None, empty):
            item = batch.score_row(2, self.row(cve="CVE-2024-0001"), threatdata=data)
            self.assertEqual(item.priority, "ERROR")
            self.assertIn("threat: value is required (no threat data loaded", item.error)
        with_threat = batch.score_row(2, self.row(cve="CVE-2024-0001", threat="public"), threatdata=empty)
        self.assertEqual(with_threat.inputs["threat"], Threat.PUBLIC)
        partial = make_threatdata(kev=[("CVE-2024-0001", "", False)], epss_loaded=False)
        self.assertEqual(batch.score_row(2, self.row(cve="CVE-2024-0001"), threatdata=partial).priority, "NOW")

    def test_invalid_cve_is_an_error_row(self):
        item = batch.score_row(2, self.row(cve="nonsense", threat="active"), threatdata=make_threatdata())
        self.assertEqual(item.priority, "ERROR")
        self.assertIn("cve:", item.error)
        blank = batch.score_row(2, self.row(cve="nonsense"), threatdata=make_threatdata())
        self.assertNotIn("no threat data loaded", blank.error)

    def test_rows_without_a_cve_keep_working(self):
        item = batch.score_row(2, self.row(threat="public"), threatdata=make_threatdata())
        self.assertEqual((item.priority, item.threat_sources), ("NOW", "Manual (threat column)"))

    def test_header_needs_threat_or_cve(self):
        path = write_csv("cvss,asset,exposure\n9.8,crown,high\n")
        self.addCleanup(os.remove, path)
        with self.assertRaisesRegex(ValueError, "threat \\(or cve\\)"):
            batch.process_file(path)
        path2 = write_csv("cvss,asset,exposure,cve\n9.8,crown,high,CVE-2024-0001\n")
        self.addCleanup(os.remove, path2)
        self.assertTrue(batch.has_cve_column(path2))
        self.assertFalse(batch.has_cve_column(path))
        item = batch.process_file(path2, threatdata=make_threatdata(kev=[("CVE-2024-0001", "", False)]))[0]
        self.assertEqual(item.priority, "NOW")

    def test_ransomware_ranks_first_within_a_bucket_only(self):
        data = make_threatdata(kev=[("CVE-2024-0001", "", False), ("CVE-2024-0002", "", True)])
        plain = batch.score_row(2, self.row(cve="CVE-2024-0001"), threatdata=data)
        ransom = batch.score_row(3, self.row(cve="CVE-2024-0002"), threatdata=data)
        self.assertEqual((plain.priority, ransom.priority), ("NOW", "NOW"))
        self.assertEqual(batch.sort_items([plain, ransom]), [ransom, plain])

    def test_export_has_sources_versions_and_neutralizes_kev_text(self):
        hostile = '=HYPERLINK("http://example.invalid","x")'
        data = make_threatdata(kev=[("CVE-2024-0001", hostile, False)])
        item = batch.score_row(2, self.row(cve="CVE-2024-0001", id="A-1"), threatdata=data)
        fd, out = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.remove, out)
        batch.write_results(out, [item], data)
        with open(out, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        row = rows[0]
        self.assertEqual((row["cve"], row["threat"], row["threat_source"]),
                         ("CVE-2024-0001", Threat.ACTIVE.value, "In CISA KEV"))
        self.assertEqual(row["threat_data"], data.versions())
        self.assertIn("KEV 2026.10.04", row["threat_data"])
        self.assertIn("CISA required action:", row["action"])
        self.assertIn(hostile, row["action"])
        for column in ("action", "rationale", "threat_source", "threat_data", "cve"):
            self.assertFalse(row[column].startswith(tuple("=+-@\t\r")), column)

    def test_exported_text_that_starts_like_a_formula_is_neutralized(self):
        data = make_threatdata(kev=[("CVE-2024-0001", "x", False)])
        item = batch.score_row(2, self.row(cve="CVE-2024-0001"), threatdata=data)
        item.result.action = "=1+1"
        item.result.reasons = ["=2+2"]
        item.threat_sources = "+cmd"
        fd, out = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.remove, out)
        batch.write_results(out, [item])
        with open(out, newline="", encoding="utf-8-sig") as fh:
            row = next(csv.DictReader(fh))
        self.assertEqual((row["action"], row["rationale"], row["threat_source"]), ("'=1+1", "'=2+2", "'+cmd"))


if __name__ == "__main__":
    unittest.main()
