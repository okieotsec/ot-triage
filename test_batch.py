import csv
import os
import tempfile
import unittest

import batch
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


if __name__ == "__main__":
    unittest.main()
