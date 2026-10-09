import csv
import os
import tempfile
import time
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
        path = write_csv("\ufeffCVSS Score,Threat Status,Asset Criticality,Network Exposure\n9.8,active,crown,high\n")
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


V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40_87 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:L/SA:L"


class CvssVectorColumnTests(unittest.TestCase):
    BASE = {"threat": "active", "asset": "crown", "exposure": "high"}

    def row(self, **changes):
        return {**self.BASE, **changes}

    def test_a_vector_alone_supplies_the_score_and_records_its_version(self):
        for vector, score, version in ((V31, 9.8, "3.1"), (V40_87, 8.7, "4.0")):
            item = batch.score_row(2, self.row(cvss_vector=vector))
            self.assertEqual((item.cvss, item.cvss_version, item.cvss_vector, item.error), (score, version, vector, ""))
            self.assertEqual(item.cvss_raw, f"{score:.1f}")
            self.assertEqual(item.priority, "NOW")

    def test_the_vector_is_normalized_and_may_carry_optional_metrics(self):
        item = batch.score_row(2, self.row(cvss_vector="CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N/E:P"))
        self.assertEqual((item.cvss, item.cvss_vector), (9.8, V31 + "/E:P"))

    def test_a_matching_score_column_is_accepted_in_any_format(self):
        for typed in ("9.8", " 9.8 ", "9.80", "9.800"):
            item = batch.score_row(2, self.row(cvss=typed, cvss_vector=V31))
            self.assertEqual((item.error, item.cvss), ("", 9.8), typed)

    def test_a_conflicting_score_column_makes_an_error_row_not_a_silent_choice(self):
        item = batch.score_row(2, self.row(cvss="7.0", cvss_vector=V31))
        self.assertEqual(item.priority, "ERROR")
        self.assertIn("cvss (7.0) does not match the base score of cvss_vector (9.8)", item.error)
        self.assertIsNone(item.cvss)
        for typed in ("9.7", "9.79", "9.81", "9.75", "9.85", "10"):
            self.assertEqual(batch.score_row(2, self.row(cvss=typed, cvss_vector=V31)).priority, "ERROR", typed)

    def test_an_invalid_vector_is_never_rescued_by_a_valid_score_column(self):
        for bad, fragment in (("nonsense", "must start with CVSS"), ("AV:N/AC:L/Au:N/C:P/I:P/A:P", "version 2"),
                              ("CVSS:3.1/AV:N", "missing required"), ("=HYPERLINK(1)", "only letters, digits"),
                              ("notcvss/AV:N", "must start with CVSS")):
            item = batch.score_row(2, self.row(cvss="9.8", cvss_vector=bad))
            self.assertEqual(item.priority, "ERROR", bad)
            self.assertIn("cvss_vector:", item.error)
            self.assertIn(fragment, item.error)
            self.assertEqual(item.cvss_version, "")

    def test_an_unreadable_score_next_to_a_valid_vector_is_reported(self):
        item = batch.score_row(2, self.row(cvss="abc", cvss_vector=V31))
        self.assertEqual(item.priority, "ERROR")
        self.assertIn("cvss:", item.error)

    def test_neither_column_gives_the_old_message(self):
        item = batch.score_row(2, self.row())
        self.assertEqual(item.priority, "ERROR")
        self.assertIn("cvss: CVSS score must be a number", item.error)
        self.assertEqual(batch.score_row(2, self.row(cvss_vector="  ", cvss="8")).cvss, 8.0)

    def test_a_giant_vector_cell_is_rejected_quickly_and_kept_short(self):
        start = time.monotonic()
        item = batch.score_row(2, self.row(cvss_vector="CVSS:3.1/" + "A" * 5_000_000))
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertEqual(item.priority, "ERROR")
        self.assertLessEqual(len(item.cvss_vector), batch.MAX_ERROR_VECTOR_CHARS)
        self.assertLess(len(item.error), 200)

    def test_header_aliases_and_missing_column_messages(self):
        path = write_csv(f"vector,threat,asset,exposure\n{V31},active,crown,high\n")
        self.addCleanup(os.remove, path)
        self.assertEqual(batch.process_file(path)[0].cvss, 9.8)
        path2 = write_csv(f"cvss vector string,threat,asset,exposure\n{V31},active,crown,high\n")
        self.addCleanup(os.remove, path2)
        self.assertEqual(batch.process_file(path2)[0].cvss_version, "3.1")
        bad = write_csv("threat,asset,exposure\nactive,crown,high\n")
        self.addCleanup(os.remove, bad)
        with self.assertRaisesRegex(ValueError, r"cvss \(or cvss_vector\)"):
            batch.process_file(bad)
        both = write_csv("cvss,asset\n9,crown\n")
        self.addCleanup(os.remove, both)
        with self.assertRaises(ValueError) as caught:
            batch.process_file(both)
        message = str(caught.exception)
        self.assertLess(message.index("threat (or cve)"), message.index("exposure"))

    def test_both_vector_header_spellings_together_are_a_duplicate(self):
        path = write_csv(f"cvss_vector,vector,threat,asset,exposure\n{V31},{V31},active,crown,high\n")
        self.addCleanup(os.remove, path)
        with self.assertRaisesRegex(ValueError, "Duplicate column"):
            batch.process_file(path)

    def test_export_has_version_and_vector_columns_and_neutralizes_them(self):
        good = batch.score_row(2, self.row(id="A", cvss_vector=V40_87))
        bad = batch.score_row(3, self.row(id="B", cvss_vector="=HYPERLINK(\"http://example.invalid\")"))
        plain = batch.score_row(4, self.row(id="C", cvss="8.0"))
        fd, out = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.remove, out)
        batch.write_results(out, batch.sort_items([good, bad, plain]))
        with open(out, newline="", encoding="utf-8-sig") as fh:
            rows = {r["id"]: r for r in csv.DictReader(fh)}
        self.assertEqual((rows["A"]["cvss"], rows["A"]["cvss_version"], rows["A"]["cvss_vector"]),
                         ("8.7", "4.0", V40_87))
        self.assertEqual((rows["C"]["cvss_version"], rows["C"]["cvss_vector"]), ("", ""))
        self.assertTrue(rows["B"]["cvss_vector"].startswith("'="))
        self.assertIn("cvss_vector:", rows["B"]["error"])
        for row in rows.values():
            self.assertFalse(row["cvss_vector"].startswith(tuple("=+-@\t\r")))

    def test_the_sample_file_and_old_files_without_vectors_are_unchanged(self):
        items = batch.process_file(SAMPLE)
        self.assertTrue(all(i.cvss_version == "" and i.cvss_vector == "" for i in items))


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


class KevReferenceTests(unittest.TestCase):
    NOTES = "https://vendor.example.com/a ; =Click me: https://www.cisa.gov/bod ; http://insecure.example.com/x"
    ROW = {"cvss": "8.0", "asset": "standard", "exposure": "high", "cve": "CVE-2024-0001"}

    def data(self, triage=False):
        entry = td.KevEntry("CVE-2024-0001", "Acme", "Widget", "Flaw", "2024-01-02", "Apply.", "2024-01-23", False,
                            self.NOTES, triage)
        return td.ThreatData(td.KevData("2026.10.04", "2026-10-04", {entry.cve: entry}),
                             td.EpssData("v2026.06.15", "2026-10-07", {}))

    def test_a_kev_row_carries_its_references_and_the_triage_flag(self):
        item = batch.score_row(2, self.ROW, threatdata=self.data(triage=True))
        self.assertEqual([r.host for r in item.references if r.is_link], ["vendor.example.com", "www.cisa.gov"])
        self.assertEqual(len(item.references), 3)
        self.assertTrue(item.forensic_triage)

    def test_rows_without_a_kev_entry_have_none(self):
        manual = batch.score_row(2, {**self.ROW, "cve": "", "threat": "none"}, threatdata=self.data())
        other = batch.score_row(3, {**self.ROW, "cve": "CVE-2030-0001"}, threatdata=self.data())
        for item in (manual, other):
            self.assertEqual((item.references, item.forensic_triage), ((), False))

    def test_the_triage_flag_never_changes_the_bucket_or_the_score(self):
        plain = batch.score_row(2, self.ROW, threatdata=self.data(triage=False))
        flagged = batch.score_row(2, self.ROW, threatdata=self.data(triage=True))
        self.assertEqual((plain.priority, plain.result.score), (flagged.priority, flagged.result.score))

    def test_the_triage_flag_adds_a_context_note_and_a_neutral_chip_only_when_set(self):
        flagged = batch.score_row(2, self.ROW, threatdata=self.data(triage=True)).result
        plain = batch.score_row(2, self.ROW, threatdata=self.data(triage=False)).result
        self.assertTrue(any("forensic triage" in r for r in flagged.reasons))
        self.assertIn(("Forensic triage advised", "neutral"), [(f.label, f.direction) for f in flagged.factors])
        self.assertFalse(any("forensic triage" in r for r in plain.reasons))
        self.assertNotIn("Forensic triage advised", [f.label for f in plain.factors])

    def test_the_export_has_the_new_columns_last_and_neutralises_formulas(self):
        items = [batch.score_row(2, self.ROW, threatdata=self.data(triage=True)),
                 batch.score_row(3, {**self.ROW, "cve": "", "threat": "none"}, threatdata=self.data())]
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "out.csv")
            batch.write_results(path, batch.sort_items(items), self.data())
            with open(path, newline="", encoding="utf-8-sig") as fh:
                reader = csv.DictReader(fh)
                rows = list(reader)
        self.assertEqual(reader.fieldnames[-2:], ["references", "forensic_triage"])
        by_cve = {r["cve"]: r for r in rows}
        kev_row = by_cve["CVE-2024-0001"]
        self.assertEqual(kev_row["forensic_triage"], "Yes")
        self.assertTrue(kev_row["references"].startswith("https://vendor.example.com/a ; "))
        self.assertIn(" ; =Click me: https://www.cisa.gov/bod ; ", kev_row["references"])
        self.assertIn("http://insecure.example.com/x", kev_row["references"])
        manual = by_cve[""]
        self.assertEqual((manual["references"], manual["forensic_triage"]), ("", ""))

    def test_a_reference_text_that_starts_like_a_formula_is_neutralised_in_the_export(self):
        entry = td.KevEntry("CVE-2024-0001", "A", "B", "C", "2024-01-02", "Apply.", "", False,
                            "=HYPERLINK(\"http://evil.example.com\") ; plain", False)
        data = td.ThreatData(td.KevData("1", "2026-10-04", {entry.cve: entry}), td.EpssData("v", "2026-10-07", {}))
        item = batch.score_row(2, self.ROW, threatdata=data)
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "out.csv")
            batch.write_results(path, [item], data)
            with open(path, newline="", encoding="utf-8-sig") as fh:
                row = next(csv.DictReader(fh))
        self.assertTrue(row["references"].startswith("'="), row["references"])


if __name__ == "__main__":
    unittest.main()
