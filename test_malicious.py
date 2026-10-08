import csv
import os
import tempfile
import time
import unittest
from pathlib import Path

import batch
import malicious_cases
import settings
import threatdata

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


if __name__ == "__main__":
    unittest.main()
