import csv
import os
import tempfile
import time
import unittest

import batch
import malicious_cases
import settings

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


if __name__ == "__main__":
    unittest.main()
