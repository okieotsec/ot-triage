import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import settings
import uiprefs
from uiprefs import DEFAULT_PREFS, UiPrefs


def valid(**changes):
    return {**UiPrefs().to_dict(), **changes}


class UiPrefsValidationTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual((DEFAULT_PREFS.theme, DEFAULT_PREFS.text_percent, DEFAULT_PREFS.startup_update),
                         ("dark", 100, False))
        self.assertEqual(DEFAULT_PREFS.text_scale, 1.0)
        self.assertEqual(UiPrefs(text_percent=130).text_scale, 1.3)

    def test_valid_values(self):
        for theme in uiprefs.THEMES:
            for percent in uiprefs.TEXT_PERCENTS:
                prefs = UiPrefs(theme, percent, True)
                self.assertEqual(UiPrefs.from_dict(prefs.to_dict()), prefs)

    def test_invalid_values_are_rejected_with_the_field_name(self):
        cases = {"theme": ["blue", "", None, 1, True, ["dark"]],
                 "text_percent": [95, "100", 100.0, True, None, 0, -100],
                 "startup_update": [1, 0, "true", None, [], "False"]}
        for name, bad_values in cases.items():
            for bad in bad_values:
                with self.subTest(name=name, value=bad), self.assertRaisesRegex(ValueError, name):
                    UiPrefs(**{name: bad})

    def test_from_dict_is_strict(self):
        for label, data in [("list", []), ("none", None), ("extra", valid(extra=1)),
                            ("missing", {k: v for k, v in valid().items() if k != "theme"}),
                            ("no version", {k: v for k, v in valid().items() if k != "version"}),
                            ("version true", valid(version=True)), ("version 2", valid(version=2))]:
            with self.subTest(case=label), self.assertRaises(ValueError):
                UiPrefs.from_dict(data)


class UiPrefsFileTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "ui.json"

    def test_missing_file_gives_defaults_without_warning(self):
        result = uiprefs.load(self.path)
        self.assertEqual((result.prefs, result.warnings), (DEFAULT_PREFS, ()))

    def test_round_trip_and_permissions(self):
        prefs = UiPrefs("light", 115, True)
        uiprefs.save(prefs, self.path)
        self.assertEqual(uiprefs.load(self.path).prefs, prefs)
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_bad_files_fall_back_to_defaults_with_one_warning(self):
        good = json.dumps(valid())
        cases = {"empty": "", "truncated": good[:20], "array": "[]", "wrong type": json.dumps(valid(theme=5)),
                 "bad value": json.dumps(valid(text_percent=250)), "extra key": json.dumps(valid(x=1)),
                 "nan": good.replace("100", "NaN"), "huge": good + " " * (uiprefs.MAX_PREFS_BYTES + 1),
                 "duplicate": '{"version": 1, "version": 1}', "null byte": good.replace("dark", "da\x00rk")}
        for label, text in cases.items():
            with self.subTest(case=label):
                self.path.write_text(text, encoding="utf-8")
                result = uiprefs.load(self.path)
                self.assertEqual(result.prefs, DEFAULT_PREFS)
                self.assertEqual(len(result.warnings), 1)
                self.assertIn("Default preferences are in effect", result.warnings[0])
        self.path.write_bytes(b"\xff\xfe\xfd")
        self.assertEqual(len(uiprefs.load(self.path).warnings), 1)

    def test_directory_in_place_of_the_file(self):
        self.path.mkdir()
        self.assertEqual(len(uiprefs.load(self.path).warnings), 1)

    def test_failed_save_keeps_the_previous_file(self):
        uiprefs.save(UiPrefs("light"), self.path)
        with mock.patch("jsonfile.json.dump", side_effect=OSError("disk full")), self.assertRaises(OSError):
            uiprefs.save(UiPrefs("dark"), self.path)
        self.assertEqual(uiprefs.load(self.path).prefs.theme, "light")
        self.assertEqual([p.name for p in self.dir.iterdir()], ["ui.json"])

    def test_preferences_never_touch_the_scoring_settings(self):
        settings.save(settings.Settings(cvss_high=6.5), self.dir / "settings.json")
        uiprefs.save(UiPrefs("light", 130, True), self.dir / "ui.json")
        self.assertEqual(settings.load(self.dir / "settings.json").settings.cvss_high, 6.5)
        self.assertNotIn("theme", json.loads((self.dir / "settings.json").read_text()))

    def test_default_path_is_next_to_the_settings_file(self):
        self.assertEqual(uiprefs.default_path().parent, settings.default_path().parent)
        self.assertEqual(uiprefs.default_path().name, "ui.json")


if __name__ == "__main__":
    unittest.main()
