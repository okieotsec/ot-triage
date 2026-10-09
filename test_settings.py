import csv
import itertools
import json
import math
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import batch
import settings
from prioritizer import NEVER, NEXT, NOW, Asset, Controls, Exposure, Patch, Threat, prioritize
from settings import DEFAULT_SETTINGS, Settings


def valid_dict(**changes):
    return {**Settings().to_dict(), **changes}


class SettingsValidationTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(Settings(), DEFAULT_SETTINGS)
        self.assertEqual((DEFAULT_SETTINGS.cvss_high, DEFAULT_SETTINGS.cvss_critical), (7.0, 9.0))
        self.assertEqual((DEFAULT_SETTINGS.epss_percentile_cutoff, DEFAULT_SETTINGS.stale_days), (0.95, 7))
        self.assertTrue(DEFAULT_SETTINGS.is_default)
        self.assertTrue(DEFAULT_SETTINGS.describe().startswith("defaults ("))

    def test_custom_values_are_accepted_and_described(self):
        custom = Settings(cvss_high=7.5, cvss_critical=9.5, epss_percentile_cutoff=0.9, stale_days=14)
        self.assertFalse(custom.is_default)
        self.assertTrue(custom.describe().startswith("custom ("))
        self.assertIn("cvss_high=7.5", custom.describe())

    def test_integers_are_coerced_to_float(self):
        self.assertIsInstance(Settings(cvss_high=7).cvss_high, float)
        self.assertTrue(Settings(cvss_high=7, cvss_critical=9).is_default)

    def test_each_value_is_range_checked_at_both_ends(self):
        for name, (kind, _default, low, high, _description) in settings.SPEC.items():
            step = 1 if kind is int else 0.001
            for bad in (low - step, high + step):
                with self.subTest(name=name, value=bad), self.assertRaisesRegex(ValueError, name):
                    Settings(**{name: bad})
            for edge in (low, high):
                with self.subTest(name=name, edge=edge):
                    self.assertEqual(getattr(Settings(**{name: edge}), name), edge)

    def test_wrong_types_and_special_numbers_are_rejected(self):
        bad_values = [True, False, None, "7.0", [7.0], {"a": 1}, float("nan"), float("inf"), -float("inf"), 10 ** 400]
        for name in settings.SPEC:
            for bad in bad_values:
                with self.subTest(name=name, value=repr(bad)[:20]), self.assertRaises(ValueError):
                    Settings(**{name: bad})
        with self.assertRaises(ValueError):
            Settings(stale_days=7.5)
        with self.assertRaises(ValueError):
            Settings(stale_days=7.0)

    def test_lines_must_stay_apart(self):
        with self.assertRaisesRegex(ValueError, "at least"):
            Settings(cvss_high=7.6, cvss_critical=8.0)
        with self.assertRaisesRegex(ValueError, "at least"):
            Settings(cvss_high=8.0, cvss_critical=8.0)
        Settings(cvss_high=7.5, cvss_critical=8.0)

    def test_all_errors_are_reported_together(self):
        with self.assertRaises(ValueError) as caught:
            Settings(cvss_high=99, stale_days="x")
        self.assertIn("cvss_high", str(caught.exception))
        self.assertIn("stale_days", str(caught.exception))

    def test_from_dict_is_strict(self):
        self.assertEqual(Settings.from_dict(valid_dict()), DEFAULT_SETTINGS)
        for label, data in [("list", []), ("none", None), ("string", "x"),
                            ("extra key", valid_dict(extra=1)),
                            ("missing key", {k: v for k, v in valid_dict().items() if k != "stale_days"}),
                            ("no version", {k: v for k, v in valid_dict().items() if k != "version"}),
                            ("version true", valid_dict(version=True)),
                            ("version 2", valid_dict(version=2)),
                            ("version string", valid_dict(version="1"))]:
            with self.subTest(case=label), self.assertRaises(ValueError):
                Settings.from_dict(data)

    def test_error_messages_are_safe_for_hostile_values(self):
        deep = []
        for _ in range(5000):
            deep = [deep]
        for value in (deep, {"a": deep}, 10 ** 5000, "A" * 10_000, b"bytes", object()):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError) as caught:
                Settings(cvss_high=value)
            self.assertIn("cvss_high", str(caught.exception))
            self.assertLess(len(str(caught.exception)), 300)

    def test_long_values_are_truncated_in_messages(self):
        with self.assertRaises(ValueError) as caught:
            Settings(cvss_high="A" * 10_000)
        self.assertLess(len(str(caught.exception)), 300)


class SettingsFileTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "settings.json"

    def write(self, data):
        self.path.write_bytes(data if isinstance(data, bytes) else data.encode())

    def assertFallsBack(self, label=""):
        result = settings.load(self.path)
        self.assertEqual(result.settings, DEFAULT_SETTINGS, label)
        self.assertEqual(len(result.warnings), 1, label)
        self.assertIn("Default settings are in effect", result.warnings[0])

    def test_missing_file_gives_defaults_without_warning(self):
        result = settings.load(self.path)
        self.assertEqual(result.settings, DEFAULT_SETTINGS)
        self.assertEqual(result.warnings, ())

    def test_save_and_load_round_trip(self):
        custom = Settings(cvss_high=6.5, cvss_critical=9.5, epss_percentile_cutoff=0.8, stale_days=30)
        settings.save(custom, self.path)
        result = settings.load(self.path)
        self.assertEqual(result.settings, custom)
        self.assertEqual(result.warnings, ())

    def test_malformed_files_fall_back_to_defaults(self):
        good = json.dumps(valid_dict())
        cases = {
            "empty": "",
            "truncated": good[: len(good) // 2],
            "not an object": "[1, 2, 3]",
            "null": "null",
            "wrong type": json.dumps(valid_dict(cvss_high="7.0")),
            "bool": json.dumps(valid_dict(stale_days=True)),
            "out of range": json.dumps(valid_dict(cvss_high=1.0)),
            "inconsistent": json.dumps(valid_dict(cvss_high=7.9, cvss_critical=8.0)),
            "extra key": json.dumps(valid_dict(extra=1)),
            "duplicate keys": '{"version": 1, "version": 1, "cvss_high": 7.0, "cvss_critical": 9.0, '
                              '"epss_percentile_cutoff": 0.95, "stale_days": 7}',
            "NaN": good.replace("7.0", "NaN", 1),
            "Infinity": good.replace("9.0", "Infinity"),
            "huge integer": good.replace('"stale_days": 7', '"stale_days": ' + "9" * 5000),
            "deep nesting": "[" * 5000 + "]" * 5000,
            "deep nesting in a value": '{"version": 1, "cvss_high": ' + "[" * 5000 + "]" * 5000 + "}",
            "null byte": good.replace("7.0", "7.0\x00", 1),
        }
        for label, text in cases.items():
            with self.subTest(case=label):
                self.write(text)
                self.assertFallsBack(label)

    def test_bad_encodings_and_oversized_files_fall_back(self):
        self.write(json.dumps(valid_dict()).encode("utf-16"))
        self.assertFallsBack("utf-16")
        self.write(b"\xff\xfe\xfd")
        self.assertFallsBack("invalid utf-8")
        self.write(json.dumps(valid_dict()) + " " * settings.MAX_SETTINGS_BYTES)
        self.assertFallsBack("oversized but otherwise valid")

    def test_utf8_bom_is_accepted(self):
        self.write(b"\xef\xbb\xbf" + json.dumps(valid_dict(stale_days=10)).encode())
        self.assertEqual(settings.load(self.path).settings.stale_days, 10)

    def test_directory_instead_of_file_falls_back(self):
        self.path.mkdir()
        self.assertFallsBack("directory")

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions")
    def test_saved_files_are_user_only(self):
        nested = self.dir / "new" / "settings.json"
        settings.save(DEFAULT_SETTINGS, nested)
        self.assertEqual(stat.S_IMODE(os.stat(nested).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(nested.parent).st_mode), 0o700)

    def test_failed_save_keeps_the_previous_file_and_leaves_no_temp_files(self):
        original = Settings(stale_days=21)
        settings.save(original, self.path)
        with mock.patch("jsonfile.json.dump", side_effect=OSError("disk full")), self.assertRaises(OSError):
            settings.save(Settings(stale_days=3), self.path)
        self.assertEqual(settings.load(self.path).settings, original)
        self.assertEqual([p.name for p in self.dir.iterdir()], ["settings.json"])

    def test_restore_defaults_returns_exactly_the_shipped_values(self):
        settings.save(Settings(cvss_high=6.0, stale_days=40), self.path)
        restored = settings.restore_defaults(self.path)
        self.assertEqual(restored, DEFAULT_SETTINGS)
        self.assertEqual(settings.load(self.path).settings, DEFAULT_SETTINGS)
        self.assertEqual(json.loads(self.path.read_text()), DEFAULT_SETTINGS.to_dict())

    def test_default_path_uses_an_absolute_xdg_folder_only(self):
        if sys.platform in ("win32", "darwin"):
            self.skipTest("XDG applies to Linux")
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.dir)}):
            self.assertEqual(settings.default_path(), self.dir / "ot-triage" / "settings.json")
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": "relative/path"}):
            self.assertEqual(settings.default_path(), Path.home() / ".config" / "ot-triage" / "settings.json")


class CustomSettingsBehaviorTests(unittest.TestCase):
    def test_high_line_changes_public_exploit_and_no_exploit_outcomes(self):
        custom = Settings(cvss_high=7.5)
        public = (7.2, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH)
        self.assertEqual(prioritize(*public).priority, NOW)
        self.assertEqual(prioritize(*public, settings=custom).priority, NEXT)
        none = (7.2, Threat.NONE, Asset.CROWN, Exposure.LOW)
        self.assertEqual(prioritize(*none).priority, NEXT)
        self.assertEqual(prioritize(*none, settings=custom).priority, NEVER)

    def test_critical_line_changes_exposed_crown_jewel_outcome(self):
        case = (9.2, Threat.NONE, Asset.CROWN, Exposure.HIGH)
        self.assertEqual(prioritize(*case).priority, NOW)
        self.assertEqual(prioritize(*case, settings=Settings(cvss_critical=9.5)).priority, NEXT)

    def test_high_line_changes_end_of_life_floor(self):
        case = (7.2, Threat.NONE, Asset.STANDARD, Exposure.LOW, Controls.STRONG, Patch.EOL)
        self.assertEqual(prioritize(*case).priority, NEXT)
        self.assertEqual(prioritize(*case, settings=Settings(cvss_high=7.5)).priority, NEVER)

    def test_reasons_and_profile_show_the_active_values(self):
        custom = Settings(cvss_high=7.25)
        result = prioritize(8.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, settings=custom)
        self.assertTrue(any("CVSS >= 7.25" in reason for reason in result.reasons))
        self.assertTrue(result.profile.startswith("custom ("))
        self.assertIn("cvss_high=7.25", result.profile)
        default = prioritize(8.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH)
        self.assertTrue(any("CVSS >= 7.0" in reason for reason in default.reasons))
        self.assertTrue(default.profile.startswith("defaults ("))

    def test_default_settings_match_implicit_defaults_everywhere(self):
        for cvss in (0.0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0):
            for combo in itertools.product(Threat, Asset, Exposure, Controls, Patch):
                self.assertEqual(prioritize(cvss, *combo), prioritize(cvss, *combo, settings=DEFAULT_SETTINGS))

    def test_batch_uses_and_exports_the_settings(self):
        row = {"cvss": "7.2", "threat": "public", "asset": "standard", "exposure": "high"}
        self.assertEqual(batch.score_row(2, row).priority, NOW)
        custom = Settings(cvss_high=7.5)
        item = batch.score_row(2, row, custom)
        self.assertEqual(item.priority, NEXT)
        fd, out = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        self.addCleanup(os.remove, out)
        batch.write_results(out, [item])
        with open(out, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(rows[0]["scoring_settings"], custom.describe())
        self.assertTrue(math.isfinite(float(rows[0]["ordering_score"])))


if __name__ == "__main__":
    unittest.main()
