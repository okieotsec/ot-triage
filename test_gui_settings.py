import json
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import gui_about
import gui_settings
import settings as scoring
import uiprefs
from gui_context import Context
from gui_testing import DisplayTestCase
from settings import DEFAULT_SETTINGS, Settings
from uiprefs import DEFAULT_PREFS, UiPrefs

HERE = Path(__file__).resolve().parent


class ParseFieldsTests(unittest.TestCase):
    GOOD = {"cvss_high": "7.0", "cvss_critical": "9.0", "epss_percentile_cutoff": "0.95", "stale_days": "7"}

    def parse(self, **changes):
        return gui_settings.parse_fields({**self.GOOD, **changes})

    def test_valid_values(self):
        settings, errors = self.parse()
        self.assertEqual((settings, errors), (DEFAULT_SETTINGS, {}))
        settings, _ = self.parse(cvss_high=" 7.5 ", stale_days="14")
        self.assertEqual((settings.cvss_high, settings.stale_days), (7.5, 14))

    def test_text_that_is_not_a_number(self):
        for field, bad in (("cvss_high", "seven"), ("cvss_high", ""), ("cvss_critical", "9,0"),
                           ("epss_percentile_cutoff", "high"), ("stale_days", "7.5"), ("stale_days", "week"),
                           ("stale_days", ""), ("cvss_high", "nan"), ("cvss_high", "inf")):
            settings, errors = self.parse(**{field: bad})
            self.assertIsNone(settings, (field, bad))
            self.assertIn(field, errors, (field, bad))

    def test_out_of_range_and_inconsistent_values_name_the_field(self):
        for field, bad in (("cvss_high", "4.9"), ("cvss_high", "8.1"), ("cvss_critical", "7.9"),
                           ("cvss_critical", "10.1"), ("epss_percentile_cutoff", "0.4"),
                           ("epss_percentile_cutoff", "1"), ("stale_days", "0"), ("stale_days", "91"),
                           ("stale_days", "-3")):
            settings, errors = self.parse(**{field: bad})
            self.assertIsNone(settings, (field, bad))
            self.assertEqual(list(errors), [field], (field, bad))
        settings, errors = self.parse(cvss_high="7.9", cvss_critical="8.0")
        self.assertIsNone(settings)
        self.assertIn("at least 0.5", " ".join(errors.values()))

    def test_every_problem_is_reported_at_once(self):
        _settings, errors = self.parse(cvss_high="x", stale_days="y", epss_percentile_cutoff="z")
        self.assertEqual(set(errors), {"cvss_high", "stale_days", "epss_percentile_cutoff"})

    def test_huge_and_odd_text_never_raises(self):
        for bad in ("9" * 5000, "1e999", "0x10", "٣", " \t ", "7.0\x00"):
            for field in self.GOOD:
                settings, errors = self.parse(**{field: bad})
                self.assertTrue(settings is None or isinstance(settings, Settings), (field, bad))
                self.assertEqual(settings is None, bool(errors), (field, bad))


class SettingsViewTestCase(DisplayTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.ctx = Context(self.root, self.style, DEFAULT_SETTINGS, DEFAULT_PREFS)
        self.ctx.settings_path = self.work / "settings.json"
        self.ctx.prefs_path = self.work / "ui.json"
        for name in ("info", "error", "warn"):
            setattr(self.ctx, name, mock.Mock())
        self.ctx.confirm = mock.Mock(return_value=True)
        self.ctx.settings_changed = mock.Mock(side_effect=self._settings_changed)
        self.ctx.prefs_changed = mock.Mock(side_effect=self._prefs_changed)
        self.holder = tk.Toplevel(self.root)
        self.holder.geometry("1000x900+0+0")
        self.addCleanup(self.holder.destroy)

    def _settings_changed(self, settings):
        self.ctx.settings = settings

    def _prefs_changed(self, prefs):
        self.ctx.prefs = prefs

    def build(self):
        self.view = gui_settings.SettingsView(self.ctx, self.holder)
        self.view.frame.pack(fill=tk.BOTH, expand=True)
        self.pump()
        return self.view

    def type_into(self, name, text):
        self.ctx.settings_state.vars[name].set(text)
        self.pump()


class SettingsViewTests(SettingsViewTestCase):
    def test_shows_the_current_values_and_nothing_to_save(self):
        view = self.build()
        self.assertEqual({n: v.get() for n, v in self.ctx.settings_state.vars.items()},
                         {"cvss_high": "7", "cvss_critical": "9", "epss_percentile_cutoff": "0.95", "stale_days": "7"})
        self.assertEqual(str(view.save_button.cget("state")), "disabled")
        self.assertIn("default values", view.status.cget("text"))

    def test_each_field_describes_its_default_and_range(self):
        view = self.build()
        texts = []
        for widget in view.scroll.body.winfo_children():
            stack = [widget]
            while stack:
                node = stack.pop()
                stack.extend(node.winfo_children())
                if isinstance(node, tk.Label):
                    texts.append(node.cget("text"))
        joined = "\n".join(texts)
        for needle in ("Default 7, allowed 5.0 to 8.0", "Default 9, allowed 8.0 to 10.0",
                       "Default 0.95, allowed 0.5 to 0.999", "Default 7, allowed 1 to 90"):
            self.assertIn(needle, joined)

    def test_invalid_input_is_flagged_beside_the_field_and_cannot_be_saved(self):
        view = self.build()
        self.type_into("cvss_high", "11")
        self.assertIn("✖", view.messages["cvss_high"].cget("text"))
        self.assertEqual(str(view.entries["cvss_high"].cget("highlightbackground")), self.style.theme.error)
        self.assertEqual(str(view.save_button.cget("state")), "disabled")
        self.assertIn("Fix the highlighted values", view.status.cget("text"))
        view.save()
        self.assertFalse(self.ctx.settings_path.exists())
        self.type_into("cvss_high", "7.5")
        self.assertEqual(view.messages["cvss_high"].cget("text"), "")
        self.assertEqual(str(view.save_button.cget("state")), "normal")
        self.assertIn("Not saved yet", view.status.cget("text"))

    def test_critical_line_too_close_to_the_high_line(self):
        view = self.build()
        self.type_into("cvss_high", "8")
        self.type_into("cvss_critical", "8")
        self.assertIn("at least 0.5", view.messages["cvss_critical"].cget("text"))
        self.assertEqual(str(view.save_button.cget("state")), "disabled")

    def test_save_writes_the_file_and_applies_the_settings(self):
        view = self.build()
        self.type_into("cvss_high", "7.5")
        view.save()
        self.assertEqual(self.ctx.settings, Settings(cvss_high=7.5))
        self.assertEqual(scoring.load(self.ctx.settings_path).settings, Settings(cvss_high=7.5))
        self.assertEqual(json.loads(self.ctx.settings_path.read_text())["cvss_high"], 7.5)
        self.assertIn("differ from the defaults", view.status.cget("text"))
        self.assertEqual(str(view.save_button.cget("state")), "disabled")
        self.ctx.settings_changed.assert_called_once()

    def test_a_failed_save_reports_the_problem_and_changes_nothing(self):
        blocker = self.work / "blocker"
        blocker.write_text("a file, not a folder")
        self.ctx.settings_path = blocker / "settings.json"
        view = self.build()
        self.type_into("stale_days", "14")
        view.save()
        self.assertEqual(self.ctx.error.call_args[0][0], "Settings not saved")
        self.assertEqual(self.ctx.settings, DEFAULT_SETTINGS)
        self.ctx.settings_changed.assert_not_called()

    def test_restore_defaults_needs_confirmation_and_resets_everything(self):
        view = self.build()
        for name, text in (("cvss_high", "6"), ("stale_days", "30")):
            self.type_into(name, text)
        view.save()
        self.ctx.confirm.return_value = False
        view.restore_defaults()
        self.assertEqual(self.ctx.settings.cvss_high, 6.0)
        self.assertEqual(scoring.load(self.ctx.settings_path).settings.stale_days, 30)
        self.ctx.confirm.return_value = True
        view.restore_defaults()
        self.assertEqual(self.ctx.settings, DEFAULT_SETTINGS)
        self.assertEqual(scoring.load(self.ctx.settings_path).settings, DEFAULT_SETTINGS)
        self.assertEqual(self.ctx.settings_state.vars["cvss_high"].get(), "7")
        self.assertIn("default values", view.status.cget("text"))

    def test_restore_defaults_failure_is_reported(self):
        blocker = self.work / "blocker"
        blocker.write_text("x")
        self.ctx.settings_path = blocker / "settings.json"
        view = self.build()
        view.restore_defaults()
        self.assertEqual(self.ctx.error.call_args[0][0], "Settings not saved")

    def test_unsaved_typing_survives_a_rebuild(self):
        view = self.build()
        self.type_into("cvss_high", "6.5")
        view.frame.destroy()
        rebuilt = self.build()
        self.assertEqual(self.ctx.settings_state.vars["cvss_high"].get(), "6.5")
        self.assertIn("Not saved yet", rebuilt.status.cget("text"))


class AppearanceTests(SettingsViewTestCase):
    def test_theme_text_size_and_startup_choices_are_saved_separately(self):
        view = self.build()
        view.theme_var.set("light")
        view.apply_appearance()
        self.assertEqual(self.ctx.prefs.theme, "light")
        self.assertEqual(uiprefs.load(self.ctx.prefs_path).prefs, UiPrefs(theme="light"))
        view.size_var.set("130")
        view.startup_var.set(True)
        view.apply_appearance()
        self.assertEqual(uiprefs.load(self.ctx.prefs_path).prefs, UiPrefs("light", 130, True))
        self.assertFalse(self.ctx.settings_path.exists())
        self.assertEqual(self.ctx.settings, DEFAULT_SETTINGS)

    def test_unchanged_choices_do_not_rebuild(self):
        view = self.build()
        view.apply_appearance()
        self.ctx.prefs_changed.assert_not_called()

    def test_a_failed_save_reverts_the_controls(self):
        blocker = self.work / "blocker"
        blocker.write_text("x")
        self.ctx.prefs_path = blocker / "ui.json"
        view = self.build()
        view.theme_var.set("light")
        view.apply_appearance()
        self.assertEqual(self.ctx.error.call_args[0][0], "Preferences not saved")
        self.assertEqual(view.theme_var.get(), "dark")
        self.ctx.prefs_changed.assert_not_called()

    def test_startup_update_is_off_by_default(self):
        view = self.build()
        self.assertFalse(view.startup_var.get())
        self.assertIn("off by default", view.startup_check.cget("text"))


class AboutViewTests(DisplayTestCase):
    def test_about_has_the_version_the_definition_and_an_attribution_without_a_named_person(self):
        ctx = Context(self.root, self.style, DEFAULT_SETTINGS, DEFAULT_PREFS)
        holder = tk.Toplevel(self.root)
        self.addCleanup(holder.destroy)
        view = gui_about.AboutView(ctx, holder)
        view.frame.pack(fill=tk.BOTH, expand=True)
        self.pump()
        texts, stack = [], [view.frame]
        while stack:
            node = stack.pop()
            stack.extend(node.winfo_children())
            if isinstance(node, tk.Label):
                texts.append(node.cget("text"))
        joined = "\n".join(texts)
        self.assertIn("0.3.0", joined)
        self.assertIn("no routable path from IT or the internet", joined)
        self.assertIn("its definitions are not Dragos'", joined)
        self.assertIn("fully offline", joined)

    def test_every_document_it_points_to_exists(self):
        for name, _description in gui_about.DOCUMENTS:
            self.assertTrue((HERE / name).exists(), name)


if __name__ == "__main__":
    unittest.main()
