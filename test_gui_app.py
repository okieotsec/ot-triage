import contextlib
import gc
import io
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import settings as scoring
import threatdata as td
import uiprefs
import vuln_prioritizer_gui as app_module
from gui_theme import DARK, LIGHT
from settings import DEFAULT_SETTINGS, Settings
from test_threatdata import epss_bytes, kev_bytes
from uiprefs import UiPrefs


class AppTestCase(unittest.TestCase):
    """Each test gets its own hidden Tk root, temp folders, a blocked network and silent dialogs."""

    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(f"no display available ({error})")
        self.root.withdraw()
        gc.disable()
        self.addCleanup(self._destroy_root)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.settings_path, self.prefs_path, self.data_dir = (self.work / "settings.json", self.work / "ui.json",
                                                              self.work / "data")
        self.dialogs = {name: mock.patch(f"gui_context.messagebox.{name}", return_value=True)
                        for name in ("showwarning", "showinfo", "showerror", "askokcancel")}
        self.mocks = {name: patch.start() for name, patch in self.dialogs.items()}
        for patch in self.dialogs.values():
            self.addCleanup(patch.stop)
        guard = mock.patch("threatdata.fetch", side_effect=AssertionError("tests must never use the network"))
        guard.start()
        self.addCleanup(guard.stop)

    def _destroy_root(self):
        with contextlib.suppress(tk.TclError):
            self.root.destroy()
        gc.collect()
        gc.enable()

    def make(self, **kwargs):
        self.app = app_module.App(self.root, self.settings_path, self.prefs_path, self.data_dir, **kwargs)
        self.pump()
        return self.app

    def pump(self, seconds=0.0, until=None):
        import time
        end = time.monotonic() + seconds
        while True:
            self.root.update()
            if until is not None and until():
                return True
            if time.monotonic() >= end:
                return until() if until is not None else True
            time.sleep(0.01)

    def labels(self, widget):
        found = []
        stack = [widget]
        while stack:
            node = stack.pop()
            stack.extend(node.winfo_children())
            if isinstance(node, tk.Label):
                found.append(node.cget("text"))
        return found

    def status_texts(self):
        return [w.cget("text") for w in self.app.status_bar.winfo_children() if isinstance(w, tk.Label)]


class ShellTests(AppTestCase):
    def test_builds_with_five_views_and_creates_them_lazily(self):
        app = self.make()
        self.assertEqual(list(app.nav_buttons), ["assess", "batch", "threat", "settings", "about"])
        self.assertEqual([b.cget("text") for b in app.nav_buttons.values()][:2], ["Assess   Ctrl+1", "Batch   Ctrl+2"])
        self.assertEqual(list(app.views), ["assess"])
        self.assertEqual(app.current, "assess")

    def test_navigation_shows_one_view_and_marks_the_current_button(self):
        app = self.make()
        for name in ("batch", "threat", "settings", "about", "assess"):
            app.show_view(name)
            self.pump()
            visible = [n for n, v in app.views.items() if v.frame.winfo_manager()]
            self.assertEqual(visible, [name])
            self.assertEqual(str(app.nav_buttons[name].cget("bg")), app.style.theme.card)
            others = [b for n, b in app.nav_buttons.items() if n != name]
            self.assertTrue(all(str(b.cget("bg")) == app.style.theme.header for b in others))
        self.assertEqual(len(app.views), 5)

    def test_nav_buttons_navigate(self):
        app = self.make()
        app.nav_buttons["threat"].invoke()
        self.assertEqual(app.current, "threat")

    def test_keyboard_shortcuts(self):
        app = self.make()
        self.root.deiconify()
        self.root.geometry("1100x800+0+0")
        self.root.focus_force()
        self.pump(0.2)
        app.show_view("assess")
        for key, expected in (("<Control-Key-3>", "threat"), ("<Control-Key-5>", "about"),
                              ("<Control-Key-2>", "batch"), ("<Control-Key-4>", "settings"),
                              ("<Control-Key-1>", "assess")):
            self.root.event_generate(key)
            self.pump(0.1)
            if app.current != expected and key == "<Control-Key-3>":
                self.skipTest("the window manager did not give the test window keyboard focus")
            self.assertEqual(app.current, expected, key)
        app.show_view("about")
        self.root.event_generate("<Control-l>")
        self.pump(0.1)
        self.assertEqual(app.current, "assess")

    def test_copy_shortcut_copies_only_when_the_view_can(self):
        app = self.make()
        assess = app.views["assess"]
        assess.ctx.copy = mock.Mock()
        app.ctx.assess_state.cvss.set("8.0")
        self.pump(0.1)
        app._copy_summary()
        self.assertTrue(assess.ctx.copy.called)
        app.show_view("about")
        assess.ctx.copy.reset_mock()
        app._copy_summary()
        assess.ctx.copy.assert_not_called()

    def test_narrow_windows_move_the_navigation_to_the_top(self):
        app = self.make()
        app._layout(True)
        self.assertEqual((app.nav.grid_info()["row"], app.nav.grid_info()["column"]), (1, 0))
        self.assertEqual(int(app.nav.grid_info()["columnspan"]), 2)
        self.assertEqual(int(app.status_bar.grid_info()["row"]), 3)
        self.assertTrue(all(b.pack_info()["side"] == "left" for b in app.nav_buttons.values()))
        app._layout(False)
        self.assertEqual((int(app.nav.grid_info()["row"]), int(app.nav.grid_info()["column"])), (1, 0))
        self.assertEqual(int(app.content.grid_info()["column"]), 1)
        self.assertTrue(all(b.pack_info()["fill"] == "x" for b in app.nav_buttons.values()))

    def test_the_header_accent_line_spans_the_whole_width(self):
        app = self.make()
        self.root.deiconify()
        self.root.geometry("1100x800+0+0")
        self.pump(0.3)
        accent = [w for w in app.header.winfo_children() if isinstance(w, tk.Frame) and w.winfo_reqheight() == 3]
        self.assertEqual(len(accent), 1)
        self.assertGreaterEqual(accent[0].winfo_width(), app.header.winfo_width() - 2)
        self.assertEqual(str(accent[0].cget("bg")), app.style.theme.accent)

    def test_header_has_the_title_and_the_exposure_definition_lives_in_assess(self):
        app = self.make()
        self.assertIn("Vulnerability Prioritizer", self.labels(app.header))
        self.assertIn(app_module.SUBTITLE, self.labels(app.header))

    def test_unexpected_errors_show_a_short_message_and_keep_details_off_the_screen(self):
        app = self.make()
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            try:
                raise KeyError("secret internal detail")
            except KeyError as exc:
                app.report_exception(type(exc), exc, exc.__traceback__)
        message = self.mocks["showerror"].call_args[0][1]
        self.assertIn("KeyError", message)
        self.assertNotIn("secret internal detail", message)
        self.assertNotIn("Traceback", message)
        self.assertIn("Traceback", error.getvalue())


class SettingsAndAppearanceTests(AppTestCase):
    def test_defaults_show_no_badge(self):
        app = self.make()
        self.assertFalse(app.badge.winfo_manager())
        self.assertIn("Scoring: defaults", self.status_texts())

    def test_a_custom_settings_file_shows_the_badge_and_changes_results(self):
        scoring.save(Settings(cvss_high=7.5), self.settings_path)
        app = self.make()
        self.assertTrue(app.badge.winfo_manager())
        self.assertIn("Custom scoring", app.badge.cget("text"))
        self.assertIn("Scoring: custom", self.status_texts())
        state = app.ctx.assess_state
        for var, value in ((state.cvss, "7.2"), (state.threat, "PUBLIC"), (state.exposure, "HIGH")):
            var.set(value)
        self.pump(0.2)
        self.assertEqual(app.views["assess"].badge.cget("text"), "NEXT")

    def test_changing_settings_updates_the_badge_status_and_the_assess_result(self):
        app = self.make()
        state = app.ctx.assess_state
        for var, value in ((state.cvss, "7.2"), (state.threat, "PUBLIC"), (state.exposure, "HIGH")):
            var.set(value)
        self.pump(0.2)
        self.assertEqual(app.views["assess"].badge.cget("text"), "NOW")
        app.ctx.settings_changed(Settings(cvss_high=7.5))
        self.pump(0.1)
        self.assertTrue(app.badge.winfo_manager())
        self.assertEqual(app.views["assess"].badge.cget("text"), "NEXT")
        self.assertIn("Scoring: custom", self.status_texts())
        app.ctx.settings_changed(DEFAULT_SETTINGS)
        self.pump(0.1)
        self.assertFalse(app.badge.winfo_manager())
        self.assertEqual(app.views["assess"].badge.cget("text"), "NOW")

    def test_an_unusable_settings_file_falls_back_and_warns_once(self):
        self.settings_path.write_text("{ not json", encoding="utf-8")
        self.prefs_path.write_text('{"version": 1, "theme": "blue"}', encoding="utf-8")
        app = self.make()
        self.pump(0.5)
        self.assertEqual(app.ctx.settings, DEFAULT_SETTINGS)
        self.assertEqual(app.ctx.prefs, uiprefs.DEFAULT_PREFS)
        self.assertEqual(self.mocks["showwarning"].call_count, 1)
        message = self.mocks["showwarning"].call_args[0][1]
        self.assertIn("Default settings are in effect", message)
        self.assertIn("Default preferences are in effect", message)
        self.assertFalse(app.badge.winfo_manager())

    def test_changing_the_theme_rebuilds_the_window_and_keeps_the_user_where_they_were(self):
        app = self.make()
        state = app.ctx.assess_state
        for var, value in ((state.cvss, "8.8"), (state.threat, "ACTIVE"), (state.exposure, "HIGH")):
            var.set(value)
        app.show_view("settings")
        self.pump(0.1)
        self.assertEqual(str(app.header.cget("bg")), DARK.header)
        app.ctx.prefs_changed(UiPrefs(theme="light"))
        self.pump(0.2)
        self.assertEqual(str(app.header.cget("bg")), LIGHT.header)
        self.assertEqual(app.current, "settings")
        self.assertEqual(app.ctx.assess_state.cvss.get(), "8.8")
        app.show_view("assess")
        self.pump(0.2)
        self.assertEqual(app.views["assess"].badge.cget("text"), "NOW")
        self.assertEqual(str(app.views["assess"].frame.cget("bg")), LIGHT.bg)

    def test_a_saved_theme_and_text_size_are_used_at_the_next_start(self):
        uiprefs.save(UiPrefs("light", 130), self.prefs_path)
        app = self.make()
        self.assertEqual((app.style.theme.name, app.style.scale), ("light", 1.3))

    def test_the_settings_screen_changes_the_theme_end_to_end(self):
        app = self.make()
        app.show_view("settings")
        view = app.views["settings"]
        view.theme_var.set("light")
        view.apply_appearance()
        self.pump(0.3)
        self.assertEqual(uiprefs.load(self.prefs_path).prefs.theme, "light")
        self.assertEqual(str(app.header.cget("bg")), LIGHT.header)
        self.assertEqual(app.current, "settings")


class HostileConfigTests(AppTestCase):
    def test_every_hostile_settings_file_starts_the_app_with_defaults_and_one_warning(self):
        import malicious_cases
        cases = malicious_cases.build_settings(str(self.work))
        for name, path in cases.items():
            with self.subTest(case=name):
                self.mocks["showwarning"].reset_mock()
                self.settings_path = Path(path)
                app = self.make()
                self.pump(0.4)
                self.assertEqual(app.ctx.settings, DEFAULT_SETTINGS, name)
                self.assertEqual(self.mocks["showwarning"].call_count, 1, name)
                self.assertLess(len(self.mocks["showwarning"].call_args[0][1]), 800)
                self.assertFalse(app.badge.winfo_manager())
                for child in self.root.winfo_children():
                    child.destroy()
                gc.collect()

    def test_hostile_preference_files_fall_back_to_defaults(self):
        cases = {"empty": "", "truncated": '{"version": 1, "the', "theme": '{"version": 1, "theme": "<script>", '
                 '"text_percent": 100, "startup_update": false}', "big": " " * 10000,
                 "types": '{"version": 1, "theme": 1, "text_percent": "100", "startup_update": "no"}',
                 "extra": '{"version": 1, "theme": "dark", "text_percent": 100, "startup_update": false, "x": 1}'}
        for name, text in cases.items():
            with self.subTest(case=name):
                self.prefs_path.write_text(text, encoding="utf-8")
                self.mocks["showwarning"].reset_mock()
                app = self.make()
                self.pump(0.4)
                self.assertEqual(app.ctx.prefs, uiprefs.DEFAULT_PREFS, name)
                self.assertEqual(self.mocks["showwarning"].call_count, 1, name)
                for child in self.root.winfo_children():
                    child.destroy()
                gc.collect()

    def test_hostile_stored_threat_data_shows_problem_chips_and_the_app_keeps_working(self):
        self.data_dir.mkdir(parents=True)
        (self.data_dir / td.KEV_FILE).write_bytes(b"{ not json")
        (self.data_dir / td.EPSS_FILE).write_bytes(b"\x1f\x8b broken")
        app = self.make()
        chips = [w.cget("text") for w in app.status_bar.winfo_children() if isinstance(w, tk.Label)]
        self.assertEqual(chips[:2], ["! KEV problem", "! EPSS problem"])
        app.show_view("assess")
        app.ctx.assess_state.cvss.set("8")
        app.ctx.assess_state.cve.set("CVE-2024-0001")
        app.views["assess"].lookup()
        self.pump(0.2)
        self.assertEqual(app.views["assess"].badge.cget("text"), "NEVER")
        self.assertIn("No threat data is loaded", app.views["assess"].cve_message.cget("text"))


class StatusBarTests(AppTestCase):
    def test_no_data_says_so(self):
        self.make()
        chips = [w.cget("text") for w in self.app.status_bar.winfo_children() if isinstance(w, tk.Label)]
        self.assertIn("⚠ KEV not loaded", chips)
        self.assertIn("⚠ EPSS not loaded", chips)

    def test_fresh_and_stale_data_are_shown_with_a_symbol_and_a_word(self):
        (self.work / "k.json").write_bytes(kev_bytes())
        (self.work / "e.gz").write_bytes(epss_bytes())
        td.import_from_files(self.work / "k.json", self.work / "e.gz", self.data_dir)
        self.make()
        chips = [w.cget("text") for w in self.app.status_bar.winfo_children() if isinstance(w, tk.Label)]
        self.assertTrue(any(c.startswith("✓ KEV 2026.10.04") and "0 days" in c for c in chips), chips)
        self.assertTrue(any(c.startswith("✓ EPSS v2026.06.15") for c in chips), chips)
        old = td.datetime.datetime(2026, 9, 1, tzinfo=td.datetime.timezone.utc)
        td.import_from_files(self.work / "k.json", None, self.data_dir, old)
        self.app.refresh_status()
        chips = [w.cget("text") for w in self.app.status_bar.winfo_children() if isinstance(w, tk.Label)]
        self.assertTrue(any(c.startswith("⚠ KEV") and c.endswith("(stale)") for c in chips), chips)

    def test_clicking_a_chip_opens_the_threat_data_view(self):
        app = self.make()
        self.root.deiconify()
        self.root.geometry("1100x800+0+0")
        self.pump(0.2)
        chip = next(w for w in app.status_bar.winfo_children() if isinstance(w, tk.Label) and "KEV" in w.cget("text"))
        chip.event_generate("<Button-1>")
        self.pump(0.1)
        self.assertEqual(app.current, "threat")

    def test_the_update_button_asks_before_downloading(self):
        app = self.make()
        self.mocks["askokcancel"].return_value = False
        app.start_update()
        self.pump(0.2)
        self.assertEqual(app.current, "threat")
        self.assertTrue(self.mocks["askokcancel"].called)
        self.assertIn("www.cisa.gov", self.mocks["askokcancel"].call_args[0][1])
        self.assertFalse(app.ctx.updater.results)
        self.assertFalse(self.data_dir.exists())

    def test_the_status_bar_follows_an_update_and_shows_when_it_is_busy(self):
        import threading
        release = threading.Event()

        def fake(url, max_bytes, hosts, **_kw):
            release.wait(5)
            return kev_bytes() if url == td.KEV_URL else epss_bytes()

        app = self.make()
        with mock.patch("threatdata.fetch", fake):
            app.start_update()
            self.pump(0.3)
            button = [w for w in app.status_bar.winfo_children() if isinstance(w, tk.Button)][0]
            self.assertEqual((button.cget("text"), str(button.cget("state"))), ("Updating…", "disabled"))
            release.set()
            self.pump(10, until=lambda: bool(app.ctx.updater.results) and not app.ctx.worker.running)
            self.pump(0.2)
        chips = [w.cget("text") for w in app.status_bar.winfo_children() if isinstance(w, tk.Label)]
        self.assertTrue(any(c.startswith("✓ KEV") for c in chips), chips)
        self.assertEqual([w.cget("text") for w in app.status_bar.winfo_children() if isinstance(w, tk.Button)],
                         ["Update"])

    def test_startup_update_runs_only_when_enabled(self):
        calls = []

        def fake(url, max_bytes, hosts, **_kw):
            calls.append(url)
            return kev_bytes() if url == td.KEV_URL else epss_bytes()

        with mock.patch("threatdata.fetch", fake):
            self.make()
            self.pump(1.2)
            self.assertEqual(calls, [])
            self.root.destroy()
            self.setUp()
            uiprefs.save(UiPrefs(startup_update=True), self.prefs_path)
            with mock.patch("threatdata.fetch", fake):
                app = self.make()
                self.pump(10, until=lambda: bool(app.ctx.updater.results) and not app.ctx.worker.running)
                self.pump(0.2)
        self.assertEqual(sorted(calls), sorted([td.KEV_URL, td.EPSS_URL]))
        self.assertFalse(self.mocks["askokcancel"].called)
        self.assertTrue(all(r.ok for r in app.ctx.updater.results))


if __name__ == "__main__":
    unittest.main()
