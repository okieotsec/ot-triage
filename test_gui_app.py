import contextlib
import gc
import io
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import gui_testing
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


class SandboxTests(unittest.TestCase):
    def test_default_paths_point_into_the_private_test_home(self):
        for path in (scoring.default_path(), uiprefs.default_path(), td.default_data_dir()):
            self.assertTrue(str(path).startswith(gui_testing.SANDBOX), path)
        self.assertTrue(str(Path.home()).startswith(gui_testing.SANDBOX))

    def test_an_app_started_without_explicit_paths_writes_only_into_the_sandbox(self):
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("no display available")
        self.addCleanup(root.destroy)
        root.withdraw()
        with mock.patch("gui_context.messagebox.showwarning"):
            app = app_module.App(root)
            app.ctx.prefs_changed(UiPrefs(theme="light"))
            uiprefs.save(UiPrefs(theme="light"))
        self.assertTrue(uiprefs.default_path().is_file())
        self.assertTrue(str(uiprefs.default_path()).startswith(gui_testing.SANDBOX))


class ShellTests(AppTestCase):
    def test_builds_with_five_views_and_creates_them_lazily(self):
        app = self.make()
        self.assertEqual(list(app.nav_buttons), ["assess", "batch", "threat", "settings", "about"])
        self.assertEqual([b.cget("text") for b in app.nav_buttons.values()], ["Assess", "Batch", "Threat data",
                                                                                "Settings", "About"])
        self.assertEqual([h.cget("text") for h in app.nav_hints.values()], [f"Ctrl+{i}" for i in range(1, 6)])
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
            self.assertEqual(str(app.nav_bars[name].cget("bg")), app.style.theme.accent)
            others = [n for n in app.nav_buttons if n != name]
            self.assertTrue(all(str(app.nav_buttons[n].cget("bg")) == app.style.theme.header for n in others))
            self.assertTrue(all(str(app.nav_bars[n].cget("bg")) == app.style.theme.header for n in others))
            self.assertTrue(all(str(b.cget("highlightbackground")) == str(b.cget("bg"))
                                for b in app.nav_buttons.values()))
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
        self.assertTrue(all(i.pack_info()["side"] == "left" for i in app.nav_items.values()))
        app._layout(False)
        self.assertEqual((int(app.nav.grid_info()["row"]), int(app.nav.grid_info()["column"])), (1, 0))
        self.assertEqual(int(app.content.grid_info()["column"]), 1)
        self.assertTrue(all(i.pack_info()["fill"] == "x" for i in app.nav_items.values()))

    def test_ctrl_plus_minus_and_zero_change_the_text_size_and_remember_it(self):
        app = self.make()
        self.root.deiconify()
        self.root.geometry("1100x800+0+0")
        self.root.focus_force()
        self.pump(0.2)
        before = app.style.font(10)[1]

        def press(key):
            self.root.focus_force()
            self.pump(0.1)
            self.root.event_generate(key)
            self.pump(0.2)

        press("<Control-plus>")
        if self.app.ctx.prefs.text_percent != 115:
            self.skipTest("the window manager did not give the test window keyboard focus")
        self.assertGreater(self.app.style.font(10)[1], before)
        self.assertEqual(uiprefs.load(self.prefs_path).prefs.text_percent, 115)
        press("<Control-minus>")
        press("<Control-minus>")
        self.assertEqual(self.app.ctx.prefs.text_percent, 90)
        press("<Control-Key-0>")
        self.assertEqual(self.app.ctx.prefs.text_percent, 100)

    def test_zoom_stops_at_the_smallest_and_largest_size_and_keeps_the_inputs(self):
        app = self.make()
        app.ctx.assess_state.cvss.set("7.5")
        for _ in range(10):
            app.zoom(+1)
        self.assertEqual(app.ctx.prefs.text_percent, max(uiprefs.TEXT_PERCENTS))
        for _ in range(10):
            app.zoom(-1)
        self.assertEqual(app.ctx.prefs.text_percent, min(uiprefs.TEXT_PERCENTS))
        self.assertEqual(app.ctx.assess_state.cvss.get(), "7.5")

    def test_zoom_that_cannot_be_saved_explains_and_changes_nothing(self):
        app = self.make()
        with mock.patch("uiprefs.save", side_effect=OSError(13, "Permission denied")):
            app.zoom(+1)
        self.assertEqual(app.ctx.prefs.text_percent, 100)
        self.assertTrue(self.mocks["showerror"].called)

    def test_the_header_accent_line_spans_the_whole_width(self):
        app = self.make()
        self.root.deiconify()
        self.root.geometry("1100x800+0+0")
        self.pump(0.3)
        accent = [w for w in app.header.winfo_children() if isinstance(w, tk.Frame) and w.winfo_reqheight() == 3]
        self.assertEqual(len(accent), 1)
        self.assertGreaterEqual(accent[0].winfo_width(), app.header.winfo_width() - 2)
        self.assertEqual(str(accent[0].cget("bg")), app.style.theme.accent)

    def test_the_narrow_tab_strip_hides_shortcut_hints_and_fits_the_minimum_width_at_every_text_size(self):
        for percent in (90, 100, 115, 130):
            with self.subTest(text_percent=percent):
                uiprefs.save(UiPrefs(text_percent=percent), self.prefs_path)
                app = self.make()
                app._layout(True)
                self.root.update_idletasks()
                self.assertTrue(all(not h.winfo_manager() for h in app.nav_hints.values()))
                total = sum(i.winfo_reqwidth() + 4 for i in app.nav_items.values())
                self.assertLessEqual(total, 700, f"{total}px of tabs at {percent}% text")
                app._layout(False)
                self.assertTrue(all(h.winfo_manager() for h in app.nav_hints.values()))
                for child in self.root.winfo_children():
                    child.destroy()
                gc.collect()

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


class KeyboardReachabilityTests(AppTestCase):
    """Every interactive control, in every view, must be on the Tab path (the keyboard-only checklist item)."""

    def interactive(self, root_widget):
        found, stack = [], [root_widget]
        while stack:
            widget = stack.pop()
            stack.extend(widget.winfo_children())
            if not widget.winfo_ismapped():
                continue
            kind = type(widget).__name__
            takes_focus = str(widget.cget("takefocus")) if "takefocus" in widget.keys() else "0"
            if (isinstance(widget, (tk.Entry, tk.Checkbutton)) or kind in ("Treeview", "Segmented")
                    or (isinstance(widget, tk.Button) and str(widget.cget("state")) == "normal")
                    or (isinstance(widget, (tk.Frame, tk.Label)) and takes_focus == "1")):
                found.append(widget)
        return found

    def tab_path(self, start):
        path, widget = [], start
        for _ in range(600):
            path.append(widget)
            widget = widget.tk_focusNext()
            if widget is None or widget is start:
                break
        return path

    def prepare(self):
        (self.work / "k.json").write_bytes(kev_bytes())
        (self.work / "e.gz").write_bytes(epss_bytes())
        td.import_from_files(self.work / "k.json", self.work / "e.gz", self.data_dir)
        app = self.make()
        self.root.wm_attributes("-type", "dialog")
        self.root.geometry("1200x900+20+20")
        self.root.deiconify()
        self.pump(0.3)
        state = app.ctx.assess_state
        state.cvss.set("8.0")
        return app

    def test_every_control_in_every_view_is_reachable_with_the_tab_key(self):
        app = self.prepare()
        for name in ("assess", "batch", "threat", "settings", "about"):
            with self.subTest(view=name):
                app.show_view(name)
                self.pump(0.2)
                path = self.tab_path(app.nav_buttons["assess"])
                controls = self.interactive(app.views[name].frame)
                if name != "about":
                    self.assertGreaterEqual(len(controls), 1, name)
                else:
                    self.assertEqual(controls, [], "the About view is read-only text")
                missing = [str(c) for c in controls if c not in path]
                self.assertEqual(missing, [], f"{name}: not reachable with Tab")
        self.assertIn(app.nav_buttons["about"], self.tab_path(app.nav_buttons["assess"]))
        status_buttons = [w for w in app.status_bar.winfo_children() if isinstance(w, tk.Button)]
        self.assertTrue(all(b in self.tab_path(app.nav_buttons["assess"]) for b in status_buttons))

    def test_the_assess_view_exposes_every_input_to_the_keyboard(self):
        app = self.prepare()
        app.show_view("assess")
        self.pump(0.2)
        controls = self.interactive(app.views["assess"].frame)
        kinds = [type(c).__name__ for c in controls]
        self.assertEqual(kinds.count("Segmented"), 5)
        self.assertGreaterEqual(kinds.count("Entry"), 3)
        self.assertGreaterEqual(kinds.count("Button"), 3)

    def test_nothing_that_is_not_interactive_steals_focus(self):
        app = self.prepare()
        app.show_view("assess")
        self.pump(0.2)
        for widget in self.tab_path(app.nav_buttons["assess"]):
            self.assertTrue(isinstance(widget, (tk.Entry, tk.Button, tk.Checkbutton, tk.Frame, tk.Label, tk.Text,
                                                tk.Canvas)) or type(widget).__name__ in ("Segmented", "Treeview",
                                                                                          "Scrollbar", "TScrollbar"),
                            type(widget).__name__)
            self.assertNotIsInstance(widget, tk.Toplevel)


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

    def test_the_status_bar_never_draws_a_black_focus_border(self):
        app = self.make()
        self.assertEqual(str(app.status_bar.cget("highlightcolor")), str(app.status_bar.cget("highlightbackground")))

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
