import tempfile
import tkinter as tk
import tkinter.font as tkfont
import unittest
from pathlib import Path
from unittest import mock

import explain
import gui_assess
import gui_theme
import threatdata as td
from gui_context import Context
from gui_testing import DisplayTestCase
from gui_theme import LIGHT, Style
from prioritizer import Asset, Controls, Exposure, Patch, Threat, prioritize
from settings import DEFAULT_SETTINGS, Settings
from test_threatdata import epss_bytes, epss_text, kev_bytes, kev_entry
from uiprefs import DEFAULT_PREFS

KEV_CVE, EPSS_CVE, QUIET_CVE = "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"


class AssessTestCase(DisplayTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data_dir = Path(tmp.name) / "data"
        self.ctx = Context(self.root, self.style, DEFAULT_SETTINGS, DEFAULT_PREFS)
        self.ctx.data_dir = self.data_dir
        self.ctx.warn = mock.Mock()
        self.ctx.copy = mock.Mock()
        self.holder = tk.Toplevel(self.root)
        self.holder.geometry("1100x900+0+0")
        self.addCleanup(self.holder.destroy)
        self.view = None

    def build(self, ctx=None):
        self.ctx = ctx or self.ctx
        self.view = gui_assess.AssessView(self.ctx, self.holder)
        self.view.frame.pack(fill=tk.BOTH, expand=True)
        self.pump()
        return self.view

    def load_data(self):
        entries = [kev_entry(KEV_CVE, knownRansomwareCampaignUse="Known")]
        rows = [f"{KEV_CVE},0.50000,0.97000", f"{EPSS_CVE},0.40000,0.99000", f"{QUIET_CVE},0.00100,0.20000"]
        results = td.import_from_files(self._write("kev.json", kev_bytes(entries)),
                                       self._write("epss.csv.gz", epss_bytes(epss_text(rows))), self.data_dir)
        self.assertTrue(all(r.ok for r in results))

    def _write(self, name, data):
        path = self.data_dir.parent / name
        path.write_bytes(data)
        return path

    def fill(self, cvss="8.0", threat=Threat.PUBLIC, asset=Asset.STANDARD, exposure=Exposure.HIGH,
             controls=Controls.NONE, patch=Patch.AVAILABLE):
        state = self.ctx.assess_state
        for var, value in ((state.cvss, cvss), (state.threat, threat.name), (state.asset, asset.name),
                           (state.exposure, exposure.name), (state.controls, controls.name),
                           (state.patch, patch.name)):
            var.set(value)
        self.pump()

    def chip_texts(self, flow):
        return [item.cget("text") for item in flow.items]


class AssessResultTests(AssessTestCase):
    def test_idle_until_a_cvss_score_is_entered(self):
        view = self.build()
        self.assertEqual(view.badge.cget("text"), "-")
        self.assertEqual(str(view.copy_button.cget("state")), "disabled")
        self.assertIsNone(view.result)

    def test_result_matches_the_rules_for_every_bucket(self):
        view = self.build()
        for args in ((8.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH), (6.0, Threat.PUBLIC, Asset.STANDARD,
                                                                           Exposure.HIGH),
                     (5.0, Threat.NONE, Asset.STANDARD, Exposure.LOW)):
            self.fill(str(args[0]), *args[1:])
            expected = prioritize(*args)
            self.assertEqual(view.badge.cget("text"), expected.priority)
            self.assertEqual((view.badge.fill, str(view.badge.cget("fg"))), self.style.bucket(expected.priority))
            self.assertEqual(view.score_label.cget("text"), f"{expected.score:.2f} / 10")
            self.assertEqual(view.action_label.cget("text"), expected.action)

    def test_invalid_scores_show_an_error_and_never_a_priority(self):
        view = self.build()
        for bad in ("abc", "11", "-1", "nan", "inf"):
            self.fill(bad)
            self.assertEqual(view.badge.cget("text"), "!", bad)
            self.assertEqual(str(view.cvss_hint.cget("fg")), self.style.theme.error)
            self.assertIsNone(view.result)
        self.fill("7.5")
        self.assertEqual(str(view.cvss_hint.cget("fg")), self.style.theme.muted)
        self.assertEqual(view.cvss_band.cget("text"), "HIGH")

    def test_chips_come_from_the_rules_and_each_has_a_symbol(self):
        view = self.build()
        self.fill("8.8", Threat.ACTIVE, Asset.CROWN, Exposure.HIGH)
        texts = self.chip_texts(view.chips)
        self.assertEqual(len(texts), len(view.result.factors))
        self.assertTrue(all(t[0] in "▲▼▬" for t in texts), texts)
        self.assertIn("▲ Crown jewel", texts)
        first_neutral = next(i for i, t in enumerate(texts) if t.startswith("▬"))
        self.assertTrue(all(t.startswith("▬") for t in texts[first_neutral:]))

    def test_reasoning_lists_inputs_and_settings(self):
        view = self.build()
        self.fill("8.0")
        view.reasoning.toggle()
        text = view.reasoning_text.cget("text")
        self.assertIn("CVSS: 8.0", text)
        self.assertIn("Scoring settings: defaults", text)
        self.assertNotIn("Threat data:", text)

    def test_what_would_change_panel_agrees_with_the_rules(self):
        view = self.build()
        self.fill("8.8", Threat.ACTIVE, Asset.CROWN, Exposure.HIGH)
        inputs = explain.AssessInputs(8.8, Threat.ACTIVE, Asset.CROWN, Exposure.HIGH, Controls.NONE, Patch.AVAILABLE)
        expected = explain.what_if_lines(explain.what_would_change(inputs))
        shown = ["".join(w.cget("text") for w in row.winfo_children()) for row in view.whatif.winfo_children()]
        self.assertEqual(len(shown), len(expected))
        self.assertTrue(any("NEXT" in line and "Strong" in line for line in shown), shown)

    def test_custom_settings_change_the_result_and_are_shown(self):
        ctx = Context(self.root, self.style, Settings(cvss_high=7.5), DEFAULT_PREFS)
        ctx.data_dir, ctx.warn, ctx.copy = self.data_dir, mock.Mock(), mock.Mock()
        view = self.build(ctx)
        self.fill("7.2", Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH)
        self.assertEqual(view.badge.cget("text"), "NEXT")
        view.reasoning.toggle()
        self.assertIn("custom (cvss_high=7.5", view.reasoning_text.cget("text"))

    def test_copy_buttons(self):
        view = self.build()
        self.fill("8.0")
        view.copy_summary()
        text = self.ctx.copy.call_args[0][0]
        self.assertTrue(text.startswith("Priority: NOW"))
        self.assertIn("Scoring settings: defaults", text)
        view.copy_markdown()
        self.assertTrue(self.ctx.copy.call_args[0][0].startswith("**Priority: NOW**"))
        self.assertIn("copied", view.copy_message.cget("text"))

    def test_copy_does_nothing_without_a_result(self):
        view = self.build()
        view.copy_summary()
        self.ctx.copy.assert_not_called()


class AssessCveTests(AssessTestCase):
    def lookup(self, cve):
        self.ctx.assess_state.cve.set(cve)
        self.view.lookup()
        self.pump()

    def test_invalid_cve_shows_a_message_and_changes_nothing(self):
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup("not a cve")
        self.assertIn("not a valid CVE", view.cve_message.cget("text"))
        self.assertIsNone(self.ctx.assess_state.info)
        self.assertEqual(self.ctx.assess_state.threat.get(), "NONE")

    def test_no_data_loaded_says_so_and_keeps_manual_control(self):
        view = self.build()
        self.fill("8.0", Threat.PUBLIC)
        self.lookup(KEV_CVE)
        self.assertIn("No threat data is loaded", view.cve_message.cget("text"))
        self.assertIn("does not mean the CVE is safe", view.cve_message.cget("text"))
        self.assertFalse(view.auto_threat)
        self.assertEqual(view.badge.cget("text"), "NOW")
        self.assertFalse(view.analyst_check.winfo_ismapped())

    def test_kev_cve_sets_the_threat_automatically(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE.lower())
        state = self.ctx.assess_state
        self.assertEqual((state.cve.get(), state.threat.get()), (KEV_CVE, "ACTIVE"))
        self.assertIn("In CISA KEV", view.threat_note.cget("text"))
        self.assertIn("▲ In CISA KEV", self.chip_texts(view.cve_chips))
        self.assertIn("▲ EPSS 97th percentile", self.chip_texts(view.cve_chips))
        self.assertIn("▲ In CISA KEV", self.chip_texts(view.chips))
        self.assertIn("▲ Ransomware use", self.chip_texts(view.chips))
        self.assertIn("CISA required action", view.action_label.cget("text"))
        view.reasoning.toggle()
        self.assertIn("Threat data: KEV 2026.10.04", view.reasoning_text.cget("text"))
        self.assertTrue(view.analyst_check.winfo_ismapped())

    def test_elevated_epss_is_labelled_as_such_and_a_quiet_cve_is_none(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(EPSS_CVE)
        self.assertEqual(self.ctx.assess_state.threat.get(), "PUBLIC")
        self.assertTrue(any("Elevated EPSS" in t for t in self.chip_texts(view.chips)))
        self.assertNotIn("exploit available", view.threat_note.cget("text"))
        self.lookup(QUIET_CVE)
        self.assertEqual(self.ctx.assess_state.threat.get(), "NONE")
        self.assertIn("▬ Not in CISA KEV", self.chip_texts(view.cve_chips))

    def test_flags_can_only_raise_the_level(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(QUIET_CVE)
        state = self.ctx.assess_state
        state.public.set(True)
        self.pump()
        self.assertEqual(state.threat.get(), "PUBLIC")
        state.analyst.set(True)
        self.pump()
        self.assertEqual((state.threat.get(), view.badge.cget("text")), ("ACTIVE", "NOW"))
        state.analyst.set(False)
        state.public.set(False)
        self.pump()
        self.assertEqual(state.threat.get(), "NONE")

    def test_override_needs_a_reason_and_is_recorded(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        state = self.ctx.assess_state
        with mock.patch("gui_assess.ask_text", return_value=None) as ask:
            state.threat.set("NONE")
            view._threat_clicked()
            ask.assert_called_once()
        self.assertEqual((state.threat.get(), state.override), ("ACTIVE", None))
        with mock.patch("gui_assess.ask_text", return_value="Patched by vendor hotfix"):
            state.threat.set("NONE")
            view._threat_clicked()
        self.pump()
        self.assertEqual(state.override, (Threat.NONE, "Patched by vendor hotfix"))
        self.assertIn("Manual override: Patched by vendor hotfix", view.threat_note.cget("text"))
        self.assertTrue(view.clear_override.winfo_ismapped())
        view.reasoning.toggle()
        self.assertIn("Manual override from ACTIVE to NONE", view.reasoning_text.cget("text"))
        view.copy_summary()
        self.assertIn("Patched by vendor hotfix", self.ctx.copy.call_args[0][0])
        view._clear_override()
        self.assertEqual((state.threat.get(), state.override), ("ACTIVE", None))

    def test_choosing_the_data_level_again_clears_an_override(self):
        self.load_data()
        view = self.build()
        self.fill("8.0")
        self.lookup(KEV_CVE)
        with mock.patch("gui_assess.ask_text", return_value="why"):
            self.ctx.assess_state.threat.set("PUBLIC")
            view._threat_clicked()
        self.assertIsNotNone(self.ctx.assess_state.override)
        self.ctx.assess_state.threat.set("ACTIVE")
        view._threat_clicked()
        self.assertIsNone(self.ctx.assess_state.override)

    def test_editing_the_cve_after_a_lookup_returns_to_manual(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.assertTrue(view.auto_threat)
        self.ctx.assess_state.cve.set("CVE-2024-000")
        self.pump()
        self.assertFalse(view.auto_threat)
        self.assertEqual(view.cve_chips.items, [])

    def test_clearing_the_cve_returns_to_manual(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.lookup("")
        self.assertFalse(view.auto_threat)

    def test_partial_data_is_reported_not_hidden(self):
        self.load_data()
        (self.data_dir / td.EPSS_FILE).unlink()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(QUIET_CVE)
        self.assertIn("⚠ EPSS not loaded", self.chip_texts(view.cve_chips))
        self.assertEqual(self.ctx.assess_state.threat.get(), "NONE")


class AssessOptionTests(unittest.TestCase):
    def test_choices_run_from_least_to_most_concerning(self):
        names = lambda enum: [value for value, _label in gui_assess._options(enum)]  # noqa: E731
        self.assertEqual(names(Threat), ["NONE", "PUBLIC", "ACTIVE"])
        self.assertEqual(names(Asset), ["STANDARD", "IMPORTANT", "CROWN"])
        self.assertEqual(names(Exposure), ["LOW", "MEDIUM", "HIGH"])
        self.assertEqual(names(Patch), ["AVAILABLE", "PENDING", "EOL"])
        self.assertEqual(names(Controls), ["NONE", "PARTIAL", "STRONG"])

    def test_every_choice_has_a_short_label_and_maps_back_to_a_member(self):
        for enum in (Threat, Asset, Exposure, Patch, Controls):
            options = gui_assess._options(enum)
            self.assertEqual(len(options), len(enum))
            for value, label in options:
                self.assertTrue(label)
                self.assertIn(value, enum.__members__)


class AssessLayoutTests(AssessTestCase):
    def test_columns_stack_when_narrow_and_return_when_wide(self):
        view = self.build()
        view._layout(wide=False)
        self.assertEqual((int(view.right.grid_info()["row"]), int(view.left.grid_info()["row"])), (0, 1))
        view._layout(wide=True)
        self.assertEqual((int(view.left.grid_info()["column"]), int(view.right.grid_info()["column"])), (0, 1))

    def test_a_rebuild_keeps_the_inputs_and_the_result(self):
        view = self.build()
        self.fill("8.8", Threat.ACTIVE, Asset.CROWN, Exposure.HIGH)
        before = (view.badge.cget("text"), self.chip_texts(view.chips))
        view.frame.destroy()
        rebuilt = self.build()
        self.assertEqual((rebuilt.badge.cget("text"), self.chip_texts(rebuilt.chips)), before)
        self.assertEqual(self.ctx.assess_state.cvss.get(), "8.8")

    def test_tab_order_follows_reading_order(self):
        view = self.build()
        order, widget = [], view.cve_entry
        for _ in range(60):
            order.append(widget)
            widget = widget.tk_focusNext()
            if widget is None or widget is view.cve_entry:
                break
        segmented = [w for w in order if isinstance(w, gui_assess.Segmented)]
        self.assertEqual(len(segmented), 5)
        expected = [view.cve_entry, view.cvss_entry]
        positions = [order.index(w) for w in expected + segmented if w in order]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(order.index(view.cve_entry), order.index(view.cvss_entry))
        self.assertLess(order.index(view.cvss_entry), order.index(segmented[0]))
        copy_positions = [order.index(b) for b in (view.copy_button, view.markdown_button) if b in order]
        self.assertTrue(all(p > order.index(segmented[-1]) for p in copy_positions))

    def test_every_interactive_control_can_take_keyboard_focus(self):
        view = self.build()
        self.fill("8.0")
        stack, controls = [view.frame], []
        while stack:
            node = stack.pop()
            stack.extend(node.winfo_children())
            if isinstance(node, (tk.Entry, tk.Button, gui_assess.Segmented)):
                controls.append(node)
        self.assertGreaterEqual(len(controls), 9)
        for control in controls:
            self.assertNotEqual(str(control.cget("takefocus")), "0", control)

    def test_focus_helpers_target_the_right_fields(self):
        view = self.build()
        self.holder.focus_force()
        self.pump(0.1)
        view.focus_cve()
        self.pump(0.1)
        if self.root.focus_get() is None:
            self.skipTest("the window manager did not give the test window focus")
        self.assertIs(self.root.focus_get(), view.cve_entry)
        view.focus_first()
        self.pump(0.1)
        self.assertIs(self.root.focus_get(), view.cvss_entry)


class AssessLightThemeTests(AssessTestCase):
    theme = LIGHT

    def test_builds_and_colours_in_the_light_theme(self):
        view = self.build()
        self.fill("8.0")
        self.assertEqual((view.badge.fill, str(view.badge.cget("fg"))), Style(LIGHT).bucket("NOW"))
        self.assertEqual(str(view.frame.cget("bg")), LIGHT.bg)


class AssessTextScaleTests(AssessTestCase):
    scale = 1.3

    def test_larger_text_is_used_and_the_content_still_scrolls(self):
        view = self.build()
        self.fill("8.0")
        expected = round(16 * gui_theme.FONT_BOOST * 1.3)
        self.assertEqual(tkfont.Font(root=self.root, font=view.verdict.cget("font")).actual("size"), expected)
        self.assertGreater(view.scroll.body.winfo_reqheight(), 0)


if __name__ == "__main__":
    unittest.main()
