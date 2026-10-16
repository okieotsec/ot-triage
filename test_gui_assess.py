import tempfile
import time
import tkinter as tk
import tkinter.font as tkfont
import unittest
from pathlib import Path
from unittest import mock

import cvss
import explain
import gui_assess
import gui_theme
import gui_widgets
import icsadvisories
import threatdata as td
from gui_context import Context
from gui_testing import DisplayTestCase
from gui_theme import LIGHT, Style
from prioritizer import Asset, Controls, Exposure, Patch, Threat, prioritize
from settings import DEFAULT_SETTINGS, Settings
from test_icsadvisories import advisory, good
from test_threatdata import epss_bytes, epss_text, kev_bytes, kev_entry
from uiprefs import DEFAULT_PREFS

KEV_CVE, EPSS_CVE, QUIET_CVE = "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"
KEV_NOTES = ("https://vendor.example.com/advisory/1 ; BOD 26-04: https://www.cisa.gov/bod-26-04 ; "
             "http://insecure.example.com/patch ; See the vendor page")


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
        if self.holder.tk.call("tk", "windowingsystem") == "x11":
            self.holder.wm_attributes("-type", "dialog")  # a floating window keeps its size on tiling window managers
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
        entries = [kev_entry(KEV_CVE, knownRansomwareCampaignUse="Known", notes=KEV_NOTES,
                              forensicTriage="Yes")]
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

    def lookup(self, cve):
        self.ctx.assess_state.cve.set(cve)
        self.view.lookup()
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


V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40_87 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:L/SA:L"


class AssessVectorTests(AssessTestCase):
    def paste(self, text):
        self.ctx.assess_state.vector.set(text)
        self.view.apply_vector()
        self.pump()

    def setup_inputs(self):
        self.build()
        self.fill("", Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH)

    def test_a_valid_v31_vector_fills_in_the_score_and_drives_the_result(self):
        self.setup_inputs()
        self.paste(V31)
        state = self.ctx.assess_state
        self.assertEqual(state.cvss.get(), "9.8")
        expected = prioritize(9.8, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH).priority
        self.assertEqual(self.view.badge.cget("text"), expected)
        self.assertIn("CVSS 3.1 vector: base score 9.8 (CRITICAL)", self.view.vector_message.cget("text"))
        self.assertEqual(str(self.view.vector_message.cget("fg")), self.style.theme.ok)
        self.assertEqual(self.view.cvss_band.cget("text"), "CRITICAL  \u00b7  CVSS 3.1")

    def hint(self):
        return self.view.exposure_hint.cget("text")

    def test_a_network_vector_with_low_exposure_gets_a_note_that_changes_nothing(self):
        self.build()
        self.fill("", Threat.NONE, Asset.CROWN, Exposure.LOW, Controls.STRONG)
        self.assertEqual(self.hint(), "")
        self.paste(V31)
        self.assertIn("Confirm the isolation by testing", self.hint())
        self.assertEqual(self.view.badge.cget("text"), "NEXT")      # crown jewel, 9.8: the floor, not the note
        self.assertIn("Exposure check: ", self.view.reasoning_text.cget("text"))
        self.view.copy_summary()
        self.assertIn("Exposure check: ", self.ctx.copy.call_args[0][0])

    def test_the_note_goes_away_when_exposure_is_checked_or_the_vector_is_not_network(self):
        self.build()
        self.fill("", Threat.NONE, Asset.CROWN, Exposure.LOW, Controls.STRONG)
        self.paste(V31)
        self.fill("9.8", Threat.NONE, Asset.CROWN, Exposure.MEDIUM, Controls.STRONG)
        self.assertEqual(self.hint(), "")
        self.assertNotIn("Exposure check", self.view.reasoning_text.cget("text"))
        self.fill("9.8", Threat.NONE, Asset.CROWN, Exposure.LOW, Controls.STRONG)
        self.assertIn("Confirm the isolation", self.hint())
        self.paste(V31.replace("AV:N", "AV:L"))
        self.assertEqual(self.hint(), "")

    def test_the_note_is_in_the_copied_summary_and_does_not_move_the_bucket(self):
        self.build()
        self.fill("9.8", Threat.NONE, Asset.CROWN, Exposure.LOW, Controls.STRONG)
        without_note = (self.view.badge.cget("text"), self.view.action_label.cget("text"))
        self.paste(V31)
        self.assertEqual((self.view.badge.cget("text"), self.view.action_label.cget("text")), without_note)
        self.assertTrue(any(line.startswith("Exposure check: ") for line in self.view.vector_lines()))

    def test_a_v40_vector_is_scored_with_the_v40_algorithm(self):
        self.setup_inputs()
        self.paste(V40_87)
        self.assertEqual(self.ctx.assess_state.cvss.get(), "8.7")
        self.assertIn("CVSS 4.0", self.view.vector_message.cget("text"))
        self.assertEqual(self.view.cvss_band.cget("text"), "HIGH  \u00b7  CVSS 4.0")

    def test_the_same_inputs_give_different_scores_in_different_versions(self):
        self.setup_inputs()
        self.paste("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        v3 = self.ctx.assess_state.cvss.get()
        self.paste("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N")
        self.assertNotEqual(self.ctx.assess_state.cvss.get(), v3)

    def test_the_vector_appears_in_summaries_and_the_reasoning_panel(self):
        self.setup_inputs()
        self.paste(V40_87)
        self.view.copy_summary()
        text = self.ctx.copy.call_args[0][0]
        self.assertIn(f"- CVSS vector: {V40_87}", text)
        self.assertIn("- CVSS version: 4.0 (base score 8.7)", text)
        self.view.copy_markdown()
        self.assertIn(f"- CVSS vector: {V40_87}", self.ctx.copy.call_args[0][0])
        self.view.reasoning.toggle()
        self.assertIn(f"CVSS vector: {V40_87}", self.view.reasoning_text.cget("text"))

    def test_no_vector_means_no_vector_lines(self):
        self.setup_inputs()
        self.fill("8.0")
        self.view.copy_summary()
        self.assertNotIn("CVSS vector", self.ctx.copy.call_args[0][0])
        self.assertEqual(self.view.vector_lines(), [])

    def test_optional_metrics_and_odd_order_are_accepted(self):
        self.setup_inputs()
        self.paste("  CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N/E:P/RL:O/RC:C\n")
        self.assertEqual(self.ctx.assess_state.cvss.get(), "9.8")

    def test_an_invalid_vector_is_explained_and_never_used(self):
        self.setup_inputs()
        self.fill("5.0", Threat.NONE, Asset.STANDARD, Exposure.LOW)
        for bad, fragment in (("notavector", "must start with CVSS"), ("not a vector", "only letters, digits"),
                              ("CVSS:3.1/AV:N", "missing required metric"),
                              ("AV:N/AC:L/Au:N/C:P/I:P/A:P", "version 2 vectors are not supported"),
                              ("CVSS:9.9/AV:N", "not supported"), (V31 + "/AV:L", "appears more than once")):
            self.paste(bad)
            message = self.view.vector_message.cget("text")
            self.assertIn(fragment, message, bad)
            self.assertTrue(message.startswith("\u2716"))
            self.assertIn("The score typed below is used instead", message)
            self.assertEqual(self.ctx.assess_state.cvss.get(), "5.0")
            self.assertIsNone(self.ctx.assess_state.vector_info)
            self.assertEqual(str(self.view.vector_message.cget("fg")), self.style.theme.error)

    def test_breaking_a_valid_vector_says_the_score_is_still_from_the_previous_one(self):
        self.setup_inputs()
        self.paste(V31)
        self.paste(V31 + "/ZZ:N")
        message = self.view.vector_message.cget("text")
        self.assertIn("still comes from the previous vector (CVSS 3.1)", message)
        self.assertNotIn("typed below", message)
        self.assertEqual(self.ctx.assess_state.cvss.get(), "9.8")

    def test_typing_a_score_by_hand_clears_the_vector(self):
        self.setup_inputs()
        self.paste(V31)
        self.ctx.assess_state.cvss.set("7.5")
        self.pump()
        self.assertEqual(self.ctx.assess_state.vector.get(), "")
        self.assertIsNone(self.ctx.assess_state.vector_info)
        self.assertIn("changed by hand", self.view.vector_message.cget("text"))
        self.assertEqual(self.view.cvss_band.cget("text"), "HIGH")
        self.assertEqual(self.view.vector_lines(), [])

    def test_retyping_the_same_score_keeps_the_vector(self):
        self.setup_inputs()
        self.paste(V31)
        self.ctx.assess_state.cvss.set("9.8")
        self.pump()
        self.assertEqual(self.ctx.assess_state.vector.get(), V31)
        self.assertIsNotNone(self.ctx.assess_state.vector_info)

    def test_clearing_the_vector_keeps_the_score_as_a_manual_value(self):
        self.setup_inputs()
        self.paste(V31)
        self.paste("")
        self.assertEqual(self.ctx.assess_state.cvss.get(), "9.8")
        self.assertEqual(self.view.vector_message.cget("text"), "")
        self.assertEqual(self.view.vector_lines(), [])

    def test_typing_waits_for_a_pause_before_checking(self):
        self.setup_inputs()
        self.ctx.assess_state.vector.set("CVSS:3.1/AV:N/AC")
        self.assertEqual(self.view.vector_message.cget("text"), "")
        self.assertIsNotNone(self.view._vector_job)
        self.pump(0.7)
        self.assertIn("\u2716", self.view.vector_message.cget("text"))

    def test_enter_checks_the_vector_immediately(self):
        self.setup_inputs()
        self.ctx.assess_state.vector.set(V31)
        self.view.vector_entry.focus_force()
        self.pump(0.1)
        if self.root.focus_get() is not self.view.vector_entry:
            self.skipTest("the window manager did not give the test window keyboard focus")
        self.view.vector_entry.event_generate("<Return>")
        self.pump()
        self.assertEqual(self.ctx.assess_state.cvss.get(), "9.8")

    def test_a_long_vector_is_reported_in_one_short_line(self):
        self.setup_inputs()
        start = time.monotonic()
        self.paste("CVSS:3.1/" + "A" * 1500)
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertIn("longer than 400", self.view.vector_message.cget("text"))
        self.assertLess(len(self.view.vector_message.cget("text")), 200)

    def test_environmental_metrics_show_a_second_score_for_comparison_and_never_change_the_priority(self):
        self.setup_inputs()
        view = self.view
        self.paste(V31)
        badge_without = view.badge.cget("text")
        self.assertEqual(view.cvss_env.winfo_manager(), "")
        env_vector = V31 + "/CR:L/IR:L/AR:L/MAV:A/MAC:H"
        self.paste(env_vector)
        self.assertEqual(self.ctx.assess_state.cvss.get(), "9.8")
        self.assertEqual(view.badge.cget("text"), badge_without)
        self.assertEqual(view.cvss_env.winfo_manager(), "pack")
        self.assertIn("Environmental score: 5.7", view.cvss_env.cget("text"))
        self.assertIn("the priority uses the base score", view.cvss_env.cget("text"))
        self.assertNotIn("Environmental", view.vector_message.cget("text"), "said once, next to the score")
        self.assertIn("CVSS environmental score: 5.7", "\n".join(view.vector_lines()))
        self.paste(V31)
        self.assertEqual(view.cvss_env.winfo_manager(), "")
        self.assertNotIn("environmental", "\n".join(view.vector_lines()).lower())

    def test_the_environmental_note_goes_away_when_the_score_is_typed_by_hand(self):
        self.setup_inputs()
        self.paste(V31 + "/CR:L/MAV:A")
        self.assertEqual(self.view.cvss_env.winfo_manager(), "pack")
        self.ctx.assess_state.cvss.set("7.0")
        self.pump(0.2)
        self.assertEqual(self.view.cvss_env.winfo_manager(), "")

    def test_a_huge_paste_into_the_box_is_refused_at_once_and_never_reaches_the_widget(self):
        self.setup_inputs()
        entry = self.view.vector_entry
        entry.insert(0, V31)
        start = time.monotonic()
        entry.insert("end", "A" * 5_000_000)  # what pasting a huge text does
        self.pump()
        self.assertLess(time.monotonic() - start, 2.0)
        self.assertEqual(entry.get(), V31)
        self.assertIn("too long", self.view.vector_message.cget("text"))
        self.assertLess(len(self.view.vector_message.cget("text")), 200)

    def test_the_vector_survives_a_rebuild_with_its_message(self):
        self.setup_inputs()
        self.paste(V40_87)
        self.view.frame.destroy()
        rebuilt = self.build()
        self.assertEqual(self.ctx.assess_state.vector.get(), V40_87)
        self.assertEqual(self.ctx.assess_state.cvss.get(), "8.7")
        self.assertIn("CVSS 4.0", rebuilt.vector_message.cget("text"))
        self.assertEqual(rebuilt.badge.cget("text"), self.view.badge.cget("text"))

    def test_the_vector_field_sits_between_the_cve_and_the_score_in_the_tab_order(self):
        view = self.build()
        order, widget = [], view.cve_entry
        for _ in range(40):
            order.append(widget)
            widget = widget.tk_focusNext()
            if widget is None or widget is view.cve_entry:
                break
        self.assertLess(order.index(view.cve_entry), order.index(view.vector_entry))
        self.assertLess(order.index(view.vector_entry), order.index(view.cvss_entry))

    def test_the_hint_mentions_the_vector_option_and_the_field_has_help(self):
        view = self.build()
        self.assertIn("paste a vector", view.cvss_hint.cget("text"))
        self.assertIn("CVSS 2 vectors are not supported", gui_assess.VECTOR_HELP)


class AssessLayoutTests(AssessTestCase):
    def test_columns_stack_when_narrow_and_return_when_wide(self):
        view = self.build()
        view._layout(wide=False)
        self.assertEqual((int(view.right.grid_info()["row"]), int(view.left.grid_info()["row"])), (0, 1))
        view._layout(wide=True)
        self.assertEqual((int(view.left.grid_info()["column"]), int(view.right.grid_info()["column"])), (0, 1))

    def test_no_headline_is_clipped_in_a_narrow_priority_card(self):
        self.holder.geometry("760x900+0+0")
        view = self.build()
        for headline, _sub in explain.HEADLINES.values():
            view.verdict.configure(text=headline)
            self.pump(0.1)
            self.assertLessEqual(view.verdict.winfo_reqwidth(), view.verdict.winfo_width() + 1, headline)

    def test_the_layout_needs_a_clearly_different_width_to_switch_so_it_cannot_flip_flop(self):
        view = self.build()
        view._layout(wide=True)
        sizes = lambda *widths: [view._on_resize(mock.Mock(width=w)) or view.wide for w in widths]  # noqa: E731
        # Wide stays wide until the width is clearly below the line, even when a scrollbar takes ~20 px
        self.assertEqual(sizes(906, 889, 870, 861), [True, True, True, True])
        self.assertEqual(sizes(859), [False])
        # Stacked stays stacked until the width is clearly above the line
        self.assertEqual(sizes(889, 906, 930, 939), [False, False, False, False])
        self.assertEqual(sizes(940, 906, 889), [True, True, True])

    def test_long_messages_in_the_left_column_never_widen_the_window_or_push_the_results_column_away(self):
        view = self.build()
        view._layout(wide=True)
        self.root.deiconify()
        self.pump(0.3)
        window, left, right = self.holder.winfo_width(), view.left.winfo_width(), view.right.winfo_width()
        long_text = "This is a long explanation that keeps going and going so that it cannot fit on one line. " * 6
        for message in (view.cve_message, view.vector_message, view.threat_note, view.cvss_hint):
            message.configure(text=long_text)
        self.pump(0.5)
        self.assertLessEqual(self.holder.winfo_width(), window + 2, "the window grew to fit the text")
        self.assertLessEqual(view.left.winfo_width(), left + 40, "the inputs column grew to fit the text")
        self.assertGreaterEqual(view.right.winfo_width(), right - 40)

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


class AssessReferenceTests(AssessTestCase):
    def labels(self, view):
        return [w for w in self.walk(view.refs_body) if isinstance(w, gui_widgets.LinkLabel)]

    def walk(self, widget):
        for child in widget.winfo_children():
            yield child
            yield from self.walk(child)

    def texts(self, view):
        return [w.cget("text") for w in self.walk(view.refs_body) if isinstance(w, tk.Label)]

    def test_a_kev_lookup_shows_the_notes_as_links_with_their_real_hosts(self):
        self.load_data()
        view = self.build()
        self.assertFalse(view.refs_card.winfo_manager())
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.assertEqual(view.refs_card.winfo_manager(), "pack")
        links = self.labels(view)
        self.assertEqual([w.cget("text") for w in links], ["vendor.example.com", "BOD 26-04"])
        shown = self.texts(view)
        for expected in ("/advisory/1", "www.cisa.gov", "http://insecure.example.com/patch", "See the vendor page"):
            self.assertIn(expected, shown)

    def test_a_cve_that_is_not_in_kev_or_a_cleared_cve_hides_the_card(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.assertTrue(view.references)
        self.lookup(EPSS_CVE)
        self.assertEqual((view.references, view.refs_card.winfo_manager()), ((), ""))
        self.lookup(KEV_CVE)
        self.ctx.assess_state.cve.set("")
        self.pump()
        self.assertEqual((view.references, view.refs_card.winfo_manager()), ((), ""))

    def test_clicking_a_link_opens_exactly_that_address_and_nothing_opens_on_its_own(self):
        self.load_data()
        view = self.build()
        with mock.patch("gui_context.webbrowser.open", return_value=True) as opener:
            self.fill("8.0", Threat.NONE)
            self.lookup(KEV_CVE)
            opener.assert_not_called()
            self.labels(view)[1].event_generate("<Button-1>")
            self.pump()
        opener.assert_called_once_with("https://www.cisa.gov/bod-26-04")

    def test_a_link_can_be_opened_from_the_keyboard(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        link = self.labels(view)[0]
        self.assertEqual(str(link.cget("takefocus")), "1")
        link.focus_force()
        self.pump(0.2)
        if link.focus_get() is not link:
            self.skipTest("the window manager did not give the test window keyboard focus")
        with mock.patch("gui_context.webbrowser.open", return_value=True) as opener:
            link.event_generate("<Return>")
            self.pump()
        opener.assert_called_once_with("https://vendor.example.com/advisory/1")

    def test_a_browser_that_cannot_open_copies_the_address_and_explains(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        for failure in ({"return_value": False}, {"side_effect": OSError("no browser")}):
            self.ctx.copy.reset_mock()
            self.ctx.warn.reset_mock()
            with mock.patch("gui_context.webbrowser.open", **failure):
                Context.open_reference(self.ctx, view.references[0])
            self.ctx.copy.assert_called_once_with("https://vendor.example.com/advisory/1")
            self.assertIn("https://vendor.example.com/advisory/1", self.ctx.warn.call_args[0][1])

    def test_both_summaries_include_the_references(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        view.copy_summary()
        plain = self.ctx.copy.call_args[0][0]
        self.assertIn("References (from the CISA KEV notes):", plain)
        self.assertIn("BOD 26-04: https://www.cisa.gov/bod-26-04", plain)
        view.copy_markdown()
        markdown = self.ctx.copy.call_args[0][0]
        self.assertIn("[BOD 26-04](https://www.cisa.gov/bod-26-04)", markdown)
        self.assertIn("[vendor.example.com](https://vendor.example.com/advisory/1)", markdown)

    def test_the_triage_flag_shows_as_a_neutral_chip_and_a_note_and_does_not_change_the_bucket(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.assertIn("Forensic triage advised", [i.cget("text") for i in view.chips.items][-1])
        self.assertTrue(any("forensic triage" in r for r in view.result.reasons))
        self.assertEqual(view.result.priority, "NOW")

    def test_a_kev_lookup_shows_its_data_straight_away_without_waiting_for_a_cvss_score(self):
        self.load_data()
        view = self.build()
        self.ctx.assess_state.cvss.set("")
        self.lookup(KEV_CVE)
        self.assertEqual(view.verdict.cget("text"), "Waiting for input")
        self.assertEqual(view.refs_card.winfo_manager(), "pack")
        self.assertEqual([w.cget("text") for w in self.labels(view)], ["vendor.example.com", "BOD 26-04"])
        self.assertTrue(view.action_label.cget("text").startswith("CISA required action: "))
        chips = [c.cget("text") for c in view.chips.items]
        for expected in ("In CISA KEV", "Ransomware use", "Forensic triage advised"):
            self.assertTrue(any(expected in text for text in chips), expected)
        self.assertFalse(view.copy_button.cget("state") == "normal", "there is still no result to copy")

    def test_an_invalid_score_still_keeps_the_kev_data_and_a_cve_outside_kev_shows_none(self):
        self.load_data()
        view = self.build()
        self.ctx.assess_state.cvss.set("abc")
        self.lookup(KEV_CVE)
        self.assertEqual(view.verdict.cget("text"), "Invalid input")
        self.assertEqual(view.refs_card.winfo_manager(), "pack")
        self.lookup(EPSS_CVE)
        self.assertEqual((view.references, view.refs_card.winfo_manager(), view.action_label.cget("text")),
                         ((), "", ""))

    def test_entering_the_score_afterwards_replaces_the_preview_with_the_full_result(self):
        self.load_data()
        view = self.build()
        self.ctx.assess_state.cvss.set("")
        self.lookup(KEV_CVE)
        self.fill("8.0", Threat.NONE)
        self.assertIn(view.badge.cget("text"), ("NOW", "NEXT"))
        self.assertEqual(len(self.labels(view)), 2)
        self.assertIn("Apply the patch", view.action_label.cget("text"))

    def test_a_manual_item_has_no_reference_section_in_its_summary(self):
        view = self.build()
        self.fill("8.0", Threat.NONE)
        view.copy_summary()
        self.assertNotIn("References", self.ctx.copy.call_args[0][0])


class AssessRequirementTests(AssessTestCase):
    def setUp(self):
        super().setUp()
        self.view = self.build()
        self.state = self.ctx.assess_state
        self.state.threat.set("PUBLIC")

    def use(self, vector):
        self.state.vector.set(vector)
        self.view.apply_vector()
        self.pump(0.2)

    def choose(self, **chosen):
        for metric, value in chosen.items():
            self.state.requirements[metric].set(value)
        self.pump(0.3)

    def test_the_section_is_there_but_collapsed_with_three_selectors_defaulting_to_not_set(self):
        self.assertFalse(self.view.requirements_box.is_open)
        self.assertEqual(set(self.view.requirement_controls), {"CR", "IR", "AR"})
        self.assertEqual({m: v.get() for m, v in self.state.requirements.items()}, {"CR": "X", "IR": "X", "AR": "X"})

    def test_the_section_opens_by_itself_when_a_vector_is_entered(self):
        self.assertFalse(self.view.requirements_box.is_open)
        self.use(V31)
        self.assertTrue(self.view.requirements_box.is_open)
        self.assertEqual(self.view.requirements_box.body.winfo_manager(), "pack")

    def test_a_plain_score_does_not_open_the_section(self):
        self.state.cvss.set("7.5")
        self.view.apply_vector()
        self.pump(0.2)
        self.assertFalse(self.view.requirements_box.is_open)

    def test_closing_the_section_by_hand_sticks_until_the_vector_is_cleared_and_entered_again(self):
        self.use(V31)
        self.view.requirements_box.toggle()
        self.use(V31 + "/CR:H")
        self.assertFalse(self.view.requirements_box.is_open)
        self.use("")
        self.use(V31)
        self.assertTrue(self.view.requirements_box.is_open)

    def test_choosing_requirements_gives_an_environmental_score_and_never_changes_the_priority(self):
        self.use(V31)
        before = self.view.badge.cget("text")
        score_before = self.view.score_label.cget("text")
        self.assertEqual(self.view.cvss_env.winfo_manager(), "")
        self.choose(CR="L", IR="H", AR="H")
        expected = cvss.parse_vector(V31 + "/CR:L/IR:H/AR:H").environmental_score
        self.assertIn(f"Environmental score: {expected:.1f}", self.view.cvss_env.cget("text"))
        self.assertEqual((self.view.badge.cget("text"), self.view.score_label.cget("text")), (before, score_before))
        self.assertEqual(self.state.cvss.get(), "9.8")

    def test_setting_the_selectors_back_to_not_set_removes_the_score(self):
        self.use(V31)
        self.choose(CR="L")
        self.assertEqual(self.view.cvss_env.winfo_manager(), "pack")
        self.choose(CR="X")
        self.assertEqual(self.view.cvss_env.winfo_manager(), "")

    def test_without_a_vector_the_note_says_a_vector_is_needed(self):
        self.state.cvss.set("8.0")
        self.choose(AR="H")
        self.assertEqual(self.view.cvss_env.winfo_manager(), "pack")
        self.assertIn("needs a CVSS vector", self.view.cvss_env.cget("text"))
        self.choose(AR="X")
        self.assertEqual(self.view.cvss_env.winfo_manager(), "")

    def test_a_requirement_written_in_the_vector_wins_over_the_selector(self):
        self.use(V31 + "/CR:H")
        self.choose(CR="L")
        expected = cvss.parse_vector(V31 + "/CR:H").environmental_score
        self.assertIn(f"Environmental score: {expected:.1f}", self.view.cvss_env.cget("text"))
        self.assertNotIn("Security requirements applied", "\n".join(self.view.vector_lines()))

    def test_the_summaries_list_the_requirements_that_were_applied(self):
        self.use(V31)
        self.choose(IR="H", AR="M")
        text = "\n".join(self.view.vector_lines())
        self.assertIn("Security requirements applied: integrity high, availability medium", text)
        self.assertIn("CVSS environmental score:", text)
        self.view.copy_summary()
        self.assertIn("Security requirements applied", self.ctx.copy.call_args[0][0])

    def test_the_choices_survive_a_rebuild_and_the_section_can_be_opened(self):
        self.use(V31)
        self.choose(AR="H")
        self.assertTrue(self.view.requirements_box.is_open)
        self.view.frame.destroy()
        rebuilt = self.build()
        self.assertTrue(rebuilt.requirements_box.is_open)
        self.assertEqual(self.ctx.assess_state.requirements["AR"].get(), "H")
        self.assertIn("Environmental score", rebuilt.cvss_env.cget("text"))


ICS_ONLY_CVE = "CVE-2026-1234"


class AssessAdvisoryTests(AssessTestCase):
    def load_ics(self, *docs):
        docs = docs or (advisory("ICSA-26-006-01", "Acme Widget Controller", (KEV_CVE, ICS_ONLY_CVE), "Acme"),)
        path = self._write("csaf.tar.gz", good(*docs))
        self.assertTrue(icsadvisories.import_from_file(path, self.data_dir).ok)

    def walk(self, widget):
        for child in widget.winfo_children():
            yield child
            yield from self.walk(child)

    def links(self, view):
        return [w for w in self.walk(view.advisories_body) if isinstance(w, gui_widgets.LinkLabel)]

    def has_chip(self, flow, text):
        return any(chip.endswith(text) for chip in self.chip_texts(flow))

    def texts(self, view):
        return [w.cget("text") for w in self.walk(view.advisories_body) if isinstance(w, tk.Label)]

    def test_a_cve_named_in_an_advisory_shows_a_card_with_a_link_title_vendor_and_date(self):
        self.load_data()
        self.load_ics()
        view = self.build()
        self.assertEqual(view.advisories_card.winfo_manager(), "")
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.assertEqual(view.advisories_card.winfo_manager(), "pack")
        self.assertEqual([w.cget("text") for w in self.links(view)], ["ICSA-26-006-01"])
        self.assertIn("Acme Widget Controller · Acme · updated 2026-01-06", self.texts(view))
        self.assertTrue(self.has_chip(view.cve_chips, "In a CISA ICS advisory"))
        self.assertTrue(self.has_chip(view.chips, "In a CISA ICS advisory"))

    def test_a_cve_in_no_advisory_hides_the_card_and_says_so(self):
        self.load_data()
        self.load_ics()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.lookup(EPSS_CVE)
        self.assertEqual((view.advisories, view.advisories_card.winfo_manager()), ((), ""))
        self.assertTrue(self.has_chip(view.cve_chips, "Not in a CISA ICS advisory"))

    def test_without_the_advisories_loaded_the_chip_says_not_loaded_and_there_is_no_card(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.assertTrue(self.has_chip(view.cve_chips, "ICS advisories not loaded"))
        self.assertEqual(view.advisories_card.winfo_manager(), "")

    def test_the_advisories_alone_still_work_without_kev_or_epss(self):
        self.load_ics()
        view = self.build()
        self.fill("8.0", Threat.PUBLIC)
        self.lookup(ICS_ONLY_CVE)
        self.assertEqual(view.advisories_card.winfo_manager(), "pack")
        self.assertTrue(self.has_chip(view.cve_chips, "KEV not loaded"))
        self.assertNotIn("No threat data is loaded", view.cve_message.cget("text"))

    def test_they_never_change_the_priority_or_the_score(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        before = (view.badge.cget("text"), view.score_label.cget("text"))
        self.load_ics()
        self.ctx.reload_threat_data()
        self.lookup(KEV_CVE)
        self.assertEqual((view.badge.cget("text"), view.score_label.cget("text")), before)
        self.assertIn("context only; does not change the bucket", view.reasoning_text.cget("text"))

    def test_clicking_the_advisory_opens_the_address_built_from_its_number_only(self):
        self.load_data()
        self.load_ics()
        view = self.build()
        with mock.patch("gui_context.webbrowser.open", return_value=True) as opener:
            self.fill("8.0", Threat.NONE)
            self.lookup(KEV_CVE)
            opener.assert_not_called()
            self.links(view)[0].event_generate("<Button-1>")
            self.pump()
        opener.assert_called_once_with("https://www.cisa.gov/news-events/ics-advisories/icsa-26-006-01")

    def test_a_hostile_title_is_shown_as_plain_text_and_escaped_in_the_markdown_summary(self):
        self.load_data()
        self.load_ics(advisory("ICSA-26-006-01", "Evil [click](https://evil.example) *title*\x07", (KEV_CVE,), "Acme"))
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.assertEqual([w.cget("text") for w in self.links(view)], ["ICSA-26-006-01"])
        view.copy_markdown()
        markdown = self.ctx.copy.call_args[0][0]
        self.assertIn(r"\[click\]\(https://evil.example\)", markdown)
        self.assertNotIn("\x07", markdown)
        self.assertNotIn("](https://evil.example)", markdown)

    def test_the_copied_summaries_list_the_advisories_with_their_addresses(self):
        self.load_data()
        self.load_ics()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        view.copy_summary()
        plain = self.ctx.copy.call_args[0][0]
        self.assertIn("CISA ICS advisories that name this CVE:", plain)
        self.assertIn("- ICSA-26-006-01: Acme Widget Controller (https://www.cisa.gov/news-events/ics-advisories/"
                      "icsa-26-006-01)", plain)
        view.copy_markdown()
        self.assertIn("[ICSA-26-006-01: Acme Widget Controller](https://www.cisa.gov/news-events/"
                      "ics-advisories/icsa-26-006-01)", self.ctx.copy.call_args[0][0])

    def test_more_than_the_listed_few_say_how_many_there_are(self):
        self.load_data()
        docs = [advisory(f"ICSA-26-{n:03d}-01", f"Product {n}", (KEV_CVE,), updated=f"2026-02-{n:02d}T00:00:00Z")
                for n in range(1, 9)]
        self.load_ics(*docs)
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.assertEqual(len(self.links(view)), icsadvisories.MAX_LISTED)
        self.assertIn("and 3 more advisories name this CVE (see cisa.gov)", self.texts(view))
        self.assertTrue(self.has_chip(view.chips, "In 8 CISA ICS advisories"))

    def test_the_card_and_hint_say_what_the_advisory_says_about_a_fix_and_change_nothing(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        before = (self.ctx.assess_state.patch.get(), view.badge.cget("text"), view.score_label.cget("text"))
        self.load_ics(advisory("ICSA-26-006-01", "Acme Widget Controller", (KEV_CVE,), "Acme",
                               fixes={KEV_CVE: ["no_fix_planned"]}))
        self.ctx.reload_threat_data()
        self.lookup(KEV_CVE)
        self.assertIn("Acme Widget Controller · Acme · updated 2026-01-06 · no fix planned", self.texts(view))
        self.assertTrue(self.has_chip(view.chips, "No fix planned (CISA)"))
        hint = view.patch_hint.cget("text")
        self.assertIn("ICSA-26-006-01: no fix planned.", hint)
        self.assertIn("None (end of life) fits", hint)
        self.assertIn("Patch status is not changed for you", hint)
        self.assertEqual((self.ctx.assess_state.patch.get(), view.badge.cget("text"),
                          view.score_label.cget("text")), before)

    def steps_doc(self, entries):
        return advisory("ICSA-26-006-01", "Acme Widget Controller", (KEV_CVE,), "Acme",
                        remediations={KEV_CVE: entries})

    def test_the_card_lists_what_the_vendor_says_to_do_and_links_open_only_when_clicked(self):
        self.load_data()
        self.load_ics(self.steps_doc([
            {"category": "vendor_fix", "details": "Upgrade to 3.11.1", "url": "https://vendor.example/fw/notes"},
            {"category": "mitigation", "details": "Disable the web GUI"}]))
        view = self.build()
        with mock.patch("gui_context.webbrowser.open", return_value=True) as opener:
            self.fill("8.0", Threat.NONE)
            self.lookup(KEV_CVE)
            self.assertIn("\u2022 Fix: Upgrade to 3.11.1", self.texts(view))
            self.assertIn("\u2022 Mitigation: Disable the web GUI", self.texts(view))
            self.assertEqual([w.cget("text") for w in self.links(view)],
                             ["ICSA-26-006-01", "vendor.example/fw/notes"])
            opener.assert_not_called()
            self.links(view)[1].event_generate("<Button-1>")
            self.pump()
        opener.assert_called_once_with("https://vendor.example/fw/notes")

    def test_a_long_list_of_steps_is_cut_and_says_how_many_are_left(self):
        self.load_data()
        self.load_ics(self.steps_doc([{"category": "mitigation", "details": f"Step {n}"} for n in range(12)]))
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        shown = [t for t in self.texts(view) if t.startswith("\u2022 Mitigation: Step")]
        self.assertEqual(len(shown), 8)
        self.assertIn("and 4 more steps (see the advisory on cisa.gov)", self.texts(view))

    def test_hostile_step_text_stays_plain_text_and_steps_change_nothing(self):
        self.load_data()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        before = (self.ctx.assess_state.patch.get(), view.badge.cget("text"), view.score_label.cget("text"))
        hostile = "[click](https://evil.example) <b>x</b>\x07"
        self.load_ics(self.steps_doc([{"category": "mitigation", "details": hostile, "url": "javascript:alert(1)"}]))
        self.ctx.reload_threat_data()
        self.lookup(KEV_CVE)
        self.assertIn("\u2022 Mitigation: [click](https://evil.example) <b>x</b>", self.texts(view))
        self.assertEqual([w.cget("text") for w in self.links(view)], ["ICSA-26-006-01"])
        self.assertEqual((self.ctx.assess_state.patch.get(), view.badge.cget("text"),
                          view.score_label.cget("text")), before)
        view.copy_markdown()
        markdown = self.ctx.copy.call_args[0][0]
        self.assertNotIn("](https://evil.example)", markdown)
        self.assertNotIn("\x07", markdown)

    def test_the_copied_summaries_include_the_vendors_steps(self):
        self.load_data()
        self.load_ics(self.steps_doc([{"category": "vendor_fix", "details": "Upgrade to 3.11.1",
                                       "url": "https://vendor.example/fw"}]))
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        view.copy_summary()
        self.assertIn("  - Fix: Upgrade to 3.11.1 (https://vendor.example/fw)", self.ctx.copy.call_args[0][0])
        view.copy_markdown()
        self.assertIn("  - [Fix: Upgrade to 3.11.1](https://vendor.example/fw)", self.ctx.copy.call_args[0][0])

    def test_there_is_no_hint_when_the_advisory_says_nothing_about_a_fix_or_there_is_no_advisory(self):
        self.load_data()
        self.load_ics()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.assertEqual(view.patch_hint.cget("text"), "")
        self.lookup(EPSS_CVE)
        self.assertEqual(view.patch_hint.cget("text"), "")

    def test_clearing_the_cve_hides_the_card(self):
        self.load_data()
        self.load_ics()
        view = self.build()
        self.fill("8.0", Threat.NONE)
        self.lookup(KEV_CVE)
        self.ctx.assess_state.cve.set("")
        self.pump()
        self.assertEqual((view.advisories, view.advisories_card.winfo_manager()), ((), ""))


if __name__ == "__main__":
    unittest.main()
