import itertools
import unittest

import explain
import threatdata as td
from explain import AssessInputs
from prioritizer import Asset, Controls, Exposure, NEVER, NEXT, NOW, Patch, Threat, prioritize
from settings import DEFAULT_SETTINGS, Settings

CUSTOM = Settings(cvss_high=7.5, cvss_critical=9.5)


def inputs(cvss=8.8, threat=Threat.ACTIVE, asset=Asset.CROWN, exposure=Exposure.HIGH, controls=Controls.NONE,
           patch=Patch.AVAILABLE):
    return AssessInputs(cvss, threat, asset, exposure, controls, patch)


class WhatWouldChangeTests(unittest.TestCase):
    def test_example_from_the_design(self):
        result = explain.what_would_change(inputs(), CUSTOM)
        self.assertEqual(result.current, NOW)
        self.assertEqual(result.more_urgent, ())
        self.assertEqual({(c.priority, c.text) for c in result.less_urgent},
                         {(NEXT, "if compensating controls were Strong"), (NEXT, "if the threat were None")})
        lines = explain.what_if_lines(result)
        self.assertEqual(lines[-1], "Already at the highest urgency, so nothing makes it more urgent.")

    def test_a_never_item_cannot_become_less_urgent(self):
        quiet = explain.what_would_change(inputs(1.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, Controls.STRONG,
                                                 Patch.AVAILABLE))
        self.assertEqual(quiet.current, NEVER)
        self.assertEqual(quiet.less_urgent, ())

    def test_an_item_that_nothing_moves(self):
        found = explain.what_would_change(inputs(0.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, Controls.STRONG,
                                                 Patch.AVAILABLE))
        self.assertTrue(all(c.priority != NEVER for c in found.more_urgent))

    def test_empty_result_has_a_sentence(self):
        empty = explain.WhatIf(NEVER, (), ())
        self.assertTrue(empty.is_empty)
        self.assertEqual(explain.what_if_lines(empty), ["No single change to one input moves this item."])

    def test_every_listed_change_is_real_and_none_are_missing(self):
        combos = list(itertools.product((0.0, 3.9, 4.0, 6.9, 7.0, 7.5, 8.9, 9.0, 10.0), Threat, Asset, Exposure,
                                        Controls, Patch))[::7]
        for config in (DEFAULT_SETTINGS, CUSTOM):
            for combo in combos:
                base = inputs(*combo)
                found = explain.what_would_change(base, config)
                listed = {c.text: c.priority for c in found.more_urgent + found.less_urgent}
                expected = {}
                for name, enum in explain.FIELD_ENUMS.items():
                    for member in enum:
                        if member is getattr(base, name):
                            continue
                        changed = AssessInputs(**{**base.__dict__, name: member}).run(config).priority
                        if changed != found.current:
                            phrase = f"if {explain.FIELD_PHRASES[name]} were {explain.SHORT_LABELS[enum][member]}"
                            expected[phrase] = changed
                field_texts = {t: p for t, p in listed.items() if "CVSS" not in t}
                self.assertEqual(field_texts, expected, (combo, config.describe()))

    def test_cvss_suggestion_is_the_nearest_changing_score(self):
        base = inputs(6.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH)
        found = explain.what_would_change(base)
        cvss = [c for c in found.more_urgent + found.less_urgent if "CVSS" in c.text]
        self.assertEqual([c.text for c in cvss], ["if the CVSS score were at or above 7.0"])
        self.assertEqual(cvss[0].priority, NOW)
        low = explain.what_would_change(inputs(7.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH))
        self.assertIn("if the CVSS score were at or below 6.9", [c.text for c in low.less_urgent])

    def test_cvss_search_agrees_with_the_rules_for_every_score(self):
        for start in (0.0, 2.5, 4.0, 7.0, 9.0, 10.0):
            base = inputs(start, Threat.NONE, Asset.CROWN, Exposure.HIGH)
            current = base.run().priority
            found = explain.what_would_change(base)
            for change in found.more_urgent + found.less_urgent:
                if "CVSS" not in change.text:
                    continue
                target = float(change.text.split()[-1])
                self.assertEqual(AssessInputs(**{**base.__dict__, "cvss": target}).run().priority, change.priority)
                step = 0.1 if "above" in change.text else -0.1
                between = round(start + step, 1)
                while (between < target) if step > 0 else (between > target):
                    self.assertEqual(AssessInputs(**{**base.__dict__, "cvss": between}).run().priority, current)
                    between = round(between + step, 1)


class CvssBandTests(unittest.TestCase):
    def test_bands_follow_the_cvss_standard(self):
        for value, label in ((0.0, "NONE"), (0.1, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"), (6.9, "MEDIUM"),
                             (7.0, "HIGH"), (8.9, "HIGH"), (9.0, "CRITICAL"), (10.0, "CRITICAL")):
            self.assertEqual(explain.cvss_band(value)[0], label, value)
        self.assertEqual(explain.cvss_band(9.5)[1], "raise")
        self.assertEqual(explain.cvss_band(5.0)[1], "warn")


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.result = prioritize(8.8, Threat.ACTIVE, Asset.CROWN, Exposure.HIGH, settings=CUSTOM)

    def test_plain_summary_lists_inputs_settings_and_versions(self):
        text = explain.summary_text(self.result, "KEV 1; EPSS 2")
        self.assertTrue(text.startswith("Priority: NOW (Act immediately)"))
        for needle in ("Inputs:", "- CVSS: 8.8", "- Scoring settings: custom (cvss_high=7.5",
                       "- Threat data: KEV 1; EPSS 2", "Rationale:"):
            self.assertIn(needle, text)
        self.assertNotIn("Threat data", explain.summary_text(self.result))

    def test_markdown_summary(self):
        text = explain.markdown_summary(self.result, "KEV 1")
        self.assertTrue(text.startswith("**Priority: NOW**"))
        self.assertIn("**Inputs**", text)
        self.assertIn("**Rationale**", text)
        self.assertIn("- Threat data: KEV 1", text)

    def test_every_bucket_has_a_headline(self):
        for bucket in (NOW, NEXT, NEVER):
            self.assertEqual(len(explain.HEADLINES[bucket]), 2)


class FactorTests(unittest.TestCase):
    def labels(self, result):
        return {f.label: f.direction for f in result.factors}

    def test_factors_follow_the_inputs(self):
        result = prioritize(8.8, Threat.ACTIVE, Asset.CROWN, Exposure.HIGH, Controls.STRONG, Patch.EOL)
        self.assertEqual(self.labels(result), {
            "CVSS 8.8": "raise", "Actively exploited": "raise", "Crown jewel": "raise", "Exposure: High": "raise",
            "End of life, no patch": "raise", "Strong controls": "lower"})
        low = prioritize(3.0, Threat.NONE, Asset.STANDARD, Exposure.LOW)
        self.assertEqual(self.labels(low)["CVSS 3.0"], "lower")
        self.assertEqual(self.labels(low)["Exposure: Low"], "lower")

    def test_rule_effects_become_factors(self):
        cap = prioritize(3.0, Threat.ACTIVE, Asset.STANDARD, Exposure.HIGH)
        self.assertEqual(self.labels(cap)["Capped at NEXT: CVSS below 4.0"], "lower")
        waived = prioritize(3.0, Threat.ACTIVE, Asset.CROWN, Exposure.HIGH)
        self.assertEqual(self.labels(waived)["Low-CVSS cap waived: exposed crown jewel"], "raise")
        floor = prioritize(5.0, Threat.NONE, Asset.CROWN, Exposure.HIGH)
        self.assertEqual(self.labels(floor)["Floored at NEXT: exposed crown jewel"], "raise")
        eol = prioritize(8.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, Controls.STRONG, Patch.EOL)
        self.assertEqual(self.labels(eol)["Floored at NEXT: end of life"], "raise")

    def test_every_factor_is_valid_for_every_combination(self):
        for cvss in (0.0, 5.0, 10.0):
            for combo in itertools.product(Threat, Asset, Exposure, Controls, Patch):
                for factor in prioritize(cvss, *combo).factors:
                    self.assertIn(factor.direction, ("raise", "lower", "neutral"))
                    self.assertTrue(factor.label)

    def test_chips_are_ordered_raise_then_lower_then_neutral(self):
        result = prioritize(3.0, Threat.ACTIVE, Asset.CROWN, Exposure.HIGH, Controls.STRONG)
        directions = [f.direction for f in explain.sorted_factors(result.factors)]
        self.assertEqual(directions, sorted(directions, key={"raise": 0, "lower": 1, "neutral": 2}.get))

    def test_threat_data_replaces_the_generic_threat_chip(self):
        entry = td.KevEntry("CVE-2024-0001", "A", "B", "C", "2024-01-02", "Do it.", "2024-01-23", True)
        info = td.CveInfo("CVE-2024-0001", entry, 0.5, 0.99, True, True)
        decision = td.derive_threat(info, DEFAULT_SETTINGS)
        result = td.apply_threat_context(prioritize(8.0, decision.level, Asset.STANDARD, Exposure.HIGH), decision, info)
        labels = [f.label for f in result.factors]
        self.assertIn("In CISA KEV", labels)
        self.assertIn("Ransomware use", labels)
        self.assertNotIn("Actively exploited", labels)
        self.assertEqual(labels[0], "CVSS 8.0")

    def test_epss_chip_shows_the_percentile_and_none_keeps_the_generic_chip(self):
        info = td.CveInfo("CVE-2024-0001", None, 0.4, 0.972, True, True)
        decision = td.derive_threat(info, DEFAULT_SETTINGS)
        result = td.apply_threat_context(prioritize(8.0, decision.level, Asset.STANDARD, Exposure.HIGH), decision, info)
        self.assertIn("Elevated EPSS (97th percentile)", [f.label for f in result.factors])
        quiet = td.CveInfo("CVE-2024-0002", None, 0.001, 0.1, True, True)
        decision = td.derive_threat(quiet, DEFAULT_SETTINGS)
        base = prioritize(8.0, decision.level, Asset.STANDARD, Exposure.HIGH)
        result = td.apply_threat_context(base, decision, quiet)
        self.assertIn("No known exploitation", [f.label for f in result.factors])


if __name__ == "__main__":
    unittest.main()
