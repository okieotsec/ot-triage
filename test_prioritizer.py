import itertools
import unittest

from prioritizer import Asset, Controls, Exposure, Patch, Threat, NOW, NEXT, NEVER, parse_cvss, prioritize


def p(cvss, threat, asset, exposure, controls=False, patch=Patch.AVAILABLE):
    # Shorthand: True -> strong controls, False -> none; a Controls member passes through.
    if isinstance(controls, bool):
        controls = Controls.STRONG if controls else Controls.NONE
    return prioritize(cvss, threat, asset, exposure, controls, patch).priority


class PrioritizeTests(unittest.TestCase):
    def test_active_exploit_low_exposure_standard_was_next_bug(self):
        # Old weighted sum put actively exploited CVSS 9.0 / standard / low into NEXT (6.55).
        self.assertEqual(p(9.0, Threat.ACTIVE, Asset.STANDARD, Exposure.MEDIUM), NOW)
        self.assertEqual(p(9.0, Threat.ACTIVE, Asset.STANDARD, Exposure.LOW), NEXT)
        self.assertEqual(p(9.0, Threat.ACTIVE, Asset.CROWN, Exposure.LOW), NOW)

    def test_public_exploit(self):
        self.assertEqual(p(8.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH), NOW)
        self.assertEqual(p(6.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH), NEXT)
        self.assertEqual(p(9.8, Threat.PUBLIC, Asset.STANDARD, Exposure.LOW), NEXT)

    def test_no_exploit(self):
        self.assertEqual(p(9.8, Threat.NONE, Asset.CROWN, Exposure.HIGH), NOW)
        self.assertEqual(p(8.0, Threat.NONE, Asset.STANDARD, Exposure.HIGH), NEXT)
        self.assertEqual(p(8.0, Threat.NONE, Asset.STANDARD, Exposure.LOW), NEVER)
        self.assertEqual(p(5.0, Threat.NONE, Asset.CROWN, Exposure.HIGH), NEVER)

    def test_low_cvss_caps_at_next(self):
        self.assertEqual(p(2.0, Threat.ACTIVE, Asset.CROWN, Exposure.HIGH), NEXT)

    def test_controls_downgrade_but_not_below_next_when_exploited(self):
        self.assertEqual(p(9.0, Threat.ACTIVE, Asset.STANDARD, Exposure.HIGH, True), NEXT)
        self.assertEqual(p(9.0, Threat.ACTIVE, Asset.STANDARD, Exposure.LOW, True), NEXT)
        self.assertEqual(p(8.0, Threat.NONE, Asset.CROWN, Exposure.LOW, True), NEVER)

    def test_no_patch_raises_priority_without_controls(self):
        for patch in (Patch.PENDING, Patch.EOL):
            # base NEXT -> NOW
            self.assertEqual(p(8.0, Threat.NONE, Asset.STANDARD, Exposure.HIGH, False, patch), NOW)
            # base NEVER (CVSS 5, no exploit) -> NEXT
            self.assertEqual(p(5.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, False, patch), NEXT)
        # already NOW stays NOW
        self.assertEqual(p(9.0, Threat.ACTIVE, Asset.STANDARD, Exposure.HIGH, False, Patch.PENDING), NOW)

    def test_no_patch_with_controls_withholds_raise_and_gives_no_downgrade(self):
        # Patched + controls downgrades; unpatched + controls stays at base.
        self.assertEqual(p(8.0, Threat.NONE, Asset.STANDARD, Exposure.HIGH, True, Patch.AVAILABLE), NEVER)
        self.assertEqual(p(8.0, Threat.NONE, Asset.STANDARD, Exposure.HIGH, True, Patch.PENDING), NEXT)

    def test_low_cvss_not_raised_for_missing_patch(self):
        self.assertEqual(p(3.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, False, Patch.PENDING), NEVER)

    def test_eol_floor_vs_pending(self):
        # CVSS 8, no exploit, standard asset, low exposure -> base NEVER; controls in place.
        self.assertEqual(p(8.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, True, Patch.PENDING), NEVER)
        self.assertEqual(p(8.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, True, Patch.EOL), NEXT)

    def test_actions_differ_by_patch_status(self):
        acts = {
            pt: prioritize(8.0, Threat.NONE, Asset.STANDARD, Exposure.HIGH, Controls.NONE, pt).action
            for pt in Patch
        }
        self.assertEqual(len(set(acts.values())), 3)
        self.assertIn("replacement", acts[Patch.EOL])
        self.assertIn("vendor advisory", acts[Patch.PENDING])

    def test_partial_credit_only_matters_near_thresholds(self):
        part = Controls.PARTIAL
        # Credit is 1.05 CVSS points: 7.5 -> 6.45 crosses the 7.0 line, 8.5 -> 7.45 does not.
        self.assertEqual(p(7.5, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH), NOW)
        self.assertEqual(p(7.5, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, part), NEXT)
        self.assertEqual(p(8.5, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, part), NOW)
        # 9.5 -> 8.45 drops below the 9.0 crown-jewel line.
        self.assertEqual(p(9.5, Threat.NONE, Asset.CROWN, Exposure.HIGH), NOW)
        self.assertEqual(p(9.5, Threat.NONE, Asset.CROWN, Exposure.HIGH, part), NEXT)
        # Partial never beats strong, and doesn't move an actively exploited, reachable issue.
        self.assertEqual(p(7.5, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, Controls.STRONG), NEXT)
        self.assertEqual(p(9.0, Threat.ACTIVE, Asset.STANDARD, Exposure.MEDIUM, part), NOW)

    def test_partial_credit_lowers_ordering_score(self):
        none = prioritize(8.0, Threat.NONE, Asset.STANDARD, Exposure.HIGH).score
        part = prioritize(8.0, Threat.NONE, Asset.STANDARD, Exposure.HIGH, Controls.PARTIAL).score
        self.assertAlmostEqual(none - part, 0.3 * 1.05, delta=0.01)

    def test_unpatched_partial_still_raised_but_credit_applied_first(self):
        # PUBLIC 7.5 high exposure: tree gives NEXT with credit, then the no-patch raise makes it NOW.
        self.assertEqual(p(7.5, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, Controls.PARTIAL, Patch.PENDING), NOW)
        # Strong controls withhold the raise but earn no downgrade when unpatched: stays at the base (NOW).
        self.assertEqual(p(7.5, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, Controls.STRONG, Patch.PENDING), NOW)
        # Base NEXT (CVSS 6.0): none -> raised to NOW; strong -> stays NEXT.
        self.assertEqual(p(6.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, Controls.NONE, Patch.PENDING), NOW)
        self.assertEqual(p(6.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, Controls.STRONG, Patch.PENDING), NEXT)

    def test_active_exploit_floor_with_strong_controls(self):
        self.assertEqual(p(9.0, Threat.ACTIVE, Asset.STANDARD, Exposure.LOW, Controls.STRONG), NEXT)

    def test_eol_floor_applies_to_partial_controls(self):
        self.assertEqual(p(8.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, Controls.PARTIAL, Patch.EOL), NEXT)

    def test_score_bounded(self):
        highest = prioritize(10.0, Threat.ACTIVE, Asset.CROWN, Exposure.HIGH)
        lowest = prioritize(0.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, Controls.STRONG, Patch.AVAILABLE)
        self.assertLessEqual(highest.score, 10.0)
        self.assertGreaterEqual(lowest.score, 0.0)

    def test_score_bounded_for_all_inputs(self):
        for cvss in (0.0, 5.0, 10.0):
            for combo in itertools.product(Threat, Asset, Exposure, Controls, Patch):
                threat, asset, exposure, controls, patch = combo
                score = prioritize(cvss, threat, asset, exposure, controls, patch).score
                self.assertTrue(0.0 <= score <= 10.0, (cvss, combo, score))

    def test_result_lists_all_inputs(self):
        r = prioritize(8.0, Threat.PUBLIC, Asset.CROWN, Exposure.HIGH, Controls.PARTIAL, Patch.PENDING)
        self.assertEqual(len(r.inputs), 6)
        for expected in ("CVSS: 8.0", Threat.PUBLIC.value, Asset.CROWN.value, Exposure.HIGH.value,
                         Controls.PARTIAL.value, Patch.PENDING.value):
            self.assertTrue(any(expected in line for line in r.inputs), expected)

    def test_rejects_bad_cvss(self):
        for bad in ("nan", "inf", "-1", "10.1", "", "abc"):
            with self.assertRaises(ValueError):
                parse_cvss(bad)
        self.assertEqual(parse_cvss(" 7.5 "), 7.5)
        with self.assertRaises(ValueError):
            prioritize(float("nan"), Threat.NONE, Asset.STANDARD, Exposure.LOW)


class BoundaryTests(unittest.TestCase):
    def test_public_exploit_line_at_7(self):
        self.assertEqual(p(7.0, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH), NOW)
        self.assertEqual(p(6.9, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH), NEXT)

    def test_no_exploit_line_at_7(self):
        self.assertEqual(p(7.0, Threat.NONE, Asset.STANDARD, Exposure.HIGH), NEXT)
        self.assertEqual(p(6.9, Threat.NONE, Asset.STANDARD, Exposure.HIGH), NEVER)

    def test_crown_jewel_line_at_9(self):
        self.assertEqual(p(9.0, Threat.NONE, Asset.CROWN, Exposure.HIGH), NOW)
        self.assertEqual(p(8.9, Threat.NONE, Asset.CROWN, Exposure.HIGH), NEXT)

    def test_low_severity_cap_at_4(self):
        self.assertEqual(p(4.0, Threat.ACTIVE, Asset.STANDARD, Exposure.HIGH), NOW)
        self.assertEqual(p(3.9, Threat.ACTIVE, Asset.STANDARD, Exposure.HIGH), NEXT)

    def test_no_patch_raise_line_at_4(self):
        self.assertEqual(p(4.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, False, Patch.PENDING), NEXT)
        self.assertEqual(p(3.9, Threat.NONE, Asset.STANDARD, Exposure.LOW, False, Patch.PENDING), NEVER)

    def test_end_of_life_floor_at_7(self):
        self.assertEqual(p(7.0, Threat.NONE, Asset.STANDARD, Exposure.LOW, True, Patch.EOL), NEXT)
        self.assertEqual(p(6.9, Threat.NONE, Asset.STANDARD, Exposure.LOW, True, Patch.EOL), NEVER)

    def test_partial_credit_at_the_7_line(self):
        part = Controls.PARTIAL
        self.assertEqual(p(8.05, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, part), NOW)
        self.assertEqual(p(8.04, Threat.PUBLIC, Asset.STANDARD, Exposure.HIGH, part), NEXT)


RANK = {NEVER: 0, NEXT: 1, NOW: 2}
# Each list runs from least to most concerning.
WORSENING = {
    "threat": [Threat.NONE, Threat.PUBLIC, Threat.ACTIVE],
    "asset": [Asset.STANDARD, Asset.IMPORTANT, Asset.CROWN],
    "exposure": [Exposure.LOW, Exposure.MEDIUM, Exposure.HIGH],
    "controls": [Controls.STRONG, Controls.PARTIAL, Controls.NONE],
    "patch": [Patch.AVAILABLE, Patch.PENDING, Patch.EOL],
}
CVSS_GRID = [x / 10 for x in range(0, 101, 5)]


def rank(cvss, args):
    result = prioritize(cvss, args["threat"], args["asset"], args["exposure"], args["controls"], args["patch"])
    return RANK[result.priority]


class MonotonicityTests(unittest.TestCase):
    def test_worse_input_never_lowers_priority(self):
        for cvss in CVSS_GRID:
            for combo in itertools.product(*WORSENING.values()):
                args = dict(zip(WORSENING, combo))
                base = rank(cvss, args)
                for key, levels in WORSENING.items():
                    i = levels.index(args[key])
                    if i + 1 < len(levels):
                        worse = {**args, key: levels[i + 1]}
                        with self.subTest(cvss=cvss, changed=key, **{k: v.name for k, v in args.items()}):
                            self.assertGreaterEqual(rank(cvss, worse), base)
                if cvss < 10.0:
                    with self.subTest(cvss=cvss, changed="cvss", **{k: v.name for k, v in args.items()}):
                        self.assertGreaterEqual(rank(cvss + 0.5, args), base)


if __name__ == "__main__":
    unittest.main()
