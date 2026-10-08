import hashlib
import itertools
import json
import re
import time
import unittest
from pathlib import Path

import cvss

FIXTURE = json.loads((Path(__file__).resolve().parent / "cvss_reference.json").read_text(encoding="utf-8"))
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

KNOWN_SCORES = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
    V31: 9.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    V40: 9.3,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H": 10.0,
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N": 0.0,
}


def all_vectors(version):
    base, _optional = cvss._allowed(version)
    names = list(base)
    for combo in itertools.product(*[base[name] for name in names]):
        yield f"CVSS:{version}/" + "/".join(f"{n}:{v}" for n, v in zip(names, combo, strict=True))


class ParserTests(unittest.TestCase):
    def test_valid_vectors_of_each_version(self):
        for text, version in ((V31, "3.1"), ("CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N", "3.0"), (V40, "4.0")):
            vector = cvss.parse_vector(text)
            self.assertEqual((vector.version, vector.label), (version, f"CVSS {version}"))
            self.assertEqual(vector.normalized, text)
            self.assertEqual(vector.score, cvss.base_score(vector))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual(cvss.parse_vector(f"  {V31}\n").normalized, V31)

    def test_metrics_in_any_order_are_normalized(self):
        shuffled = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N"
        self.assertEqual(cvss.parse_vector(shuffled).normalized, V31)
        self.assertEqual(cvss.parse_vector(shuffled).score, 9.8)

    def test_optional_metrics_are_accepted_but_never_change_the_base_score(self):
        extras3 = "/E:P/RL:O/RC:C/CR:H/IR:L/AR:M/MAV:L/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:L/MA:H"
        extras4 = ("/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:S/MSA:S/S:P/AU:Y/R:U"
                   "/V:C/RE:L/U:Red")
        for base, extras in ((V31, extras3), ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", extras3), (V40, extras4)):
            plain, rich = cvss.parse_vector(base), cvss.parse_vector(base + extras)
            self.assertEqual(rich.score, plain.score, base)
            self.assertTrue(rich.normalized.startswith(plain.normalized))
            self.assertGreater(len(rich.metrics), len(plain.metrics))

    def test_rejected_inputs_give_a_clear_message(self):
        cases = {
            "": "Enter a CVSS vector", "   ": "Enter a CVSS vector", "CVSS:3.1": "missing required metric",
            "CVSS:3.1/": "not a metric", "AV:N/AC:L/Au:N/C:P/I:P/A:P": "version 2 vectors are not supported",
            "(AV:N/AC:L/Au:N/C:P/I:P/A:P)": "version 2 vectors are not supported",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "must start with CVSS:3.0/",
            "cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "must start with CVSS:3.0/",
            "CVSS:2.0/AV:N": "not supported", "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "not supported",
            "CVSS:5.0/AV:N": "not supported", "CVSS:3.1.1/AV:N": "not supported", "CVSS:/AV:N": "not supported",
            V31 + "/AV:L": "appears more than once",
            V31 + "/ZZ:N": "Unknown CVSS 3.1 metric 'ZZ'",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:X": "not a valid value for A",
            "CVSS:3.1/AV:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "not a valid value for AV",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H": "missing required metric(s): A",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U": "missing required metric(s): C, I, A",
            "CVSS:3.1/AV/AC:L": "not a metric", "CVSS:3.1/AV:/AC:L": "not a metric", "CVSS:3.1/:N/AC:L": "not a metric",
            "CVSS:3.1/AV:N:X/AC:L": "not a metric", V31 + "/": "not a metric", V31 + "//": "not a metric",
            "CVSS:3.1/VC:H/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "Unknown CVSS 3.1 metric 'VC'",
            "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": "missing required metric(s): AT",
            V40 + "/S:C": "not a valid value for S",
            V40.replace("PR:N", "PR:X"): "not a valid value for PR",
        }
        for text, fragment in cases.items():
            with self.subTest(text=text[:50]), self.assertRaisesRegex(ValueError, re.escape(fragment)):
                cvss.parse_vector(text)

    def test_non_text_input_is_rejected(self):
        for bad in (None, 9.8, 3, b"CVSS:3.1/AV:N", ["CVSS:3.1/AV:N"], {"v": V31}):
            with self.subTest(bad=repr(bad)[:20]), self.assertRaises(ValueError):
                cvss.parse_vector(bad)

    def test_unsafe_characters_are_rejected_before_any_parsing(self):
        for char in (" ", "\t", "\n", "\r", "\x00", "%", ";", "'", '"', "=", "$", "`", "\\", "А", "／", "​",
                     "‮", "<", ">", "&", "|"):
            with self.subTest(char=repr(char)), self.assertRaisesRegex(ValueError, "only letters, digits"):
                cvss.parse_vector(V31.replace("AV:N", "AV:N" + char))

    def test_unicode_lookalikes_do_not_pass_as_ascii_letters(self):
        with self.assertRaises(ValueError):
            cvss.parse_vector(V31.replace("CVSS", "CѵSS"))
        with self.assertRaises(ValueError):
            cvss.parse_vector(V31.replace("AV:N", "АV:N"))

    def test_long_input_is_rejected_quickly_and_messages_stay_short(self):
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, "longer than 400"):
            cvss.parse_vector(V31 + "/" + "A" * 10_000_000)
        self.assertLess(time.monotonic() - start, 0.5)
        longest_ok = cvss.parse_vector(V40 + "/E:U/CR:L/IR:L/AR:L/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/"
                                       "MSC:N/MSI:S/MSA:S/S:P/AU:Y/R:U/V:C/RE:L/U:Amber")
        self.assertLessEqual(len(longest_ok.normalized), cvss.MAX_VECTOR_CHARS)
        for text in ("CVSS:3.1/" + "Z" * 300 + ":N", "CVSS:3.1/AV:" + "N" * 300, "CVSS:" + "9" * 300 + "/AV:N",
                     "CVSS:3.1/" + "A" * 300):
            with self.assertRaises(ValueError) as caught:
                cvss.parse_vector(text)
            self.assertLess(len(str(caught.exception)), 200, text[:30])

    def test_normalizing_twice_changes_nothing(self):
        for text in (V31, V40, "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N/E:H"):
            once = cvss.parse_vector(text).normalized
            self.assertEqual(cvss.parse_vector(once).normalized, once)


class ScoreTests(unittest.TestCase):
    def test_well_known_scores(self):
        for text, expected in KNOWN_SCORES.items():
            with self.subTest(vector=text):
                self.assertEqual(cvss.parse_vector(text).score, expected)

    def test_score_from_vector_returns_both(self):
        vector, score = cvss.score_from_vector(V31)
        self.assertEqual((vector.version, score), ("3.1", 9.8))

    def test_scores_are_numbers_between_0_and_10_with_one_decimal(self):
        for version in cvss.SUPPORTED_VERSIONS:
            for index, text in enumerate(all_vectors(version)):
                if index % 17:
                    continue
                score = cvss.parse_vector(text).score
                self.assertIsInstance(score, float)
                self.assertTrue(0.0 <= score <= 10.0, text)
                self.assertEqual(round(score, 1), score, text)

    def test_the_same_vector_always_gives_the_same_score(self):
        for text in KNOWN_SCORES:
            self.assertEqual(len({cvss.parse_vector(text).score for _ in range(5)}), 1)

    def test_v3_scores_never_fall_when_a_single_metric_gets_worse(self):
        worse_order = {"AV": "PLAN", "AC": "HL", "PR": "HLN", "UI": "RN", "C": "NLH", "I": "NLH", "A": "NLH"}

        def score(version, scope, metrics):
            text = f"CVSS:{version}/" + "/".join(f"{n}:{v}" for n, v in metrics.items()) + f"/S:{scope}"
            return cvss.parse_vector(text).score

        for version in ("3.0", "3.1"):
            for scope in "UC":
                for combo in itertools.product(*[worse_order[n] for n in worse_order]):
                    metrics = dict(zip(worse_order, combo, strict=True))
                    base = score(version, scope, metrics)
                    for name, order in worse_order.items():
                        position = order.index(metrics[name])
                        if position + 1 < len(order):
                            worse = {**metrics, name: order[position + 1]}
                            self.assertGreaterEqual(score(version, scope, worse), base, (version, scope, metrics, name))

    def test_v30_and_v31_base_scores_are_identical_for_every_vector(self):
        for v30, v31 in zip(all_vectors("3.0"), all_vectors("3.1"), strict=True):
            self.assertEqual(cvss.parse_vector(v30).score, cvss.parse_vector(v31).score, v30)


class OfficialReferenceTests(unittest.TestCase):
    """Compare with scores recorded from the official FIRST calculators (tools/verify_cvss_against_reference.py)."""

    def test_every_recorded_sample_matches(self):
        for rows in FIXTURE["samples"].values():
            self.assertGreaterEqual(len(rows), 300)
            for text, expected in rows:
                self.assertEqual(cvss.parse_vector(text).score, expected, text)

    def test_the_v4_samples_cover_every_macrovector_a_base_vector_can_reach(self):
        def macro(text):
            return cvss._macro_vector(cvss._selection(cvss.parse_vector(text).metrics))

        reachable = {macro(text) for text in all_vectors("4.0")}
        sampled = {macro(text) for text, _score in FIXTURE["samples"]["4.0"]}
        self.assertEqual(len(reachable), 36)
        self.assertEqual(sampled, reachable)

    def test_every_possible_base_vector_matches_the_official_calculators(self):
        for version in cvss.SUPPORTED_VERSIONS:
            lines = "\n".join(f"{text} {cvss.parse_vector(text).score:.1f}" for text in all_vectors(version))
            self.assertEqual(hashlib.sha256(lines.encode()).hexdigest(), FIXTURE["digests"][version], version)
            self.assertEqual(lines.count("\n") + 1, FIXTURE["counts"][version])

    def test_the_fixture_is_well_formed(self):
        self.assertEqual(set(FIXTURE["digests"]), {"3.0", "3.1", "4.0"})
        self.assertEqual(FIXTURE["counts"], {"3.0": 2592, "3.1": 2592, "4.0": 104976})
        for digest in FIXTURE["digests"].values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


class TableTests(unittest.TestCase):
    def test_the_v4_lookup_table_is_complete_and_sane(self):
        import cvss4_tables as tables
        self.assertEqual(len(tables.LOOKUP), 270)
        for key, value in tables.LOOKUP.items():
            self.assertRegex(key, r"^[012][01][012][012][012][01]$")
            self.assertTrue(0.0 < value <= 10.0)
        self.assertEqual(tables.LOOKUP["000000"], 10)
        self.assertEqual(set(tables.MAX_COMPOSED), {"eq1", "eq2", "eq3", "eq4", "eq5"})
        self.assertEqual(set(tables.MAX_SEVERITY), {"eq1", "eq2", "eq3eq6", "eq4", "eq5"})


if __name__ == "__main__":
    unittest.main()
