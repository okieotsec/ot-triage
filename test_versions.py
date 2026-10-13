import unittest

import versions as vs

try:
    from hypothesis import given
    from hypothesis import settings as hyp_settings
    from hypothesis import strategies as st
except ImportError:      # the property tests are optional
    given = None


def inside(version, listed):
    return vs.in_range(vs.parse_version(version), vs.parse_range(listed))


class VersionTests(unittest.TestCase):
    def test_a_version_is_read_from_the_text_around_it(self):
        cases = {"3.11.0": ((3, 11, 0), ""), "V3.01.012": ((3, 1, 12), ""), "Firmware_3.11.0": ((3, 11, 0), ""),
                 "FW 7.20.56": ((7, 20, 56), ""), "7.1_SP2": ((7, 1), "sp2"), "9": ((9,), ""),
                 "R2.60.00": ((2, 60, 0), ""), "v4.1.14 ": ((4, 1, 14), ""), "2.0.2870_xxx_2.2.12": ((2, 0, 2870),
                                                                                                    "xxx_2.2.12")}
        for text, (parts, suffix) in cases.items():
            with self.subTest(text):
                self.assertEqual(vs.parse_version(text), vs.Version(parts, suffix))

    def test_a_long_text_is_not_read_even_when_it_has_a_number(self):
        self.assertIsNone(vs.parse_version("1.0" + "x" * 200))
        self.assertIsNotNone(vs.parse_version("1.0" + "x" * 20))
        self.assertLessEqual(len(vs.parse_version("1.0" + "x" * 100).suffix), vs.MAX_SUFFIX_CHARS)

    def test_text_that_is_not_a_version_is_not_read(self):
        for text in ("", "   ", "banana", "latest", None, 5, [], "x" * 200, "1." * 9 + "1", "1" * 10, "(1.2)",
                     "ver#1.2"):
            with self.subTest(text=text):
                self.assertIsNone(vs.parse_version(text))

    def test_numbers_compare_as_numbers_not_as_text(self):
        low, high = vs.parse_version("3.9"), vs.parse_version("3.10")
        self.assertEqual((vs.compare(low, high), vs.compare(high, low), vs.compare(high, high)), (-1, 1, 0))
        self.assertEqual(vs.compare(vs.parse_version("3.1"), vs.parse_version("3.1.0")), 0)
        self.assertEqual(vs.compare(vs.parse_version("3.1.0.1"), vs.parse_version("3.1")), 1)

    def test_a_qualifier_alone_cannot_order_two_versions(self):
        self.assertIsNone(vs.compare(vs.parse_version("7.1"), vs.parse_version("7.1_SP2")))
        self.assertIsNone(vs.compare(vs.parse_version("7.1 SP1"), vs.parse_version("7.1 SP2")))
        self.assertEqual(vs.compare(vs.parse_version("7.1 SP2"), vs.parse_version("7.1_SP2")), 0)
        self.assertEqual(vs.compare(vs.parse_version("7.0"), vs.parse_version("7.1_SP2")), -1)


class RangeTests(unittest.TestCase):
    def test_the_shapes_cisa_uses_are_read(self):
        cases = [
            # (text, version, expected)
            ("<=Firmware_3.11.0", "3.8", True), ("<=Firmware_3.11.0", "3.11.0", True),
            ("<=Firmware_3.11.0", "3.11.1", False), ("<=Firmware_3.11.0", "3.12", False),
            ("<3.52", "3.52", False), ("< 3.52", "3.51.9", True),
            (">=4.01", "4.01", True), (">4.01", "4.01", False), (">4.01", "4.02", True),
            ("vers:intdot/<4.3.4", "4.3.3", True), ("vers:intdot/<4.3.4", "4.3.4", False),
            ("vers:intdot/>=4.0|<5.2", "4.0", True), ("vers:intdot/>=4.0|<5.2", "5.2", False),
            ("vers:intdot/>=4.0|<5.2", "3.9", False), ("vers:intdot/>=4.0|<5.2", "5.1.9", True),
            (">= 6.02 | <= 6.05", "6.05", True), (">= 6.02 | <= 6.05", "6.06", False),
            (">=R2.02.50|<R2.80.00", "R2.60.00", True), ("<=9", "9.0.1", False), ("<=9", "9", True),
            ("vers:all/*", "1.2.3", True), ("*", "1", True), ("All versions", "9", True), ("all", "9", True),
            ("vers:all/<V3.1.1", "3.1.0", True), ("vers:all/<V3.1.1", "3.1.1", False),
            ("9.21", "9.21", True), ("9.21", "9.2", False), ("V6.53", "6.53", True), ("CPR9", "9", True),
            ("== 4.1", "4.1", True), ("= 4.1", "4.2", False),
            ("V7.1_SP2 and prior", "7.0", True), ("7.1 and earlier", "7.1", True), ("7.1 and earlier", "7.2", False),
            ("prior to 3.1", "3.0", True), ("prior to 3.1", "3.1", False), ("before 2.5", "2.4", True),
            ("3.0 and later", "3.0", True), ("3.0 and above", "2.9", False),
            ("<=4.0 , >=3.0", "3.5", True), ("<4.0|>=3.0", "4.0", False),
        ]
        for text, version, expected in cases:
            with self.subTest(text=text, version=version):
                self.assertIs(inside(version, text), expected)

    def test_qualifiers_make_the_answer_unknown_only_when_they_decide_it(self):
        self.assertIsNone(inside("7.1", "<V7.1_SP2"))
        self.assertIs(inside("7.0", "<V7.1_SP2"), True)
        self.assertIs(inside("7.2", "<V7.1_SP2"), False)
        self.assertIs(inside("7.1 SP2", "<V7.1_SP2"), False)

    def test_text_that_is_not_understood_gives_no_answer_never_a_guess(self):
        for text in ("", "   ", "7_until_7.1.2", "7.0 | 7.1 | 7.2", "<April/2/2", "<1.0|>=2.0|<3.0", "between 1 and 2",
                     "<<3", "<", ">=", "V3.1.x", "x" * 300, None, 5, "<1 | <2", ">1 | >2", "=1 | <2", "1.0 | <2",
                     ">1 | =2", "<5 | =2", "=2 | >1", "1.0x" + "y" * 200):
            with self.subTest(text=text):
                self.assertIsNone(vs.parse_range(text))
                self.assertIsNone(vs.in_range(vs.parse_version("1.0"), vs.parse_range(text)))

    def test_a_version_that_cannot_be_read_gives_no_answer(self):
        self.assertIsNone(vs.in_range(None, vs.parse_range("<5")))
        self.assertIsNone(vs.in_range(vs.parse_version("1"), None))

    def test_one_open_bound_still_decides_when_the_other_is_unclear(self):
        self.assertIs(inside("3.0", ">=3.1_beta|<4.0"), False)         # below the lower bound whatever the qualifier
        self.assertIsNone(inside("3.1", ">=3.1_beta|<4.0"))
        self.assertIs(inside("4.0", ">=3.1_beta|<4.0"), False)

    def test_the_text_is_shown_as_a_person_reads_it(self):
        self.assertEqual(vs.describe_range("vers:intdot/<4.3.4"), "<4.3.4")
        self.assertEqual(vs.describe_range("vers:all/*"), "all versions")
        self.assertEqual(vs.describe_range("  <=Firmware_3.11.0  "), "<=Firmware_3.11.0")
        self.assertEqual(vs.describe_range(None), "")

    def test_a_huge_number_of_distinct_texts_does_not_grow_without_limit(self):
        for n in range(vs.CACHE_SIZE + 500):
            vs.parse_range(f"<{n}.1")
        self.assertLessEqual(vs._parse_range.cache_info().currsize, vs.CACHE_SIZE)


if given is not None:
    class FuzzTests(unittest.TestCase):
        @hyp_settings(max_examples=400, deadline=None)
        @given(st.text(max_size=150), st.text(max_size=150))
        def test_any_text_gives_an_answer_or_none_and_never_raises(self, listed, version):
            answer = vs.in_range(vs.parse_version(version), vs.parse_range(listed))
            self.assertIn(answer, (True, False, None))

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.lists(st.integers(0, 999), min_size=1, max_size=5),
               st.lists(st.integers(0, 999), min_size=1, max_size=5))
        def test_numbers_agree_with_python_ordering(self, a, b):
            left, right = vs.parse_version(".".join(map(str, a))), vs.parse_version(".".join(map(str, b)))
            width = max(len(a), len(b))
            pa, pb = tuple(a) + (0,) * (width - len(a)), tuple(b) + (0,) * (width - len(b))
            expected = (pa > pb) - (pa < pb)
            self.assertEqual(vs.compare(left, right), expected)
            self.assertIs(vs.in_range(left, vs.parse_range("<" + ".".join(map(str, b)))), expected < 0)


if __name__ == "__main__":
    unittest.main()
