import tempfile
import time
import unittest
from pathlib import Path

try:
    from hypothesis import given
    from hypothesis import settings as hyp_settings
    from hypothesis import strategies as st
except ImportError:  # hypothesis is an optional test dependency
    st = None

import batch
import compare
from prioritizer import NEXT, NOW

HEADER = "rank,id,cve,name,priority,ordering_score,asset_id\n"
NOW_ROW = {"cvss": "9.0", "threat": "active"}
NEXT_ROW = {"cvss": "7.5", "threat": "public", "exposure": "medium"}
NEVER_ROW = {"cvss": "3.0", "threat": "none"}
BAD_ROW = {"cvss": "not a number", "threat": "none"}
COMMON = {"asset": "standard", "exposure": "high", "patch": "available"}


def item(kind, line=2, **extra):
    return batch.score_row(line, {**COMMON, **kind, **extra})


class CompareCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def previous(self, text, name="previous.csv"):
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return compare.load_previous(path)

    def run_compare(self, items, text):
        rows, skipped = self.previous(text)
        return compare.compare(items, rows, "previous.csv", skipped)

    def kind(self, comparison, current):
        return comparison.changes[id(current)].kind


class MatchingTests(CompareCase):
    def test_a_finding_is_recognised_by_its_id_and_reports_how_it_moved(self):
        up, down, same = item(NOW_ROW, id="A"), item(NEVER_ROW, id="B"), item(NEXT_ROW, id="C")
        result = self.run_compare([up, down, same], HEADER + "1,A,,,NEVER,1.00,\n2,B,,,NOW,9.00,\n3,C,,,NEXT,5.00,\n")
        self.assertEqual([self.kind(result, x) for x in (up, down, same)], [compare.UP, compare.DOWN, compare.SAME])
        self.assertEqual(result.changes[id(up)].text, "Up from NEVER")
        self.assertEqual(result.changes[id(down)].text, "Down from NOW")
        self.assertEqual(result.changes[id(same)].text, "Same")
        self.assertEqual(result.changes[id(up)].previous.score, 1.0)

    def test_without_ids_the_cve_and_asset_identify_a_finding(self):
        a = item(NOW_ROW, cve="CVE-2024-0001", asset_id="PLC-1")
        b = item(NOW_ROW, cve="CVE-2024-0001", asset_id="PLC-2")
        result = self.run_compare([a, b], HEADER + "1,,CVE-2024-0001,,NEXT,5.00,plc-1\n")
        self.assertEqual((self.kind(result, a), self.kind(result, b)), (compare.UP, compare.NEW))

    def test_without_ids_or_cves_the_name_and_asset_identify_a_finding(self):
        a = item(NEVER_ROW, name="Weak password policy", asset_id="HMI-1")
        result = self.run_compare([a], HEADER + "1,,,weak  PASSWORD policy,NEVER,2.00,hmi-1\n")
        self.assertEqual(self.kind(result, a), compare.SAME)

    def test_case_and_extra_spaces_do_not_matter(self):
        a = item(NOW_ROW, id="  f-1 ", cve="cve-2024-0001")
        result = self.run_compare([a], HEADER + "1,F-1,,,NOW,9.00,\n")
        self.assertEqual(self.kind(result, a), compare.SAME)

    def test_cells_that_the_export_protected_from_formulas_still_match(self):
        a = item(NOW_ROW, id="=1+1", name="-dash")
        result = self.run_compare([a], HEADER + "1,'=1+1,,'-dash,NEXT,5.00,\n")
        self.assertEqual(self.kind(result, a), compare.UP)

    def test_a_finding_in_no_previous_row_is_new_and_a_previous_row_in_no_finding_is_resolved(self):
        kept, fresh = item(NOW_ROW, id="KEPT"), item(NOW_ROW, id="FRESH")
        result = self.run_compare([kept, fresh], HEADER + "1,KEPT,,,NOW,9.00,\n2,GONE,CVE-2020-1,Old flaw,NEXT,4.00,\n")
        self.assertEqual((self.kind(result, kept), self.kind(result, fresh)), (compare.SAME, compare.NEW))
        self.assertEqual([r.id for r in result.resolved], ["GONE"])
        self.assertEqual(result.resolved[0].label, "GONE \u00b7 CVE-2020-1 \u00b7 Old flaw")
        self.assertEqual(result.counts(), {**dict.fromkeys(compare.KINDS, 0), "same": 1, "new": 1, "resolved": 1})

    def test_two_previous_rows_that_could_be_the_same_finding_are_not_guessed_at(self):
        a = item(NOW_ROW, id="DUP")
        result = self.run_compare([a], HEADER + "1,DUP,,,NEXT,5.00,\n2,DUP,,,NEVER,1.00,\n")
        self.assertEqual(self.kind(result, a), compare.AMBIGUOUS)
        self.assertEqual(len(result.resolved), 2)    # neither was used, so neither is claimed
        self.assertIn("1 could not be matched", result.summary())

    def test_a_second_key_can_settle_what_the_first_could_not(self):
        a = item(NOW_ROW, id="DUP", cve="CVE-2024-0001", asset_id="X")
        result = self.run_compare([a], HEADER + "1,DUP,CVE-2024-0001,,NEXT,5.00,X\n2,DUP,CVE-2024-0002,,NEVER,1.00,X\n")
        self.assertEqual(self.kind(result, a), compare.UP)
        self.assertEqual(result.changes[id(a)].previous.line, 2)

    def test_a_file_of_identical_ids_does_not_make_the_comparison_slow(self):
        count = compare.MAX_ROWS
        rows = [compare.PreviousRow(n + 2, "SAME", "", "", "", NOW) for n in range(count)]
        items = [item(NOW_ROW, id="SAME") for _ in range(count)]
        start = time.monotonic()
        result = compare.compare(items, rows)
        self.assertLess(time.monotonic() - start, 5.0)       # quadratic work would take minutes
        self.assertEqual(result.counts()[compare.AMBIGUOUS], count)
        self.assertEqual(len(result.resolved), count)

    def test_one_previous_row_is_used_once(self):
        a, b = item(NOW_ROW, id="SAME"), item(NOW_ROW, id="SAME")
        result = self.run_compare([a, b], HEADER + "1,SAME,,,NOW,9.00,\n")
        self.assertEqual(sorted((self.kind(result, a), self.kind(result, b))), [compare.NEW, compare.SAME])

    def test_unscorable_findings_are_compared_only_with_each_other(self):
        bad, good = item(BAD_ROW, id="B"), item(NOW_ROW, id="G")
        result = self.run_compare([bad, good], HEADER + "1,B,,,ERROR,,\n2,G,,,ERROR,,\n")
        self.assertEqual((self.kind(result, bad), self.kind(result, good)), (compare.SAME, compare.UNSCORED))
        self.assertEqual(result.changes[id(good)].text, "Not comparable")

    def test_the_summary_reads_in_plain_words(self):
        result = self.run_compare([item(NOW_ROW, id="A")], HEADER + "1,A,,,NEVER,1.00,\n2,Z,,,NOW,9.00,\n")
        self.assertEqual(result.summary(), "Compared with previous.csv: 0 new, 1 moved up, 0 moved down, 1 resolved")

    def test_the_result_does_not_depend_on_the_order_of_the_previous_rows(self):
        items = [item(NOW_ROW, id="A"), item(NEVER_ROW, id="B")]
        one = self.run_compare(items, HEADER + "1,A,,,NEVER,1.00,\n2,B,,,NOW,9.00,\n")
        two = self.run_compare(items, HEADER + "1,B,,,NOW,9.00,\n2,A,,,NEVER,1.00,\n")
        self.assertEqual([c.kind for c in one.changes.values()], [c.kind for c in two.changes.values()])


class LoadTests(CompareCase):
    def refused(self, text_or_bytes, message):
        path = self.dir / "p.csv"
        path.write_bytes(text_or_bytes if isinstance(text_or_bytes, bytes) else text_or_bytes.encode("utf-8"))
        with self.assertRaisesRegex(compare.CompareError, message):
            compare.load_previous(path)

    def test_the_header_must_have_a_priority_and_a_way_to_recognise_findings(self):
        self.refused("id,cve\nA,CVE-2024-0001\n", "priority")
        self.refused("priority,score\nNOW,9\n", "at least one of id, cve or name")
        self.refused("", "priority")

    def test_other_files_are_refused_clearly(self):
        self.refused(b"\xff\xfe\x00\x01 not text", "UTF-8|valid CSV|priority")
        self.refused(b"\x00" * 100, "priority|valid CSV")
        self.refused(HEADER, "no rows")
        self.refused(HEADER + "1,A,,,MAYBE,1,\n", "no rows")

    def test_a_missing_file_or_folder_is_a_clear_error_not_a_crash(self):
        with self.assertRaises(compare.CompareError):
            compare.load_previous(self.dir / "nope.csv")
        with self.assertRaises(compare.CompareError):
            compare.load_previous(self.dir)

    def test_rows_with_an_unknown_priority_are_skipped_and_counted(self):
        rows, skipped = self.previous(HEADER + "1,A,,,NOW,9.00,\n2,B,,,whatever,1,\n3,C,,,next,5.00,\n")
        self.assertEqual(([r.id for r in rows], skipped), (["A", "C"], 1))
        self.assertEqual(rows[1].priority, NEXT)

    def test_scores_outside_zero_to_ten_or_not_numbers_are_ignored(self):
        rows, _ = self.previous(HEADER + "1,A,,,NOW,99,\n2,B,,,NOW,nan,\n3,C,,,NOW,abc,\n4,D,,,NOW,7.5,\n")
        self.assertEqual([r.score for r in rows], [None, None, None, 7.5])

    def test_a_file_over_the_size_limit_is_refused_without_reading_it(self):
        old = compare.MAX_FILE_BYTES
        compare.MAX_FILE_BYTES = 100
        try:
            self.refused(HEADER + "1,A,,,NOW,9.00,\n" * 20, "larger than")
        finally:
            compare.MAX_FILE_BYTES = old

    def test_a_file_with_too_many_rows_is_refused(self):
        old = compare.MAX_ROWS
        compare.MAX_ROWS = 5
        try:
            self.refused(HEADER + "1,A,,,NOW,9.00,\n" * 10, "more than 5 rows")
        finally:
            compare.MAX_ROWS = old

    def test_text_is_cleaned_and_limited(self):
        rows, _ = self.previous(HEADER + f'1,"A\x07B","CVE\u202e",{"x" * 1000},NOW,9.00,"  PLC \n 1 "\n')
        row = rows[0]
        self.assertTrue(all(c.isprintable() for c in (row.id + row.cve + row.name + row.asset_id)))
        self.assertLessEqual(len(row.name), compare.MAX_CELL_CHARS)
        self.assertEqual(row.asset_id, "PLC 1")

    def test_a_byte_order_mark_and_odd_header_case_are_accepted(self):
        path = self.dir / "bom.csv"
        path.write_bytes("\ufeffPRIORITY, ID ,CVE\nNOW,A,\n".encode())
        rows, _ = compare.load_previous(path)
        self.assertEqual((rows[0].id, rows[0].priority), ("A", NOW))

    def test_a_real_export_round_trips(self):
        items = batch.sort_items([item(NOW_ROW, id="A", cve="CVE-2024-0001"), item(NEVER_ROW, id="=B")])
        path = self.dir / "out.csv"
        batch.write_results(path, items)
        rows, skipped = compare.load_previous(path)
        self.assertEqual(skipped, 0)
        result = compare.compare(items, rows)
        self.assertEqual({c.kind for c in result.changes.values()}, {compare.SAME})
        self.assertEqual(result.resolved, ())


@unittest.skipIf(st is None, "hypothesis is not installed")
class CompareFuzzTests(CompareCase):
    if st is not None:
        cell = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=10)

        @hyp_settings(max_examples=150, deadline=None)
        @given(st.text(max_size=2000))
        def test_any_text_as_a_previous_export_loads_or_is_refused_cleanly(self, text):
            path = self.dir / "fuzz.csv"
            path.write_text(HEADER + text, encoding="utf-8", errors="replace")
            try:
                rows, _skipped = compare.load_previous(path)
            except compare.CompareError:
                return
            self.assertTrue(rows)
            for row in rows:
                self.assertIn(row.priority, compare.PRIORITIES)
                self.assertTrue((row.id + row.cve + row.name + row.asset_id).isprintable())

        previous = st.lists(st.builds(compare.PreviousRow, st.integers(2, 99), cell, cell, cell, cell,
                                      st.sampled_from(compare.PRIORITIES)), max_size=15)
        current = st.lists(st.fixed_dictionaries({"id": cell, "cve": cell, "name": cell, "asset_id": cell,
                                                  "cvss": st.sampled_from(["9.8", "3.0", "x"]),
                                                  "threat": st.sampled_from(["active", "none"])}), max_size=15)

        @hyp_settings(max_examples=150, deadline=None)
        @given(current, previous)
        def test_every_finding_gets_one_change_and_every_previous_row_is_used_or_resolved(self, rows, before):
            items = [item({}, line=n, **r) for n, r in enumerate(rows, start=2)]
            result = compare.compare(items, before)
            self.assertEqual(len(result.changes), len(items))
            matched = [c.previous for c in result.changes.values() if c.previous is not None]
            self.assertEqual(len({id(m) for m in matched}), len(matched))           # no row used twice
            self.assertEqual(len(matched) + len(result.resolved), len(before))
            self.assertEqual(sum(v for k, v in result.counts().items() if k != "resolved"), len(items))


if __name__ == "__main__":
    unittest.main()
