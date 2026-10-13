import csv
import tempfile
import unittest
from pathlib import Path

try:
    from hypothesis import given
    from hypothesis import settings as hyp_settings
    from hypothesis import strategies as st
except ImportError:  # hypothesis is an optional test dependency
    st = None

import batch
import icsadvisories as ics
import inventory
import rollup
from prioritizer import NEVER, NEXT, NOW
from test_icsadvisories import advisory, good

# Each row is scored with a fixed asset, exposure and patch status, so cvss and threat decide the bucket
COMMON = {"asset": "standard", "exposure": "high", "patch": "available"}
NOW_ROW = {"cvss": "9.0", "threat": "active"}                 # actively exploited and reachable: NOW
NEVER_ROW = {"cvss": "3.0", "threat": "none"}                 # low severity, not exploited: NEVER
BAD_ROW = {"cvss": "not a number", "threat": "none"}          # cannot be scored
NEXT_ROW = {"cvss": "7.5", "threat": "public", "exposure": "medium"}   # public exploit, not high exposure: NEXT


def row(asset_id, kind, ident, **extra):
    return {**COMMON, **kind, "id": ident, "asset_id": asset_id, **extra}


def scored(*rows):
    items = [batch.score_row(n, r) for n, r in enumerate(rows, start=2)]
    return batch.sort_items(items)


class RollupTests(unittest.TestCase):
    def test_the_helper_rows_land_in_the_buckets_the_tests_assume(self):
        items = scored(row("A", NOW_ROW, "1"), row("A", NEXT_ROW, "2"), row("A", NEVER_ROW, "3"),
                       row("A", BAD_ROW, "4"))
        self.assertEqual({i.id: i.priority for i in items}, {"1": NOW, "2": NEXT, "3": NEVER, "4": "ERROR"})

    def test_rows_are_grouped_by_asset_with_counts_and_the_worst_bucket(self):
        items = scored(row("PLC-1", NOW_ROW, "a"), row("PLC-1", NEVER_ROW, "b"), row("RTU-2", NEVER_ROW, "c"),
                       row("PLC-1", NEVER_ROW, "d"))
        summaries, unassigned = rollup.rollup(items)
        self.assertEqual(unassigned, ())
        by_id = {s.asset_id: s for s in summaries}
        self.assertEqual(by_id["PLC-1"].counts, {NOW: 1, NEXT: 0, NEVER: 2, "ERROR": 0})
        mixed = rollup.rollup(scored(row("M", NEXT_ROW, "1"), row("M", NEVER_ROW, "2")))[0][0]
        self.assertEqual((mixed.worst, mixed.counts[NEXT]), (NEXT, 1))
        self.assertEqual((by_id["PLC-1"].worst, by_id["RTU-2"].worst), (NOW, NEVER))
        self.assertEqual(len(by_id["PLC-1"].items), 3)

    def test_assets_are_ordered_worst_first_then_by_how_many_urgent_rows_they_have(self):
        items = scored(row("QUIET", NEVER_ROW, "1"), row("ONE-NOW", NOW_ROW, "2"),
                       row("TWO-NOW", NOW_ROW, "3"), row("TWO-NOW", NOW_ROW, "4"), row("ONE-NOW", NEVER_ROW, "5"))
        summaries, _ = rollup.rollup(items)
        self.assertEqual([s.asset_id for s in summaries], ["TWO-NOW", "ONE-NOW", "QUIET"])

    def test_asset_ids_match_without_regard_to_case_or_spaces_and_show_the_first_spelling(self):
        items = scored(row("Plc-01", NOW_ROW, "1"), row(" PLC-01 ", NEVER_ROW, "2"), row("plc-01", NEVER_ROW, "3"))
        summaries, _ = rollup.rollup(items)
        self.assertEqual(len(summaries), 1)
        self.assertEqual(len(summaries[0].items), 3)
        self.assertEqual(summaries[0].asset_id, summaries[0].items[0].asset_id)

    def test_rows_without_an_asset_id_are_set_aside_not_merged(self):
        items = scored(row("", NOW_ROW, "1"), row("   ", NEVER_ROW, "2"), row("A", NEVER_ROW, "3"))
        summaries, unassigned = rollup.rollup(items)
        self.assertEqual([s.asset_id for s in summaries], ["A"])
        self.assertEqual(sorted(i.id for i in unassigned), ["1", "2"])

    def test_an_asset_with_only_unscorable_rows_is_listed_last_and_has_no_top_finding(self):
        items = scored(row("BROKEN", BAD_ROW, "1"), row("OK", NEVER_ROW, "2"))
        summaries, _ = rollup.rollup(items)
        self.assertEqual([s.asset_id for s in summaries], ["OK", "BROKEN"])
        broken = summaries[1]
        self.assertEqual((broken.worst, broken.top, broken.top_score), ("ERROR", None, None))
        self.assertEqual(broken.counts["ERROR"], 1)

    def test_the_top_row_is_the_most_urgent_then_the_highest_scoring(self):
        items = scored(row("A", NEVER_ROW, "low"), row("A", {"cvss": "9.0", "threat": "active"}, "now-a"),
                       row("A", {"cvss": "10.0", "threat": "active"}, "now-b"))
        top = rollup.rollup(items)[0][0].top
        self.assertEqual(top.id, "now-b")
        self.assertEqual(rollup.rollup(items)[0][0].top_score, top.result.score)

    def test_only_urgent_rows_are_offered_for_the_same_visit(self):
        items = scored(row("A", NOW_ROW, "1"), row("A", NEVER_ROW, "2"), row("A", BAD_ROW, "3"),
                       row("A", NEXT_ROW, "4"))
        summary = rollup.rollup(items)[0][0]
        self.assertEqual({i.id for i in summary.visit_items}, {"1", "4"})
        self.assertTrue(all(i.priority in (NOW, NEXT) for i in summary.visit_items))

    def test_the_row_order_inside_an_asset_is_the_order_given(self):
        items = scored(row("A", NEVER_ROW, "z"), row("A", NOW_ROW, "y"), row("A", NEVER_ROW, "x"))
        self.assertEqual([i.id for i in rollup.rollup(items)[0][0].items], [i.id for i in items])

    def test_nothing_in_nothing_out(self):
        self.assertEqual(rollup.rollup([]), ([], ()))

    def test_a_label_falls_back_to_the_source_line(self):
        item = batch.score_row(7, {**COMMON, **NEVER_ROW, "asset_id": "A"})
        self.assertEqual(rollup.label(item), "line 7")
        named = batch.score_row(7, {**COMMON, **NEVER_ROW, "asset_id": "A", "id": "F1", "cve": "", "name": "Flaw"})
        self.assertEqual(rollup.label(named), "F1 · Flaw")



class RollupExportTests(unittest.TestCase):
    def write(self, *rows):
        summaries, _ = rollup.rollup(scored(*rows))
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / "assets.csv"
        rollup.write_rollup(path, summaries)
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            return reader.fieldnames, list(reader)

    def test_the_columns_and_values(self):
        fields, rows = self.write(row("PLC-1", NOW_ROW, "a", cve="CVE-2024-0001"), row("PLC-1", NEVER_ROW, "b"),
                                  row("RTU-2", NEVER_ROW, "c"))
        self.assertEqual(fields, rollup.COLUMNS)
        first = rows[0]
        self.assertEqual((first["asset_id"], first["worst_priority"], first["now"], first["never"],
                          first["findings"], first["visit_together"]), ("PLC-1", NOW, "1", "1", "2", "1"))
        self.assertTrue(first["top_finding"].startswith("a"))
        self.assertEqual(rows[1]["worst_priority"], NEVER)
        self.assertEqual(rows[1]["visit_together"], "0")

    def test_text_cells_cannot_run_as_spreadsheet_formulas(self):
        _fields, rows = self.write(row("=cmd|' /C calc'!A0", NOW_ROW, "=1+1"), row("+SUM(A1)", NEVER_ROW, "-2"))
        for cell in ("asset_id", "top_finding", "finding_ids"):
            for entry in rows:
                self.assertFalse(entry[cell].startswith(("=", "+", "-", "@")), (cell, entry[cell]))

    def test_a_long_list_of_findings_is_cut_and_says_how_many_are_left(self):
        _fields, rows = self.write(*[row("BIG", NEVER_ROW, f"f{n}") for n in range(rollup.MAX_LISTED_IDS + 7)])
        self.assertTrue(rows[0]["finding_ids"].endswith("; and 7 more"))
        self.assertEqual(rows[0]["findings"], str(rollup.MAX_LISTED_IDS + 7))

    def test_unscored_assets_have_blank_top_fields(self):
        _fields, rows = self.write(row("BROKEN", BAD_ROW, "1"))
        self.assertEqual((rows[0]["worst_priority"], rows[0]["top_ordering_score"], rows[0]["top_finding"]),
                         ("ERROR", "", ""))


class PossibleAdvisoriesTests(unittest.TestCase):
    INVENTORY = ("asset_id,vendor,product\nPLC-1,Siemens AG,S7-1500\nRTU-2,Allen-Bradley,MicroLogix 1400\n"
                 "HMI-3,Siemens,\nGW-4,Siemens,PROFINET\n")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        (self.dir / "i.csv").write_text(self.INVENTORY, encoding="utf-8")
        self.inventory = inventory.load(self.dir / "i.csv")
        docs = [advisory("ICSA-26-001-01", "Siemens SIMATIC S7-1500 CPU", ("CVE-2026-0001",), "Siemens",
                         products=["SIMATIC S7-1500 CPU 1511-1 PN"]),
                advisory("ICSA-26-002-01", "Siemens PROFINET Devices", ("CVE-2026-0002",), "Siemens",
                         products=["PROFINET Driver"])]
        self.ics = ics.parse_archive(good(*docs))
        rows = [row(a, NEVER_ROW, a) for a in ("PLC-1", "RTU-2", "HMI-3", "GW-4", "NOT-LISTED")]
        self.summaries, _ = rollup.rollup(scored(*rows))

    def test_each_asset_with_a_vendor_and_a_product_is_matched(self):
        found = rollup.possible_advisories(self.summaries, self.inventory, self.ics)
        self.assertEqual(set(found), {"PLC-1", "RTU-2", "GW-4"})
        self.assertEqual([a.id for a in found["PLC-1"].advisories], ["ICSA-26-001-01"])
        self.assertEqual((found["PLC-1"].vendor, found["PLC-1"].product), ("Siemens AG", "S7-1500"))
        self.assertEqual((found["RTU-2"].count, found["RTU-2"].vendor_known), (0, False))
        self.assertEqual([a.id for a in found["GW-4"].advisories], ["ICSA-26-002-01"])

    def test_nothing_is_matched_without_an_inventory_or_advisory_data(self):
        self.assertEqual(rollup.possible_advisories(self.summaries, None, self.ics), {})
        self.assertEqual(rollup.possible_advisories(self.summaries, self.inventory, None), {})

    def test_the_export_carries_the_vendor_product_and_the_newest_advisory(self):
        found = rollup.possible_advisories(self.summaries, self.inventory, self.ics)
        path = self.dir / "assets.csv"
        rollup.write_rollup(path, self.summaries, found)
        with open(path, newline="", encoding="utf-8-sig") as fh:
            rows = {r["asset_id"]: r for r in csv.DictReader(fh)}
        self.assertEqual((rows["PLC-1"]["vendor"], rows["PLC-1"]["product"], rows["PLC-1"]["possible_advisories"],
                          rows["PLC-1"]["newest_possible_advisory"]), ("Siemens AG", "S7-1500", "1", "ICSA-26-001-01"))
        self.assertEqual(rows["RTU-2"]["possible_advisories"], "0")
        self.assertEqual((rows["HMI-3"]["vendor"], rows["HMI-3"]["possible_advisories"]), ("", ""))

    def test_the_vendor_and_product_cells_cannot_run_as_formulas(self):
        found = {"PLC-1": rollup.PossibleAdvisories("=cmd", "+SUM", (), 0, False)}
        path = self.dir / "assets.csv"
        rollup.write_rollup(path, self.summaries, found)
        with open(path, newline="", encoding="utf-8-sig") as fh:
            row = next(r for r in csv.DictReader(fh) if r["asset_id"] == "PLC-1")
        self.assertTrue(row["vendor"].startswith("'") and row["product"].startswith("'"))


@unittest.skipIf(st is None, "hypothesis is not installed")
class RollupFuzzTests(unittest.TestCase):
    if st is not None:
        cell = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=12)
        rows = st.lists(st.fixed_dictionaries({
            "asset_id": st.sampled_from(["A", "a", " A ", "B", "", "C-1", "=X"]) | cell,
            "cvss": st.sampled_from(["9.8", "7.5", "3.0", "x"]),
            "threat": st.sampled_from(["active", "public", "none"]),
            "id": cell}), max_size=30)

        @hyp_settings(max_examples=150, deadline=None)
        @given(rows)
        def test_every_row_lands_in_exactly_one_place_and_the_order_never_gets_less_urgent(self, rows):
            items = scored(*[{**COMMON, **r} for r in rows])
            summaries, unassigned = rollup.rollup(items)
            placed = [id(i) for s in summaries for i in s.items] + [id(i) for i in unassigned]
            self.assertEqual(sorted(placed), sorted(id(i) for i in items))
            for s in summaries:
                self.assertEqual(sum(s.counts.values()), len(s.items))
            urgency = {NOW: 3, NEXT: 2, NEVER: 1, "ERROR": 0}
            order = [urgency[s.worst] for s in summaries]
            self.assertEqual(order, sorted(order, reverse=True))


if __name__ == "__main__":
    unittest.main()
