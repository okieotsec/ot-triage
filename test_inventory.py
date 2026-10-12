import tempfile
import unittest
from pathlib import Path
from unittest import mock

import batch
import cvss
import inventory
from prioritizer import NEVER, NEXT, NOW, Asset, Controls, Exposure

try:
    from hypothesis import given
    from hypothesis import settings as hyp_settings
    from hypothesis import strategies as st
except ImportError:  # hypothesis is an optional test dependency
    st = None

GOOD = ("asset_id,name,criticality,exposure,controls\n"
        "PLC-01,Packaging PLC,standard,low,partial\n"
        "GW-01,Edge gateway,crown jewel,high,none\n"
        "HMI-01,Operator HMI,important,medium,\n")


class InventoryCase(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dir = Path(folder.name)

    def write(self, name, text, binary=False):
        path = self.dir / name
        path.write_bytes(text) if binary else path.write_text(text, encoding="utf-8")
        return path

    def load(self, text, name="inventory.csv"):
        return inventory.load(self.write(name, text))


class LoadingTests(InventoryCase):
    def test_a_good_inventory_loads_with_its_values(self):
        inv = self.load(GOOD)
        self.assertEqual((len(inv), inv.skipped, inv.problems, inv.label), (3, 0, [], "inventory.csv"))
        status, record = inv.lookup("gw-01")
        self.assertEqual((status, record.name), ("found", "Edge gateway"))
        self.assertEqual(record.values, {"asset": Asset.CROWN, "exposure": Exposure.HIGH, "controls": Controls.NONE})
        self.assertEqual(inv.lookup("HMI-01")[1].values, {"asset": Asset.IMPORTANT, "exposure": Exposure.MEDIUM})

    def test_matching_ignores_case_and_stray_spaces_and_a_byte_order_mark(self):
        inv = inventory.load(self.write("bom.csv", b"\xef\xbb\xbfasset_id,exposure\n  Plc-01 ,low\n", binary=True))
        self.assertEqual(inv.lookup("PLC-01")[0], "found")
        self.assertEqual(inv.lookup("  plc-01\t")[0], "found")
        self.assertEqual(inv.lookup("PLC-02")[0], "missing")

    def test_header_aliases_are_accepted(self):
        inv = self.load("AssetID,Asset Criticality,Network Exposure,Compensating Controls\nA1,critical,high,strong\n")
        self.assertEqual(inv.lookup("a1")[1].values,
                         {"asset": Asset.CROWN, "exposure": Exposure.HIGH, "controls": Controls.STRONG})

    def test_a_row_with_a_bad_value_is_skipped_and_reported_and_the_rest_still_load(self):
        inv = self.load("asset_id,exposure\nA,low\nB,sideways\nC,high\n")
        self.assertEqual((sorted(r.asset_id for r in inv.records.values()), inv.skipped), (["A", "C"], 1))
        self.assertIn("line 3", inv.problems[0])
        self.assertIn("exposure", inv.problems[0])
        self.assertEqual(inv.lookup("B")[0], "missing")

    def test_rows_without_an_id_or_with_a_huge_id_are_skipped(self):
        inv = self.load(f"asset_id,exposure\n,low\n{'x' * 101},low\nok,low\n")
        self.assertEqual((len(inv), inv.skipped), (1, 2))

    def test_an_asset_listed_twice_is_never_used(self):
        inv = self.load("asset_id,exposure\nA,low\na ,high\nB,low\n")
        self.assertEqual(inv.lookup("A")[0], "duplicate")
        self.assertEqual(inv.lookup("B")[0], "found")
        self.assertEqual((len(inv), len(inv.duplicates), inv.skipped), (1, 1, 0))
        self.assertIn("appears 2 times", inv.problems[0])
        self.assertIn("1 duplicated id", inv.summary())

    def test_control_characters_and_invisible_text_are_cleaned_from_ids_and_names(self):
        inv = self.load("asset_id,name,exposure\nA\x1b[31m1,Pump\u202e house\x00,low\n")
        record = next(iter(inv.records.values()))
        for text in (record.asset_id, record.name):
            self.assertTrue(text.isprintable(), repr(text))

    def test_blank_values_are_left_out_not_guessed(self):
        inv = self.load("asset_id,criticality,exposure\nA,,low\n")
        self.assertEqual(inv.lookup("A")[1].values, {"exposure": Exposure.LOW})

    def test_a_binary_or_oversized_cell_file_is_refused_with_a_readable_message(self):
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            inventory.load(self.write("latin1.csv", b"asset_id,exposure\nCaf\xe9,low\n", binary=True))
        with self.assertRaisesRegex(ValueError, "not a valid CSV"):
            inventory.load(self.write("huge.csv", b"asset_id,exposure\n" + b"x" * 300_000 + b",low\n", binary=True))

    def test_a_file_that_cannot_be_used_at_all_is_refused_with_a_clear_message(self):
        cases = {"": "empty", "name,exposure\nA,low\n": "asset_id", "asset_id,name\nA,x\n": "at least one of",
                 "asset_id,exposure,exposure\nA,low,low\n": "Duplicate column"}
        for text, message in cases.items():
            with self.subTest(text=text[:30]), self.assertRaisesRegex(ValueError, message):
                self.load(text)

    def test_size_and_row_limits_are_enforced(self):
        big = self.write("big.csv", "asset_id,exposure\n" + "A,low\n")
        with mock.patch.object(inventory, "MAX_FILE_BYTES", 5), self.assertRaisesRegex(ValueError, "larger than"):
            inventory.load(big)
        many = self.write("many.csv", "asset_id,exposure\n" + "".join(f"A{i},low\n" for i in range(5)))
        with mock.patch.object(inventory, "MAX_ASSETS", 3), self.assertRaisesRegex(ValueError, "more than"):
            inventory.load(many)

    def test_only_a_limited_number_of_problems_are_kept_but_all_skipped_rows_are_counted(self):
        inv = self.load("asset_id,exposure\n" + "".join(f"A{i},bad\n" for i in range(50)))
        self.assertEqual((len(inv.problems), inv.skipped), (inventory.MAX_PROBLEMS, 50))

    def test_ragged_and_odd_rows_do_not_crash(self):
        inv = self.load('asset_id,exposure,controls\nA\nB,low\nC,low,none,extra,more\n"D\nE",high,partial\n')
        self.assertEqual(sorted(r.asset_id for r in inv.records.values()), ["A", "B", "C", "D E"])


class ScoringWithAnInventoryTests(InventoryCase):
    FINDINGS = "id,asset_id,cvss,threat\nF1,GW-01,8.8,active\nF2,PLC-01,5.0,none\nF3,NOPE-9,7.0,none\n"

    def process(self, findings=None, inv=True, **kwargs):
        path = self.write("findings.csv", findings or self.FINDINGS)
        return {i.id: i for i in batch.process_file(path, inventory=self.load(GOOD) if inv else None, **kwargs)}

    def test_the_inventory_fills_in_criticality_exposure_and_controls(self):
        items = self.process()
        gateway = items["F1"]
        self.assertEqual(gateway.priority, NOW)
        self.assertEqual(gateway.from_inventory, ("asset", "exposure", "controls"))
        self.assertEqual(gateway.inputs["asset"], Asset.CROWN)
        self.assertEqual(items["F2"].inputs["controls"], Controls.PARTIAL)
        self.assertEqual(items["F2"].priority, NEVER)

    def test_a_value_on_the_finding_row_wins_over_the_inventory(self):
        findings = "id,asset_id,cvss,threat,exposure,controls\nF1,GW-01,6.0,none,low,strong\n"
        item = self.process(findings)["F1"]
        self.assertEqual((item.inputs["exposure"], item.inputs["controls"]), (Exposure.LOW, Controls.STRONG))
        self.assertEqual(item.from_inventory, ("asset",))

    def test_an_asset_id_that_is_not_in_the_inventory_is_an_error_not_a_guess(self):
        item = self.process()["F3"]
        self.assertEqual(item.priority, "ERROR")
        self.assertIn("is not in the inventory", item.error)

    def test_a_missing_asset_still_works_when_the_row_has_the_values_itself(self):
        findings = "id,asset_id,cvss,threat,asset,exposure\nF1,NOPE-9,7.0,none,standard,low\n"
        item = self.process(findings)["F1"]
        self.assertEqual((item.priority != "ERROR", item.from_inventory), (True, ()))

    def test_an_asset_id_without_any_inventory_explains_that_none_is_loaded(self):
        item = self.process(inv=False)["F1"]
        self.assertEqual(item.priority, "ERROR")
        self.assertIn("no inventory is loaded", item.error)

    def test_a_duplicated_asset_is_reported_as_such(self):
        inv = self.load("asset_id,asset,exposure\nGW-01,crown,high\nGW-01,standard,low\n")
        path = self.write("f.csv", "id,asset_id,cvss,threat\nF1,GW-01,8.0,none\n")
        item = batch.process_file(path, inventory=inv)[0]
        self.assertIn("more than once in the inventory", item.error)

    def test_an_asset_whose_record_lacks_a_value_the_row_also_lacks_is_an_error_that_names_it(self):
        inv = self.load("asset_id,exposure\nA,low\n")
        path = self.write("f.csv", "id,asset_id,cvss,threat\nF1,A,8.0,none\n")
        item = batch.process_file(path, inventory=inv)[0]
        self.assertIn("asset: value is required (the inventory has no asset for asset_id 'A')", item.error)

    def test_the_findings_file_does_not_need_asset_and_exposure_columns_when_it_has_asset_id(self):
        batch.read_rows(self.write("f.csv", "asset_id,cvss,threat\nA,5,none\n"))
        with self.assertRaisesRegex(ValueError, "asset, exposure"):
            batch.read_rows(self.write("g.csv", "cvss,threat\n5,none\n"))

    def test_the_explicit_row_values_work_exactly_as_before_without_any_asset_id(self):
        path = self.write("plain.csv", "id,cvss,threat,asset,exposure\nA,8.0,active,crown,high\n")
        item = batch.process_file(path)[0]
        self.assertEqual((item.priority, item.asset_id, item.from_inventory), (NOW, "", ()))

    def test_hostile_asset_ids_in_findings_cannot_break_anything(self):
        findings = ("id,asset_id,cvss,threat\nF1,\"=HYPERLINK(\"\"http://x\"\")\",5,none\n"
                    f"F2,{'x' * 5000},5,none\nF3,\x1b[2J\u202eevil,5,none\n")
        items = self.process(findings)
        self.assertTrue(all(i.priority == "ERROR" for i in items.values()))
        self.assertLessEqual(len(items["F2"].asset_id), batch.MAX_ASSET_ID_CHARS)
        self.assertTrue(all(i.asset_id.isprintable() for i in items.values()))

    def test_the_export_carries_the_asset_id_and_where_the_values_came_from_and_is_formula_safe(self):
        import csv as csvmodule
        findings = "id,asset_id,cvss,threat\nF1,GW-01,8.8,active\nF2,=cmd|x,5,none\n"
        items = self.process(findings).values()
        out = self.dir / "out.csv"
        batch.write_results(out, batch.sort_items(list(items)))
        with open(out, newline="", encoding="utf-8-sig") as fh:
            rows = {r["id"]: r for r in csvmodule.DictReader(fh)}
        self.assertEqual((rows["F1"]["asset_id"], rows["F1"]["from_inventory"]), ("GW-01", "asset; exposure; controls"))
        self.assertTrue(rows["F2"]["asset_id"].startswith("'="))

    def test_buckets_come_out_the_same_as_typing_the_values_by_hand(self):
        by_inventory = self.process()["F1"]
        by_hand = batch.process_file(self.write("h.csv", "id,cvss,threat,asset,exposure,controls\n"
                                                         "F1,8.8,active,crown,high,none\n"))[0]
        self.assertEqual((by_inventory.priority, by_inventory.result.score), (by_hand.priority, by_hand.result.score))
        self.assertIn(by_inventory.priority, (NOW, NEXT, NEVER))


@unittest.skipIf(st is None, "hypothesis is not installed")
class InventoryFuzzTests(unittest.TestCase):
    if st is not None:
        @hyp_settings(max_examples=200, deadline=None)
        @given(st.text(max_size=3000))
        def test_any_text_as_an_inventory_loads_or_is_refused_cleanly(self, text):
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "i.csv"
                path.write_text("asset_id,exposure,controls,name,confidentiality,integrity,availability\n" + text,
                                encoding="utf-8", errors="replace")
                try:
                    inv = inventory.load(path)
                except ValueError:
                    return
                self.assertLessEqual(len(inv.problems), inventory.MAX_PROBLEMS)
                for record in inv.records.values():
                    self.assertTrue(record.asset_id.isprintable() and record.name.isprintable())
                    self.assertLessEqual(len(record.asset_id), inventory.MAX_KEY_CHARS)
                inv.lookup(text)
                inv.summary()


class SecurityRequirementTests(InventoryCase):
    VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    INVENTORY = ("asset_id,exposure,confidentiality,integrity,availability\n"
                 "PLC-01,low,low,high,high\nHMI-01,low,medium,,\nNONE-01,low,,,\n")

    def score(self, vector_cell, asset="PLC-01", text=None):
        inv = self.load(text or self.INVENTORY)
        path = self.write("f.csv", f"id,asset_id,cvss_vector,threat,asset\nF1,{asset},{vector_cell},none,standard\n")
        return batch.process_file(path, inventory=inv)[0]

    def test_the_requirement_columns_and_their_aliases_are_read(self):
        inv = self.load("asset_id,CR,Integrity Requirement,AR\nA,Low,HIGH,m\n")
        self.assertEqual(inv.lookup("A")[1].requirements, {"CR": "L", "IR": "H", "AR": "M"})

    def test_every_accepted_word_means_the_right_level(self):
        words = {"low": "L", "l": "L", "LOW": "L", "medium": "M", "med": "M", "m": "M", " Medium ": "M", "high": "H",
                 "h": "H", "HIGH": "H"}
        for word, letter in words.items():
            inv = self.load(f'asset_id,availability\nA,"{word}"\n')
            self.assertEqual(inv.lookup("A")[1].requirements, {"AR": letter}, repr(word))

    def test_blank_and_not_set_values_are_left_out_and_others_are_refused_by_row(self):
        inv = self.load("asset_id,confidentiality,integrity\nA,not defined,\nB,medium,whatever\nC,x,high\n")
        self.assertEqual(inv.lookup("A")[1].requirements, {})
        self.assertEqual(inv.lookup("B")[0], "missing")
        self.assertIn("integrity: unrecognized value 'whatever'", inv.problems[0])
        self.assertEqual(inv.lookup("C")[1].requirements, {"IR": "H"})

    def test_an_inventory_with_only_requirement_columns_is_accepted(self):
        self.assertEqual(len(self.load("asset_id,availability\nA,high\nB,low\n")), 2)

    def test_the_environmental_score_uses_the_assets_requirements_without_changing_anything_else(self):
        with_inventory = self.score(self.VECTOR)
        plain = batch.process_file(self.write("p.csv", f"id,cvss_vector,threat,asset,exposure\nF1,{self.VECTOR},none,"
                                                      "standard,low\n"))[0]
        written = cvss.parse_vector(self.VECTOR + "/CR:L/IR:H/AR:H").environmental_score
        self.assertEqual(with_inventory.cvss_environmental, written)
        self.assertIsNone(plain.cvss_environmental)
        self.assertIn("security requirements", with_inventory.from_inventory)
        self.assertEqual((with_inventory.priority, with_inventory.result.score, with_inventory.cvss),
                         (plain.priority, plain.result.score, plain.cvss))

    def test_a_requirement_written_in_the_vector_wins_over_the_inventory(self):
        item = self.score(self.VECTOR + "/CR:H/IR:H/AR:H")
        self.assertEqual(item.cvss_environmental,
                         cvss.parse_vector(self.VECTOR + "/CR:H/IR:H/AR:H").environmental_score)
        self.assertFalse(item.requirements_from_inventory)

    def test_only_the_missing_requirements_are_filled_in(self):
        item = self.score(self.VECTOR + "/CR:H", asset="HMI-01")
        # CR comes from the vector (H, not the inventory's M); IR and AR are not stated anywhere, so stay undefined
        self.assertEqual(item.cvss_environmental, cvss.parse_vector(self.VECTOR + "/CR:H").environmental_score)

    def test_an_asset_without_requirements_or_a_finding_without_a_vector_gets_no_environmental_score(self):
        self.assertIsNone(self.score(self.VECTOR, asset="NONE-01").cvss_environmental)
        inv = self.load(self.INVENTORY)
        path = self.write("n.csv", "id,asset_id,cvss,threat\nF1,PLC-01,9.8,none\n")
        item = batch.process_file(path, inventory=inv)[0]
        self.assertIsNone(item.cvss_environmental)
        self.assertNotIn("security requirements", item.from_inventory)

    def test_the_export_carries_the_environmental_score_and_says_the_requirements_came_from_the_inventory(self):
        import csv as csvmodule
        item = self.score(self.VECTOR)
        out = self.dir / "out.csv"
        batch.write_results(out, [item])
        with open(out, newline="", encoding="utf-8-sig") as fh:
            row = next(csvmodule.DictReader(fh))
        self.assertIn("security requirements", row["from_inventory"])
        self.assertNotEqual(row["cvss_environmental"], "")


if __name__ == "__main__":
    unittest.main()
