import csv
import os
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import batch
import compare
import gui_batch
import gui_widgets
import icsadvisories
import inventory
import rollup
import threatdata as td
from gui_context import Context
from gui_testing import DisplayTestCase
from settings import DEFAULT_SETTINGS, Settings
from test_icsadvisories import advisory, good
from test_threatdata import epss_bytes, epss_text, kev_bytes, kev_entry
from uiprefs import DEFAULT_PREFS

HERE = Path(__file__).resolve().parent
COL = {name: index for index, (name, *_rest) in enumerate(gui_batch.COLUMNS)}
SAMPLE = str(HERE / "sample_vulns.csv")


class BatchViewTestCase(DisplayTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.ctx = Context(self.root, self.style, DEFAULT_SETTINGS, DEFAULT_PREFS)
        self.ctx.data_dir = self.work / "data"
        for name in ("info", "error", "warn", "copy", "confirm"):
            setattr(self.ctx, name, mock.Mock())
        self.holder = tk.Toplevel(self.root)
        if self.holder.tk.call("tk", "windowingsystem") == "x11":
            self.holder.wm_attributes("-type", "dialog")  # a floating window keeps its size on tiling window managers
        self.holder.geometry("1200x800+0+0")
        self.addCleanup(self.holder.destroy)
        self.view = None

    def build(self):
        self.view = gui_batch.BatchView(self.ctx, self.holder)
        self.view.frame.pack(fill=tk.BOTH, expand=True)
        self.pump()
        return self.view

    def load(self, path=SAMPLE):
        view = self.view or self.build()
        view.load(path)
        self.assertTrue(self.pump(10, until=lambda: (not self.ctx.worker.running and bool(self.view.state.items))
                                  or self.ctx.error.called or self.ctx.info.called))
        self.pump(0.05)
        return view

    def write_csv(self, name, text):
        path = self.work / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def rows(self, view=None):
        view = view or self.view
        return [view.tree.item(iid, "values") for iid in view.tree.get_children()]

    def counter_numbers(self):
        return {key: self.view.counters[key][1].cget("text") for key in self.view.counters}


class BatchLoadTests(BatchViewTestCase):
    def test_empty_view_explains_what_to_do(self):
        view = self.build()
        self.assertIn("Open a CSV file", view.detail_title.cget("text"))
        self.assertEqual(str(view.export_button.cget("state")), "disabled")
        self.assertEqual(self.counter_numbers(), dict.fromkeys(view.counters, "0"))

    def test_sample_file_is_loaded_ranked_and_counted(self):
        view = self.load()
        expected = batch.process_file(SAMPLE)
        counts = batch.summarize(expected)
        self.assertEqual(self.counter_numbers(), {"all": str(len(expected)), "NOW": str(counts["NOW"]),
                                                  "NEXT": str(counts["NEXT"]), "NEVER": str(counts["NEVER"]),
                                                  "ERROR": str(counts["ERROR"])})
        rows = self.rows()
        self.assertEqual(len(rows), len(expected))
        self.assertEqual([r[COL["id"]] for r in rows], [i.id for i in expected])
        ranks = [r[COL["rank"]] for r in rows if r[COL["rank"]] != ""]
        self.assertEqual([int(r) for r in ranks], list(range(1, len(ranks) + 1)))
        self.assertTrue(rows[0][COL["priority"]].startswith("▲ NOW"))
        self.assertIn("sample_vulns.csv", view.file_label.cget("text"))
        self.assertEqual(str(view.export_button.cget("state")), "normal")
        self.assertEqual(str(view.open_button.cget("state")), "normal")
        self.assertFalse(view.progress_row.winfo_ismapped())

    def test_the_table_corners_match_what_is_underneath_them(self):
        view = self.build()
        t = self.style.theme
        rgb = lambda colour: tuple(int(colour[i:i + 2], 16) for i in (1, 3, 5))  # noqa: E731
        wrap = view.table_wrap
        tl, tr, bl, br = (label.image for label in wrap.corner_labels)
        radius = tl.width()
        # the pixel of each corner image that lies deepest inside the table
        self.assertEqual(tl.get(radius - 1, radius - 1), rgb(t.border))
        self.assertEqual(tr.get(0, radius - 1), rgb(t.card))
        self.assertEqual(bl.get(radius - 1, 0), rgb(t.card))
        self.assertEqual(br.get(0, 0), rgb(t.card))

    def test_the_empty_hint_names_every_accepted_score_column(self):
        view = self.build()
        self.assertIn("cvss (or cvss_vector)", view.detail_title.cget("text"))

    def test_first_row_is_selected_and_explained(self):
        view = self.load()
        self.assertEqual(len(view.tree.selection()), 1)
        self.assertIn("source line", view.detail_title.cget("text"))
        self.assertGreater(len(view.detail_chips.items), 3)
        self.assertIn("Action:", view.detail_text.cget("text"))

    def test_error_rows_say_why_and_are_marked_with_a_symbol(self):
        view = self.load()
        view.set_filter("ERROR")
        self.pump()
        rows = self.rows()
        self.assertTrue(rows and all(r[COL["priority"]].startswith("! ERROR") for r in rows))
        self.assertTrue(all(r[COL["rank"]] == "" and r[COL["source"]] for r in rows))
        self.assertEqual(view.detail_chips.items[0].cget("text"), "! Not scored")
        self.assertIn("•", view.detail_text.cget("text"))

    def test_bad_files_show_a_message_and_leave_the_view_usable(self):
        view = self.build()
        for name, text in (("missing.csv", "cvss,threat\n9.8,active\n"), ("empty.csv", ""),
                           ("dupes.csv", "cvss,cvss,threat,asset,exposure\n1,2,none,standard,low\n")):
            self.ctx.error.reset_mock()
            view.load(self.write_csv(name, text))
            self.pump(5, until=lambda: self.ctx.error.called)
            self.assertTrue(self.ctx.error.called, name)
            self.assertEqual(self.ctx.error.call_args[0][0], "Batch import failed")
            self.assertNotIn("Traceback", self.ctx.error.call_args[0][1])
            self.assertEqual(str(view.open_button.cget("state")), "normal")
            self.assertFalse(view.progress_row.winfo_ismapped())
        self.assertEqual(view.state.items, [])

    def test_a_non_utf8_file_is_reported(self):
        view = self.build()
        path = self.work / "latin1.csv"
        path.write_bytes(b"cvss,threat,asset,exposure\n9.8,active,crown,high\n\xe9\xff\n")
        view.load(str(path))
        self.pump(5, until=lambda: self.ctx.error.called)
        self.assertTrue(self.ctx.error.called)

    def test_header_only_file_is_reported_not_loaded(self):
        view = self.build()
        view.load(self.write_csv("header.csv", "cvss,threat,asset,exposure\n"))
        self.pump(5, until=lambda: self.ctx.info.called)
        self.assertIn("no data rows", self.ctx.info.call_args[0][1])
        self.assertEqual(view.state.items, [])

    def test_a_second_load_while_busy_is_refused_politely(self):
        view = self.build()
        release = threading.Event()
        real = batch.process_file

        def slow(*args, **kwargs):
            release.wait(5)
            return real(*args, **kwargs)

        with mock.patch("gui_batch.batch.process_file", side_effect=slow):
            view.load(SAMPLE)
            self.pump()
            self.assertEqual(str(view.open_button.cget("state")), "disabled")
            self.assertTrue(view.progress_row.winfo_ismapped())
            view.load(SAMPLE)
            self.assertIn("still running", self.ctx.info.call_args[0][1])
            release.set()
            self.pump(5, until=lambda: bool(view.state.items))
        self.assertTrue(view.state.items)

    def test_the_details_card_claims_its_space_before_the_expanding_table(self):
        view = self.build()
        order = view.body.pack_slaves()
        self.assertLess(order.index(view.details.master), order.index(view.table_wrap))
        self.assertEqual(view.details.master.pack_info()["side"], "bottom")

    def test_the_progress_row_sits_right_under_the_toolbar_so_a_tall_table_cannot_squeeze_it_out(self):
        view = self.build()
        release = threading.Event()
        real = batch.process_file

        def slow(*args, **kwargs):
            release.wait(5)
            return real(*args, **kwargs)

        with mock.patch("gui_batch.batch.process_file", side_effect=slow):
            view.load(SAMPLE)
            self.pump()
            order = view.body.pack_slaves()
            self.assertEqual(order.index(view.progress_row), order.index(view.toolbar) + 1)
            release.set()
            self.pump(5, until=lambda: bool(view.state.items))

    def test_a_load_that_finishes_after_a_rebuild_still_lands_in_the_state(self):
        view = self.build()
        release = threading.Event()
        real = batch.process_file

        def slow(*args, **kwargs):
            release.wait(5)
            return real(*args, **kwargs)

        with mock.patch("gui_batch.batch.process_file", side_effect=slow):
            view.load(SAMPLE)
            view.frame.destroy()
            release.set()
            self.pump(5, until=lambda: bool(self.ctx.batch_state.items))
        rebuilt = self.build()
        self.assertEqual(len(rebuilt.tree.get_children()), len(batch.process_file(SAMPLE)))

    def test_a_cancelled_load_is_discarded(self):
        view = self.build()
        view.load(SAMPLE)
        self.ctx.worker.cancel()
        self.pump(5, until=lambda: not self.ctx.worker.running)
        self.pump(0.2)
        self.assertEqual(view.state.items, [])
        self.assertEqual(str(view.open_button.cget("state")), "normal")

    def test_open_file_dialog_is_used_and_cancelling_does_nothing(self):
        view = self.build()
        self.ctx.open_file = mock.Mock(return_value="")
        view.open_file()
        self.assertEqual(view.state.items, [])
        self.ctx.open_file = mock.Mock(return_value=SAMPLE)
        view.open_file()
        self.pump(10, until=lambda: bool(view.state.items))
        self.assertTrue(view.state.items)

    def test_large_file_loads_and_displays_in_reasonable_time(self):
        lines = ["id,cvss,threat,asset,exposure"] + [
            f"V-{i},{(i % 100) / 10:.1f},{('active', 'public', 'none')[i % 3]},"
            f"{('crown', 'important', 'standard')[i % 3]},{('high', 'medium', 'low')[i % 3]}" for i in range(20000)]
        view = self.load(self.write_csv("big.csv", "\n".join(lines) + "\n"))
        self.assertEqual(len(view.tree.get_children()), 20000)
        view.set_filter("NOW")
        self.assertLess(len(view.tree.get_children()), 20000)


class BatchHostileFileTests(BatchViewTestCase):
    def test_every_hostile_csv_ends_in_a_message_or_a_table_never_a_crash(self):
        import malicious_cases
        view = self.build()
        cases = malicious_cases.build(str(self.work))
        for name, path in cases.items():
            with self.subTest(case=name):
                self.ctx.error.reset_mock()
                self.ctx.info.reset_mock()
                view.state.items = []
                start = time.monotonic()
                view.load(path)
                self.assertTrue(self.pump(30, until=lambda: not self.ctx.worker.running), name)
                self.pump(0.1)
                self.assertLess(time.monotonic() - start, 30)
                shown = bool(view.state.items) or self.ctx.error.called or self.ctx.info.called
                self.assertTrue(shown, name)
                if self.ctx.error.called:
                    message = self.ctx.error.call_args[0][1]
                    self.assertNotIn("Traceback", message)
                    self.assertLess(len(message), 600, name)
                self.assertEqual(str(view.open_button.cget("state")), "normal")
                self.assertFalse(view.progress_row.winfo_ismapped())

    def test_formula_payloads_are_displayed_as_plain_text_and_neutralized_on_export(self):
        import malicious_cases
        view = self.build()
        path = malicious_cases.build(str(self.work))["formula_payloads"]
        view.load(path)
        self.pump(10, until=lambda: bool(view.state.items))
        self.assertTrue(any(str(v).startswith("=") for r in self.rows() for v in r))
        out = self.work / "out.csv"
        self.ctx.save_file = mock.Mock(return_value=str(out))
        view.export()
        with open(out, newline="", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                for key in ("id", "name", "cve", "action", "rationale", "threat_source"):
                    self.assertFalse(row[key].startswith(tuple("=+-@\t\r")), (key, row[key]))


class BatchFilterSortTests(BatchViewTestCase):
    def test_counters_filter_and_do_not_change_their_numbers(self):
        view = self.load()
        numbers = self.counter_numbers()
        for key in ("NOW", "NEXT", "NEVER", "ERROR"):
            view.set_filter(key)
            rows = self.rows()
            self.assertEqual(len(rows), int(numbers[key]))
            self.assertTrue(all(key in r[COL["priority"]] for r in rows))
            self.assertEqual(self.counter_numbers(), numbers)
            self.assertEqual(str(view.counters[key][0].cget("highlightbackground")), self.style.theme.accent)
        view.set_filter("all")
        self.assertEqual(len(self.rows()), int(numbers["all"]))
        self.assertIn(f"Showing {numbers['all']} of {numbers['all']}", view.count_label.cget("text"))

    def test_search_matches_id_name_cve_and_error_text_and_is_case_insensitive(self):
        view = self.load()
        sample = batch.process_file(SAMPLE)
        target = sample[0]
        for text in (target.id.upper(), target.id.lower(), target.name.split()[0]):
            view.search_var.set(text)
            view.apply_search()
            rows = self.rows()
            self.assertTrue(rows, text)
            self.assertIn(target.id, [r[COL["id"]] for r in rows])
            self.assertTrue(all(text.lower() in " ".join(map(str, r)).lower() for r in rows), text)
        view.search_var.set("zzzz-nothing")
        view.apply_search()
        self.assertEqual(self.rows(), [])
        self.assertIn("Showing 0 of", view.count_label.cget("text"))
        view.search_var.set("")
        view.apply_search()
        self.assertEqual(len(self.rows()), len(sample))

    def test_search_is_debounced(self):
        view = self.load()
        total = len(self.rows())
        view.search_var.set("zzzz")
        self.assertEqual(len(self.rows()), total)
        self.pump(0.5)
        self.assertEqual(self.rows(), [])

    def test_search_and_filter_combine(self):
        view = self.load()
        view.set_filter("NOW")
        now_ids = {r[COL["id"]] for r in self.rows()}
        view.search_var.set("")
        view.apply_search()
        self.assertEqual({r[COL["id"]] for r in self.rows()}, now_ids)

    def test_sorting_toggles_direction_and_marks_the_heading(self):
        view = self.load()
        view.sort_by("score")
        asc = [r[COL["score"]] for r in self.rows() if r[COL["score"]]]
        self.assertEqual(asc, sorted(asc, key=float))
        self.assertTrue(view.tree.heading("score", "text").endswith("▲"))
        view.sort_by("score")
        desc = [r[COL["score"]] for r in self.rows() if r[COL["score"]]]
        self.assertEqual(desc, sorted(desc, key=float, reverse=True))
        self.assertTrue(view.tree.heading("score", "text").endswith("▼"))
        self.assertNotIn("▲", view.tree.heading("id", "text"))

    def test_sorting_keeps_the_original_ranks_and_rank_restores_the_order(self):
        view = self.load()
        original = [r[COL["id"]] for r in self.rows()]
        view.sort_by("id")
        ids = [r[COL["id"]] for r in self.rows()]
        self.assertEqual(ids, sorted(ids, key=str.lower))
        by_id = {r[COL["id"]]: r[COL["rank"]] for r in self.rows()}
        for rank, item in enumerate((i for i in batch.process_file(SAMPLE) if i.result), start=1):
            self.assertEqual(int(by_id[item.id]), rank)
        view.sort_by("rank")
        self.assertEqual([r[COL["id"]] for r in self.rows()], original)

    def test_every_column_sorts_without_error(self):
        view = self.load()
        for key, _title, _w, _a in gui_batch.COLUMNS:
            view.sort_by(key)
            view.sort_by(key)
            self.assertEqual(len(self.rows()), len(view.state.items))


NOTES = " ; ".join(f"Link {i}: https://vendor.example.com/{i}" for i in range(8))


class BatchThreatDataTests(BatchViewTestCase):
    def load_data(self):
        entries = [kev_entry("CVE-2024-0001", knownRansomwareCampaignUse="Known", notes=NOTES,
                              forensicTriage="Yes")]
        rows = ["CVE-2024-0001,0.5,0.97", "CVE-2024-0002,0.4,0.99", "CVE-2024-0003,0.001,0.2"]
        (self.work / "kev.json").write_bytes(kev_bytes(entries))
        (self.work / "epss.csv.gz").write_bytes(epss_bytes(epss_text(rows)))
        results = td.import_from_files(self.work / "kev.json", self.work / "epss.csv.gz", self.ctx.data_dir)
        self.assertTrue(all(r.ok for r in results))

    CSV = ("id,cve,cvss,asset,exposure\nA,CVE-2024-0001,8.0,standard,high\nB,CVE-2024-0002,8.0,standard,high\n"
           "C,CVE-2024-0003,8.0,standard,high\nD,nonsense,8.0,standard,high\n")

    def test_cve_file_uses_local_data_and_shows_sources_and_versions(self):
        self.load_data()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        by_id = {r[COL["id"]]: r for r in self.rows()}
        self.assertEqual(by_id["A"][COL["source"]], "In CISA KEV")
        self.assertTrue(by_id["B"][COL["source"]].startswith("Elevated EPSS"))
        self.assertEqual(by_id["C"][COL["source"]], "No KEV or elevated EPSS signal")
        self.assertIn("cve:", by_id["D"][COL["source"]])
        self.assertIn("KEV 2026.10.04", view.file_label.cget("text"))
        self.assertIsNotNone(self.ctx.threat_data)

    def test_cve_file_without_data_reports_rows_as_errors_not_safe(self):
        view = self.load(self.write_csv("cves.csv", self.CSV))
        by_id = {r[COL["id"]]: r for r in self.rows()}
        self.assertTrue(all(by_id[k][COL["priority"]].startswith("! ERROR") for k in "ABCD"))
        self.assertIn("no threat data loaded", by_id["A"][COL["source"]])
        self.assertEqual(view.state.data.versions(), "KEV not loaded; EPSS not loaded")
        self.assertIn("KEV not loaded", view.file_label.cget("text"))

    def test_files_without_a_cve_column_never_load_threat_data(self):
        self.load_data()
        self.load()
        self.assertIsNone(self.ctx.threat_data)

    def test_export_includes_sources_and_versions(self):
        self.load_data()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        out = self.work / "out.csv"
        self.ctx.save_file = mock.Mock(return_value=str(out))
        view.export()
        self.assertEqual(self.ctx.save_file.call_args[0][1], "cves_ranked.csv")
        with open(out, newline="", encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 4)
        first = next(r for r in rows if r["id"] == "A")
        self.assertEqual((first["cve"], first["threat_source"]), ("CVE-2024-0001", "In CISA KEV"))
        self.assertIn("KEV 2026.10.04", first["threat_data"])
        self.assertIn("defaults", first["scoring_settings"])
        self.assertIn("Saved 4 rows", self.ctx.info.call_args[0][1])

    def test_export_cancel_and_failure(self):
        view = self.load()
        self.ctx.save_file = mock.Mock(return_value="")
        view.export()
        self.assertFalse(self.ctx.info.called)
        self.ctx.save_file = mock.Mock(return_value=str(self.work / "no" / "such" / "dir" / "x.csv"))
        view.export()
        self.assertTrue(self.ctx.error.called)
        self.assertEqual(self.ctx.error.call_args[0][0], "Export failed")

    def test_changing_settings_after_loading_flags_the_results_as_outdated(self):
        view = self.load()
        self.assertNotIn("different scoring settings", view.file_label.cget("text"))
        self.ctx.settings = Settings(cvss_high=7.5)
        view.refresh()
        self.assertIn("open the file again to re-score", view.file_label.cget("text"))
        self.assertEqual(str(view.file_label.cget("fg")), self.style.theme.warn)

    def test_custom_settings_are_used_when_scoring(self):
        self.ctx.settings = Settings(cvss_high=7.5)
        view = self.load(self.write_csv("one.csv", "cvss,threat,asset,exposure\n7.2,public,standard,high\n"))
        self.assertEqual(self.rows(view)[0][COL["priority"]], "▬ NEXT")


class BatchVectorTests(BatchViewTestCase):
    V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:L/SI:L/SA:L"

    def csv_text(self):
        return ("id,cvss_vector,cvss,threat,asset,exposure\n"
                f"A,{self.V31},,active,crown,high\n"
                f"B,{self.V40},8.7,public,standard,high\n"
                f"C,{self.V31},5.0,none,standard,low\n"
                "D,CVSS:3.1/AV:N,,none,standard,low\n")

    def test_scores_come_from_vectors_and_the_details_name_the_vector(self):
        view = self.load(self.write_csv("vectors.csv", self.csv_text()))
        by_id = {r[COL["id"]]: r for r in self.rows()}
        self.assertEqual(by_id["A"][COL["cvss"]], "9.8")
        self.assertEqual(by_id["B"][COL["cvss"]], "8.7")
        self.assertTrue(by_id["C"][COL["priority"]].startswith("! ERROR"))
        self.assertIn("cvss (5.0) does not match", by_id["C"][COL["source"]])
        self.assertIn("cvss_vector:", by_id["D"][COL["source"]])
        view.tree.selection_set(view.tree.get_children()[0])
        self.pump()
        text = view.detail_text.cget("text")
        selected_id = view.tree.item(view.tree.selection()[0], "values")[COL["id"]]
        first = next(i for i in view.state.items if i.id == selected_id)
        self.assertIn(f"CVSS vector: {first.cvss_vector} (CVSS {first.cvss_version}", text)

    def test_an_error_row_shows_the_vector_as_given(self):
        view = self.load(self.write_csv("vectors.csv", self.csv_text()))
        view.set_filter("ERROR")
        self.pump()
        view.tree.selection_set(view.tree.get_children()[0])
        self.pump()
        self.assertIn("CVSS vector as given: ", view.detail_text.cget("text"))

    def test_the_export_carries_the_version_and_vector(self):
        view = self.load(self.write_csv("vectors.csv", self.csv_text()))
        out = self.work / "out.csv"
        self.ctx.save_file = mock.Mock(return_value=str(out))
        view.export()
        with open(out, newline="", encoding="utf-8-sig") as fh:
            rows = {r["id"]: r for r in csv.DictReader(fh)}
        self.assertEqual((rows["A"]["cvss"], rows["A"]["cvss_version"], rows["A"]["cvss_vector"]),
                         ("9.8", "3.1", self.V31))
        self.assertEqual(rows["B"]["cvss_version"], "4.0")


class BatchRebuildTests(BatchViewTestCase):
    def test_a_rebuild_keeps_the_loaded_file_filter_and_sort(self):
        view = self.load()
        view.set_filter("NEXT")
        view.sort_by("score")
        before = self.rows()
        view.frame.destroy()
        rebuilt = self.build()
        self.assertEqual(self.rows(rebuilt), before)
        self.assertEqual((rebuilt.state.filter, rebuilt.state.sort_key), ("NEXT", "score"))



class BatchReferenceTests(BatchViewTestCase):
    load_data = BatchThreatDataTests.load_data
    CSV = BatchThreatDataTests.CSV

    def select(self, view, item_id):
        iid = next(i for i in view.tree.get_children() if view.tree.item(i, "values")[COL["id"]] == item_id)
        view.tree.selection_set(iid)
        view.tree.focus(iid)
        self.pump(0.1)

    def link_texts(self, view):
        return [w.cget("text") for w in self.walk(view.detail_refs) if isinstance(w, gui_widgets.LinkLabel)]

    def walk(self, widget):
        for child in widget.winfo_children():
            yield child
            yield from self.walk(child)

    def test_the_details_of_a_kev_row_list_its_references_and_other_rows_show_none(self):
        self.load_data()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        self.select(view, "A")
        self.assertEqual(view.detail_refs.winfo_manager(), "pack")
        self.assertEqual(self.link_texts(view), [f"Link {i}" for i in range(gui_batch.REFERENCE_LIMIT)])
        more = [w.cget("text") for w in self.walk(view.detail_refs) if isinstance(w, tk.Label)
                and "more" in w.cget("text")]
        self.assertEqual(more, [f"and {8 - gui_batch.REFERENCE_LIMIT} more (see Assess or the CSV export)"])
        self.assertTrue(any("Forensic triage advised" in c.cget("text") for c in view.detail_chips.items))
        for other in ("B", "C", "D"):
            self.select(view, other)
            self.assertEqual((view.detail_refs.winfo_manager(), view.detail_refs_title.winfo_manager()), ("", ""))

    def test_clicking_a_reference_in_the_details_opens_exactly_that_address(self):
        self.load_data()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        self.select(view, "A")
        link = next(w for w in self.walk(view.detail_refs) if isinstance(w, gui_widgets.LinkLabel))
        with mock.patch("gui_context.webbrowser.open", return_value=True) as opener:
            link.event_generate("<Button-1>")
            self.pump()
        opener.assert_called_once_with("https://vendor.example.com/0")

    def test_long_details_scroll_inside_a_limited_height_instead_of_growing(self):
        self.load_data()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        self.select(view, "A")
        self.pump(0.2)
        limit = int(gui_batch.DETAILS_MAX_HEIGHT * self.style.scale)
        self.assertLessEqual(view.detail_scroll.canvas.winfo_reqheight(), limit)
        self.assertGreater(view.detail_scroll.body.winfo_reqheight(), limit)
        self.select(view, "D")
        self.pump(0.2)
        self.assertLess(view.detail_scroll.canvas.winfo_reqheight(), limit)

    def test_a_new_selection_starts_at_the_top(self):
        self.load_data()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        self.select(view, "A")
        self.pump(0.2)
        view.detail_scroll.canvas.yview_moveto(1.0)
        self.select(view, "B")
        self.pump(0.2)
        self.assertEqual(view.detail_scroll.canvas.yview()[0], 0.0)

    def test_the_search_box_keeps_its_label_even_with_a_long_file_description(self):
        self.load_data()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        self.pump(0.2)
        toolbar_slaves = view.toolbar.pack_slaves()
        self.assertLess(toolbar_slaves.index(view.search_entry), toolbar_slaves.index(view.file_label))


INVENTORY = ("asset_id,name,criticality,exposure,controls\n"
             "GW-01,Edge gateway,crown jewel,high,none\n"
             "PLC-01,Packaging PLC,standard,low,partial\n")
FINDINGS = "id,asset_id,cvss,threat\nF1,GW-01,8.8,active\nF2,PLC-01,5.0,none\nF3,NOPE-9,7.0,none\n"


class BatchInventoryTests(BatchViewTestCase):
    def pick_inventory(self, text):
        path = self.write_csv("inventory.csv", text)
        self.ctx.open_file = mock.Mock(return_value=path)
        self.view.load_inventory()
        self.assertTrue(self.pump(10, until=lambda: not self.ctx.worker.running))
        self.pump(0.1)

    def by_id(self):
        return {values[COL["id"]]: values for values in self.rows()}

    def test_the_inventory_fills_in_the_findings_and_the_label_says_what_was_loaded(self):
        view = self.build()
        self.pick_inventory(INVENTORY)
        self.assertIn("inventory.csv", view.inventory_label.cget("text"))
        self.assertIn("2 assets", view.inventory_label.cget("text"))
        self.assertEqual(str(view.inventory_clear_button.cget("state")), "normal")
        self.load(self.write_csv("findings.csv", FINDINGS))
        rows = self.by_id()
        self.assertTrue(rows["F1"][COL["priority"]].endswith("NOW"))
        self.assertTrue(rows["F2"][COL["priority"]].endswith("NEVER"))
        self.assertTrue(rows["F3"][COL["priority"]].startswith("! ERROR"))
        self.assertIn("is not in the inventory", rows["F3"][COL["source"]])

    def test_loading_an_inventory_after_the_findings_scores_them_again_and_clearing_undoes_it(self):
        view = self.build()
        self.load(self.write_csv("findings.csv", FINDINGS))
        self.assertTrue(all(v[COL["priority"]].startswith("! ERROR") for v in self.rows()))
        self.assertIn("no inventory is loaded", self.by_id()["F1"][COL["source"]])
        self.pick_inventory(INVENTORY)
        self.assertTrue(self.by_id()["F1"][COL["priority"]].endswith("NOW"))
        self.assertEqual(self.counter_numbers()["ERROR"], "1")
        view.clear_inventory()
        self.assertTrue(self.pump(10, until=lambda: not self.ctx.worker.running))
        self.pump(0.2)
        self.assertEqual(self.counter_numbers()["ERROR"], "3")
        self.assertIsNone(self.ctx.batch_state.inventory)
        self.assertIn("No inventory loaded", view.inventory_label.cget("text"))
        self.assertEqual(str(view.inventory_clear_button.cget("state")), "disabled")

    def test_rows_that_cannot_be_used_are_reported_once_and_the_rest_still_load(self):
        self.build()
        self.pick_inventory("asset_id,exposure\nA,low\nB,sideways\nC,high\nC,low\n")
        self.ctx.warn.assert_called_once()
        message = self.ctx.warn.call_args[0][1]
        self.assertIn("line 3", message)
        self.assertIn("appears 2 times", message)
        self.assertIn("1 row skipped", self.view.inventory_label.cget("text"))

    def test_an_unusable_inventory_is_refused_with_a_message_and_changes_nothing(self):
        view = self.build()
        self.pick_inventory(INVENTORY)
        before = view.inventory_label.cget("text")
        self.pick_inventory("name,exposure\nA,low\n")
        self.assertTrue(self.ctx.error.called)
        self.assertIn("asset_id", self.ctx.error.call_args[0][1])
        self.assertEqual(view.inventory_label.cget("text"), before)
        self.assertEqual(len(self.ctx.batch_state.inventory), 2)

    def test_a_cancelled_file_dialog_does_nothing(self):
        view = self.build()
        self.ctx.open_file = mock.Mock(return_value="")
        view.load_inventory()
        self.pump(0.2)
        self.assertFalse(self.ctx.worker.running)
        self.assertIsNone(self.ctx.batch_state.inventory)

    def test_the_details_say_which_values_came_from_the_inventory_and_search_finds_asset_ids(self):
        view = self.build()
        self.pick_inventory(INVENTORY)
        self.load(self.write_csv("findings.csv", FINDINGS))
        first = next(i for i in view.tree.get_children() if view.tree.item(i, "values")[COL["id"]] == "F1")
        view.tree.selection_set(first)
        self.pump(0.2)
        self.assertIn("Asset GW-01: asset, exposure, controls filled in from the inventory",
                      view.detail_text.cget("text"))
        self.assertTrue(any("From inventory: GW-01" in c.cget("text") for c in view.detail_chips.items))
        view.search_var.set("plc-01")
        self.pump(0.6)
        self.assertEqual([v[COL["id"]] for v in self.rows()], ["F2"])

    def test_the_inventory_survives_a_rebuild_of_the_window(self):
        view = self.build()
        self.pick_inventory(INVENTORY)
        text = view.inventory_label.cget("text")
        view.frame.destroy()
        rebuilt = self.build()
        self.assertEqual(rebuilt.inventory_label.cget("text"), text)
        self.assertEqual(str(rebuilt.inventory_clear_button.cget("state")), "normal")

    def test_the_inventory_buttons_are_disabled_while_a_load_is_running(self):
        view = self.build()
        release = threading.Event()
        real = inventory.load

        def slow(*args, **kwargs):
            release.wait(5)
            return real(*args, **kwargs)

        path = self.write_csv("inventory.csv", INVENTORY)
        self.ctx.open_file = mock.Mock(return_value=path)
        with mock.patch("gui_batch.inventory.load", side_effect=slow):
            view.load_inventory()
            self.pump(0.2)
            self.assertEqual(str(view.inventory_button.cget("state")), "disabled")
            self.assertEqual(str(view.open_button.cget("state")), "disabled")
            release.set()
            self.assertTrue(self.pump(10, until=lambda: not self.ctx.worker.running))
        self.pump(0.2)
        self.assertEqual(str(view.inventory_button.cget("state")), "normal")


class BatchEnvironmentalTests(BatchViewTestCase):
    def test_the_details_show_the_environmental_score_for_comparison(self):
        view = self.build()
        text = ("id,cvss_vector,threat,asset,exposure\n"
                "E1,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:L/IR:L/AR:L/MAV:A/MAC:H,none,important,medium\n"
                "E2,CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H,none,important,medium\n")
        self.load(self.write_csv("env.csv", text))
        for item_id, expected in (("E1", True), ("E2", False)):
            row = next(i for i in view.tree.get_children() if view.tree.item(i, "values")[COL["id"]] == item_id)
            view.tree.selection_set(row)
            self.pump(0.2)
            shown = "Environmental score: 5.7, shown for comparison; the priority uses the base score." in \
                view.detail_text.cget("text")
            self.assertEqual(shown, expected, item_id)
        scores = {v[COL["id"]]: v[COL["score"]] for v in self.rows()}
        self.assertEqual(scores["E1"], scores["E2"])


class BatchAssetColumnTests(BatchViewTestCase):
    MANY = ("id,asset_id,cvss,threat\nF1,PLC-01,5.0,none\nF2,GW-01,8.8,active\nF3,GW-01,3.0,none\n"
            "F4,PLC-01,7.0,public\n")

    def shown_columns(self, view):
        return list(view.tree.cget("displaycolumns"))

    def reload(self, path):
        """Load a findings file and wait until that file (not an earlier one) is what is shown."""
        self.view.load(path)
        self.assertTrue(self.pump(15, until=lambda: not self.ctx.worker.running
                                  and os.path.samefile(self.ctx.batch_state.path, path)))
        self.pump(0.2)

    def load_with_inventory(self, findings):
        view = self.build()
        path = self.write_csv("inventory.csv", INVENTORY)
        self.ctx.open_file = mock.Mock(return_value=path)
        view.load_inventory()
        self.assertTrue(self.pump(10, until=lambda: not self.ctx.worker.running))
        self.load(self.write_csv("findings.csv", findings))
        return view

    def test_the_asset_column_shows_each_rows_asset_so_several_findings_on_one_asset_are_visible(self):
        view = self.load_with_inventory(self.MANY)
        self.assertIn("asset", self.shown_columns(view))
        self.assertEqual(self.shown_columns(view)[:3], ["rank", "id", "asset"])
        assets = {values[COL["id"]]: values[COL["asset"]] for values in self.rows()}
        self.assertEqual(assets, {"F1": "PLC-01", "F2": "GW-01", "F3": "GW-01", "F4": "PLC-01"})

    def test_a_file_without_asset_ids_does_not_show_the_column(self):
        view = self.build()
        self.load(SAMPLE)
        self.assertNotIn("asset", self.shown_columns(view))
        self.assertTrue(all(values[COL["asset"]] == "" for values in self.rows()))

    def test_the_column_appears_and_disappears_with_the_data(self):
        view = self.load_with_inventory(self.MANY)
        self.assertIn("asset", self.shown_columns(view))
        self.reload(SAMPLE)
        self.assertNotIn("asset", self.shown_columns(view))

    def test_clicking_the_asset_heading_sorts_by_asset_and_clicking_again_reverses_it(self):
        view = self.load_with_inventory(self.MANY)
        view.sort_by("asset")
        self.pump(0.1)
        ascending = [values[COL["asset"]] for values in self.rows()]
        self.assertEqual(ascending, sorted(ascending, key=str.lower))
        view.sort_by("asset")
        self.pump(0.1)
        descending = [values[COL["asset"]] for values in self.rows()]
        self.assertEqual(descending, sorted(descending, key=str.lower, reverse=True))
        self.assertIn("Asset", view.tree.heading("asset", "text"))

    def test_sorting_by_asset_groups_the_findings_of_one_asset_together(self):
        view = self.load_with_inventory(self.MANY)
        view.sort_by("asset")
        self.pump(0.1)
        assets = [values[COL["asset"]] for values in self.rows()]
        self.assertEqual(assets, ["GW-01", "GW-01", "PLC-01", "PLC-01"])


class BatchTableFitTests(BatchViewTestCase):
    def test_the_columns_always_fit_inside_the_table_at_any_window_width(self):
        view = self.build()
        self.root.deiconify()
        self.load(SAMPLE)
        for width in (1300, 1100, 900):
            self.holder.geometry(f"{width}x700+0+0")
            self.pump(0.5)
            shown = view.tree.cget("displaycolumns")
            total = sum(int(view.tree.column(key, "width")) for key in shown)
            self.assertLessEqual(total, view.tree.winfo_width() + 2, (width, total, view.tree.winfo_width()))

    def test_name_and_threat_source_get_the_room_the_fixed_columns_leave(self):
        view = self.build()
        self.root.deiconify()
        self.holder.geometry("1300x700+0+0")
        self.load(SAMPLE)
        self.pump(0.4)
        wide = int(view.tree.column("name", "width"))
        self.holder.geometry("900x700+0+0")
        self.pump(0.5)
        self.assertLess(int(view.tree.column("name", "width")), wide)
        self.assertGreaterEqual(int(view.tree.column("name", "width")), gui_batch.MIN_FLEXIBLE["name"])


class BatchAdvisoryTests(BatchViewTestCase):
    load_data = BatchThreatDataTests.load_data
    CSV = BatchThreatDataTests.CSV

    def load_ics(self):
        path = self.work / "csaf.tar.gz"
        path.write_bytes(good(advisory("ICSA-26-006-01", "Acme Widget Controller", ("CVE-2024-0001",), "Acme")))
        self.assertTrue(icsadvisories.import_from_file(path, self.ctx.data_dir).ok)

    def select(self, view, item_id):
        iid = next(i for i in view.tree.get_children() if view.tree.item(i, "values")[COL["id"]] == item_id)
        view.tree.selection_set(iid)
        view.tree.focus(iid)
        self.pump(0.1)

    def walk(self, widget):
        for child in widget.winfo_children():
            yield child
            yield from self.walk(child)

    def links(self, view):
        return [w for w in self.walk(view.detail_adv) if isinstance(w, gui_widgets.LinkLabel)]

    def test_the_details_of_a_row_list_the_advisories_that_name_its_cve_and_other_rows_show_none(self):
        self.load_data()
        self.load_ics()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        self.select(view, "A")
        self.assertEqual((view.detail_adv.winfo_manager(), view.detail_adv_title.winfo_manager()), ("pack", "pack"))
        self.assertEqual([w.cget("text") for w in self.links(view)], ["ICSA-26-006-01"])
        self.assertTrue(any("Acme Widget Controller" in w.cget("text") for w in self.walk(view.detail_adv)
                            if isinstance(w, tk.Label)))
        self.assertIn("ICS advisory ICSA-26-006-01 names this CVE", view.detail_text.cget("text"))
        for other in ("B", "C", "D"):
            self.select(view, other)
            self.assertEqual((view.detail_adv.winfo_manager(), view.detail_adv_title.winfo_manager()), ("", ""))

    def test_clicking_an_advisory_opens_the_address_built_from_its_number(self):
        self.load_data()
        self.load_ics()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        self.select(view, "A")
        with mock.patch("gui_context.webbrowser.open", return_value=True) as opener:
            self.links(view)[0].event_generate("<Button-1>")
            self.pump()
        opener.assert_called_once_with("https://www.cisa.gov/news-events/ics-advisories/icsa-26-006-01")

    def test_the_ranking_is_the_same_with_and_without_the_advisories(self):
        self.load_data()
        without = [(r[COL["id"]], r[COL["priority"]], r[COL["score"]])
                   for r in self.rows(self.load(self.write_csv("cves.csv", self.CSV)))]
        self.load_ics()
        self.ctx.reload_threat_data()
        self.view.load(self.write_csv("cves2.csv", self.CSV))
        self.assertTrue(self.pump(10, until=lambda: not self.ctx.worker.running))
        self.pump(0.2)
        with_ics = [(r[COL["id"]], r[COL["priority"]], r[COL["score"]]) for r in self.rows()]
        self.assertEqual(with_ics, without)

    def test_the_export_has_the_advisories_column(self):
        self.load_data()
        self.load_ics()
        view = self.load(self.write_csv("cves.csv", self.CSV))
        target = self.work / "out.csv"
        self.ctx.save_file = mock.Mock(return_value=str(target))
        view.export()
        self.pump(0.3)
        with open(target, newline="", encoding="utf-8-sig") as fh:
            rows = {r["id"]: r for r in csv.DictReader(fh)}
        self.assertIn("ICSA-26-006-01: https://www.cisa.gov/news-events/ics-advisories/icsa-26-006-01",
                      rows["A"]["ics_advisories"])
        self.assertEqual(rows["B"]["ics_advisories"], "")


class BatchByAssetTests(BatchViewTestCase):
    FINDINGS = ("id,asset_id,name,cvss,threat\n"
                "F1,PLC-01,Flaw one,9.0,active\nF2,PLC-01,Flaw two,7.5,public\nF3,PLC-01,Flaw three,3.0,none\n"
                "F4,GW-01,Gateway flaw,3.0,none\nF5,GW-01,Another,3.5,none\nF6,,No asset id,8.0,active\n"
                "F7,NOPE-9,Not in the inventory,2.0,none\n")

    def prepare(self):
        view = self.build()
        path = self.write_csv("inventory.csv", INVENTORY)
        self.ctx.open_file = mock.Mock(return_value=path)
        view.load_inventory()
        self.assertTrue(self.pump(10, until=lambda: view.state.inventory is not None
                                  and not self.ctx.worker.running))
        self.load(self.write_csv("findings.csv", self.FINDINGS))
        return view

    def asset_rows(self, view):
        return [view.asset_tree.item(i, "values") for i in view.asset_tree.get_children()]

    def select_asset(self, view, name):
        iid = next(i for i in view.asset_tree.get_children() if view.asset_tree.item(i, "values")[0] == name)
        view.asset_tree.selection_set(iid)
        view.asset_tree.focus(iid)
        self.pump(0.1)

    def test_the_toggle_starts_on_findings_and_by_asset_with_no_file_is_just_empty(self):
        view = self.build()
        self.assertEqual((view.state.mode, view.mode_var.get()), ("findings", "findings"))
        view.set_mode("assets")
        self.pump(0.2)
        self.assertEqual(self.asset_rows(view), [])
        self.assertEqual(str(view.export_button.cget("state")), "disabled")
        view.set_mode("findings")
        self.assertEqual(view.findings_frame.winfo_manager(), "pack")

    def test_by_asset_lists_each_asset_once_worst_first_with_its_counts(self):
        view = self.prepare()
        view.set_mode("assets")
        self.pump(0.2)
        rows = self.asset_rows(view)
        names = [r[0] for r in rows]
        self.assertEqual(sorted(names), ["GW-01", "NOPE-9", "PLC-01"])
        self.assertEqual(names, ["PLC-01", "GW-01", "NOPE-9"])      # NEXT, NEVER, then the one that cannot be scored
        plc = next(r for r in rows if r[0] == "PLC-01")
        self.assertIn("NEXT", plc[1])
        self.assertEqual((plc[2], plc[3], plc[4], plc[5]), ("0", "2", "1", "3"))
        self.assertEqual(next(r for r in rows if r[0] == "NOPE-9")[7], "not scored")
        self.assertEqual(view.assets_frame.winfo_manager(), "pack")
        self.assertEqual(view.findings_frame.winfo_manager(), "")
        self.assertEqual(view.counter_row.winfo_manager(), "")
        self.assertIn("1 row has no asset id", view.mode_note.cget("text"))
        self.assertEqual(view.export_button.cget("text"), "Export asset roll-up")
        self.assertIn("findings.csv", view.file_label.cget("text"))

    def test_switching_back_shows_the_findings_table_and_counters_again(self):
        view = self.prepare()
        view.set_mode("assets")
        view.set_mode("findings")
        self.pump(0.2)
        self.assertEqual((view.findings_frame.winfo_manager(), view.assets_frame.winfo_manager()), ("pack", ""))
        self.assertEqual(view.counter_row.winfo_manager(), "pack")
        self.assertEqual(view.export_button.cget("text"), "Export ranked CSV")
        self.assertEqual(len(self.rows()), 7)

    def test_the_segmented_control_drives_the_mode(self):
        view = self.prepare()
        view.mode_var.set("assets")
        self.pump(0.2)
        self.assertEqual(view.state.mode, "assets")
        self.assertEqual(view.assets_frame.winfo_manager(), "pack")

    def test_selecting_an_asset_lists_what_could_be_handled_on_one_visit_and_nothing_scheduled_for_never(self):
        view = self.prepare()
        view.set_mode("assets")
        self.pump(0.2)
        self.select_asset(view, "PLC-01")
        text = view.detail_text.cget("text")
        self.assertIn("Could be handled on one visit (2 findings, most urgent first):", text)
        self.assertIn("Flaw one", text)
        self.assertIn("Flaw two", text)
        self.assertIn("1 more finding NEVER", text)
        self.assertIn("Asset PLC-01: 3 findings", view.detail_title.cget("text"))
        self.select_asset(view, "GW-01")
        self.assertIn("Nothing on this asset needs scheduling.", view.detail_text.cget("text"))

    def test_clicking_a_heading_sorts_the_assets_and_clicking_again_reverses_it(self):
        view = self.prepare()
        view.set_mode("assets")
        view.sort_assets_by("asset")
        self.pump(0.1)
        ascending = [r[0] for r in self.asset_rows(view)]
        self.assertEqual(ascending, sorted(ascending, key=str.lower))
        view.sort_assets_by("asset")
        self.pump(0.1)
        self.assertEqual([r[0] for r in self.asset_rows(view)], list(reversed(ascending)))
        self.assertIn("Asset", view.asset_tree.heading("asset", "text"))

    def test_the_search_box_filters_assets_by_id_and_by_their_findings(self):
        view = self.prepare()
        view.set_mode("assets")
        view.search_var.set("gateway flaw")
        view.apply_search()
        self.pump(0.1)
        self.assertEqual([r[0] for r in self.asset_rows(view)], ["GW-01"])
        view.search_var.set("plc")
        view.apply_search()
        self.pump(0.1)
        self.assertEqual([r[0] for r in self.asset_rows(view)], ["PLC-01"])

    def test_the_mode_survives_a_rebuild_and_a_new_file_resets_the_roll_up(self):
        view = self.prepare()
        view.set_mode("assets")
        view.frame.destroy()
        rebuilt = self.build()
        self.pump(0.2)
        self.assertEqual((rebuilt.mode_var.get(), rebuilt.assets_frame.winfo_manager()), ("assets", "pack"))
        self.assertEqual(len(self.asset_rows(rebuilt)), 3)
        self.reload_findings(rebuilt, "id,asset_id,cvss,threat\nZ1,ONLY-1,5.0,none\n")
        self.assertEqual([r[0] for r in self.asset_rows(rebuilt)], ["ONLY-1"])

    def reload_findings(self, view, text):
        path = self.write_csv("second.csv", text)
        view.load(path)
        self.assertTrue(self.pump(15, until=lambda: not self.ctx.worker.running
                                  and os.path.samefile(self.ctx.batch_state.path, path)))
        self.pump(0.2)

    def test_the_roll_up_export_writes_the_summary_and_the_findings_export_still_works(self):
        view = self.prepare()
        view.set_mode("assets")
        target = self.work / "assets.csv"
        self.ctx.save_file = mock.Mock(return_value=str(target))
        view.export_current()
        self.pump(0.2)
        with open(target, newline="", encoding="utf-8-sig") as fh:
            rows = {r["asset_id"]: r for r in csv.DictReader(fh)}
        self.assertEqual(set(rows), {"PLC-01", "GW-01", "NOPE-9"})
        self.assertEqual((rows["PLC-01"]["findings"], rows["PLC-01"]["worst_priority"]), ("3", "NEXT"))
        self.assertEqual(self.ctx.save_file.call_args[0][1], "ot-triage-assets.csv")
        view.set_mode("findings")
        findings_target = self.work / "findings.csv"
        self.ctx.save_file = mock.Mock(return_value=str(findings_target))
        view.export_current()
        self.pump(0.2)
        with open(findings_target, newline="", encoding="utf-8-sig") as fh:
            self.assertIn("rank", next(csv.reader(fh)))

    def test_a_file_with_no_asset_ids_says_so_instead_of_showing_an_empty_table(self):
        view = self.build()
        self.load(SAMPLE)
        view.set_mode("assets")
        self.pump(0.2)
        self.assertEqual(self.asset_rows(view), [])
        self.assertIn("rows have no asset id", view.mode_note.cget("text"))

    def test_the_roll_up_matches_the_rollup_module(self):
        view = self.prepare()
        expected, _unassigned = rollup.rollup(view.state.items)
        view.set_mode("assets")
        self.pump(0.2)
        self.assertEqual([r[0] for r in self.asset_rows(view)], [s.asset_id for s in expected])


class BatchCompareTests(BatchViewTestCase):
    FINDINGS = ("id,name,cvss,threat,asset,exposure\n"
                "F1,Gets worse,9.0,active,standard,high\nF2,Gets better,3.0,none,standard,high\n"
                "F3,Stays,3.5,none,standard,high\nF4,Brand new,9.0,active,standard,high\n")
    PREVIOUS = ("rank,id,cve,name,priority,ordering_score,asset_id\n"
                "1,F1,,Gets worse,NEVER,1.00,\n2,F2,,Gets better,NOW,9.00,\n3,F3,,Stays,NEVER,2.00,\n"
                "4,F9,CVE-2020-0001,Fixed since,NEXT,5.00,PLC-1\n")

    def prepare(self, previous=None):
        view = self.build()
        self.load(self.write_csv("findings.csv", self.FINDINGS))
        self.ctx.open_file = mock.Mock(return_value=self.write_csv("previous.csv", previous or self.PREVIOUS))
        view.compare_with()
        self.assertTrue(self.pump(10, until=lambda: not self.ctx.worker.running and view.state.previous is not None))
        self.pump(0.2)
        return view

    def by_id(self):
        return {values[COL["id"]]: values for values in self.rows()}

    def test_without_a_comparison_there_is_no_change_column(self):
        view = self.build()
        self.load(self.write_csv("findings.csv", self.FINDINGS))
        self.assertNotIn("change", view.tree.cget("displaycolumns"))
        self.assertIn("No comparison", view.compare_label.cget("text"))
        self.assertEqual(str(view.compare_clear_button.cget("state")), "disabled")
        self.assertEqual(str(view.resolved_button.cget("state")), "disabled")

    def test_the_change_column_says_how_each_finding_moved(self):
        view = self.prepare()
        self.assertIn("change", view.tree.cget("displaycolumns"))
        rows = self.by_id()
        self.assertEqual({k: v[COL["change"]] for k, v in rows.items()},
                         {"F1": "Up from NEVER", "F2": "Down from NOW", "F3": "Same", "F4": "New"})
        self.assertEqual(view.compare_label.cget("text"),
                         "Compared with previous.csv: 1 new, 1 moved up, 1 moved down, 1 resolved")

    def test_the_priorities_and_scores_are_the_same_with_and_without_a_comparison(self):
        view = self.build()
        self.load(self.write_csv("findings.csv", self.FINDINGS))
        before = {v[COL["id"]]: (v[COL["priority"]], v[COL["score"]]) for v in self.rows()}
        self.ctx.open_file = mock.Mock(return_value=self.write_csv("previous.csv", self.PREVIOUS))
        view.compare_with()
        self.assertTrue(self.pump(10, until=lambda: view.state.previous is not None))
        self.pump(0.2)
        self.assertEqual({v[COL["id"]]: (v[COL["priority"]], v[COL["score"]]) for v in self.rows()}, before)

    def test_the_details_of_a_row_say_what_it_was_before(self):
        view = self.prepare()
        iid = next(i for i in view.tree.get_children() if view.tree.item(i, "values")[COL["id"]] == "F1")
        view.tree.selection_set(iid)
        self.pump(0.2)
        text = view.detail_text.cget("text")
        self.assertIn("Compared with the previous export: Up from NEVER (it was NEVER, ordering score 1.00).", text)

    def test_sorting_by_change_puts_new_findings_first(self):
        view = self.prepare()
        view.sort_by("change")
        self.pump(0.1)
        self.assertEqual([v[COL["id"]] for v in self.rows()][:2], ["F4", "F1"])

    def test_show_resolved_lists_what_is_gone(self):
        view = self.prepare()
        self.assertEqual(str(view.resolved_button.cget("state")), "normal")
        self.ctx.info = mock.Mock()
        view.show_resolved()
        title, message = self.ctx.info.call_args[0]
        self.assertEqual(title, "Resolved since the previous export")
        self.assertIn("F9 \u00b7 CVE-2020-0001 \u00b7 Fixed since  (PLC-1, was NEXT)", message)

    def test_opening_another_findings_file_compares_it_with_the_same_previous_export(self):
        view = self.prepare()
        path = self.write_csv("later.csv", "id,name,cvss,threat,asset,exposure\n"
                              "F9,Back again,3.0,none,standard,high\nF1,Gets worse,3.0,none,standard,high\n")
        view.load(path)
        self.assertTrue(self.pump(15, until=lambda: not self.ctx.worker.running
                                  and os.path.samefile(self.ctx.batch_state.path, path)))
        self.pump(0.2)
        rows = self.by_id()
        self.assertEqual((rows["F9"][COL["change"]], rows["F1"][COL["change"]]), ("Down from NEXT", "Same"))
        self.assertIn("1 moved down, 2 resolved", view.compare_label.cget("text"))

    def test_clear_stops_comparing_and_the_column_goes(self):
        view = self.prepare()
        view.clear_comparison()
        self.pump(0.2)
        self.assertNotIn("change", view.tree.cget("displaycolumns"))
        self.assertIsNone(view.state.comparison)
        self.assertIn("No comparison", view.compare_label.cget("text"))

    def test_a_previous_file_that_cannot_be_used_is_reported_and_changes_nothing(self):
        view = self.build()
        self.load(self.write_csv("findings.csv", self.FINDINGS))
        self.ctx.open_file = mock.Mock(return_value=self.write_csv("previous.csv", "id,cve\nA,B\n"))
        view.compare_with()
        self.assertTrue(self.pump(10, until=lambda: not self.ctx.worker.running and self.ctx.error.called))
        self.assertIn("priority", self.ctx.error.call_args[0][1])
        self.assertIsNone(view.state.previous)
        self.assertNotIn("change", view.tree.cget("displaycolumns"))

    def test_cancelling_the_file_dialog_does_nothing(self):
        view = self.build()
        self.load(self.write_csv("findings.csv", self.FINDINGS))
        self.ctx.open_file = mock.Mock(return_value="")
        view.compare_with()
        self.pump(0.2)
        self.assertIsNone(view.state.previous)
        self.assertFalse(self.ctx.worker.running)

    def test_the_exported_file_carries_the_change_columns_and_round_trips(self):
        view = self.prepare()
        target = self.work / "out.csv"
        self.ctx.save_file = mock.Mock(return_value=str(target))
        view.export()
        self.pump(0.2)
        with open(target, newline="", encoding="utf-8-sig") as fh:
            rows = {r["id"]: r for r in csv.DictReader(fh)}
        self.assertEqual((rows["F1"]["change"], rows["F1"]["previous_priority"]), ("up", "NEVER"))
        self.assertEqual((rows["F4"]["change"], rows["F4"]["previous_priority"]), ("new", ""))
        again, _skipped = compare.load_previous(target)
        self.assertEqual({r.id for r in again}, {"F1", "F2", "F3", "F4"})

    def test_the_comparison_works_in_by_asset_mode_without_changing_it(self):
        view = self.prepare()
        view.set_mode("assets")
        self.pump(0.2)
        self.assertIn("Compared with previous.csv", view.compare_label.cget("text"))
        view.set_mode("findings")
        self.assertIn("change", view.tree.cget("displaycolumns"))


if __name__ == "__main__":
    unittest.main()
