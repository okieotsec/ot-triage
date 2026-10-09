import csv
import tempfile
import threading
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import batch
import gui_batch
import threatdata as td
from gui_context import Context
from gui_testing import DisplayTestCase
from test_threatdata import epss_bytes, epss_text, kev_bytes, kev_entry
from settings import DEFAULT_SETTINGS, Settings
from uiprefs import DEFAULT_PREFS

HERE = Path(__file__).resolve().parent
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
        self.assertTrue(self.pump(10, until=lambda: not self.ctx.worker.running and bool(self.view.state.items)
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
        self.assertEqual(self.counter_numbers(), {k: "0" for k in view.counters})

    def test_sample_file_is_loaded_ranked_and_counted(self):
        view = self.load()
        expected = batch.process_file(SAMPLE)
        counts = batch.summarize(expected)
        self.assertEqual(self.counter_numbers(), {"all": str(len(expected)), "NOW": str(counts["NOW"]),
                                                  "NEXT": str(counts["NEXT"]), "NEVER": str(counts["NEVER"]),
                                                  "ERROR": str(counts["ERROR"])})
        rows = self.rows()
        self.assertEqual(len(rows), len(expected))
        self.assertEqual([r[1] for r in rows], [i.id for i in expected])
        ranks = [r[0] for r in rows if r[0] != ""]
        self.assertEqual([int(r) for r in ranks], list(range(1, len(ranks) + 1)))
        self.assertTrue(rows[0][4].startswith("▲ NOW"))
        self.assertIn("sample_vulns.csv", view.file_label.cget("text"))
        self.assertEqual(str(view.export_button.cget("state")), "normal")
        self.assertEqual(str(view.open_button.cget("state")), "normal")
        self.assertFalse(view.progress_row.winfo_ismapped())

    def test_the_table_corners_match_what_is_underneath_them(self):
        view = self.build()
        t = self.style.theme
        rgb = lambda colour: tuple(int(colour[i:i + 2], 16) for i in (1, 3, 5))  # noqa: E731
        wrap = view.tree.master
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
        self.assertTrue(rows and all(r[4].startswith("! ERROR") for r in rows))
        self.assertTrue(all(r[0] == "" and r[7] for r in rows))
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
            self.assertTrue(all(key in r[4] for r in rows))
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
            self.assertIn(target.id, [r[1] for r in rows])
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
        now_ids = {r[1] for r in self.rows()}
        view.search_var.set("")
        view.apply_search()
        self.assertEqual({r[1] for r in self.rows()}, now_ids)

    def test_sorting_toggles_direction_and_marks_the_heading(self):
        view = self.load()
        view.sort_by("score")
        asc = [r[5] for r in self.rows() if r[5]]
        self.assertEqual(asc, sorted(asc, key=float))
        self.assertTrue(view.tree.heading("score", "text").endswith("▲"))
        view.sort_by("score")
        desc = [r[5] for r in self.rows() if r[5]]
        self.assertEqual(desc, sorted(desc, key=float, reverse=True))
        self.assertTrue(view.tree.heading("score", "text").endswith("▼"))
        self.assertNotIn("▲", view.tree.heading("id", "text"))

    def test_sorting_keeps_the_original_ranks_and_rank_restores_the_order(self):
        view = self.load()
        original = [r[1] for r in self.rows()]
        view.sort_by("id")
        ids = [r[1] for r in self.rows()]
        self.assertEqual(ids, sorted(ids, key=str.lower))
        by_id = {r[1]: r[0] for r in self.rows()}
        for rank, item in enumerate((i for i in batch.process_file(SAMPLE) if i.result), start=1):
            self.assertEqual(int(by_id[item.id]), rank)
        view.sort_by("rank")
        self.assertEqual([r[1] for r in self.rows()], original)

    def test_every_column_sorts_without_error(self):
        view = self.load()
        for key, _title, _w, _a in gui_batch.COLUMNS:
            view.sort_by(key)
            view.sort_by(key)
            self.assertEqual(len(self.rows()), len(view.state.items))


class BatchThreatDataTests(BatchViewTestCase):
    def load_data(self):
        entries = [kev_entry("CVE-2024-0001", knownRansomwareCampaignUse="Known")]
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
        by_id = {r[1]: r for r in self.rows()}
        self.assertEqual(by_id["A"][7], "In CISA KEV")
        self.assertTrue(by_id["B"][7].startswith("Elevated EPSS"))
        self.assertEqual(by_id["C"][7], "No KEV or elevated EPSS signal")
        self.assertIn("cve:", by_id["D"][7])
        self.assertIn("KEV 2026.10.04", view.file_label.cget("text"))
        self.assertIsNotNone(self.ctx.threat_data)

    def test_cve_file_without_data_reports_rows_as_errors_not_safe(self):
        view = self.load(self.write_csv("cves.csv", self.CSV))
        by_id = {r[1]: r for r in self.rows()}
        self.assertTrue(all(by_id[k][4].startswith("! ERROR") for k in "ABCD"))
        self.assertIn("no threat data loaded", by_id["A"][7])
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
        self.assertEqual(self.rows(view)[0][4], "▬ NEXT")


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
        by_id = {r[1]: r for r in self.rows()}
        self.assertEqual(by_id["A"][6], "9.8")
        self.assertEqual(by_id["B"][6], "8.7")
        self.assertTrue(by_id["C"][4].startswith("! ERROR"))
        self.assertIn("cvss (5.0) does not match", by_id["C"][7])
        self.assertIn("cvss_vector:", by_id["D"][7])
        view.tree.selection_set(view.tree.get_children()[0])
        self.pump()
        text = view.detail_text.cget("text")
        first = next(i for i in view.state.items if i.id == view.tree.item(view.tree.selection()[0], "values")[1])
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


if __name__ == "__main__":
    unittest.main()
