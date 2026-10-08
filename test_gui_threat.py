import datetime
import tempfile
import threading
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import gui_threat
import threatdata as td
from gui_context import Context
from gui_testing import DisplayTestCase
from settings import DEFAULT_SETTINGS, Settings
from test_threatdata import epss_bytes, kev_bytes
from uiprefs import DEFAULT_PREFS


class ThreatViewTestCase(DisplayTestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.ctx = Context(self.root, self.style, DEFAULT_SETTINGS, DEFAULT_PREFS)
        self.ctx.data_dir = self.work / "data"
        for name in ("info", "error", "warn", "copy"):
            setattr(self.ctx, name, mock.Mock())
        self.ctx.confirm = mock.Mock(return_value=True)
        guard = mock.patch("threatdata.fetch", side_effect=AssertionError("tests must never use the network"))
        guard.start()
        self.addCleanup(guard.stop)
        self.holder = tk.Toplevel(self.root)
        self.holder.geometry("1100x800+0+0")
        self.addCleanup(self.holder.destroy)
        self.view = None

    def build(self):
        self.view = gui_threat.ThreatView(self.ctx, self.holder)
        self.view.frame.pack(fill=tk.BOTH, expand=True)
        self.pump()
        return self.view

    def fake_network(self, kev=None, epss=None, block=None):
        def fetch(url, max_bytes, hosts, cancel=None, **_kwargs):
            if block:
                block.wait(5)
            result = kev if url == td.KEV_URL else epss
            if isinstance(result, Exception):
                raise result
            return result
        return mock.patch("threatdata.fetch", fetch)

    def wait_idle(self):
        self.assertTrue(self.pump(10, until=lambda: not self.ctx.worker.running and bool(self.ctx.updater.results)))
        self.pump(0.1)

    def card_text(self, name):
        slot, version, detail = self.view.cards[name]
        return [w.cget("text") for w in slot.winfo_children()], version.cget("text"), detail.cget("text")

    def results_text(self):
        texts = []
        for line in self.view.results_box.winfo_children():
            texts.append(" ".join(w.cget("text") for w in line.winfo_children() if isinstance(w, tk.Label))
                         if isinstance(line, tk.Frame) else line.cget("text"))
        return texts


class ThreatViewTests(ThreatViewTestCase):
    def test_nothing_stored_says_so_and_never_implies_safety(self):
        view = self.build()
        for name in ("kev", "epss"):
            chips, version, detail = self.card_text(name)
            self.assertEqual(chips, ["⚠ Not loaded"])
            self.assertIn("CVE lookups cannot use this source", detail)
        self.assertIn("No update has been run", self.results_text()[0])
        self.assertEqual(str(view.update_button.cget("state")), "normal")
        self.assertFalse(view.progress_row.winfo_ismapped())

    def test_update_asks_for_confirmation_once_and_lists_exactly_who_is_contacted(self):
        view = self.build()
        with self.fake_network(kev_bytes(), epss_bytes()):
            view.update()
            self.wait_idle()
            message = self.ctx.confirm.call_args[0][1]
            for host in gui_threat.HOSTS:
                self.assertIn(host, message)
            self.assertIn("HTTPS", message)
            view.update()
            self.wait_idle()
        self.assertEqual(self.ctx.confirm.call_count, 1)

    def test_declining_the_confirmation_downloads_nothing(self):
        view = self.build()
        self.ctx.confirm.return_value = False
        view.update()
        self.pump(0.3)
        self.assertFalse(self.ctx.worker.running)
        self.assertFalse(self.ctx.updater.results)
        self.assertFalse((self.ctx.data_dir).exists())

    def test_successful_update_shows_fresh_cards_and_results(self):
        view = self.build()
        with self.fake_network(kev_bytes(), epss_bytes()):
            view.update()
            self.wait_idle()
        self.assertEqual(self.card_text("kev")[0], ["✓ Fresh"])
        chips, version, detail = self.card_text("kev")
        self.assertEqual(version, "Catalog 2026.10.04")
        self.assertIn("Released 2026-10-04", detail)
        self.assertIn("1 entry", detail)
        self.assertEqual(self.card_text("epss")[1], "Model v2026.06.15")
        self.assertIn("2 scores", self.card_text("epss")[2])
        self.assertEqual(self.results_text(), ["✓ OK  KEV updated.", "✓ OK  EPSS updated."])
        self.assertEqual(str(view.update_button.cget("state")), "normal")
        self.assertFalse(view.progress_row.winfo_ismapped())

    def test_failures_are_listed_and_the_previous_copy_is_kept(self):
        view = self.build()
        with self.fake_network(kev_bytes(), epss_bytes()):
            view.update()
            self.wait_idle()
        before = (self.ctx.data_dir / td.KEV_FILE).read_bytes()
        with self.fake_network(td.FetchError("the connection timed out"), b"not an epss file"):
            view.update()
            self.pump(10, until=lambda: all(not r.ok for r in self.ctx.updater.results) and not self.ctx.worker.running)
            self.pump(0.1)
        texts = self.results_text()
        self.assertTrue(all(t.startswith("⚠ Failed") for t in texts), texts)
        self.assertIn("timed out", texts[0])
        self.assertIn("previous copy was kept", texts[1])
        self.assertEqual((self.ctx.data_dir / td.KEV_FILE).read_bytes(), before)
        self.assertEqual(self.card_text("kev")[0], ["✓ Fresh"])

    def test_progress_and_cancel_while_downloading(self):
        view = self.build()
        release = threading.Event()
        with self.fake_network(kev_bytes(), epss_bytes(), block=release):
            view.update()
            self.pump(0.3)
            self.assertTrue(view.progress_row.winfo_ismapped())
            self.assertEqual(str(view.update_button.cget("state")), "disabled")
            self.assertEqual(str(view.import_button.cget("state")), "disabled")
            self.assertIn("Downloading KEV", view.progress_label.cget("text"))
            self.assertFalse(view.updater.update(ask=False))
            view.cancel_button.invoke()
            release.set()
            self.wait_idle()
        self.assertTrue(any("cancelled" in t for t in self.results_text()))

    def test_stale_data_is_flagged_but_still_listed(self):
        view = self.build()
        long_ago = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)
        td.update_from_network(self.ctx.data_dir, lambda url, cap, hosts, **_kw: kev_bytes() if url == td.KEV_URL
                               else epss_bytes(), long_ago)
        view.refresh()
        chips, _version, detail = self.card_text("kev")
        self.assertEqual(chips, ["⚠ Stale"])
        self.assertIn("Older than the 7-day limit", detail)
        self.ctx.settings = Settings(stale_days=90)
        view.refresh()
        self.assertEqual(self.card_text("kev")[0], ["✓ Fresh"])

    def test_damaged_stored_data_is_reported_as_a_problem(self):
        self.build()
        with self.fake_network(kev_bytes(), epss_bytes()):
            self.view.update()
            self.wait_idle()
        (self.ctx.data_dir / td.KEV_FILE).write_bytes(b"corrupt")
        self.view.refresh()
        chips, _version, detail = self.card_text("kev")
        self.assertEqual(chips, ["! Problem"])
        self.assertIn("could not be used", detail)

    def test_import_uses_the_chosen_files_and_skipping_both_does_nothing(self):
        view = self.build()
        (self.work / "kev.json").write_bytes(kev_bytes())
        (self.work / "epss.csv.gz").write_bytes(epss_bytes())
        self.ctx.open_file = mock.Mock(side_effect=["", ""])
        view.import_files()
        self.pump(0.2)
        self.assertEqual(self.ctx.updater.results, [])
        self.ctx.open_file = mock.Mock(side_effect=[str(self.work / "kev.json"), str(self.work / "epss.csv.gz")])
        view.import_files()
        self.wait_idle()
        self.assertEqual([r.ok for r in self.ctx.updater.results], [True, True])
        self.assertEqual(self.card_text("epss")[0], ["✓ Fresh"])

    def test_importing_only_one_file_and_a_bad_file(self):
        view = self.build()
        (self.work / "bad.json").write_bytes(b"nope")
        self.ctx.open_file = mock.Mock(side_effect=[str(self.work / "bad.json"), ""])
        view.import_files()
        self.wait_idle()
        self.assertEqual(len(self.ctx.updater.results), 1)
        self.assertFalse(self.ctx.updater.results[0].ok)
        self.assertEqual(self.card_text("kev")[0], ["⚠ Not loaded"])

    def test_an_update_clears_cached_data_so_lookups_see_the_new_files(self):
        self.build()
        self.ctx.threat_data = td.ThreatData()
        with self.fake_network(kev_bytes(), epss_bytes()):
            self.view.update()
            self.wait_idle()
        self.assertIsNone(self.ctx.threat_data)

    def test_results_survive_a_rebuild_and_the_old_view_stops_listening(self):
        view = self.build()
        with self.fake_network(kev_bytes(), epss_bytes()):
            view.update()
            self.wait_idle()
        view.frame.destroy()
        self.assertIsNone(self.ctx.updater.on_change)
        rebuilt = self.build()
        self.assertEqual(len(self.results_text()), 2)
        self.assertEqual(self.ctx.updater.on_change, rebuilt.refresh)

    def test_a_job_finishing_after_the_view_is_gone_does_not_crash(self):
        view = self.build()
        release = threading.Event()
        with self.fake_network(kev_bytes(), epss_bytes(), block=release):
            view.update()
            self.pump(0.2)
            view.frame.destroy()
            release.set()
            self.pump(10, until=lambda: not self.ctx.worker.running and bool(self.ctx.updater.results))
        self.assertEqual([r.ok for r in self.ctx.updater.results], [True, True])

    def test_updater_is_usable_without_any_view(self):
        updater = gui_threat.ThreatUpdater(self.ctx)
        with self.fake_network(kev_bytes(), epss_bytes()):
            self.assertTrue(updater.update(ask=False))
            self.pump(10, until=lambda: bool(updater.results))
        self.assertTrue(all(r.ok for r in updater.results))
        self.assertFalse(self.ctx.confirm.called)


if __name__ == "__main__":
    unittest.main()
