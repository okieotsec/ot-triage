import contextlib
import csv
import io
import subprocess  # nosec B404 - runs this project's own script with fixed arguments
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import icsadvisories
import ot_triage_cli as cli
import settings as scoring
import threatdata as td
from test_icsadvisories import advisory, good
from test_threatdata import epss_bytes, kev_bytes
from version import __version__

HERE = Path(__file__).parent
FINDINGS = ("id,asset_id,name,cvss,threat\n"
            "F1,PLC-01,Flaw one,9.0,active\nF2,PLC-01,Flaw two,7.5,public\nF3,GW-01,Gateway flaw,3.0,none\n"
            "F4,GW-01,Another,3.5,none\n")
INVENTORY = ("asset_id,name,criticality,exposure,controls\n"
             "GW-01,Edge gateway,crown jewel,high,none\nPLC-01,Packaging PLC,standard,low,partial\n")


class CliCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        guard = mock.patch("threatdata.fetch", side_effect=AssertionError("the command line must not use the network"))
        guard.start()
        self.addCleanup(guard.stop)

    def write(self, name, text):
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def run_cli(self, *argv, settings=None):
        out, err = io.StringIO(), io.StringIO()
        extra = ["--settings", settings or str(self.dir / "no-settings.json"), "--data-dir", str(self.dir / "data")]
        code = cli.main(list(argv) + extra, out, err)
        return code, out.getvalue(), err.getvalue()

    def csv_rows(self, path):
        with open(path, newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))


class RankingTests(CliCase):
    def test_it_ranks_a_file_and_prints_the_counts_and_the_top_findings(self):
        code, out, err = self.run_cli(self.write("f.csv", FINDINGS), "--inventory", self.write("i.csv", INVENTORY))
        self.assertEqual((code, err), (0, ""))
        self.assertIn(f"OT Triage {__version__} · f.csv · 4 rows", out)
        self.assertIn("NOW 0 · NEXT 2 · NEVER 2 · not scored 0", out)
        self.assertIn("Scoring settings: defaults", out)
        self.assertIn("Inventory: i.csv · 2 assets", out)
        self.assertIn("Top findings:", out)
        self.assertIn("F1 · Flaw one  [PLC-01]", out)

    def test_the_ranked_csv_is_the_same_as_the_applications_export(self):
        findings = self.write("f.csv", FINDINGS)
        inv = self.write("i.csv", INVENTORY)
        target = str(self.dir / "ranked.csv")
        code, out, _err = self.run_cli(findings, "-i", inv, "-o", target)
        self.assertEqual(code, 0)
        self.assertIn(f"Wrote {target}", out)
        rows = self.csv_rows(target)
        self.assertEqual([r["id"] for r in rows], ["F1", "F2", "F4", "F3"])
        self.assertEqual(rows[0]["priority"], "NEXT")
        self.assertEqual((rows[0]["change"], rows[0]["previous_priority"]), ("", ""))

    def test_the_asset_roll_up_is_written(self):
        target = str(self.dir / "assets.csv")
        code, out, _err = self.run_cli(self.write("f.csv", FINDINGS), "-i", self.write("i.csv", INVENTORY), "-a",
                                       target)
        self.assertEqual(code, 0)
        rows = {r["asset_id"]: r for r in self.csv_rows(target)}
        self.assertEqual((rows["PLC-01"]["worst_priority"], rows["PLC-01"]["findings"]), ("NEXT", "2"))
        self.assertIn("(2 assets)", out)

    def test_the_asset_roll_up_names_the_advisories_that_may_apply_from_the_inventory_vendor_and_product(self):
        data = self.dir / "data"
        data.mkdir()
        archive = self.dir / "csaf.tar.gz"
        archive.write_bytes(good(advisory("ICSA-26-001-01", "Siemens SIMATIC S7-1500", ("CVE-2026-0001",), "Siemens",
                                          products=["SIMATIC S7-1500 CPU"])))
        self.assertTrue(icsadvisories.import_from_file(archive, data).ok)
        inv = self.write("i.csv", "asset_id,criticality,exposure,controls,vendor,product\n"
                                  "PLC-01,standard,low,none,Siemens AG,S7-1500\nGW-01,standard,low,none,,\n")
        target = str(self.dir / "assets.csv")
        code, _out, err = self.run_cli(self.write("f.csv", FINDINGS), "-i", inv, "-a", target)
        self.assertEqual((code, err), (0, ""))
        rows = {r["asset_id"]: r for r in self.csv_rows(target)}
        self.assertEqual((rows["PLC-01"]["vendor"], rows["PLC-01"]["possible_advisories"],
                          rows["PLC-01"]["newest_possible_advisory"]), ("Siemens AG", "1", "ICSA-26-001-01"))
        self.assertEqual(rows["GW-01"]["possible_advisories"], "")

    def test_quiet_prints_nothing_but_still_writes_files(self):
        target = str(self.dir / "ranked.csv")
        code, out, err = self.run_cli(self.write("f.csv", FINDINGS), "-i", self.write("i.csv", INVENTORY), "-o", target,
                                      "-q")
        self.assertEqual((code, out, err), (0, "", ""))
        self.assertEqual(len(self.csv_rows(target)), 4)

    def test_top_limits_the_listing(self):
        findings, inv = self.write("f.csv", FINDINGS), self.write("i.csv", INVENTORY)
        _code, out, _err = self.run_cli(findings, "-i", inv, "--top", "1")
        self.assertEqual(out.count(". NEXT") + out.count(". NEVER"), 1)
        _code, out, _err = self.run_cli(findings, "-i", inv, "--top", "0")
        self.assertNotIn("Top findings:", out)

    def test_the_scoring_settings_file_is_used(self):
        settings = str(self.dir / "s.json")
        scoring.save(scoring.Settings(cvss_high=7.5), settings)
        _code, out, _err = self.run_cli(self.write("f.csv", FINDINGS), "-i", self.write("i.csv", INVENTORY),
                                        settings=settings)
        self.assertIn("cvss_high=7.5", out)
        self.assertNotIn("Scoring settings: defaults", out)

    def test_a_bad_settings_file_gives_a_warning_and_defaults(self):
        code, out, err = self.run_cli(self.write("f.csv", FINDINGS), "-i", self.write("i.csv", INVENTORY),
                                      settings=self.write("s.json", "{not json"))
        self.assertEqual(code, 0)
        self.assertIn("warning: Scoring settings", err)
        self.assertIn("Scoring settings: defaults", out)


class ExitCodeTests(CliCase):
    def test_fail_on_now_and_next(self):
        findings = self.write("f.csv", "id,cvss,threat,asset,exposure\nA,9.0,active,standard,high\n")
        self.assertEqual(self.run_cli(findings, "--fail-on", "NOW")[0], 3)
        self.assertEqual(self.run_cli(findings, "--fail-on", "NEXT")[0], 3)
        quiet = self.write("q.csv", "id,cvss,threat,asset,exposure\nA,3.0,none,standard,high\n")
        self.assertEqual(self.run_cli(quiet, "--fail-on", "NOW")[0], 0)
        self.assertEqual(self.run_cli(quiet, "--fail-on", "NEXT")[0], 0)
        next_only = self.write("n.csv", "id,cvss,threat,asset,exposure\nA,7.5,public,standard,medium\n")
        self.assertEqual(self.run_cli(next_only, "--fail-on", "NOW")[0], 0)
        self.assertEqual(self.run_cli(next_only, "--fail-on", "NEXT")[0], 3)

    def test_missing_unreadable_and_empty_files_are_an_error_message_and_exit_one(self):
        cases = {"missing": str(self.dir / "nope.csv"), "a folder": str(self.dir),
                 "no header": self.write("e.csv", ""), "no rows": self.write("h.csv", "cvss,asset,exposure,threat\n"),
                 "binary": self.write("b.csv", "\x00\x01\x02" * 50)}
        for label, path in cases.items():
            with self.subTest(label):
                code, out, err = self.run_cli(path)
                self.assertEqual(code, 1)
                self.assertTrue(err.startswith("error: "), err)
                self.assertNotIn("Traceback", err + out)

    def test_nothing_to_do_and_wrong_arguments(self):
        self.assertEqual(self.run_cli()[0], 1)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            cli.main(["--nope"], io.StringIO(), io.StringIO())
        self.assertEqual(raised.exception.code, 2)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["f.csv", "--fail-on", "NEVER"], io.StringIO(), io.StringIO())

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as raised:
            cli.main(["--version"])
        self.assertEqual((raised.exception.code, out.getvalue().strip()), (0, f"OT Triage {__version__}"))

    def test_a_bad_inventory_or_previous_export_is_an_error(self):
        findings = self.write("f.csv", FINDINGS)
        self.assertEqual(self.run_cli(findings, "-i", self.write("i.csv", "nothing useful\n"))[0], 1)
        inv = self.write("i2.csv", INVENTORY)
        self.assertEqual(self.run_cli(findings, "-i", inv, "-c", self.write("p.csv", "a,b\n"))[0], 1)


class OutputSafetyTests(CliCase):
    def test_an_existing_output_is_not_replaced_without_force(self):
        findings = self.write("f.csv", FINDINGS)
        inv = self.write("i.csv", INVENTORY)
        existing = self.write("out.csv", "precious")
        code, _out, err = self.run_cli(findings, "-i", inv, "-o", existing)
        self.assertEqual(code, 1)
        self.assertIn("already exists (use --force", err)
        self.assertEqual(Path(existing).read_text(), "precious")
        self.assertEqual(self.run_cli(findings, "-i", inv, "-o", existing, "--force")[0], 0)
        self.assertIn("rank", Path(existing).read_text(encoding="utf-8-sig"))

    def test_an_input_file_is_never_overwritten_even_with_force(self):
        findings = self.write("f.csv", FINDINGS)
        inv = self.write("i.csv", INVENTORY)
        for flag, target in (("-o", findings), ("-o", inv), ("-a", findings)):
            with self.subTest(flag=flag, target=Path(target).name):
                code, _out, err = self.run_cli(findings, "-i", inv, flag, target, "--force")
                self.assertEqual(code, 1)
                self.assertIn("also an input file", err)
        self.assertEqual(Path(findings).read_text(), FINDINGS)

    def test_the_two_outputs_cannot_be_the_same_file(self):
        target = str(self.dir / "same.csv")
        self.write("same.csv", "x")
        findings, inv = self.write("f.csv", FINDINGS), self.write("i.csv", INVENTORY)
        code, _out, err = self.run_cli(findings, "-i", inv, "-o", target, "-a", target, "--force")
        self.assertEqual(code, 1)
        self.assertIn("also an input file", err)

    def test_a_failed_write_leaves_no_partial_file(self):
        target = self.dir / "ranked.csv"
        with mock.patch("batch.write_results", side_effect=OSError(28, "No space left on device")):
            code, _out, err = self.run_cli(self.write("f.csv", FINDINGS), "-i", self.write("i.csv", INVENTORY),
                                           "-o", str(target))
        self.assertEqual(code, 1)
        self.assertIn("No space left", err)
        self.assertFalse(target.exists())
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.startswith(".ot-triage-")], [])

    def test_a_write_that_fails_half_way_does_not_leave_a_broken_file_or_damage_an_old_one(self):
        def half_written(path, *_args, **_kwargs):
            Path(path).write_text("rank,id\n1,half")
            raise OSError(5, "Input/output error")

        findings, inv = self.write("f.csv", FINDINGS), self.write("i.csv", INVENTORY)
        target = self.dir / "ranked.csv"
        with mock.patch("batch.write_results", half_written):
            self.assertEqual(self.run_cli(findings, "-i", inv, "-o", str(target))[0], 1)
        self.assertFalse(target.exists())
        target.write_text("old, complete file")
        with mock.patch("batch.write_results", half_written):
            self.assertEqual(self.run_cli(findings, "-i", inv, "-o", str(target), "--force")[0], 1)
        self.assertEqual(target.read_text(), "old, complete file")

    def test_text_from_the_file_cannot_send_terminal_commands(self):
        evil = "id,name,cvss,threat,asset,exposure\nA,\x1b[31mRED\x1b]0;title\x07 \u202eevil,9.0,active,standard,high\n"
        _code, out, err = self.run_cli(self.write("f.csv", evil))
        self.assertNotIn("\x1b", out + err)
        self.assertNotIn("\x07", out + err)
        self.assertNotIn("\u202e", out + err)
        self.assertIn("RED", out)

    def test_long_text_is_cut_when_printed(self):
        long_name = "id,name,cvss,threat,asset,exposure\nA," + "x" * 500 + ",9.0,active,standard,high\n"
        _code, out, _err = self.run_cli(self.write("f.csv", long_name))
        self.assertLess(max(len(line) for line in out.splitlines()), 200)


class CompareAndDataTests(CliCase):
    def test_it_compares_with_a_previous_export_and_lists_what_was_resolved(self):
        findings = self.write("f.csv", FINDINGS)
        inv = self.write("i.csv", INVENTORY)
        previous = self.write("p.csv", "rank,id,cve,name,priority,ordering_score,asset_id\n"
                                       "1,F1,,Flaw one,NEVER,1.00,PLC-01\n2,GONE,,Old,NOW,9.00,X\n")
        target = str(self.dir / "ranked.csv")
        code, out, _err = self.run_cli(findings, "-i", inv, "-c", previous, "-o", target)
        self.assertEqual(code, 0)
        self.assertIn("Compared with p.csv: 3 new, 1 moved up, 0 moved down, 1 resolved", out)
        self.assertIn("resolved: GONE · Old (was NOW)", out)
        rows = {r["id"]: r for r in self.csv_rows(target)}
        self.assertEqual((rows["F1"]["change"], rows["F1"]["previous_priority"]), ("up", "NEVER"))

    def test_threat_data_is_read_from_the_data_folder_when_the_file_has_a_cve_column(self):
        data = self.dir / "data"
        data.mkdir()
        (self.dir / "k.json").write_bytes(kev_bytes())
        (self.dir / "e.gz").write_bytes(epss_bytes())
        self.assertTrue(all(r.ok for r in td.import_from_files(self.dir / "k.json", self.dir / "e.gz", data)))
        findings = self.write("c.csv", "id,cve,cvss,asset,exposure\nA,CVE-2024-0001,8.0,standard,high\n")
        code, out, _err = self.run_cli(findings, "--fail-on", "NOW")
        self.assertEqual(code, 3)
        self.assertIn("Threat data: KEV 2026.10.04", out)

    def test_without_threat_data_a_cve_row_is_not_scored_as_safe(self):
        findings = self.write("c.csv", "id,cve,cvss,asset,exposure\nA,CVE-2024-0001,8.0,standard,high\n")
        code, out, _err = self.run_cli(findings, "--fail-on", "NOW")
        self.assertEqual(code, 0)
        self.assertIn("not scored 1", out)

    def test_nothing_uses_the_network_unless_update_is_given(self):
        # the guard in setUp makes any download fail the test
        self.assertEqual(self.run_cli(self.write("f.csv", FINDINGS), "-i", self.write("i.csv", INVENTORY))[0], 0)


class UpdateTests(CliCase):
    def fetcher(self, ics_ok=True):
        def fetch(url, max_bytes, hosts, **_kwargs):
            if url == td.KEV_URL:
                return kev_bytes()
            if url == td.EPSS_URL:
                return epss_bytes()
            if ics_ok:
                return good(advisory())
            raise td.FetchError("the connection timed out")
        return fetch

    def test_update_alone_downloads_all_three_and_exits_zero(self):
        with mock.patch("threatdata.fetch", self.fetcher()):
            code, out, err = self.run_cli("--update")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("ok: KEV updated.", out)
        self.assertIn("ok: EPSS updated.", out)
        self.assertIn("ok: ICS advisories updated", out)
        self.assertTrue((self.dir / "data" / "kev.json").exists())

    def test_a_failed_update_alone_is_exit_one_and_keeps_the_old_data(self):
        with mock.patch("threatdata.fetch", self.fetcher(ics_ok=False)):
            code, _out, err = self.run_cli("--update")
        self.assertEqual(code, 1)
        self.assertIn("FAILED: ICS advisories not updated", err)

    def test_update_then_rank_uses_the_new_data_and_a_failure_only_warns(self):
        findings = self.write("c.csv", "id,cve,cvss,asset,exposure\nA,CVE-2024-0001,8.0,standard,high\n")
        with mock.patch("threatdata.fetch", self.fetcher(ics_ok=False)):
            code, out, err = self.run_cli(findings, "--update")
        self.assertEqual(code, 0)
        self.assertIn("warning: some threat data could not be updated", err)
        self.assertIn("NOW 1", out)


class ScriptTests(CliCase):
    def run_script(self, *argv):
        return subprocess.run([sys.executable, str(HERE / "ot_triage_cli.py"), *argv],  # noqa: S603  # nosec B603
                              capture_output=True, text=True, timeout=60, check=False, cwd=self.dir)

    def test_the_script_runs_on_its_own_and_exits_with_the_right_code(self):
        findings = self.write("f.csv", "id,cvss,threat,asset,exposure\nA,9.0,active,standard,high\n")
        done = self.run_script(findings, "--settings", str(self.dir / "none.json"), "--fail-on", "NOW")
        self.assertEqual(done.returncode, 3, done.stderr)
        self.assertIn("NOW 1", done.stdout)
        self.assertEqual(self.run_script("--version").stdout.strip(), f"OT Triage {__version__}")
        self.assertEqual(self.run_script(str(self.dir / "missing.csv")).returncode, 1)
        self.assertEqual(self.run_script("--bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
