import contextlib
import csv
import hashlib
import io
import subprocess  # nosec B404 - runs this project's own script with fixed arguments
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import ot_triage_import as cli
from version import __version__

HERE = Path(__file__).parent
NESSUS = HERE / "sample_scan_nessus.csv"
OPENVAS = HERE / "sample_scan_openvas.csv"


class ImportCliCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        guard = mock.patch("threatdata.fetch", side_effect=AssertionError("the importer must not use the network"))
        guard.start()
        self.addCleanup(guard.stop)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        return cli.main(list(argv), out, err), out.getvalue(), err.getvalue()

    def rows(self, path):
        with open(path, newline="", encoding="utf-8-sig") as fh:
            return list(csv.DictReader(fh))

    def digest(self, path):
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class RunTests(ImportCliCase):
    def test_it_imports_and_says_what_it_did(self):
        out = self.dir / "f.csv"
        code, text, err = self.run_cli(str(NESSUS), str(OPENVAS), "-o", str(out))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("sample_scan_nessus.csv: Nessus CSV, 8 rows, 6 findings kept", text)
        self.assertIn("  skipped 2: informational (no risk)", text)
        self.assertIn(f"Wrote {out}", text)
        self.assertIn("assets were seen; add --inventory-out", text)
        self.assertEqual(len(self.rows(out)), 10)

    def test_it_writes_an_inventory_for_the_new_assets(self):
        code, text, _err = self.run_cli(
            str(NESSUS), "-o", str(self.dir / "f.csv"), "--inventory-out", str(self.dir / "i.csv")
        )
        self.assertEqual(code, 0)
        self.assertIn("4 new assets: fill in their criticality, exposure and controls", text)
        self.assertEqual(
            sorted(r["asset_id"] for r in self.rows(self.dir / "i.csv")),
            ["192.0.2.21", "192.0.2.22", "192.0.2.5", "198.51.100.4"],
        )

    def test_aliases_the_default_threat_and_the_quality_threshold_are_used(self):
        aliases = self.dir / "a.csv"
        aliases.write_text("alias,asset_id\n192.0.2.21,CC-HIST-01\n", encoding="utf-8")
        out = self.dir / "f.csv"
        code, text, _e = self.run_cli(
            str(NESSUS),
            str(OPENVAS),
            "-o",
            str(out),
            "--aliases",
            str(aliases),
            "--default-threat",
            "none",
            "--min-qod",
            "90",
        )
        self.assertEqual(code, 0)
        rows = self.rows(out)
        self.assertIn("CC-HIST-01", {r["asset_id"] for r in rows})
        self.assertEqual({r["threat"] for r in rows if not r["cve"]}, {"none"})
        self.assertEqual({r["threat"] for r in rows if r["cve"]}, {""})
        self.assertIn("skipped 2: quality of detection below 90", text)
        self.assertIn("moved to their asset id through the aliases file", text)

    def test_quiet_prints_nothing_on_success(self):
        code, text, err = self.run_cli(str(NESSUS), "-o", str(self.dir / "f.csv"), "-q")
        self.assertEqual((code, text, err), (0, "", ""))

    def test_the_version_is_shown(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as stop:
            cli.main(["--version"])
        self.assertEqual((stop.exception.code, out.getvalue().strip()), (0, f"OT Triage {__version__}"))


class NessusXmlCliTests(ImportCliCase):
    def test_a_nessus_file_is_imported_with_the_csv_exports_and_merged(self):
        out = self.dir / "f.csv"
        code, text, err = self.run_cli(str(NESSUS), str(HERE / "sample_scan.nessus"), "-o", str(out))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("sample_scan.nessus: Nessus .nessus (v2 XML), 4 rows, 4 findings kept", text)
        self.assertIn("  skipped 1: informational (no risk)", text)
        self.assertEqual(len(self.rows(out)), 10)

    def test_a_nessus_file_with_a_doctype_is_refused_with_no_output(self):
        bad = self.dir / "bad.nessus"
        bad.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><NessusClientData_v2/>', encoding="utf-8")
        out = self.dir / "f.csv"
        code, _t, err = self.run_cli(str(bad), "-o", str(out))
        self.assertEqual(code, 1)
        self.assertIn("declares a DTD or an entity", err)
        self.assertFalse(out.exists())


class SafetyTests(ImportCliCase):
    def test_an_existing_output_is_not_replaced_without_force(self):
        out = self.dir / "f.csv"
        out.write_text("keep me", encoding="utf-8")
        code, _t, err = self.run_cli(str(NESSUS), "-o", str(out))
        self.assertEqual((code, out.read_text(encoding="utf-8")), (1, "keep me"))
        self.assertIn("already exists", err)
        self.assertEqual(self.run_cli(str(NESSUS), "-o", str(out), "--force")[0], 0)
        self.assertTrue(out.read_text(encoding="utf-8").startswith("id,asset_id"))

    def test_an_input_file_is_never_overwritten_even_with_force(self):
        before = self.digest(NESSUS)
        copy = self.dir / "scan.csv"
        copy.write_bytes(NESSUS.read_bytes())
        for flags in (["-o", str(copy)], ["-o", str(self.dir / "f.csv"), "--inventory-out", str(copy)]):
            with self.subTest(flags):
                code, _t, err = self.run_cli(str(copy), *flags, "--force")
                self.assertEqual(code, 1)
                self.assertIn("is also an input file", err)
        self.assertEqual(self.digest(copy), before)
        inventory = self.dir / "inv.csv"
        inventory.write_text("asset_id,name\nA,B\n", encoding="utf-8")
        self.assertEqual(
            self.run_cli(
                str(NESSUS),
                "-o",
                str(self.dir / "f.csv"),
                "-i",
                str(inventory),
                "--inventory-out",
                str(inventory),
                "--force",
            )[0],
            1,
        )
        self.assertEqual(inventory.read_text(encoding="utf-8"), "asset_id,name\nA,B\n")

    def test_the_findings_and_the_inventory_cannot_share_a_file_name(self):
        out = self.dir / "same.csv"
        code, _t, err = self.run_cli(str(NESSUS), "-o", str(out), "--inventory-out", str(out))
        self.assertEqual(code, 1)
        self.assertIn("need different file names", err)
        self.assertFalse(out.exists())

    def test_a_failed_import_leaves_no_output_behind(self):
        bad = self.dir / "bad.csv"
        bad.write_text("id,name\n1,2\n", encoding="utf-8")
        out = self.dir / "f.csv"
        code, _t, err = self.run_cli(str(NESSUS), str(bad), "-o", str(out))
        self.assertEqual(code, 1)
        self.assertIn("bad.csv is not an export this tool knows", err)
        self.assertEqual(list(self.dir.glob("f.csv*")) + list(self.dir.glob(".ot-triage-*")), [])

    def test_an_export_with_nothing_left_after_skipping_is_an_error_not_an_empty_file(self):
        only_info = self.dir / "info.csv"
        only_info.write_text("Plugin ID,CVE,CVSS,Risk,Host,Name\n1,,0,None,h,Scan info\n", encoding="utf-8")
        code, _t, err = self.run_cli(str(only_info), "-o", str(self.dir / "f.csv"))
        self.assertEqual(code, 1)
        self.assertIn("nothing to import", err)
        self.assertFalse((self.dir / "f.csv").exists())

    def test_wrong_arguments_exit_with_two_and_the_threshold_is_checked(self):
        for argv in ([], [str(NESSUS)], ["-o", "x.csv"], [str(NESSUS), "-o", "x", "--default-threat", "high"]):
            with self.subTest(argv), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stop:
                cli.main(argv)
            self.assertEqual(stop.exception.code, 2)
        code, _t, err = self.run_cli(str(NESSUS), "-o", str(self.dir / "f.csv"), "--min-qod", "101")
        self.assertEqual(code, 1)
        self.assertIn("between 0 and 100", err)

    @unittest.skipIf(sys.platform == "win32", "Windows file names cannot contain control characters")
    def test_printed_text_from_a_file_is_cleaned(self):
        evil = self.dir / "e\x1b[31mvil.csv"
        evil.write_text("Plugin ID,CVE,CVSS,Risk,Host,Name\n1,CVE-2020-0001,5,High,h,n\n", encoding="utf-8")
        code, text, _e = self.run_cli(str(evil), "-o", str(self.dir / "f.csv"))
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", text)

    def test_a_missing_input_is_reported_cleanly(self):
        code, _t, err = self.run_cli(str(self.dir / "nope.csv"), "-o", str(self.dir / "f.csv"))
        self.assertEqual(code, 1)
        self.assertIn("could not be read", err)


class ScriptTests(ImportCliCase):
    def test_it_runs_as_a_script_and_never_opens_a_window_or_the_network(self):
        command = [sys.executable, str(HERE / "ot_triage_import.py"), str(NESSUS), "-o", str(self.dir / "f.csv")]
        done = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=self.dir,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("6 findings kept", done.stdout)


if __name__ == "__main__":
    unittest.main()
