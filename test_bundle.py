import hashlib
import py_compile
import subprocess  # nosec B404 - runs this project's own scripts with fixed arguments
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tools import make_bundle
from version import __version__

HERE = Path(__file__).parent
TOP = f"ot-triage-{__version__}"


class BundleCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            make_bundle.tracked_files()
        except (SystemExit, subprocess.CalledProcessError, OSError):
            # The bundle is built from the files git tracks: a source zip without git (or without the repository)
            # cannot build one, and that must skip these tests, not end the whole run (SystemExit would)
            raise unittest.SkipTest("git is not available here, or this is not a git checkout") from None
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "dist"
        cls.zip, cls.digest = make_bundle.build(cls.out)
        with zipfile.ZipFile(cls.zip) as archive:
            cls.names = archive.namelist()
            archive.extractall(cls.tmp.name)
        cls.root = Path(cls.tmp.name) / TOP

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_python(self, *args):
        return subprocess.run([sys.executable, *args], cwd=self.root, capture_output=True, text=True,  # noqa: S603
                              timeout=120, check=False)


class ContentTests(BundleCase):
    def test_everything_is_under_one_folder_named_for_the_version_with_safe_paths(self):
        self.assertTrue(all(n.startswith(f"{TOP}/") for n in self.names))
        for name in self.names:
            self.assertFalse(name.startswith("/") or ".." in Path(name).parts or "\\" in name, name)

    def test_it_has_what_a_person_needs(self):
        for needed in ("ot_triage_gui.py", "ot_triage_cli.py", "ot_triage_import.py", "scanimport.py",
                       "OT Triage.pyw", "README.md", "LICENSE", "CHANGELOG.md",
                       "SECURITY.md", "THIRD_PARTY_NOTICES.md", "START-HERE.txt", "sbom/sbom.cdx.json",
                       "docs/CLI.md", "docs/POLICY.md", "sample_inventory.csv", "sample_scan_nessus.csv",
                       "sample_scan.nessus", "sample_scan_nozomi.json", "sample_scan_dragos.json",
                       "sample_findings_multiple_per_asset.csv", "requirements.txt"):
            self.assertIn(f"{TOP}/{needed}", self.names, needed)

    def test_it_has_no_tests_tools_reports_or_repository_files(self):
        for name in self.names:
            relative = name.removeprefix(f"{TOP}/")
            self.assertFalse(relative.startswith(("test_", "tools/", "reports/", ".github/", ".git", "malicious_cases",
                                                  "gui_testing")), relative)
            self.assertNotIn("__pycache__", relative)

    def test_every_module_the_application_imports_is_in_it(self):
        for module in make_bundle.runtime_modules():
            self.assertIn(f"{TOP}/{module}.py", self.names, module)
        self.assertNotIn("gui_testing", make_bundle.runtime_modules())

    def test_the_start_here_text_names_the_version_and_the_launcher(self):
        text = (self.root / "START-HERE.txt").read_text(encoding="utf-8")
        self.assertIn(__version__, text)
        self.assertIn("OT Triage.pyw", text)


class ReproducibleTests(BundleCase):
    def test_building_twice_gives_the_same_bytes_and_a_matching_checksum_file(self):
        with tempfile.TemporaryDirectory() as folder:
            again, digest = make_bundle.build(folder)
            self.assertEqual(digest, self.digest)
            self.assertEqual(again.read_bytes(), self.zip.read_bytes())
        line = (self.out / f"{TOP}.zip.sha256").read_text(encoding="utf-8")
        self.assertEqual(line, f"{hashlib.sha256(self.zip.read_bytes()).hexdigest()}  {TOP}.zip\n")

    def test_the_files_are_stored_in_sorted_order(self):
        self.assertEqual(self.names, sorted(self.names))

    def test_a_file_that_git_does_not_track_stops_the_build_instead_of_slipping_in(self):
        tracked = [name for name in make_bundle.tracked_files() if name != "ot_triage_cli.py"]
        patched = mock.patch.object(make_bundle, "tracked_files", return_value=tracked)
        with patched, tempfile.TemporaryDirectory() as out, self.assertRaisesRegex(SystemExit, "ot_triage_cli.py"):
            make_bundle.build(out)

    def test_dates_and_modes_are_fixed(self):
        with zipfile.ZipFile(self.zip) as archive:
            for info in archive.infolist():
                self.assertEqual(info.date_time, make_bundle.FIXED_TIME, info.filename)
                self.assertEqual((info.external_attr >> 16) & 0o022, 0, info.filename)


class RunsOnItsOwnTests(BundleCase):
    def test_the_command_line_runs_from_the_extracted_bundle(self):
        done = self.run_python("ot_triage_cli.py", "--version")
        self.assertEqual((done.returncode, done.stdout.strip()), (0, f"OT Triage {__version__}"))

    def test_it_ranks_a_sample_from_the_extracted_bundle(self):
        done = self.run_python("ot_triage_cli.py", "sample_findings_multiple_per_asset.csv", "--inventory",
                               "sample_inventory.csv", "--settings", str(self.root / "none.json"), "--data-dir",
                               str(self.root / "data"))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("NOW", done.stdout)

    def test_the_scanner_import_runs_from_the_extracted_bundle(self):
        out = self.root / "imported.csv"
        done = self.run_python("ot_triage_import.py", "sample_scan_nessus.csv", "sample_scan_openvas.csv",
                               "sample_scan.nessus", "sample_scan_nozomi.json", "sample_scan_dragos.json",
                               "-o", str(out),
                               "--inventory-out", str(self.root / "inventory.new.csv"))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("Nessus CSV", done.stdout)
        self.assertIn("Nessus .nessus (v2 XML)", done.stdout)
        self.assertIn("Nozomi node_cves (experimental)", done.stdout)
        self.assertIn("Dragos detections (experimental)", done.stdout)
        self.assertTrue(out.read_text(encoding="utf-8").startswith("id,asset_id,name,cve,cvss,patch,source_tool"))

    def test_every_module_imports_from_the_extracted_bundle_alone(self):
        modules = [p.stem for p in self.root.glob("*.py")]
        code = "import sys; sys.path.insert(0, '.'); [__import__(m) for m in sys.argv[1:]]"
        done = self.run_python("-I", "-c", code, *modules)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_the_launcher_compiles_and_refuses_an_old_python_with_a_message(self):
        py_compile.compile(str(self.root / "OT Triage.pyw"), cfile=str(self.root / "launcher.pyc"), doraise=True)
        code = ("import runpy, sys, io; sys.version_info = (3, 8, 0); err = io.StringIO(); sys.stderr = err; "
                "sys.modules['tkinter'] = None; "
                "ns = runpy.run_path('OT Triage.pyw', run_name='launcher'); "
                "code = ns['main'](); sys.stderr = sys.__stderr__; print(code, err.getvalue().strip())")
        done = self.run_python("-c", code)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("1 OT Triage needs Python 3.12 or newer; this is 3.8.", done.stdout)


if __name__ == "__main__":
    unittest.main()
