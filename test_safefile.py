"""Every file the application reads is opened once and checked as a regular file within its size limit (CP23-05)."""
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import batch
import compare
import inventory
import jsonfile
import safefile
import threatdata as td

CSV = "asset,threat,exposure,cvss\nPLC-1,none,low,5.0\n"
INVENTORY = "asset_id,criticality,exposure,controls\nA-1,standard,low,none\n"
PREVIOUS = "id,cve,name,priority\n1,CVE-2024-0001,x,NOW\n"


class Case(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def write(self, name, text):
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return path


class OpenRegularTests(Case):
    def test_a_regular_file_is_opened_and_read(self):
        path = self.write("a.txt", "hello")
        with safefile.open_regular(path) as fh:
            self.assertEqual(fh.read(), "hello")
        self.assertEqual(safefile.read_regular(path, 100), b"hello")

    def test_a_folder_a_pipe_and_a_device_are_refused_with_the_callers_error(self):
        class MyError(Exception):
            pass

        targets = [self.dir] if os.name != "nt" else []
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.dir / "pipe")
            targets.append(self.dir / "pipe")
        if os.path.exists("/dev/zero"):
            targets.append(Path("/dev/zero"))
        for target in targets:
            outcome = []

            def attempt(target=target, outcome=outcome):
                try:
                    safefile.open_regular(target, error=MyError)
                except MyError as error:
                    outcome.append(str(error))

            worker = threading.Thread(target=attempt, daemon=True)
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive(), f"opening {target} blocked")
            self.assertTrue(outcome and "not a regular file" in outcome[0], (target, outcome))

    def test_the_size_is_judged_on_the_open_file_not_on_the_name(self):
        path = self.write("big.txt", "x" * 50)
        with self.assertRaisesRegex(ValueError, "larger than"):
            safefile.open_regular(path, limit=10)
        small = self.write("small.txt", "x" * 5)
        with mock.patch("os.path.getsize", side_effect=AssertionError("the name must not be measured")), \
                mock.patch("os.stat", side_effect=AssertionError("the name must not be measured")):
            safefile.read_regular(small, 10)

    def test_a_file_that_grows_after_the_check_is_still_held_to_the_limit(self):
        path = self.write("grow.bin", "x" * 5)
        real = safefile.open_regular

        def grown(target, *args, **kwargs):
            handle = real(target, *args, **kwargs)
            with open(target, "ab") as extra:
                extra.write(b"x" * 100)
            return handle

        with mock.patch.object(safefile, "open_regular", grown), self.assertRaisesRegex(ValueError, "larger than"):
            safefile.read_regular(path, 10)

    def test_a_refused_file_is_closed_again(self):
        path = self.write("big.txt", "x" * 50)
        with mock.patch("os.close", wraps=os.close) as closer, self.assertRaises(ValueError):
            safefile.open_regular(path, limit=10)
        self.assertTrue(closer.called)


class EveryLoaderTests(Case):
    """Each loader must refuse a pipe without blocking and measure the open file, not the name."""

    def loaders(self):
        return [
            ("batch.read_rows", batch.read_rows, "a.csv", CSV, ValueError),
            ("batch.has_cve_column", batch.has_cve_column, "b.csv", CSV, ValueError),
            ("inventory.load", inventory.load, "c.csv", INVENTORY, ValueError),
            ("compare.load_previous", compare.load_previous, "d.csv", PREVIOUS, compare.CompareError),
            ("jsonfile.read_json", lambda p: jsonfile.read_json(p, 1000), "e.json", "{}", ValueError),
            ("threatdata._read_capped", lambda p: td._read_capped(Path(p), 1000), "f.bin", "x", td.ThreatDataError),
            ("threatdata._epss_header", lambda p: td._epss_header(Path(p)), "g.csv", "x", td.ThreatDataError),
        ]

    def test_a_pipe_is_refused_instead_of_blocking_for_ever(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("no named pipes on this system")
        for label, load, name, _text, error in self.loaders():
            pipe = self.dir / ("pipe-" + name)
            os.mkfifo(pipe)
            outcome = []

            def attempt(load=load, pipe=pipe, error=error, outcome=outcome):
                try:
                    load(pipe)
                except error as caught:
                    outcome.append(str(caught))
                except Exception as other:
                    outcome.append(f"wrong error {type(other).__name__}: {other}")

            worker = threading.Thread(target=attempt, daemon=True)
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive(), f"{label} blocked on a named pipe")
            self.assertTrue(outcome and "not a regular file" in outcome[0], (label, outcome))

    def test_the_name_is_never_measured(self):
        for label, load, name, text, _error in self.loaders()[:5]:
            path = self.write(name, text)
            with mock.patch("os.path.getsize", side_effect=AssertionError(f"{label} measured the name")):
                load(path)

    def test_oversized_files_are_refused_by_each_loader(self):
        cases = [
            ("batch.read_rows", lambda p: batch.read_rows(p), batch, "MAX_FILE_BYTES", "a.csv", CSV),
            ("inventory.load", lambda p: inventory.load(p), inventory, "MAX_FILE_BYTES", "c.csv", INVENTORY),
            ("compare.load_previous", lambda p: compare.load_previous(p), compare, "MAX_FILE_BYTES", "d.csv",
             PREVIOUS),
        ]
        for label, load, module, limit, name, text in cases:
            path = self.write(name, text)
            with mock.patch.object(module, limit, 5), self.assertRaisesRegex(Exception, "larger than", msg=label):
                load(path)
        path = self.write("big.json", "{" + " " * 2000 + "}")
        with self.assertRaisesRegex(ValueError, "larger than"):
            jsonfile.read_json(path, 1000)
        with self.assertRaisesRegex(td.ThreatDataError, "larger than"):
            td._read_capped(path, 1000)


if __name__ == "__main__":
    unittest.main()
