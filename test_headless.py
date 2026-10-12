import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
UNREACHABLE = ":65534"   # a display number nothing listens on, so a mistake here could never show a window


def load_runner():
    path = ROOT / "tools" / "headless_tests.py"
    spec = importlib.util.spec_from_file_location("headless_tests_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GuardTests(unittest.TestCase):
    """With the guard on, importing the test helpers must leave no way to reach a real display."""

    def run_probe(self, extra_env):
        env = {**{k: v for k, v in os.environ.items() if not k.startswith("OT_TRIAGE_")}, "DISPLAY": UNREACHABLE,
               "WAYLAND_DISPLAY": "wayland-unreachable", **extra_env}
        code = ("import os, gui_testing; print(os.environ.get('DISPLAY'), os.environ.get('WAYLAND_DISPLAY'))")
        done = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True,  # noqa: S603
                              timeout=60, check=False)
        return done.stdout.strip(), done.stderr

    def test_the_guard_removes_both_display_variables_and_explains(self):
        out, err = self.run_probe({"OT_TRIAGE_REQUIRE_PRIVATE_DISPLAY": "1"})
        self.assertEqual(out, "None None")
        self.assertIn("tools/headless_tests.py", err)

    def test_a_private_display_is_left_alone(self):
        out, err = self.run_probe({"OT_TRIAGE_REQUIRE_PRIVATE_DISPLAY": "1", "OT_TRIAGE_PRIVATE_DISPLAY": "1"})
        self.assertEqual(out, f"{UNREACHABLE} wayland-unreachable")
        self.assertNotIn("skipped", err)

    def test_without_the_guard_nothing_changes(self):
        out, _err = self.run_probe({})
        self.assertEqual(out, f"{UNREACHABLE} wayland-unreachable")

    @unittest.skipUnless(sys.platform.startswith("linux"), "only Linux chooses its display from environment variables")
    def test_with_the_guard_a_window_cannot_even_be_attempted(self):
        env = {**{k: v for k, v in os.environ.items() if not k.startswith("OT_TRIAGE_")},
               "OT_TRIAGE_REQUIRE_PRIVATE_DISPLAY": "1", "DISPLAY": UNREACHABLE}
        code = ("import gui_testing, tkinter\ntry:\n    tkinter.Tk()\nexcept tkinter.TclError as e:\n"
                "    print('blocked', e)")
        done = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True, text=True,  # noqa: S603
                              timeout=60, check=False)
        self.assertIn("blocked", done.stdout)


class RunnerPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = load_runner()

    def test_on_linux_with_xvfb_the_tests_run_on_a_private_display(self):
        command, env, message = self.runner.plan("linux", "/usr/bin/xvfb-run", {"DISPLAY": ":0"}, ["900"])
        self.assertEqual(command[:4], ["/usr/bin/xvfb-run", "-a", "-s", self.runner.SCREEN])
        self.assertEqual(command[-1], "900")
        self.assertEqual(env["OT_TRIAGE_PRIVATE_DISPLAY"], "1")
        self.assertIsNone(message)

    def test_on_linux_without_xvfb_the_real_display_is_hidden_and_the_install_hint_is_shown(self):
        command, env, message = self.runner.plan("linux", None, {"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-1",
                                                                 "HOME": "/x"}, [])
        self.assertNotIn("DISPLAY", env)
        self.assertNotIn("WAYLAND_DISPLAY", env)
        self.assertEqual(env["HOME"], "/x")
        self.assertNotIn("OT_TRIAGE_PRIVATE_DISPLAY", env)
        self.assertIn("xorg-server-xvfb", message)
        self.assertTrue(command[-1].endswith("ci_run_tests.py"))

    def test_only_a_plain_number_of_seconds_is_accepted_as_the_stall_limit(self):
        self.assertEqual(self.runner.stall_limit([]), [])
        self.assertEqual(self.runner.stall_limit(["0900"]), ["900"])
        for bad in (["abc"], ["-5"], ["0"], ["99999999"], ["1", "2"], ["; rm -rf /"], ["1e3"], [" 5"], ["\u0663"]):
            with self.subTest(args=bad), self.assertRaises(SystemExit):
                self.runner.stall_limit(bad)

    def test_on_other_systems_the_suite_just_runs(self):
        command, env, message = self.runner.plan("win32", None, {"A": "1"}, [])
        self.assertEqual((env, message), ({"A": "1"}, None))
        self.assertTrue(command[-1].endswith("ci_run_tests.py"))


if __name__ == "__main__":
    unittest.main()
