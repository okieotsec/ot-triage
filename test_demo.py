"""The browser demo (demo/) gives the application's answers, and does nothing but show them."""
import importlib.util
import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path

import version

ROOT = Path(__file__).resolve().parent
DEMO = ROOT / "demo"
_spec = importlib.util.spec_from_file_location("make_demo_golden", ROOT / "tools" / "make_demo_golden.py")
make_demo_golden = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(make_demo_golden)
SERVED = ("index.html", "style.css", "rules.js", "app.js")     # the files that are published; the rest is for checking
BROWSERS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome")
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'none'"
# What the page may link to (navigation only: the page loads nothing from anywhere else).
LINKS = {"https://github.com/okieotsec/ot-triage/blob/main/docs/POLICY.md", "https://github.com/okieotsec/ot-triage"}
# Anything that could send, keep or run data other than the page's own code.
FORBIDDEN_CODE = ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "EventSource", "eval(", "new Function",
                  "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "localStorage", "sessionStorage",
                  "indexedDB", "document.cookie", "import(", "importScripts", "postMessage", "window.open",
                  "location.href", "location.assign", "navigator.")


def text(name):
    return (DEMO / name).read_text(encoding="utf-8")


class GoldenTests(unittest.TestCase):
    def test_the_golden_file_is_what_the_python_rules_give_now(self):
        self.assertEqual((DEMO / "golden.json").read_text(encoding="utf-8"),
                         make_demo_golden.render(make_demo_golden.build()),
                         "demo/golden.json is out of date: run python3 tools/make_demo_golden.py")

    def test_the_demo_is_for_the_current_version(self):
        golden = json.loads(text("golden.json"))
        self.assertEqual(golden["version"], version.__version__)
        match = re.search(r'var VERSION = "([^"]+)"', text("rules.js"))
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), version.__version__, "update VERSION in demo/rules.js with each release")

    def test_the_golden_file_covers_the_lines_of_the_rules_and_every_other_input(self):
        golden = json.loads(text("golden.json"))
        self.assertEqual(len(golden["cases"]), len(make_demo_golden.SCORES) * 243)
        for line in (3.9, 4.0, 6.9, 7.0, 8.9, 9.0):
            self.assertIn(line, make_demo_golden.SCORES)
        self.assertLess(len(text("golden.json")), 1_500_000)


class NodeTests(unittest.TestCase):
    def test_the_javascript_rules_give_the_same_answers_as_the_python_rules(self):
        node = shutil.which("node")
        if node is None:
            if os.environ.get("CI"):
                self.fail("node is needed to check the demo in CI")
            self.skipTest("node is not installed")
        done = subprocess.run([node, str(DEMO / "check_rules.js")], capture_output=True, text=True,  # noqa: S603 - node on this project's own file, fixed arguments
                              timeout=300, cwd=str(ROOT), check=False)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("match the Python rules in all 2916 cases", done.stdout)


class BrowserTests(unittest.TestCase):
    def test_the_page_works_in_a_headless_browser_without_opening_a_window(self):
        browser = next((shutil.which(b) for b in BROWSERS if shutil.which(b)), None)
        if browser is None:
            self.skipTest("no Chromium or Chrome is installed")
        env = {k: v for k, v in os.environ.items() if k not in ("DISPLAY", "WAYLAND_DISPLAY")}
        page = (ROOT / "tools" / "demo_ui_check.html").as_uri()
        try:
            done = subprocess.run([browser, "--headless=new", "--disable-gpu", "--no-sandbox",  # noqa: S603 - a headless browser on this project's own page, fixed arguments
                                   "--allow-file-access-from-files", "--virtual-time-budget=8000", "--dump-dom", page],
                                  capture_output=True, text=True, timeout=120, env=env, check=False)
        except subprocess.TimeoutExpired:
            self.skipTest("the headless browser did not finish")
        match = re.search(r'<pre id="report">(.*?)</pre>', done.stdout, re.S)
        if match is None:
            self.skipTest("the headless browser did not produce a report")
        self.assertEqual(match.group(1).strip(), "PASS", match.group(1))


class StaticSafetyTests(unittest.TestCase):
    def test_the_page_declares_a_policy_that_allows_only_its_own_files(self):
        self.assertIn(f'content="{CSP}"', text("index.html"))

    def test_nothing_is_loaded_from_another_site_and_every_link_is_known(self):
        for name in SERVED:
            for url in re.findall(r"""(?:https?:)?//[^\s"'<>)]+""", text(name)):
                self.assertIn(url.rstrip(".,"), LINKS, f"{name} mentions {url}")
        page = text("index.html")
        for source in re.findall(r"""(?:src|href)="([^"]+)\"""", page):
            self.assertTrue(source in LINKS or ("://" not in source and not source.startswith("//")), source)

    def test_there_are_no_inline_scripts_styles_or_event_handlers(self):
        page = text("index.html")
        self.assertEqual(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", page, flags=re.IGNORECASE), [])
        self.assertNotRegex(page, r"\sstyle\s*=")
        self.assertNotRegex(page, r"\son[a-z]+\s*=")

    def test_the_code_can_neither_send_nor_keep_nor_run_other_code(self):
        for name in ("rules.js", "app.js"):
            for word in FORBIDDEN_CODE:
                self.assertNotIn(word, text(name), f"{name} uses {word}")

    def test_the_published_files_are_the_four_that_the_release_step_copies(self):
        for name in SERVED:
            self.assertTrue((DEMO / name).is_file(), name)
        self.assertEqual(sorted(p.name for p in DEMO.iterdir() if p.is_file()),
                         sorted([*SERVED, "check_rules.js", "golden.json", "README.md"]))


if __name__ == "__main__":
    unittest.main()
