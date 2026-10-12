"""Helpers for tests that need a real Tk display."""
import atexit
import gc
import os
import shutil
import sys
import tempfile
import time
import tkinter as tk
import unittest

from gui_theme import DARK, Style, apply_ttk_styles

# GUI tests run with a private home folder, so an accidental write to a default settings, preferences or data path can
# never touch the real user's files.
SANDBOX = tempfile.mkdtemp(prefix="vp-test-home-")
os.environ.update({"HOME": SANDBOX, "USERPROFILE": SANDBOX, "XDG_CONFIG_HOME": os.path.join(SANDBOX, "config"),
                   "XDG_DATA_HOME": os.path.join(SANDBOX, "data"), "APPDATA": os.path.join(SANDBOX, "appdata"),
                   "LOCALAPPDATA": os.path.join(SANDBOX, "localappdata")})
atexit.register(shutil.rmtree, SANDBOX, ignore_errors=True)

# Tests that create windows are disruptive on a real desktop, especially a tiling window manager. When this variable is
# set (by a developer's own environment), the GUI tests may only run on a private display such as the one that
# tools/headless_tests.py starts; on the real display they skip themselves instead of opening any window.
REQUIRE_PRIVATE_DISPLAY = "OT_TRIAGE_REQUIRE_PRIVATE_DISPLAY"
PRIVATE_DISPLAY = "OT_TRIAGE_PRIVATE_DISPLAY"
if os.environ.get(REQUIRE_PRIVATE_DISPLAY) == "1" and os.environ.get(PRIVATE_DISPLAY) != "1":
    for _name in ("DISPLAY", "WAYLAND_DISPLAY"):
        os.environ.pop(_name, None)
    print("GUI tests skipped: this environment keeps them off the real display. Run tools/headless_tests.py to run "
          "them on a private, invisible display.", file=sys.stderr)


class DisplayTestCase(unittest.TestCase):
    """Base class: builds one hidden Tk root per test class, skipping when no display exists."""

    theme = DARK
    scale = 1.0

    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
        except tk.TclError as error:
            raise unittest.SkipTest(f"no display available ({error})") from None
        cls.root.withdraw()
        cls.style = Style(cls.theme, cls.scale)
        apply_ttk_styles(cls.root, cls.style)
        # Cyclic garbage must be freed on the main thread: a tkinter variable freed on a worker thread blocks while
        # the test loop is not inside mainloop().
        gc.disable()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()
        gc.collect()
        gc.enable()

    def tearDown(self):
        gc.collect()

    def pump(self, seconds=0.0, until=None):
        """Process Tk events, optionally until a condition holds or time runs out."""
        if until is None and seconds <= 0:
            for _ in range(3):
                self.root.update()
                time.sleep(0.005)
            return True
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.root.update()
            if until is not None and until():
                return True
            time.sleep(0.01)
        self.root.update()
        return until() if until is not None else True

    def make_frame(self, width=400, height=300):
        """Create a sized frame inside a visible-enough toplevel for geometry tests."""
        top = tk.Toplevel(self.root)
        if top.tk.call("tk", "windowingsystem") == "x11":
            top.wm_attributes("-type", "dialog")  # tiling window managers keep the exact size of floating windows
        top.geometry(f"{width}x{height}+0+0")
        frame = tk.Frame(top, bg=self.style.theme.card)
        frame.pack(fill=tk.BOTH, expand=True)
        self.addCleanup(top.destroy)
        self.root.update()
        return frame
