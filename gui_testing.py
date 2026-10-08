"""Helpers for tests that need a real Tk display."""
import time
import tkinter as tk
import unittest

from gui_theme import DARK, Style, apply_ttk_styles


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

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def pump(self, seconds=0.0, until=None):
        """Process Tk events, optionally until a condition holds or time runs out."""
        end = time.monotonic() + max(seconds, 0.05 if until is None else seconds)
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
        top.geometry(f"{width}x{height}+0+0")
        frame = tk.Frame(top, bg=self.style.theme.card)
        frame.pack(fill=tk.BOTH, expand=True)
        self.addCleanup(top.destroy)
        self.root.update()
        return frame
