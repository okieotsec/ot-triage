import unittest
from unittest import mock

import gui_theme
from gui_theme import DARK, LIGHT, THEMES, contrast

MIN_TEXT_CONTRAST = 4.5


class ThemeContrastTests(unittest.TestCase):
    def test_every_text_pair_meets_the_minimum_contrast_in_both_themes(self):
        for theme in THEMES.values():
            for foreground, background in gui_theme.TEXT_PAIRS:
                ratio = contrast(getattr(theme, foreground), getattr(theme, background))
                with self.subTest(theme=theme.name, pair=f"{foreground} on {background}"):
                    self.assertGreaterEqual(ratio, MIN_TEXT_CONTRAST, f"{ratio:.2f}")

    def test_disabled_button_text_is_still_readable(self):
        for theme in THEMES.values():
            with self.subTest(theme=theme.name):
                self.assertGreaterEqual(contrast(theme.muted, theme.border), 3.0)

    def test_no_default_theme_colours_leak_through_in_any_state(self):
        import tkinter as tk
        from tkinter import ttk
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("no display available")
        self.addCleanup(root.destroy)
        root.withdraw()
        for theme in THEMES.values():
            gui_theme.apply_ttk_styles(root, gui_theme.Style(theme))
            style = ttk.Style(root)
            leaks = {"#9e9a91", "#eeebe7", "#dcdad5", "#bab5ab", "#cfcdc8"}
            applicable = {"Treeview": ("background", "bordercolor", "lightcolor", "darkcolor"),
                          "Treeview.Heading": ("background", "bordercolor", "lightcolor", "darkcolor"),
                          "Vertical.TScrollbar": ("background", "bordercolor", "lightcolor", "darkcolor",
                                                  "troughcolor"),
                          "Score.Horizontal.TProgressbar": ("background", "bordercolor", "lightcolor", "darkcolor",
                                                            "troughcolor")}
            applicable["Busy.Horizontal.TProgressbar"] = applicable["Score.Horizontal.TProgressbar"]
            for widget, options in applicable.items():
                for option in options:
                    for states in ([], ["disabled"], ["active"], ["pressed"], ["selected"]):
                        value = str(style.lookup(widget, option, states) or "").lower()
                        self.assertNotIn(value, leaks, f"{theme.name}: {widget} {option} {states} is {value}")

    def test_contrast_helper_matches_known_values(self):
        self.assertAlmostEqual(contrast("#000000", "#ffffff"), 21.0, places=2)
        self.assertAlmostEqual(contrast("#ffffff", "#ffffff"), 1.0, places=2)
        self.assertGreater(contrast("#0f172a", "#f59e0b"), 8.0)

    def test_themes_are_complete_and_well_formed(self):
        self.assertEqual(set(THEMES), {"dark", "light"})
        for theme in (DARK, LIGHT):
            for name, value in theme.__dict__.items():
                if name != "name":
                    self.assertRegex(value, r"^#[0-9a-f]{6}$", f"{theme.name}.{name}")

    def test_style_helpers(self):
        style = gui_theme.Style(DARK, 1.15)
        self.assertEqual(style.font(10)[1], round(10 * gui_theme.FONT_BOOST * 1.15))
        self.assertEqual(style.font(10, "bold")[2], "bold")
        self.assertEqual(style.bucket("NOW"), (DARK.now, DARK.on_now))
        self.assertEqual(style.bucket("ERROR")[1], DARK.error)
        self.assertEqual(style.direction("lower"), DARK.lower)
        self.assertEqual(style.direction("unknown"), DARK.neutral)
        self.assertEqual(gui_theme.Style(DARK, 0.5).font(8)[1], 7)

    def test_font_choice_prefers_the_first_installed_modern_family(self):
        with mock.patch("gui_theme.tkfont.families", return_value=("Liberation Sans", "Noto Sans", "Adwaita Sans")):
            self.assertEqual(gui_theme.choose_family(object()), "Adwaita Sans")
        with mock.patch("gui_theme.tkfont.families", return_value=("Liberation Sans", "Inter", "Adwaita Sans")):
            self.assertEqual(gui_theme.choose_family(object()), "Inter")

    def test_font_choice_falls_back_to_the_system_default(self):
        fake = mock.Mock()
        fake.actual.return_value = "Liberation Sans"
        with (mock.patch("gui_theme.tkfont.families", return_value=("Liberation Sans",)),
              mock.patch("gui_theme.tkfont.nametofont", return_value=fake)):
            self.assertEqual(gui_theme.choose_family(object()), "Liberation Sans")

    def test_every_status_has_a_symbol_as_well_as_a_colour(self):
        for key in ("raise", "lower", "neutral", "ok", "warn", "error"):
            self.assertTrue(gui_theme.SYMBOLS[key])
        self.assertEqual(set(gui_theme.PRIORITY_SYMBOLS), {"NOW", "NEXT", "NEVER", "ERROR"})
        self.assertEqual(len(set(gui_theme.PRIORITY_SYMBOLS.values())), 4)


if __name__ == "__main__":
    unittest.main()
