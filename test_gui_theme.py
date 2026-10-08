import unittest

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
        self.assertEqual(style.font(10)[1], 12)
        self.assertEqual(style.font(10, "bold")[2], "bold")
        self.assertEqual(style.bucket("NOW"), (DARK.now, DARK.on_now))
        self.assertEqual(style.bucket("ERROR")[1], DARK.error)
        self.assertEqual(style.direction("lower"), DARK.lower)
        self.assertEqual(style.direction("unknown"), DARK.neutral)
        self.assertEqual(gui_theme.Style(DARK, 0.5).font(8)[1], 7)

    def test_every_status_has_a_symbol_as_well_as_a_colour(self):
        for key in ("raise", "lower", "neutral", "ok", "warn", "error"):
            self.assertTrue(gui_theme.SYMBOLS[key])
        self.assertEqual(set(gui_theme.PRIORITY_SYMBOLS), {"NOW", "NEXT", "NEVER", "ERROR"})
        self.assertEqual(len(set(gui_theme.PRIORITY_SYMBOLS.values())), 4)


if __name__ == "__main__":
    unittest.main()
