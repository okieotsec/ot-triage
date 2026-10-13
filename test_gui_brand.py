import struct
import tkinter as tk
import unittest
from pathlib import Path
from unittest import mock

import gui_about
import gui_brand
import gui_theme
from gui_context import Context
from gui_testing import DisplayTestCase
from settings import DEFAULT_SETTINGS
from uiprefs import DEFAULT_PREFS


def png_size(path):
    """Width and height from a PNG file's header."""
    data = Path(path).read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path} is not a PNG file")
    return struct.unpack(">II", data[16:24])


class AssetTests(unittest.TestCase):
    def test_every_icon_the_code_asks_for_exists_with_the_size_it_is_named_for(self):
        for size in gui_brand.ICON_SIZES:
            self.assertEqual(png_size(gui_brand.ASSETS / "icons" / f"tile-{size}.png"), (size, size))
        self.assertTrue(gui_brand.FAVICON.is_file())

    def test_every_header_shield_exists_in_both_colour_sets_at_its_height(self):
        for height in gui_brand.HEADER_HEIGHTS:
            for prefix in ("shield", "shield-dark"):
                width, found = png_size(gui_brand.ASSETS / "header" / f"{prefix}-{height}.png")
                self.assertEqual(found, height)
                self.assertLess(width, height)           # the shield is taller than it is wide

    def test_every_lockup_exists_in_both_colour_sets_at_its_width(self):
        for width in gui_brand.LOCKUP_WIDTHS:
            for prefix in ("lockup", "lockup-dark"):
                found, height = png_size(gui_brand.ASSETS / "lockup" / f"{prefix}-{width}.png")
                self.assertEqual(found, width)
                self.assertLess(height, width)

    def test_the_images_carry_no_hidden_metadata(self):
        for path in gui_brand.ASSETS.rglob("*.png"):
            data, pos, chunks = path.read_bytes(), 8, []
            while pos < len(data):
                length, = struct.unpack(">I", data[pos:pos + 4])
                chunks.append(data[pos + 4:pos + 8].decode("latin1"))
                pos += 12 + length
            extra = set(chunks) - {"IHDR", "IDAT", "IEND", "PLTE", "tRNS", "pHYs", "sRGB", "gAMA", "cHRM", "bKGD"}
            self.assertEqual(extra, set(), path.name)

    def test_the_svgs_hold_no_scripts_or_outside_references(self):
        for path in (gui_brand.ASSETS / "svg").glob("*.svg"):
            text = path.read_text(encoding="utf-8").lower()
            for bad in ("<script", "onload", "onclick", "javascript:", "<foreignobject", "href=\"http", "@import"):
                self.assertNotIn(bad, text, f"{path.name}: {bad}")

    def test_the_rights_notice_says_the_licence_covers_the_code_and_forks_may_not_keep_the_logo(self):
        notice = (gui_brand.ASSETS / "README.md").read_text(encoding="utf-8")
        for needed in ("not** covered by the MIT", "Forks and modified versions may not use them", "assets/brand/"):
            self.assertIn(needed, notice)
        readme = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")
        self.assertIn("forks must not use them", readme)

    def test_the_nearest_size_is_chosen(self):
        self.assertEqual(gui_brand.nearest(gui_brand.HEADER_HEIGHTS, 40), 40)
        self.assertEqual(gui_brand.nearest(gui_brand.HEADER_HEIGHTS, 44), 40)
        self.assertEqual(gui_brand.nearest(gui_brand.HEADER_HEIGHTS, 1000), 64)
        self.assertEqual(gui_brand.nearest(gui_brand.HEADER_HEIGHTS, 1), 32)


class LinkTests(unittest.TestCase):
    def test_every_public_link_is_a_plain_https_address_to_the_expected_site(self):
        hosts = {name: url.split("/")[2] for name, url in gui_brand.LINKS}
        self.assertEqual(hosts, {"Website": "okieotsec.com", "GitHub": "github.com", "YouTube": "www.youtube.com",
                                 "X": "x.com"})
        for _name, url in gui_brand.LINKS:
            self.assertTrue(url.startswith("https://") and url.isascii() and " " not in url, url)
        self.assertIn("https://x.com/okieotsec", [u for _n, u in gui_brand.LINKS])


class BrandWidgetsTests(DisplayTestCase):
    def test_the_wordmark_spells_okieotsec_with_ot_in_the_accent_colour(self):
        mark = gui_brand.wordmark(self.root, self.style, self.style.theme.bg)
        labels = mark.winfo_children()
        self.assertEqual([w.cget("text") for w in labels], ["Okie", "OT", "Sec"])
        self.assertEqual([str(w.cget("fg")) for w in labels],
                         [self.style.theme.text, self.style.theme.accent, self.style.theme.text])

    def test_the_icon_is_installed_on_the_window(self):
        images = gui_brand.app_icon(self.root)
        self.assertEqual([i.width() for i in images], list(gui_brand.ICON_SIZES))
        self.assertIs(self.root.app_icons, images)

    def test_the_header_shield_follows_the_theme_and_the_text_size(self):
        for theme_name, text_scale, expected in (("dark", 1.0, "shield-dark-40"), ("light", 1.0, "shield-40"),
                                                 ("dark", 1.4, "shield-dark-56"), ("light", 0.8, "shield-32")):
            style = gui_theme.Style(gui_theme.THEMES[theme_name], text_scale)
            with mock.patch.object(gui_brand, "_photo", wraps=gui_brand._photo) as loader:
                label = gui_brand.header_logo(self.root, style, "#000000")
            self.assertIsNotNone(label)
            self.assertEqual(loader.call_args[0][1], f"header/{expected}.png", (theme_name, text_scale))
            label.destroy()

    def test_the_lockup_follows_the_theme(self):
        dark = gui_brand.lockup(self.root, gui_theme.Style(gui_theme.DARK), "#000000")
        light = gui_brand.lockup(self.root, gui_theme.Style(gui_theme.LIGHT), "#ffffff")
        self.assertEqual((dark.image.width(), light.image.width()), (320, 320))
        self.assertNotEqual(dark.image.cget("file"), light.image.cget("file"))

    def test_without_the_image_files_everything_still_works_and_just_has_no_pictures(self):
        import tempfile
        with tempfile.TemporaryDirectory() as empty, mock.patch.object(gui_brand, "ASSETS", Path(empty)):
            self.assertIsNone(gui_brand.app_icon(self.root))
            self.assertIsNone(gui_brand.header_logo(self.root, self.style, "#000000"))
            self.assertIsNone(gui_brand.lockup(self.root, self.style, "#000000"))


class AboutLinksTests(DisplayTestCase):
    def build(self):
        ctx = Context(self.root, self.style, DEFAULT_SETTINGS, DEFAULT_PREFS)
        for name in ("info", "error", "warn", "copy", "confirm"):
            setattr(ctx, name, mock.Mock())
        holder = tk.Toplevel(self.root)
        self.addCleanup(holder.destroy)
        holder.geometry("900x900+0+0")
        view = gui_about.AboutView(ctx, holder)
        view.frame.pack(fill=tk.BOTH, expand=True)
        self.root.deiconify()
        self.pump(0.2)
        return view

    def test_the_about_page_lists_each_link_and_opens_exactly_that_address_only_on_click(self):
        view = self.build()
        self.assertEqual([w.cget("text") for w in view.link_labels], [n for n, _u in gui_brand.LINKS])
        with mock.patch("gui_context.webbrowser.open", return_value=True) as opener:
            opener.assert_not_called()
            view.link_labels[0].event_generate("<Button-1>")
            self.pump(0.1)
        opener.assert_called_once_with("https://okieotsec.com")

    def test_the_about_page_credits_the_brand_and_the_tagline(self):
        view = self.build()
        texts = []

        def walk(widget):
            for child in widget.winfo_children():
                if child.winfo_class() == "Label":
                    texts.append(child.cget("text"))
                walk(child)
        walk(view.frame)
        self.assertIn(gui_brand.TAGLINE, texts)
        self.assertTrue(any(t.startswith("OT Triage ") and t.endswith("an OkieOTSec project") for t in texts))
        self.assertIsNotNone(view.lockup)                      # the logo picture is shown above them


if __name__ == "__main__":
    unittest.main()
