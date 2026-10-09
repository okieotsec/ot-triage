import unittest
from unittest import mock

import gui_about
import gui_brand
from gui_context import Context
from gui_testing import DisplayTestCase
from gui_theme import DARK
from settings import DEFAULT_SETTINGS
from uiprefs import DEFAULT_PREFS


class IconTests(unittest.TestCase):
    def test_the_icon_is_a_navy_rounded_square_with_a_red_an_amber_and_a_green_bar(self):
        rows = gui_brand.icon_rows(64)
        self.assertEqual((len(rows), len(rows[0])), (64, 64))
        self.assertEqual(rows[0][0][3], 0, "the corner outside the rounded square is transparent")

        def rgb(colour):
            return tuple(int(colour[i:i + 2], 16) for i in (1, 3, 5))
        column = [rgb_pixel[:3] for rgb_pixel in (row[20] for row in rows)]
        for colour in (DARK.now, DARK.next, DARK.never, DARK.bg):
            self.assertIn(rgb(colour), column)
        self.assertEqual(column.index(rgb(DARK.now)) < column.index(rgb(DARK.next)) < column.index(rgb(DARK.never)),
                         True)

    def test_every_icon_size_draws_without_error_and_is_square(self):
        for size in gui_brand.ICON_SIZES:
            rows = gui_brand.icon_rows(size)
            self.assertEqual((len(rows), {len(r) for r in rows}), (size, {size}))


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


class AboutLinksTests(DisplayTestCase):
    def build(self):
        import tkinter as tk
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
        for expected in ("Okie", "OT", "Sec", gui_brand.TAGLINE):
            self.assertIn(expected, texts)
        self.assertTrue(any(t.startswith("OT Triage ") for t in texts))


if __name__ == "__main__":
    unittest.main()
