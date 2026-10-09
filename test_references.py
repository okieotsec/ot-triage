import unittest

import references as refs
import threatdata as td
from test_threatdata import kev_bytes, kev_entry

try:
    from hypothesis import given, settings as hyp_settings, strategies as st
except ImportError:  # hypothesis is an optional test dependency
    st = None

REAL = ("https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697174 ; "
        "https://community.citrix.com/techzone-blogs/110_security-updates/some-post/ ; "
        "BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04 ; "
        "Forensics Triage Requirements: https://www.cisa.gov/news-events/directives/bod-26-04-implementation ; "
        "https://nvd.nist.gov/vuln/detail/CVE-2026-88779")


def links(notes):
    return [r.url for r in refs.parse_references(notes) if r.is_link]


class ParsingTests(unittest.TestCase):
    def test_real_notes_become_labelled_and_bare_links(self):
        found = refs.parse_references(REAL)
        self.assertEqual(len(found), 5)
        self.assertTrue(all(r.is_link for r in found))
        self.assertEqual((found[0].label, found[0].host), ("", "support.citrix.com"))
        self.assertEqual((found[2].label, found[2].host), ("BOD 26-04", "www.cisa.gov"))
        self.assertEqual(found[3].label, "Forensics Triage Requirements")
        self.assertIn("articleNumber=CTX697174", found[0].url)

    def test_text_without_a_link_is_kept_as_text(self):
        found = refs.parse_references("N/A ; This affects a library. For more information, please see:")
        self.assertEqual([r.text for r in found], ["N/A", "This affects a library. For more information, please see:"])
        self.assertFalse(any(r.is_link for r in found))

    def test_empty_missing_and_non_text_notes_give_nothing(self):
        for notes in ("", "   ", " ; ; ", None, 5, b"https://a.example.com", ["https://a.example.com"]):
            self.assertEqual(refs.parse_references(notes), (), repr(notes))

    def test_only_plain_https_links_with_ordinary_host_names_are_clickable(self):
        refused = [
            "http://example.com/a",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html;base64,AAAA",
            "ftp://example.com/x",
            "https://user:pass@example.com/",
            "https://example.com@evil.example.org/",
            "https://example.com:8443/x",
            "https://example.com:99999999/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://localhost/x",
            "https://intranet/x",
            "https://exa_mple.com/x",
            "https://-bad.example.com/x",
            "https://example.com\\@evil.example.org/",
            "https://\u0435xample.com/",
            "https:///nohost",
            "https://" + "a" * 70 + ".com/",
            "https://example.com/" + "a" * 2100,
        ]
        for url in refused:
            self.assertEqual(links("see " + url), [], url)
            self.assertEqual(links(url), [], url)

    def test_ordinary_links_are_accepted_including_an_explicit_default_port_and_a_trailing_full_stop(self):
        self.assertEqual(links("https://Example.COM:443/a?b=c&d=e#f."), ["https://Example.COM:443/a?b=c&d=e#f"])
        self.assertEqual(links("https://sub.example.co.uk/path,"), ["https://sub.example.co.uk/path"])

    def test_a_refused_link_stays_visible_as_text_and_is_never_dropped_silently(self):
        found = refs.parse_references("http://ftp.gnu.org/gnu/bash/patch-027")
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0].is_link)
        self.assertIn("http://ftp.gnu.org", found[0].text)

    def test_duplicates_are_shown_once_and_the_list_is_capped(self):
        self.assertEqual(len(refs.parse_references("https://a.example.com/x ; https://a.example.com/x")), 1)
        many = " ; ".join(f"https://a.example.com/{i}" for i in range(100))
        self.assertEqual(len(refs.parse_references(many)), refs.MAX_REFERENCES)

    def test_control_and_invisible_characters_are_removed(self):
        notes = "Read\u202e this\x1b[31m now\x00\U00014647: https://a.example.com/\u200bpage"
        for item in refs.parse_references(notes):
            for ch in item.label + item.text + item.url:
                self.assertTrue(ch.isprintable(), repr(ch))
        self.assertEqual(links(notes), ["https://a.example.com/page"])

    def test_long_labels_and_text_are_cut_short(self):
        found = refs.parse_references("x" * 5000 + ": https://a.example.com/ ; " + "y" * 5000)
        self.assertTrue(all(len(r.label) <= refs.MAX_TEXT_CHARS and len(r.text) <= refs.MAX_TEXT_CHARS for r in found))

    def test_the_description_always_shows_the_real_address(self):
        found = refs.parse_references("Click here: https://a.example.com/real")
        self.assertEqual(refs.describe(found[0]), "Click here: https://a.example.com/real")
        self.assertEqual(refs.describe(refs.Reference(text="plain")), "plain")


class MarkdownTests(unittest.TestCase):
    def test_labels_and_addresses_cannot_break_out_of_the_link(self):
        item = refs.Reference("Evil](https://bad.example.com) <b>x</b>", "https://a.example.com/p_(1)<x>")
        line = refs.markdown_item(item)
        self.assertEqual(line.count("](https://a.example.com/"), 1)
        self.assertNotIn("<", line.split("](")[0].replace("\\<", ""))
        self.assertTrue(line.endswith("p_%281%29%3Cx%3E)"))
        self.assertIn("\\]\\(https://bad.example.com\\)", line)

    def test_plain_text_is_escaped(self):
        self.assertEqual(refs.markdown_item(refs.Reference(text="*bold* [x](y)")), "- \\*bold\\* \\[x\\]\\(y\\)")

    def test_an_unlabelled_link_is_shown_by_its_host(self):
        self.assertEqual(refs.markdown_item(refs.Reference(url="https://a.example.com/x")),
                         "- [a.example.com](https://a.example.com/x)")


class KevIntegrationTests(unittest.TestCase):
    def parse(self, **changes):
        return td.parse_kev(kev_bytes([kev_entry(**changes)])).entries["CVE-2024-0001"]

    def test_notes_reach_the_entry_and_its_references(self):
        entry = self.parse(notes=REAL)
        self.assertEqual(len(entry.references), 5)
        self.assertIn("support.citrix.com", entry.notes)

    def test_an_entry_without_notes_is_fine(self):
        entry = td.parse_kev(kev_bytes([{k: v for k, v in kev_entry().items() if k != "notes"}])).entries[
            "CVE-2024-0001"]
        self.assertEqual((entry.notes, entry.references), ("", ()))

    def test_notes_must_be_text_and_not_enormous(self):
        for bad in (5, ["x"], {"a": 1}, None):
            with self.assertRaisesRegex(td.ThreatDataError, "notes"):
                self.parse(notes=bad)
        with self.assertRaisesRegex(td.ThreatDataError, "notes"):
            self.parse(notes="x" * (td.MAX_FIELD_CHARS + 1))

    def test_the_forensic_triage_flag_is_read_leniently(self):
        for value, expected in (("Yes", True), ("No", False), ("yes", False), ("", False), (5, False), (None, False),
                                (["Yes"], False)):
            self.assertIs(self.parse(forensicTriage=value).forensic_triage, expected, repr(value))
        without = {k: v for k, v in kev_entry().items() if k != "forensicTriage"}
        self.assertFalse(td.parse_kev(kev_bytes([without])).entries["CVE-2024-0001"].forensic_triage)

    def test_the_stored_notes_have_no_control_characters(self):
        entry = self.parse(notes="a\x00b\x1b[2J ; https://a.example.com/")
        self.assertFalse(any(ord(ch) < 32 for ch in entry.notes))


@unittest.skipIf(st is None, "hypothesis is not installed")
class FuzzTests(unittest.TestCase):
    if st is not None:
        @hyp_settings(max_examples=500, deadline=None)
        @given(st.text())
        def test_any_text_gives_a_bounded_list_of_safe_items(self, text):
            found = refs.parse_references(text)
            self.assertLessEqual(len(found), refs.MAX_REFERENCES)
            for item in found:
                if item.is_link:
                    self.assertTrue(item.url.startswith("https://") and item.url.isascii() and item.host)
                    self.assertNotIn("@", item.url.split("/")[2])
                self.assertTrue((item.label + item.text + item.url).isprintable())
                refs.describe(item)
                refs.markdown_item(item)

        @hyp_settings(max_examples=300, deadline=None)
        @given(st.lists(st.sampled_from(["https://a.example.com/x", "http://b.example.com", "javascript:x", "see:",
                                         "\u202e", "@", "[", "](", ";", " ; ", "\x00", "https://", "\u0435"]),
                        max_size=30))
        def test_stitched_hostile_pieces_never_make_an_unsafe_link(self, pieces):
            for url in links("".join(pieces)):
                self.assertTrue(url.startswith("https://"))
                self.assertTrue(url.isascii())


if __name__ == "__main__":
    unittest.main()
