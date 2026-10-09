import unicodedata
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# The only non-ASCII characters source code may contain: visible interface symbols.
ALLOWED = {0x00B7, 0x2022, 0x2026, 0x25AC, 0x25B2, 0x25B8, 0x25BC, 0x25BE, 0x26A0, 0x2713, 0x2716}
SOURCES = sorted([*ROOT.glob("*.py"), *(ROOT / "tools").glob("*.py"), *(ROOT / "tools").glob("*.js")])


class SourceHygieneTests(unittest.TestCase):
    """Source files must not hide characters from a reader (invisible, direction-changing or look-alike letters)."""

    def test_there_are_sources_to_check(self):
        self.assertGreater(len(SOURCES), 30)

    def test_no_invisible_or_direction_changing_characters(self):
        for path in SOURCES:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                for char in line:
                    if unicodedata.category(char) in ("Cf", "Cc", "Zl", "Zp") and char != "\t":
                        self.fail(f"{path.name}:{number} contains U+{ord(char):04X} ({unicodedata.name(char, '?')}); "
                                  "write it as an escape sequence")

    def test_no_look_alike_or_unreviewed_non_ascii_characters(self):
        for path in SOURCES:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                for char in line:
                    if ord(char) > 127 and ord(char) not in ALLOWED:
                        self.fail(f"{path.name}:{number} contains U+{ord(char):04X} ({unicodedata.name(char, '?')}); "
                                  "use an escape sequence, or add a reviewed interface symbol to ALLOWED")

    def test_files_have_no_byte_order_mark(self):
        for path in SOURCES:
            self.assertFalse(path.read_bytes().startswith(b"\xef\xbb\xbf"), path.name)

    def test_no_personal_name_or_home_folder_path_is_in_any_file_of_the_repository(self):
        # Built from pieces so this test does not contain what it forbids. The project is published under a handle.
        forbidden = ("ja" + "red", "frit" + "ts", "/ho" + "me/")
        suffixes = {".py", ".md", ".json", ".html", ".yml", ".yaml", ".toml", ".txt", ".js", ".csv"}
        checked = 0
        for path in sorted(ROOT.rglob("*")):
            if (not path.is_file() or path.suffix not in suffixes
                    or any(part in (".git", "__pycache__") for part in path.relative_to(ROOT).parts)):
                continue
            checked += 1
            text = path.read_text(encoding="utf-8", errors="replace").lower()
            for word in forbidden:
                self.assertNotIn(word, text, f"{path.relative_to(ROOT)} contains {word!r}")
        self.assertGreater(checked, 50)

    def test_the_checks_themselves_catch_the_hostile_characters(self):
        for codepoint in (0x202E, 0x200B, 0xFEFF, 0x2066, 0x0410, 0xFF0F, 0x0663):
            char = chr(codepoint)
            hidden = unicodedata.category(char) in ("Cf", "Cc", "Zl", "Zp")
            self.assertTrue(hidden or codepoint not in ALLOWED, hex(codepoint))


if __name__ == "__main__":
    unittest.main()
