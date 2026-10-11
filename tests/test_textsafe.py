import unittest

from webposture.textsafe import printable

# OSC 52 asks the terminal to put "evil" (base64 ZXZpbA==) on the clipboard.
OSC52 = "\x1b]52;c;ZXZpbA==\x07"


class PrintableTest(unittest.TestCase):
    def test_ordinary_text_is_unchanged(self):
        for text in ("max-age=31536000; includeSubDomains", "default-src 'self'", "nginx/1.25.3",
                     "café", "bücher.example", "日本語", "🔒 locked", "a | b ` c * d _ e [f](g) <h>"):
            self.assertEqual(printable(text), text)

    def test_terminal_control_sequences_become_visible(self):
        self.assertEqual(printable(f"nginx {OSC52}"), "nginx \\x1b]52;c;ZXZpbA==\\x07")
        self.assertEqual(printable("\x1b[2J\x1b[H"), "\\x1b[2J\\x1b[H")
        self.assertEqual(printable("a\x00b\x7fc"), "a\\x00b\\x7fc")

    def test_c1_controls_become_visible(self):
        # Header bytes are decoded as Latin-1, so bytes 0x9b and 0x9d arrive as
        # U+009B and U+009D, the one-byte CSI and OSC that some terminals act on.
        self.assertEqual(printable("\x9b2J\x9d52;c;x"), "\\x9b2J\\x9d52;c;x")
        # U+0085 (next line) is a line break, so like any whitespace it becomes a space.
        self.assertEqual(printable("a\x85b"), "a b")

    def test_invisible_and_reordering_characters_become_visible(self):
        self.assertEqual(printable("abc\u202edef"), "abc\\u202edef")  # right-to-left override
        self.assertEqual(printable("a\u200bb\ufeff"), "a\\u200bb\\ufeff")  # zero-width space, BOM
        self.assertEqual(printable("\U000f0000"), "\\U000f0000")  # private use, outside the BMP

    def test_whitespace_runs_become_one_space_so_a_line_cannot_be_forged(self):
        self.assertEqual(printable("one\n  [PASS] hsts: forged"), "one [PASS] hsts: forged")
        self.assertEqual(printable("\ttab\r\nand\u2028separator\u00a0nbsp "), "tab and separator nbsp")
        self.assertEqual(printable(""), "")


if __name__ == "__main__":
    unittest.main()
