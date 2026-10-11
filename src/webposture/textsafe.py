"""Making text from a scanned site safe to print.

Findings quote what the site sent: header values, cookie names, DNS records,
redirect URLs. A hostile site can put terminal control sequences in them that
clear the screen, move the cursor, rewrite earlier lines or, through OSC 52,
set the clipboard of the person running the scan; bidirectional overrides can
reorder what a reader sees; a line break can forge a line of the report. Text
and Markdown reports pass everything through printable() first. JSON and
SARIF are already safe: json.dumps escapes control characters and, by
default, every non-ASCII character.
"""

from __future__ import annotations


def _escape(char: str) -> str:
    code = ord(char)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def printable(text: str) -> str:
    r"""text on one line, with nothing in it that a terminal or viewer would act on.

    Every run of whitespace, line breaks and tabs included, becomes one space.
    Every other character that str.isprintable() rejects becomes a visible
    escape such as \x1b: control characters (C0 and C1), format characters such
    as the bidirectional overrides, and unassigned or private-use code points.
    Letters, digits, punctuation and symbols in any script are kept.
    """
    return "".join(char if char.isprintable() else _escape(char) for char in " ".join(text.split()))
