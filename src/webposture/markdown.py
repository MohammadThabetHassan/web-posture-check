"""Markdown report, for pasting into tickets, pull requests or emails.

render takes the findings and returns text; it does no I/O, so the layout
can be tested directly. The output is plain ASCII apart from the findings
themselves, so it survives consoles and files that are not UTF-8.

The URL (where the redirects ended) and the details quote what the scanned
site sent, and the report is usually rendered: in a GitHub Actions job
summary, an issue or a pull request. So they are written as code spans, the
one Markdown construct whose content is always shown literally. A site cannot
add a link, an image, HTML, an @mention, an issue reference or a table cell of
its choosing. Backslash escapes are not enough on GitHub: an autolinked URL
takes the backslash meant for the next character (so "\\<img" became an
image), and mentions and issue references are linked after the Markdown is
rendered. Control characters are made visible first (textsafe.printable).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime

from .findings import FAIL, PASS, WARN, Finding
from .textsafe import printable

_ORDER = {FAIL: 0, WARN: 1, PASS: 2}


def _code(text: object, in_table: bool = True) -> str:
    """text as a code span on one line; empty text gives an empty string."""
    text = printable(str(text))
    if not text:
        return ""
    # The fence must be longer than any run of backticks inside.
    fence = "`" * (max((len(run) for run in re.findall("`+", text)), default=0) + 1)
    if text[0] == "`" or text[-1] == "`":
        # Renderers strip one space from each end, so a backtick there cannot join the fence.
        text = f" {text} "
    if in_table:
        # GitHub splits table cells on | even inside a code span; \| keeps it in the
        # cell, and the table parser removes the backslash again.
        text = text.replace("|", "\\|")
    return f"{fence}{text}{fence}"


def render(url: str, status: int | None, findings: Sequence[Finding], version: str, generated_at: datetime,
           note: str | None = None, score: tuple[int, str] | None = None, error: str | None = None) -> str:
    """The report for one target. error, if given, says why the target could not be (fully) scanned."""
    counts = {s: sum(1 for f in findings if f.status == s) for s in (FAIL, WARN, PASS)}
    status_text = f"HTTP {status}" if status is not None else "no HTTP response"
    lines = [
        f"## Web posture report: {_code(url, in_table=False)}",
        "",
        f"{status_text}, generated {generated_at:%Y-%m-%d %H:%M} UTC by web-posture-check {version}",
        "",
    ]
    if error:
        # Error messages quote the target and the server, so they are code spans too.
        lines += [f"**Error:** {_code(error, in_table=False)}", ""]
        if not findings:
            return "\n".join(lines)
    lines += [
        (f"**Grade {score[1]}** ({score[0]}/100): " if score else "")
        + f"**{counts[FAIL]} FAIL**, **{counts[WARN]} WARN**, {counts[PASS]} PASS",
        "",
    ]
    if note:
        # Notes are the tool's own sentences, never text from the site.
        lines += [f"> {printable(note)}", ""]
    lines += ["| Status | Check | Detail |", "|---|---|---|"]
    # Failures first, so the reader sees what to fix before what passed.
    # sorted() is stable, so the report order is kept within each status.
    for f in sorted(findings, key=lambda f: _ORDER.get(f.status, 3)):
        lines.append(f"| {f.status} | `{f.check}` | {_code(f.detail)} |")
    return "\n".join(lines) + "\n"
