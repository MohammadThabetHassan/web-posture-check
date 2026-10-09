"""Markdown report, for pasting into tickets, pull requests or emails.

render takes the findings and returns text; it does no I/O, so the layout
can be tested directly. The output is plain ASCII apart from the findings
themselves, so it survives consoles and files that are not UTF-8.
"""

from .findings import PASS, WARN, FAIL

_ORDER = {FAIL: 0, WARN: 1, PASS: 2}


def _cell(text):
    """Make text safe inside a Markdown table cell."""
    return " ".join(str(text).split()).replace("|", "\\|")


def render(url, status, findings, version, generated_at, note=None, score=None):
    counts = {s: sum(1 for f in findings if f.status == s) for s in (FAIL, WARN, PASS)}
    status_text = f"HTTP {status}" if status is not None else "no HTTP response"
    lines = [
        f"## Web posture report: {url}",
        "",
        f"{status_text}, generated {generated_at:%Y-%m-%d %H:%M} UTC by web-posture-check {version}",
        "",
        (f"**Grade {score[1]}** ({score[0]}/100): " if score else "")
        + f"**{counts[FAIL]} FAIL**, **{counts[WARN]} WARN**, {counts[PASS]} PASS",
        "",
    ]
    if note:
        lines += [f"> {_cell(note)}", ""]
    lines += ["| Status | Check | Detail |", "|---|---|---|"]
    # Failures first, so the reader sees what to fix before what passed.
    # sorted() is stable, so the report order is kept within each status.
    for f in sorted(findings, key=lambda f: _ORDER.get(f.status, 3)):
        lines.append(f"| {f.status} | `{f.check}` | {_cell(f.detail)} |")
    return "\n".join(lines) + "\n"
