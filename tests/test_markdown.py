import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from unittest import mock

from webposture import cli, fetch, markdown
from webposture.findings import FAIL, PASS, WARN, Finding

WHEN = datetime(2026, 10, 10, 9, 30, tzinfo=timezone.utc)
FINDINGS = [
    Finding("hsts", PASS, "max-age=31536000"),
    Finding("csp", FAIL, "Content-Security-Policy header is missing"),
    Finding("cookies", WARN, "sid: missing HttpOnly"),
    Finding("https-redirect", FAIL, "http://example.com/ is served over plain HTTP"),
]


def render(findings=FINDINGS, **kwargs):
    return markdown.render("https://example.com/", 200, findings, "0.1.0", WHEN, **kwargs)


class RenderTest(unittest.TestCase):
    def test_header_and_summary(self):
        out = render()
        self.assertTrue(out.startswith("## Web posture report: `https://example.com/`\n"))
        self.assertIn("HTTP 200, generated 2026-10-10 09:30 UTC by web-posture-check 0.1.0", out)
        self.assertIn("**2 FAIL**, **1 WARN**, 1 PASS", out)

    def test_table_rows_put_failures_first_and_keep_order_within_a_status(self):
        rows = [line for line in render().splitlines() if line.startswith("| ") and "`" in line]
        self.assertEqual([r.split("`")[1] for r in rows], ["csp", "https-redirect", "cookies", "hsts"])
        self.assertIn("| FAIL | `csp` | `Content-Security-Policy header is missing` |", rows[0])

    def test_pipes_and_newlines_cannot_break_the_table(self):
        out = render([Finding("cors", WARN, "a | b\nc")])
        self.assertIn("| WARN | `cors` | `a \\| b c` |", out)

    def test_note_and_missing_status(self):
        out = markdown.render("https://bad.example/", None, [Finding("tls-certificate", FAIL, "expired")], "0.1.0", WHEN,
                              note="other checks skipped: no trusted HTTPS connection")
        self.assertIn("no HTTP response, generated", out)
        self.assertIn("> other checks skipped: no trusted HTTPS connection", out)

    def test_grade_leads_the_summary_when_given(self):
        out = render(score=(55, "F"))
        self.assertIn("**Grade F** (55/100): **2 FAIL**, **1 WARN**, 1 PASS", out)
        self.assertNotIn("Grade", render())

    def test_report_template_stays_ascii(self):
        # The report must be plain ASCII apart from the findings themselves, so
        # it survives non-UTF-8 consoles and files on Windows (an early version
        # used a non-ASCII separator that was written as "?"). With ASCII
        # findings and URL, the whole report must encode as ASCII.
        self.assertTrue(render().isascii())


class HostileTextTest(unittest.TestCase):
    """What a site sends must show literally, never as a link, image, HTML, mention or new cell.

    GitHub renders the report in job summaries, issues and pull requests, where
    a backslash escape can be undone by an autolinked URL, and @mentions and
    issue references are linked after rendering; only a code span stays literal.
    """

    def _row(self, detail):
        return render([Finding("information-leakage", WARN, detail)]).splitlines()[-1]

    def test_details_are_code_spans(self):
        for detail in ("<img src=https://evil.example/p.png>", "[click](https://evil.example)",
                       "![x](https://evil.example/p.png)", "ping @octocat about #1", "**Grade A** (100/100)",
                       "https://evil.example/\\<img src=x>", "~~struck~~ _em_"):
            self.assertEqual(self._row(detail), f"| WARN | `information-leakage` | `{detail}` |", detail)

    def test_backticks_inside_get_a_longer_fence(self):
        self.assertEqual(self._row("a ` b"), "| WARN | `information-leakage` | ``a ` b`` |")
        self.assertEqual(self._row("has `` two"), "| WARN | `information-leakage` | ```has `` two``` |")
        # Renderers strip one space at each end, which keeps an edge backtick off the fence.
        self.assertEqual(self._row("`x`"), "| WARN | `information-leakage` | `` `x` `` |")

    def test_pipes_stay_in_their_cell(self):
        # GitHub's table parser treats every \\| as a literal | and removes one backslash.
        self.assertEqual(self._row("a|b a\\|b"), "| WARN | `information-leakage` | `a\\|b a\\\\|b` |")

    def test_control_characters_are_visible(self):
        row = self._row("nginx/1.25 \x1b]52;c;ZXZpbA==\x07 \u202e")
        self.assertEqual(row, "| WARN | `information-leakage` | `nginx/1.25 \\x1b]52;c;ZXZpbA==\\x07 \\u202e` |")

    def test_empty_detail_is_an_empty_cell(self):
        self.assertEqual(self._row(" \n "), "| WARN | `information-leakage` |  |")

    def test_url_in_the_heading_is_a_code_span_without_escaped_pipes(self):
        out = markdown.render("https://example.com/?a=1|2&b=<i>", 200, [], "0.1.0", WHEN)
        self.assertTrue(out.startswith("## Web posture report: `https://example.com/?a=1|2&b=<i>`\n"))


class FormatOptionTest(unittest.TestCase):
    def _run(self, *argv):
        out = io.StringIO()
        with mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", {}, [], 200)), \
                redirect_stdout(out):
            code = cli.main(["example.com", "--only", "hsts,csp", *argv])
        return code, out.getvalue()

    def test_format_markdown(self):
        code, out = self._run("--format", "markdown")
        self.assertEqual(code, 1)
        self.assertIn("## Web posture report: `https://example.com/`", out)
        self.assertIn("| FAIL | `hsts` |", out)

    def test_json_flag_still_works_as_a_shortcut(self):
        _, via_flag = self._run("--json")
        _, via_format = self._run("--format", "json")
        self.assertEqual(via_flag, via_format)
        self.assertTrue(via_flag.lstrip().startswith("{"))

    def test_json_and_format_cannot_be_combined(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["example.com", "--json", "--format", "markdown"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
