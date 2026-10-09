import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from unittest import mock

from webposture import cli, markdown
from webposture.findings import Finding, PASS, WARN, FAIL

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
        self.assertTrue(out.startswith("## Web posture report: https://example.com/\n"))
        self.assertIn("HTTP 200, generated 2026-10-10 09:30 UTC by web-posture-check 0.1.0", out)
        self.assertIn("**2 FAIL**, **1 WARN**, 1 PASS", out)

    def test_table_rows_put_failures_first_and_keep_order_within_a_status(self):
        rows = [line for line in render().splitlines() if line.startswith("| ") and "`" in line]
        self.assertEqual([r.split("`")[1] for r in rows], ["csp", "https-redirect", "cookies", "hsts"])
        self.assertIn("| FAIL | `csp` | Content-Security-Policy header is missing |", rows[0])

    def test_pipes_and_newlines_cannot_break_the_table(self):
        out = render([Finding("cors", WARN, "a | b\nc")])
        self.assertIn("| WARN | `cors` | a \\| b c |", out)

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


class FormatOptionTest(unittest.TestCase):
    def _run(self, *argv):
        out = io.StringIO()
        with mock.patch.object(cli, "fetch_headers", return_value=("https://example.com/", {}, [], 200)), \
                redirect_stdout(out):
            code = cli.main(["example.com", "--only", "hsts,csp", *argv])
        return code, out.getvalue()

    def test_format_markdown(self):
        code, out = self._run("--format", "markdown")
        self.assertEqual(code, 1)
        self.assertIn("## Web posture report: https://example.com/", out)
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
