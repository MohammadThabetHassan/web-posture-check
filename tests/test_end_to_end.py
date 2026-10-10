"""End-to-end tests: the real CLI against real local web servers.

Nothing inside the tool is mocked. Each test starts small HTTP servers on
127.0.0.1 and runs cli.main on them, so the fetches, the CORS probe, the
security.txt request, the checks and the output formats are exercised
together. The DNS and TLS checks need real domains and HTTPS, so the runs
select the checks that a local plain-HTTP server can answer.
"""

import io
import json
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from webposture import cli

LOCAL_CHECKS = "http-status,hsts,csp,x-content-type-options,clickjacking,cookies,cors,security-txt"


def _security_txt():
    expires = (datetime.now(timezone.utc) + timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"Contact: mailto:security@example.test\nExpires: {expires}\n"


class _GoodSite(BaseHTTPRequestHandler):
    """Sends the headers a well-configured site sends, and a valid security.txt."""

    def do_GET(self):
        if self.path == "/.well-known/security.txt":
            body = _security_txt().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "sid=abc; Path=/; HttpOnly; SameSite=Lax")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class _BadSite(BaseHTTPRequestHandler):
    """No security headers, a weak cookie, a CORS policy that trusts any origin, no security.txt."""

    def do_GET(self):
        if self.path == "/.well-known/security.txt":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Set-Cookie", "track=1; Path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class _ErrorSite(BaseHTTPRequestHandler):
    """Answers every path with 503, as a server behind bot protection does."""

    def do_GET(self):
        self.send_response(503)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class EndToEndTest(unittest.TestCase):
    def _serve(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}/"

    def _run(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main([*argv, "--only", LOCAL_CHECKS, "--retries", "0", "--timeout", "5"])
        return code, out.getvalue()

    def _statuses(self, result):
        return {f["check"]: f["status"] for f in result["findings"]}

    def test_well_configured_site_passes_every_local_check(self):
        code, out = self._run(self._serve(_GoodSite), "--json")
        result = json.loads(out)
        self.assertEqual(self._statuses(result), dict.fromkeys(LOCAL_CHECKS.split(","), "PASS"))
        self.assertEqual((result["score"], result["grade"]), (100, "A"))
        self.assertEqual(code, 0)

    def test_badly_configured_site_reports_each_problem(self):
        code, out = self._run(self._serve(_BadSite), "--json")
        statuses = self._statuses(json.loads(out))
        self.assertEqual(statuses["http-status"], "PASS")
        for check in ("hsts", "csp", "x-content-type-options", "clickjacking"):
            self.assertEqual(statuses[check], "FAIL", check)
        # Over plain HTTP a missing Secure flag is not a FAIL; HttpOnly and SameSite still warn.
        self.assertEqual(statuses["cookies"], "WARN")
        # The server echoes the probe Origin with credentials: the probe must catch it.
        self.assertEqual(statuses["cors"], "FAIL")
        self.assertEqual(statuses["security-txt"], "WARN")
        self.assertEqual(code, 1)

    def test_several_sites_in_one_run_with_markdown_output(self):
        good, bad = self._serve(_GoodSite), self._serve(_BadSite)
        code, out = self._run(good, bad, "--format", "markdown")
        self.assertEqual(out.count("## Web posture report:"), 2)
        self.assertIn(f"## Web posture report: {good}", out)
        self.assertIn("**Grade A** (100/100)", out)
        self.assertIn("| FAIL | `cors` |", out)
        self.assertEqual(code, 1)

    def test_fail_on_warn_exit_codes(self):
        self.assertEqual(self._run(self._serve(_GoodSite), "--fail-on", "warn")[0], 0)
        self.assertEqual(self._run(self._serve(_BadSite), "--fail-on", "warn")[0], 1)

    def test_error_page_is_flagged_and_other_checks_still_run(self):
        # A 503 (e.g. bot protection): http-status must flag it with the
        # bot-protection hint, and the header checks must still run on the error
        # page rather than the fetch aborting the whole scan.
        code, out = self._run(self._serve(_ErrorSite), "--json")
        statuses = self._statuses(json.loads(out))
        self.assertEqual(statuses["http-status"], "WARN")
        self.assertEqual(statuses["hsts"], "FAIL")  # the checks ran on the 503 response
        http_status = next(f for f in json.loads(out)["findings"] if f["check"] == "http-status")
        self.assertIn("bot protection", http_status["detail"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
