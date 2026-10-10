import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from webposture import cors
from webposture.cli import probe_cors
from webposture.findings import FAIL, PASS, WARN

PROBE = cors.PROBE_ORIGIN


class CheckCorsTest(unittest.TestCase):
    def test_no_cors_headers_pass(self):
        self.assertEqual(cors.check_cors(None, None).status, PASS)

    def test_reflected_origin_with_credentials_fails(self):
        f = cors.check_cors(PROBE, "true")
        self.assertEqual(f.status, FAIL)
        self.assertIn("reflects any Origin", f.detail)

    def test_reflected_origin_without_credentials_warns(self):
        self.assertEqual(cors.check_cors(PROBE, None).status, WARN)

    def test_credentials_value_is_case_sensitive(self):
        # Browsers ignore "TRUE": credentials stay off, so this is only a WARN.
        self.assertEqual(cors.check_cors(PROBE, "TRUE").status, WARN)
        self.assertEqual(cors.check_cors(PROBE, " true ").status, FAIL)

    def test_credentials_only_true_escalates_to_fail(self):
        # Browsers enable credentials only on the exact value "true", so a
        # reflected origin with any other Allow-Credentials value is a WARN,
        # not a FAIL. Guards against a truthy check that would escalate a
        # non-"true" value (e.g. "false") into a false high-severity finding.
        f = cors.check_cors(PROBE, "false")
        self.assertEqual(f.status, WARN)
        self.assertIn("without credentials", f.detail)

    def test_null_origin_with_credentials_fails(self):
        f = cors.check_cors("null", "true")
        self.assertEqual(f.status, FAIL)
        self.assertIn("null", f.detail)

    def test_wildcard_with_credentials_warns(self):
        self.assertEqual(cors.check_cors("*", "true").status, WARN)

    def test_wildcard_without_credentials_passes(self):
        self.assertEqual(cors.check_cors("*", None).status, PASS)

    def test_fixed_trusted_origin_passes(self):
        f = cors.check_cors("https://app.example.com", "true")
        self.assertEqual(f.status, PASS)
        self.assertIn("https://app.example.com", f.detail)


class _ReflectingHandler(BaseHTTPRequestHandler):
    """Mimics a misconfigured API that echoes whatever Origin it receives."""

    def do_GET(self):
        self.send_response(200)
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    def log_message(self, *args):
        pass


class ProbeCorsTest(unittest.TestCase):
    """Runs against a local server only, no internet access needed."""

    def test_probe_sends_foreign_origin_and_detects_reflection(self):
        server = HTTPServer(("127.0.0.1", 0), _ReflectingHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        f = probe_cors(f"http://127.0.0.1:{server.server_address[1]}/", timeout=5)
        self.assertEqual(f.status, FAIL)


if __name__ == "__main__":
    unittest.main()
