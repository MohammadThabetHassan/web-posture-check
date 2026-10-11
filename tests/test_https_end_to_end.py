"""End-to-end tests over HTTPS: the real CLI against a local HTTPS server.

test_end_to_end covers plain HTTP. Here the server speaks TLS with a
certificate from a throwaway CA (tls_fixtures), and SSL_CERT_FILE makes that
CA the only one trusted, so every request the tool makes verifies against it:
the page itself, the CORS probe, security.txt and the certificate check.
That exercises the checks that only mean something over HTTPS (HSTS, Secure
cookies, the certificate), and --insecure with a certificate that is not
trusted. Skipped when openssl is not installed. No internet needed.
"""

import io
import json
import os
import shutil
import ssl
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from tls_fixtures import OPENSSL, make_certificates
from webposture import cli

# Every check a local HTTPS server can answer. https-redirect would probe port
# 80, tls-protocols depends on what the local OpenSSL offers (test_tls_live
# covers it), and the DNS checks need real domains.
HTTPS_CHECKS = ("http-status,hsts,csp,x-content-type-options,clickjacking,referrer-policy,permissions-policy,"
                "cross-origin-isolation,x-xss-protection,information-leakage,cookies,cors,tls-certificate,security-txt")


class _Site(BaseHTTPRequestHandler):
    # No version in the Server header, so information-leakage has nothing to report.
    server_version = "test-site"
    sys_version = ""

    def log_message(self, *args):
        pass


class _GoodSite(_Site):
    """The headers and security.txt of a well-configured HTTPS site."""

    def do_GET(self):
        if self.path == "/.well-known/security.txt":
            expires = (datetime.now(timezone.utc) + timedelta(days=180)).strftime("%Y-%m-%dT%H:%M:%SZ")
            body = f"Contact: mailto:security@example.test\nExpires: {expires}\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Set-Cookie", "__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.send_header("Content-Length", "0")
        self.end_headers()


class _BadSite(_Site):
    """HTTPS without HSTS, and a session cookie without Secure."""

    def do_GET(self):
        self.send_response(200 if self.path == "/" else 404)
        if self.path == "/":
            self.send_header("Set-Cookie", "sid=abc; Path=/; HttpOnly; SameSite=Lax")
        self.send_header("Content-Length", "0")
        self.end_headers()


class _HttpsServer(ThreadingHTTPServer):
    """An HTTP server whose connections are TLS (1.2 or newer), with the given certificate."""

    def __init__(self, handler, certfile, keyfile):
        super().__init__(("127.0.0.1", 0), handler)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(certfile, keyfile)

    def finish_request(self, request, client_address):
        # The handshake runs in the request's own thread, so a client that
        # gives up on it affects only its own connection.
        request.settimeout(5)
        try:
            connection = self.context.wrap_socket(request, server_side=True)
        except OSError:
            return
        try:
            super().finish_request(connection, client_address)
        finally:
            connection.close()

    def handle_error(self, request, client_address):
        pass  # a client that hangs up mid-request is not a test failure


@unittest.skipUnless(OPENSSL, "the openssl command is needed to make test certificates")
class HttpsEndToEndTest(unittest.TestCase):
    folder: str
    ca: str
    certfile: str
    keyfile: str

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.mkdtemp()
        cls.ca, cls.certfile, cls.keyfile = make_certificates(cls.folder)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.folder, ignore_errors=True)

    def _serve(self, handler):
        server = _HttpsServer(handler, self.certfile, self.keyfile)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"https://127.0.0.1:{server.server_address[1]}/"

    def _run(self, *argv, trusted=True):
        """Run the CLI with only the test CA trusted (trusted=True) or with no CA that knows the server."""
        out = io.StringIO()
        # An empty file means no CA at all, so the test does not depend on the system's trust store.
        trust = self.ca if trusted else os.devnull
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": trust}), redirect_stdout(out), \
                mock.patch("sys.stderr", io.StringIO()):
            code = cli.main([*argv, "--json", "--retries", "0", "--timeout", "5"])
        return code, json.loads(out.getvalue())

    @staticmethod
    def _statuses(result):
        return {f["check"]: f["status"] for f in result["findings"]}

    def test_well_configured_https_site_passes_every_check(self):
        code, result = self._run(self._serve(_GoodSite), "--only", HTTPS_CHECKS)
        statuses = self._statuses(result)
        self.assertEqual(statuses, dict.fromkeys(HTTPS_CHECKS.split(","), "PASS"), result["findings"])
        self.assertEqual((result["score"], result["grade"], code), (100, "A", 0))
        details = {f["check"]: f["detail"] for f in result["findings"]}
        self.assertIn("certificate valid until", details["tls-certificate"])
        self.assertIn("Contact: mailto:security@example.test", details["security-txt"])

    def test_https_site_without_hsts_or_secure_cookie_fails_them(self):
        code, result = self._run(self._serve(_BadSite), "--only", "hsts,cookies,tls-certificate")
        statuses = self._statuses(result)
        self.assertEqual(statuses["hsts"], "FAIL")
        # Over HTTPS a session cookie without Secure can still leak over plain HTTP.
        self.assertEqual(statuses["cookies"], "FAIL")
        self.assertEqual(statuses["tls-certificate"], "PASS")
        self.assertEqual(code, 1)

    def test_untrusted_certificate_is_a_finding_and_the_other_checks_wait_for_insecure(self):
        url = self._serve(_GoodSite)
        code, result = self._run(url, "--only", "hsts,csp", trusted=False)
        self.assertEqual([(f["check"], f["status"]) for f in result["findings"]], [("tls-certificate", "FAIL")])
        self.assertIn("not trusted", result["findings"][0]["detail"])
        self.assertIn("--insecure runs them anyway", result["note"])
        self.assertEqual(code, 1)

        code, result = self._run(url, "--only", "hsts,csp", "--insecure", trusted=False)
        self.assertEqual(self._statuses(result), {"tls-certificate": "FAIL", "hsts": "PASS", "csp": "PASS"})
        self.assertIn("ran with --insecure", result["note"])
        self.assertNotIn("error", result)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
