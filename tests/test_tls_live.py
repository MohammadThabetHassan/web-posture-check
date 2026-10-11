"""The TLS code against a real TLS server on 127.0.0.1.

A throwaway CA and a certificate for localhost are made with the openssl
command, so the certificate fetch and the protocol probes run real
handshakes. Skipped when openssl is not installed. No internet needed.
"""

import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from webposture import runner, tls
from webposture.findings import FAIL, PASS, WARN

OPENSSL = shutil.which("openssl")
CERT_DAYS = 60


def _openssl(folder, *args):
    # A minimal config of our own, so a missing or unusual system openssl.cnf does not matter.
    env = dict(os.environ, OPENSSL_CONF=os.path.join(folder, "openssl.cnf"))
    done = subprocess.run([OPENSSL or "openssl", *args], cwd=folder, env=env, capture_output=True, text=True)
    if done.returncode:
        raise RuntimeError(f"openssl {args[0]} failed: {done.stderr}")


def _make_certificates(folder):
    """CA certificate ca.pem, and server.pem/server.key for localhost signed by it."""
    with open(os.path.join(folder, "openssl.cnf"), "w", encoding="ascii") as handle:
        handle.write("[req]\ndistinguished_name = dn\n[dn]\n")
    _openssl(folder, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
             "-days", "2", "-subj", "/CN=web-posture-check test CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    _openssl(folder, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr",
             "-subj", "/CN=localhost")
    with open(os.path.join(folder, "server.ext"), "w", encoding="ascii") as handle:
        handle.write("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                     "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                     "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    _openssl(folder, "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
             "-out", "server.pem", "-days", str(CERT_DAYS), "-extfile", "server.ext")


class _TlsServer:
    """Completes TLS handshakes (TLS 1.2 or newer only) until stopped."""

    def __init__(self, certfile, keyfile):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(certfile, keyfile)
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return  # the listening socket was closed
            try:
                conn.settimeout(5)
                with self.context.wrap_socket(conn, server_side=True):
                    pass
            except OSError:
                pass  # a refused or abandoned handshake is what some tests want
            finally:
                conn.close()

    def stop(self):
        self.sock.close()
        self.thread.join(5)


@unittest.skipUnless(OPENSSL, "the openssl command is needed to make test certificates")
class LiveTlsTest(unittest.TestCase):
    folder: str
    ca: str
    server: _TlsServer

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.mkdtemp()
        _make_certificates(cls.folder)
        cls.ca = os.path.join(cls.folder, "ca.pem")
        cls.server = _TlsServer(os.path.join(cls.folder, "server.pem"), os.path.join(cls.folder, "server.key"))

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        shutil.rmtree(cls.folder, ignore_errors=True)

    def _trusting_our_ca(self):
        """fetch_certificate with the system trust store replaced by the test CA."""
        real = ssl.create_default_context
        return mock.patch.object(ssl, "create_default_context", side_effect=lambda *a, **k: real(cafile=self.ca))

    def test_certificate_from_an_unknown_ca_is_not_trusted(self):
        not_after, verify_code, verify_message = tls.fetch_certificate("localhost", self.server.port, timeout=5)
        self.assertIsNone(not_after)
        self.assertTrue(verify_code)
        self.assertTrue(verify_message)
        finding = tls.check_certificate(not_after, verify_code, verify_message, now=datetime.now(timezone.utc))
        self.assertEqual(finding.status, FAIL)
        self.assertIn("not trusted", finding.detail)

    def test_trusted_certificate_returns_its_expiry(self):
        with self._trusting_our_ca():
            not_after, verify_code, _ = tls.fetch_certificate("localhost", self.server.port, timeout=5)
        self.assertIsNone(verify_code)
        assert not_after is not None
        expected = datetime.now(timezone.utc) + timedelta(days=CERT_DAYS)
        self.assertLess(abs(not_after - expected), timedelta(days=1))

    def test_wrong_host_name_is_not_trusted(self):
        # The certificate is for localhost and 127.0.0.1 only. Connect to our server while asking for another name.
        connect = socket.create_connection
        with self._trusting_our_ca(), \
                mock.patch.object(socket, "create_connection",
                                  side_effect=lambda address, timeout: connect(("127.0.0.1", address[1]), timeout)):
            not_after, verify_code, verify_message = tls.fetch_certificate("wrong.example", self.server.port, timeout=5)
        self.assertIsNone(not_after)
        self.assertTrue(verify_code)
        self.assertIn("mismatch", str(verify_message).lower())

    def test_runner_check_tls_passes_a_trusted_certificate(self):
        with self._trusting_our_ca():
            finding = runner.check_tls(f"https://localhost:{self.server.port}/", timeout=5)
        self.assertEqual(finding.status, PASS)
        self.assertIn("certificate valid until", finding.detail)

    def test_modern_tls_is_accepted(self):
        self.assertEqual(tls.probe_version("localhost", self.server.port, ssl.TLSVersion.TLSv1_2, timeout=5), tls.ACCEPTED)

    def test_server_refusing_tls_1_0_and_1_1_is_never_reported_as_accepting_them(self):
        # Refused when the local OpenSSL can offer the old versions, untestable when it cannot: never a false FAIL.
        outcomes = tls.probe_legacy_protocols("localhost", self.server.port, timeout=5)
        self.assertEqual(list(outcomes), ["TLS 1.0", "TLS 1.1"])
        self.assertNotIn(tls.ACCEPTED, outcomes.values())
        finding = runner.check_legacy_tls(f"https://localhost:{self.server.port}/", timeout=5)
        self.assertIn(finding.status, (PASS, WARN))


class TlsWithoutServerTest(unittest.TestCase):
    """Paths that need no server at all."""

    def test_nothing_listening_is_an_os_error_for_the_runner_to_report(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        finding = runner.check_tls(f"https://127.0.0.1:{port}/", timeout=2)
        self.assertEqual(finding.status, WARN)
        self.assertIn("could not check the certificate", finding.detail)

    def test_plain_http_has_no_certificate_or_tls_versions_to_check(self):
        self.assertEqual(runner.check_tls("http://example.com/", 5).status, WARN)
        self.assertEqual(runner.check_legacy_tls("http://example.com/", 5).status, WARN)

    def test_version_the_local_library_cannot_set_is_untestable(self):
        with mock.patch.object(ssl.SSLContext, "set_ciphers", side_effect=ssl.SSLError("no cipher match")):
            self.assertEqual(tls.probe_version("127.0.0.1", 1, ssl.TLSVersion.TLSv1_2, timeout=1), tls.UNTESTABLE)

    def test_a_certificate_without_an_expiry_date_is_not_trusted(self):
        class FakeTls:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def getpeercert(self):
                return {}

        context = mock.Mock()
        context.wrap_socket.return_value = FakeTls()
        with mock.patch.object(ssl, "create_default_context", return_value=context), \
                mock.patch.object(socket, "create_connection", return_value=FakeTls()):
            self.assertEqual(tls.fetch_certificate("example.com"), (None, None, "the server sent no certificate expiry date"))


if __name__ == "__main__":
    unittest.main()
