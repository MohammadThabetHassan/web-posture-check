import socket
import ssl
import unittest
from datetime import datetime, timedelta, timezone

from webposture import tls
from webposture.findings import PASS, WARN, FAIL

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


class CheckCertificateTest(unittest.TestCase):
    def test_long_validity_passes(self):
        f = tls.check_certificate(NOW + timedelta(days=90), None, None, NOW)
        self.assertEqual(f.status, PASS)
        self.assertIn("valid until 2027-01-08 (90 days)", f.detail)

    def test_expiring_within_14_days_warns(self):
        f = tls.check_certificate(NOW + timedelta(days=5), None, None, NOW)
        self.assertEqual(f.status, WARN)
        self.assertIn("expires in 5 day(s)", f.detail)

    def test_expiring_within_a_day_reads_clearly(self):
        # A certificate with hours left is still valid but the most urgent case.
        # "expires in 0 day(s)" reads like a bug, so under a day it says so plainly.
        f = tls.check_certificate(NOW + timedelta(hours=12), None, None, NOW)
        self.assertEqual(f.status, WARN)
        self.assertIn("expires in less than a day", f.detail)
        self.assertNotIn("0 day(s)", f.detail)

    def test_boundary_14_days_passes_and_just_under_warns(self):
        self.assertEqual(tls.check_certificate(NOW + timedelta(days=14), None, None, NOW).status, PASS)
        self.assertEqual(tls.check_certificate(NOW + timedelta(days=13, hours=23), None, None, NOW).status, WARN)

    def test_expired_verify_error_fails(self):
        f = tls.check_certificate(None, tls.VERIFY_CODE_EXPIRED, "certificate has expired", NOW)
        self.assertEqual(f.status, FAIL)
        self.assertIn("expired", f.detail)

    def test_past_not_after_fails(self):
        f = tls.check_certificate(NOW - timedelta(days=1), None, None, NOW)
        self.assertEqual(f.status, FAIL)
        self.assertIn("expired on 2026-10-09", f.detail)

    def test_other_verify_errors_fail_with_the_reason(self):
        for code, message in ((62, "Hostname mismatch"), (18, "self-signed certificate"), (9, "certificate is not yet valid")):
            f = tls.check_certificate(None, code, message, NOW)
            self.assertEqual(f.status, FAIL, code)
            self.assertIn(f"not trusted: {message}", f.detail)



def _ssl_error(reason):
    err = ssl.SSLError(1, reason)
    err.reason = reason
    return err


class LegacyProtocolsTest(unittest.TestCase):
    def test_all_refused_passes(self):
        f = tls.check_legacy_protocols({"TLS 1.0": tls.REFUSED, "TLS 1.1": tls.REFUSED})
        self.assertEqual(f.status, PASS)

    def test_any_accepted_fails_and_names_it(self):
        f = tls.check_legacy_protocols({"TLS 1.0": tls.REFUSED, "TLS 1.1": tls.ACCEPTED})
        self.assertEqual(f.status, FAIL)
        self.assertIn("accepts TLS 1.1", f.detail)
        self.assertNotIn("TLS 1.0", f.detail)

    def test_accepted_wins_over_untestable(self):
        f = tls.check_legacy_protocols({"TLS 1.0": tls.UNTESTABLE, "TLS 1.1": tls.ACCEPTED})
        self.assertEqual(f.status, FAIL)

    def test_multiple_accepted_versions_are_all_named(self):
        # The common real case (e.g. example.com) accepts both versions, so the
        # finding must name every accepted version, not just the first one.
        f = tls.check_legacy_protocols({"TLS 1.0": tls.ACCEPTED, "TLS 1.1": tls.ACCEPTED})
        self.assertEqual(f.status, FAIL)
        self.assertIn("accepts TLS 1.0, TLS 1.1", f.detail)

    def test_untestable_is_a_warning_not_a_pass(self):
        # Our own OpenSSL refusing must never be reported as the server refusing.
        f = tls.check_legacy_protocols({"TLS 1.0": tls.UNTESTABLE, "TLS 1.1": tls.REFUSED})
        self.assertEqual(f.status, WARN)
        self.assertIn("could not test TLS 1.0", f.detail)


class ClassifyHandshakeErrorTest(unittest.TestCase):
    def test_local_cipher_refusal_is_untestable(self):
        for reason in ("NO_CIPHERS_AVAILABLE", "NO_PROTOCOLS_AVAILABLE"):
            self.assertEqual(tls.classify_handshake_error(_ssl_error(reason)), tls.UNTESTABLE, reason)

    def test_server_alerts_are_refusals(self):
        for reason in ("TLSV1_ALERT_PROTOCOL_VERSION", "UNSUPPORTED_PROTOCOL", "WRONG_VERSION_NUMBER"):
            self.assertEqual(tls.classify_handshake_error(_ssl_error(reason)), tls.REFUSED, reason)

    def test_connection_reset_is_a_refusal(self):
        self.assertEqual(tls.classify_handshake_error(ConnectionResetError()), tls.REFUSED)

    def test_timeout_is_untestable(self):
        self.assertEqual(tls.classify_handshake_error(socket.timeout()), tls.UNTESTABLE)


if __name__ == "__main__":
    unittest.main()
