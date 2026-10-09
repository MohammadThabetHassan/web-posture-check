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

    def test_other_verify_error_is_reported_without_checking_expiry(self):
        f = tls.check_certificate(None, 62, "Hostname mismatch", NOW)
        self.assertEqual(f.status, WARN)
        self.assertIn("Hostname mismatch", f.detail)
        self.assertIn("expiry was not checked", f.detail)


if __name__ == "__main__":
    unittest.main()
