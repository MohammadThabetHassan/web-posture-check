import unittest
from datetime import datetime, timezone

from webposture import securitytxt
from webposture.findings import PASS, WARN

NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
GOOD = "Contact: mailto:security@example.com\nExpires: 2027-06-01T00:00:00.000Z\nPreferred-Languages: en\n"


def check(body=GOOD, status=200, content_type="text/plain; charset=utf-8"):
    return securitytxt.check_security_txt(status, content_type, body, NOW)


class SecurityTxtTest(unittest.TestCase):
    def test_valid_file_passes(self):
        f = check()
        self.assertEqual(f.status, PASS)
        self.assertIn("Contact: mailto:security@example.com", f.detail)
        self.assertIn("expires 2027-06-01", f.detail)

    def test_missing_file_warns(self):
        for status in (None, 404):
            f = check(body="", status=status)
            self.assertEqual(f.status, WARN, status)
            self.assertIn("no /.well-known/security.txt", f.detail)

    def test_non_404_error_status_warns_with_the_status(self):
        # A 403 or 500 on the path is not the same as a missing file (some WAFs
        # block /.well-known/); report the status rather than the fields.
        for status in (403, 500):
            f = check(body="", status=status)
            self.assertEqual(f.status, WARN, status)
            self.assertIn(f"returned HTTP {status}", f.detail)

    def test_html_catch_all_page_is_not_accepted(self):
        f = check(body="<html>Contact: x</html>", content_type="text/html; charset=utf-8")
        self.assertEqual(f.status, WARN)
        self.assertIn("not text/plain", f.detail)

    def test_missing_contact_warns(self):
        f = check("Expires: 2027-06-01T00:00:00Z\n")
        self.assertEqual(f.status, WARN)
        self.assertIn("required Contact", f.detail)

    def test_missing_expires_warns(self):
        self.assertIn("required Expires", check("Contact: mailto:a@example.com\n").detail)

    def test_expired_warns(self):
        f = check("Contact: mailto:a@example.com\nExpires: 2026-01-01T00:00:00Z\n")
        self.assertEqual(f.status, WARN)
        self.assertIn("expired on 2026-01-01", f.detail)

    def test_expires_more_than_a_year_away_warns(self):
        f = check("Contact: mailto:a@example.com\nExpires: 2030-04-01T00:00:00z\n")
        self.assertEqual(f.status, WARN)
        self.assertIn("more than a year away", f.detail)

    def test_duplicate_or_invalid_expires_warns(self):
        self.assertIn("only once", check(GOOD + "Expires: 2027-01-01T00:00:00Z\n").detail)
        self.assertIn("not a valid RFC 3339", check("Contact: x\nExpires: next year\n").detail)
        # No time zone offset: not RFC 3339.
        self.assertIn("not a valid RFC 3339", check("Contact: x\nExpires: 2027-06-01T00:00:00\n").detail)

    def test_field_names_are_case_insensitive_and_comments_ignored(self):
        f = check("# Contact: wrong\nCONTACT: https://example.com/report\nexpires: 2027-06-01T00:00:00+04:00\n")
        self.assertEqual(f.status, PASS)
        self.assertIn("https://example.com/report", f.detail)

    def test_pgp_signed_file_with_dash_escaping(self):
        body = (
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
            "Contact: mailto:security@example.com\n- Expires: 2027-06-01T00:00:00Z\n"
            "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n"
        )
        self.assertEqual(check(body).status, PASS)


if __name__ == "__main__":
    unittest.main()
