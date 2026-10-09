import sys
import unittest
from unittest import mock

from webposture import emailauth
from webposture.findings import PASS, WARN, FAIL


class MailDomainTest(unittest.TestCase):
    def test_strips_www_and_trailing_dot(self):
        self.assertEqual(emailauth.mail_domain("www.Example.com."), "example.com")
        self.assertEqual(emailauth.mail_domain("shop.example.com"), "shop.example.com")


class CheckSpfTest(unittest.TestCase):
    def check(self, *txt):
        return emailauth.check_spf("example.com", list(txt))

    def test_hard_and_soft_fail_pass(self):
        for record in ("v=spf1 -all", "v=spf1 include:_spf.google.com ~all", "V=SPF1 mx -ALL"):
            self.assertEqual(self.check(record).status, PASS, record)

    def test_other_txt_records_are_ignored(self):
        f = self.check("google-site-verification=abc", "v=spf1 -all", "v=spf10 nonsense")
        self.assertEqual(f.status, PASS)

    def test_missing_record_warns(self):
        f = self.check("google-site-verification=abc")
        self.assertEqual(f.status, WARN)
        self.assertIn("no SPF record", f.detail)

    def test_multiple_records_fail(self):
        f = self.check("v=spf1 -all", "v=spf1 include:x ~all")
        self.assertEqual(f.status, FAIL)
        self.assertIn("2 SPF records", f.detail)

    def test_plus_all_fails(self):
        for record in ("v=spf1 +all", "v=spf1 include:x all"):
            f = self.check(record)
            self.assertEqual(f.status, FAIL, record)
            self.assertIn("every server", f.detail)

    def test_neutral_all_warns(self):
        self.assertIn("neutral", self.check("v=spf1 mx ?all").detail)

    def test_no_all_mechanism_warns(self):
        f = self.check("v=spf1 mx include:x")
        self.assertEqual(f.status, WARN)
        self.assertIn("no 'all' mechanism", f.detail)

    def test_redirect_without_all_passes(self):
        f = self.check("v=spf1 redirect=_spf.example.net")
        self.assertEqual(f.status, PASS)
        self.assertIn("redirect=_spf.example.net", f.detail)


class LookupTxtTest(unittest.TestCase):
    def test_missing_dnspython_is_reported_as_skipped(self):
        blocked = {"dns": None, "dns.resolver": None, "dns.exception": None}
        with mock.patch.dict(sys.modules, blocked):
            txt, problem = emailauth.lookup_txt("example.com", 5)
        self.assertIsNone(txt)
        self.assertIn("web-posture-check[dns]", problem)


if __name__ == "__main__":
    unittest.main()
