"""The runner's check wrappers and lookups when something goes wrong. No network needed."""

import ssl
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest import mock

import dns.exception
import dns.resolver

from webposture import caa, cli, cookies, emailauth, fetch, runner
from webposture.findings import FAIL, WARN


def _cert_error():
    err = ssl.SSLCertVerificationError(1, "certificate verify failed")
    err.verify_code = 62
    err.verify_message = "Hostname mismatch"
    return urllib.error.URLError(err)


class WrapperProblemTest(unittest.TestCase):
    """A lookup that cannot be done is a WARN naming the problem, never a PASS or a crash."""

    def test_cors_probe_failure_warns(self):
        with mock.patch.object(fetch, "fetch_headers", side_effect=OSError("connection reset")):
            finding = runner.probe_cors("https://example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("cors", WARN))
        self.assertIn("could not run the CORS probe: connection reset", finding.detail)

    def test_spf_lookup_problem_warns(self):
        with mock.patch.object(emailauth, "lookup_txt", return_value=(None, "DNS lookup for example.com failed: Timeout")):
            finding = runner.check_spf("https://www.example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("spf", WARN))
        self.assertIn("Timeout", finding.detail)

    def test_dmarc_lookup_problem_warns(self):
        with mock.patch.object(emailauth, "lookup_txt", return_value=(None, "DNS lookup failed: Timeout")):
            finding = runner.check_dmarc("https://example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("dmarc", WARN))

    def test_dkim_lookup_problem_warns(self):
        with mock.patch.object(emailauth, "lookup_txt", return_value=(None, "DNS lookup failed: Timeout")):
            finding = runner.check_dkim("https://example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("dkim", WARN))

    def test_caa_lookup_problem_warns(self):
        with mock.patch.object(caa, "lookup_caa", return_value=(None, [], "CAA lookup for example.com failed: Timeout")):
            finding = runner.check_caa("https://example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("caa", WARN))


class DnsLookupTest(unittest.TestCase):
    """caa.lookup_caa and emailauth.lookup_txt against a mocked resolver."""

    def test_caa_lookup_error_is_reported(self):
        with mock.patch.object(dns.resolver, "resolve", side_effect=dns.exception.Timeout()):
            found_on, records, problem = caa.lookup_caa("www.example.com", 5)
        self.assertEqual((found_on, records), (None, []))
        self.assertEqual(problem, "CAA lookup for www.example.com failed: Timeout")

    def test_no_caa_record_anywhere(self):
        with mock.patch.object(dns.resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
            self.assertEqual(caa.lookup_caa("www.example.com", 5), (None, [], None))

    def test_missing_txt_record_is_an_empty_answer(self):
        with mock.patch.object(dns.resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
            self.assertEqual(emailauth.lookup_txt("example.com", 5), ([], None))

    def test_txt_lookup_error_is_reported(self):
        with mock.patch.object(dns.resolver, "resolve", side_effect=dns.exception.Timeout()):
            self.assertEqual(emailauth.lookup_txt("example.com", 5), (None, "DNS lookup for example.com failed: Timeout"))


class InsecureFetchFailureTest(unittest.TestCase):
    def test_target_that_fails_even_unverified_keeps_the_certificate_finding(self):
        args = cli.build_parser().parse_args(["bad-cert.example", "--insecure", "--retries", "0"])
        with mock.patch.object(fetch, "fetch_with_retries", side_effect=[_cert_error(), urllib.error.URLError("refused")]):
            result, code, error = runner.scan("bad-cert.example", args)
        self.assertEqual(code, 1)
        self.assertEqual([(f.check, f.status) for f in result["findings"]], [("tls-certificate", FAIL)])
        self.assertIn("even without certificate verification", result["note"])
        self.assertIn("bad-cert.example", error)


class CookieEdgeCaseTest(unittest.TestCase):
    NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)

    def test_empty_attributes_are_ignored(self):
        name, attributes = cookies.parse_set_cookie("id=1;; Secure;")
        self.assertEqual(name, "id")
        self.assertIn("secure", attributes)

    def test_invalid_max_age_falls_back_to_expires(self):
        past = (self.NOW - timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S GMT")
        self.assertTrue(cookies.is_deletion({"max-age": "soon", "expires": past}, self.NOW))
        self.assertFalse(cookies.is_deletion({"max-age": "soon"}, self.NOW))

    def test_invalid_expires_is_not_a_deletion(self):
        self.assertFalse(cookies.is_deletion({"expires": "not a date"}, self.NOW))

    def test_expires_without_a_zone_is_read_as_utc(self):
        self.assertTrue(cookies.is_deletion({"expires": "Thu, 01 Jan 1970 00:00:00"}, self.NOW))


class FetchFailureTest(unittest.TestCase):
    def test_fetch_text_returns_no_status_when_nothing_answers(self):
        with mock.patch.object(fetch.urllib.request, "urlopen", side_effect=urllib.error.URLError("refused")):
            self.assertEqual(fetch.fetch_text("https://example.com/.well-known/security.txt", 5, 1024), (None, None, ""))


if __name__ == "__main__":
    unittest.main()
