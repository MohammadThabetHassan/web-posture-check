"""The runner's check wrappers and lookups when something goes wrong. No network needed."""

import io
import json
import socket
import ssl
import unittest
import urllib.error
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest import mock

import dns.exception
import dns.resolver

from webposture import caa, cli, cookies, emailauth, fetch, runner
from webposture.findings import FAIL, PASS, WARN


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
        with mock.patch.object(emailauth, "lookup_txt", return_value=([], "DNS lookup for example.com failed: Timeout")):
            finding = runner.check_spf("https://www.example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("spf", WARN))
        self.assertIn("Timeout", finding.detail)

    def test_dmarc_lookup_problem_warns(self):
        with mock.patch.object(emailauth, "lookup_txt", return_value=([], "DNS lookup failed: Timeout")):
            finding = runner.check_dmarc("https://example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("dmarc", WARN))

    def test_dkim_lookup_problem_warns(self):
        with mock.patch.object(emailauth, "lookup_txt", return_value=([], "DNS lookup failed: Timeout")):
            finding = runner.check_dkim("https://example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("dkim", WARN))

    def test_caa_lookup_problem_warns(self):
        with mock.patch.object(caa, "lookup_caa", return_value=(None, [], "CAA lookup for example.com failed: Timeout")):
            finding = runner.check_caa("https://example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("caa", WARN))


class DnsWrapperTest(unittest.TestCase):
    """What the wrappers pass on when the lookups work. No network needed."""

    def test_spf_record_of_the_mail_domain_is_checked(self):
        with mock.patch.object(emailauth, "lookup_txt", return_value=(["v=spf1 -all"], None)) as lookup:
            finding = runner.check_spf("https://www.example.com/", 5)
        lookup.assert_called_once_with("example.com", 5)
        self.assertEqual((finding.check, finding.status), ("spf", PASS))

    def test_no_dmarc_record_on_any_candidate(self):
        with mock.patch.object(emailauth, "lookup_txt", return_value=([], None)) as lookup:
            finding = runner.check_dmarc("https://shop.example.com/", 5)
        self.assertEqual([c.args[0] for c in lookup.call_args_list], ["_dmarc.shop.example.com", "_dmarc.example.com"])
        self.assertEqual((finding.check, finding.status), ("dmarc", WARN))
        self.assertIn("no DMARC record", finding.detail)

    def test_caa_records_are_checked(self):
        with mock.patch.object(caa, "lookup_caa", return_value=("example.com", [(0, "issue", "letsencrypt.org")], None)):
            finding = runner.check_caa("https://www.example.com/", 5)
        self.assertEqual((finding.check, finding.status), ("caa", PASS))
        self.assertIn("letsencrypt.org", finding.detail)


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
            self.assertEqual(emailauth.lookup_txt("example.com", 5), ([], "DNS lookup for example.com failed: Timeout"))


class InsecureFetchFailureTest(unittest.TestCase):
    def test_target_that_fails_even_unverified_keeps_the_certificate_finding(self):
        options = runner.ScanOptions(insecure=True, retries=0)
        with mock.patch.object(fetch, "fetch_with_retries", side_effect=[_cert_error(), urllib.error.URLError("refused")]):
            result, code = runner.scan("bad-cert.example", options)
        # Nothing could be fetched, so the target was not scanned: exit 2, as for any unreachable target.
        self.assertEqual(code, 2)
        self.assertEqual([(f.check, f.status) for f in result["findings"]], [("tls-certificate", FAIL)])
        self.assertIn("even without certificate verification", str(result["note"]))
        self.assertIn("bad-cert.example", result["error"])

    def test_json_keeps_the_finding_the_note_and_the_error(self):
        out = io.StringIO()
        with mock.patch.object(fetch, "fetch_with_retries", side_effect=[_cert_error(), urllib.error.URLError("refused")]), \
                redirect_stdout(out), mock.patch("sys.stderr", io.StringIO()):
            code = cli.main(["bad-cert.example", "--insecure", "--retries", "0", "--json"])
        data = json.loads(out.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual([(f["check"], f["status"]) for f in data["findings"]], [("tls-certificate", "FAIL")])
        self.assertIn("even without certificate verification", data["note"])
        self.assertEqual(data["error"], "could not fetch https://bad-cert.example: refused")


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

    def test_max_age_must_be_an_optional_minus_and_digits(self):
        # RFC 6265 section 5.2.2. Python's int() would accept "+0" and "0_0" and
        # call the cookie deleted, hiding it from the check.
        for value in ("+0", "0_0", " 0x0", ""):
            self.assertFalse(cookies.is_deletion({"max-age": value}, self.NOW), repr(value))
        for value in ("0", "-1", "-0"):
            self.assertTrue(cookies.is_deletion({"max-age": value}, self.NOW), value)

    def test_invalid_expires_is_not_a_deletion(self):
        self.assertFalse(cookies.is_deletion({"expires": "not a date"}, self.NOW))

    def test_expires_without_a_zone_is_read_as_utc(self):
        self.assertTrue(cookies.is_deletion({"expires": "Thu, 01 Jan 1970 00:00:00"}, self.NOW))


class FetchFailureTest(unittest.TestCase):
    def test_fetch_text_returns_no_status_when_nothing_answers(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.assertEqual(fetch.fetch_text(f"http://127.0.0.1:{port}/.well-known/security.txt", 5, 1024), (None, None, ""))



class DnsApplicabilityTest(unittest.TestCase):
    """An IP address or a single-label host has no domain records, so the DNS checks are skipped, not scored."""

    def test_ip_addresses_and_single_label_hosts_are_skipped(self):
        for url in ("https://127.0.0.1/", "http://[::1]:8443/x", "https://203.0.113.7:8443/", "http://localhost:8080/"):
            for check in (runner.check_spf, runner.check_dmarc, runner.check_dkim, runner.check_caa):
                with mock.patch.object(emailauth, "lookup_txt") as lookup, mock.patch.object(caa, "lookup_caa") as caa_lookup:
                    finding = check(url, 5)
                lookup.assert_not_called()
                caa_lookup.assert_not_called()
                self.assertEqual(finding.status, WARN, url)
                self.assertTrue(finding.detail.startswith("skipped:"), finding.detail)

    def test_skipped_dns_checks_leave_the_score_and_exit_code_alone(self):
        from webposture import score
        findings = [runner.check_spf("https://127.0.0.1/", 5), runner.check_caa("https://127.0.0.1/", 5)]
        self.assertIsNone(score.compute(findings))
        self.assertEqual(runner.exit_code(findings, "warn"), 0)

    def test_a_domain_name_is_looked_up(self):
        self.assertIsNone(runner.dns_not_applicable("https://www.example.com/"))

if __name__ == "__main__":
    unittest.main()
