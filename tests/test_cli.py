import io
import json
import ssl
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

from webposture import cli, emailauth


def _cert_error(code, message):
    err = ssl.SSLCertVerificationError(1, "certificate verify failed")
    err.verify_code = code
    err.verify_message = message
    return urllib.error.URLError(err)


class CertificateErrorTest(unittest.TestCase):
    """The main fetch failing on a certificate is a finding, not a crash. No network needed."""

    def _run(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(list(argv))
        return code, out.getvalue()

    def test_expired_certificate_is_reported_and_exits_1(self):
        with mock.patch.object(cli, "fetch_headers", side_effect=_cert_error(10, "certificate has expired")):
            code, out = self._run("expired.example")
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] tls-certificate: certificate has expired", out)
        self.assertIn("other checks skipped", out)

    def test_untrusted_certificate_in_json(self):
        with mock.patch.object(cli, "fetch_headers", side_effect=_cert_error(62, "Hostname mismatch")):
            code, out = self._run("wrong.example", "--json")
        result = json.loads(out)
        self.assertEqual(code, 1)
        self.assertIsNone(result["status"])
        self.assertEqual(result["findings"][0]["status"], "FAIL")
        self.assertIn("not trusted: Hostname mismatch", result["findings"][0]["detail"])

    def test_certificate_error_json_carries_skip_note(self):
        # --json documents a top-level note explaining that the other checks
        # were skipped. A consumer parsing the output relies on it, so pin it.
        with mock.patch.object(cli, "fetch_headers", side_effect=_cert_error(10, "certificate has expired")):
            code, out = self._run("expired.example", "--json")
        result = json.loads(out)
        self.assertEqual(code, 1)
        self.assertIn("note", result)
        self.assertIn("other checks skipped", result["note"])

    def test_other_fetch_errors_still_exit_2(self):
        err = urllib.error.URLError(OSError("Name or service not known"))
        with mock.patch.object(cli, "fetch_headers", side_effect=err):
            with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(cli.main(["missing.example"]), 2)


class DmarcFallbackTest(unittest.TestCase):
    """The CLI walks from the subdomain up to the organizational domain. No network needed."""

    def test_falls_back_to_parent_when_subdomain_has_no_record(self):
        # mail.google.com publishes no _dmarc record, so the check must fall
        # back to _dmarc.google.com and report the policy found there.
        def fake_lookup(name, timeout):
            if name == "_dmarc.google.com":
                return ["v=DMARC1; p=reject"], None
            return [], None  # every other name, including the subdomain, has nothing

        with mock.patch.object(emailauth, "lookup_txt", side_effect=fake_lookup):
            finding = cli.check_dmarc("https://mail.google.com/", 5)
        self.assertEqual(finding.status, "PASS")
        self.assertIn("_dmarc.google.com", finding.detail)


class DkimSelectorTest(unittest.TestCase):
    """--dkim-selector checks only the given selectors, not the common guesses. No network."""

    def test_only_given_selectors_are_queried(self):
        looked_up = []

        def fake_lookup(name, timeout):
            looked_up.append(name)
            if name == "custom._domainkey.example.com":
                return ["v=DKIM1; p=MIIBkey"], None
            return [], None

        with mock.patch.object(emailauth, "lookup_txt", side_effect=fake_lookup):
            finding = cli.check_dkim("https://example.com/", 5, selectors=["custom"])
        self.assertEqual(finding.status, "PASS")
        self.assertIn("custom", finding.detail)
        # The common selectors must not be probed once a selector is given.
        self.assertEqual(looked_up, ["custom._domainkey.example.com"])


class CheckSelectionTest(unittest.TestCase):
    """--only/--skip choose checks, and skipped checks make no requests. No network needed."""

    NETWORK = {
        "probe_cors": "cors", "check_tls": "tls-certificate", "check_legacy_tls": "tls-protocols",
        "check_caa": "caa", "check_security_txt": "security-txt", "check_spf": "spf",
        "check_dmarc": "dmarc", "check_dkim": "dkim",
    }

    def _run(self, *argv):
        called = []
        patches = [mock.patch.object(cli, "fetch_headers", return_value=("https://example.com/", {}, [], 200)),
                   mock.patch.object(cli, "fetch_final_url", side_effect=lambda *a: called.append("https-redirect") or "https://example.com/")]
        for func, name in self.NETWORK.items():
            patches.append(mock.patch.object(
                cli, func, side_effect=lambda *a, _n=name: called.append(_n) or cli.Finding(_n, "PASS", "ok")))
        out = io.StringIO()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        with redirect_stdout(out):
            code = cli.main(["example.com", "--json", *argv])
        return code, [f["check"] for f in json.loads(out.getvalue())["findings"]], called

    def test_default_runs_every_check_in_documented_order(self):
        _, checks, _ = self._run()
        self.assertEqual(checks, cli.ALL_CHECKS)

    def test_only_runs_the_named_checks_and_nothing_else(self):
        _, checks, called = self._run("--only", "tls-certificate,caa,hsts")
        self.assertEqual(checks, ["hsts", "tls-certificate", "caa"])
        self.assertEqual(called, ["tls-certificate", "caa"])

    def test_skip_leaves_out_the_named_checks_and_their_requests(self):
        _, checks, called = self._run("--skip", "spf,dmarc,dkim,https-redirect")
        for name in ("spf", "dmarc", "dkim", "https-redirect"):
            self.assertNotIn(name, checks)
            self.assertNotIn(name, called)
        self.assertIn("caa", checks)

    def test_unknown_name_is_a_usage_error_listing_valid_names(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err), self.assertRaises(SystemExit) as ctx:
            cli.main(["example.com", "--only", "tls,caa"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("unknown check name(s): tls", err.getvalue())
        self.assertIn("tls-certificate", err.getvalue())

    def test_only_and_skip_cannot_be_combined(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["example.com", "--only", "caa", "--skip", "spf"])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
