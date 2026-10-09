import io
import json
import os
import ssl
import tempfile
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

    def test_empty_value_is_a_usage_error_not_zero_checks(self):
        # A value with no names (e.g. "--only ,") must be rejected, not accepted
        # as an empty selection that would silently run no checks and exit 0.
        err = io.StringIO()
        with mock.patch("sys.stderr", err), self.assertRaises(SystemExit) as ctx:
            cli.main(["example.com", "--only", ","])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("no check names given", err.getvalue())

    def test_only_and_skip_cannot_be_combined(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["example.com", "--only", "caa", "--skip", "spf"])
        self.assertEqual(ctx.exception.code, 2)


class ScoreOutputTest(unittest.TestCase):
    """The score and grade reach the JSON output. No network needed."""

    def test_json_carries_score_and_grade(self):
        out = io.StringIO()
        with mock.patch.object(cli, "fetch_headers", return_value=("https://example.com/", {}, [], 200)), \
                redirect_stdout(out):
            code = cli.main(["example.com", "--only", "http-status,hsts", "--json"])
        result = json.loads(out.getvalue())
        # http-status passes and hsts fails on empty headers: 1 of 2 scored -> 50, F.
        self.assertEqual(result["score"], 50)
        self.assertEqual(result["grade"], "F")
        self.assertEqual(code, 1)


class MultipleTargetsTest(unittest.TestCase):
    """Several targets in one run. Fetches are mocked; no network needed."""

    # hsts passes on good.example, fails on bad.example; down.example is unreachable.
    RESPONSES = {
        "https://good.example": ("https://good.example/", {"Strict-Transport-Security": "max-age=31536000"}, [], 200),
        "https://bad.example": ("https://bad.example/", {}, [], 200),
    }

    def _fetch(self, url, timeout, extra_headers=None):
        if url not in self.RESPONSES:
            raise urllib.error.URLError(OSError("Name or service not known"))
        return self.RESPONSES[url]

    def _run(self, *argv):
        out = io.StringIO()
        with mock.patch.object(cli, "fetch_headers", side_effect=self._fetch), redirect_stdout(out), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            code = cli.main([*argv, "--only", "hsts"])
        return code, out.getvalue()

    def test_json_lists_every_reachable_target(self):
        code, out = self._run("good.example", "bad.example", "--json")
        results = json.loads(out)["results"]
        self.assertEqual([r["url"] for r in results], ["https://good.example/", "https://bad.example/"])
        self.assertEqual([r["findings"][0]["status"] for r in results], ["PASS", "FAIL"])
        self.assertEqual(code, 1)

    def test_single_target_json_shape_is_unchanged(self):
        _, out = self._run("good.example", "--json")
        self.assertNotIn("results", json.loads(out))

    def test_worst_exit_code_wins_and_other_targets_still_run(self):
        code, out = self._run("good.example", "down.example", "bad.example")
        self.assertEqual(code, 2)
        self.assertIn("Target: https://good.example/", out)
        self.assertIn("Target: https://bad.example/", out)

    def test_all_passing_targets_exit_0(self):
        self.assertEqual(self._run("good.example", "good.example")[0], 0)

    def test_targets_file_skips_blanks_and_comments_and_adds_to_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "sites.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# client sites\nbad.example\n\n  good.example  \n")
            _, out = self._run("good.example", "--targets-file", path, "--json")
        self.assertEqual([r["url"] for r in json.loads(out)["results"]],
                         ["https://good.example/", "https://bad.example/", "https://good.example/"])

    def test_no_targets_is_a_usage_error(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main([])
        self.assertEqual(ctx.exception.code, 2)

    def test_missing_targets_file_is_a_usage_error(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err), self.assertRaises(SystemExit) as ctx:
            cli.main(["--targets-file", "does-not-exist.txt"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("could not read --targets-file", err.getvalue())


if __name__ == "__main__":
    unittest.main()
