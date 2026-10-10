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

    def test_markdown_prints_one_report_per_target(self):
        # Markdown has no "results" wrapper like JSON, so each target must get
        # its own full report. Guards against only the first target rendering.
        _, out = self._run("good.example", "bad.example", "--format", "markdown")
        self.assertEqual(out.count("## Web posture report:"), 2)
        self.assertIn("## Web posture report: https://good.example/", out)
        self.assertIn("## Web posture report: https://bad.example/", out)

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


class FailOnTest(unittest.TestCase):
    """--fail-on sets which status makes the run exit 1. No network needed."""

    # hsts passes; referrer-policy is missing, which is a WARN.
    HEADERS = {"Strict-Transport-Security": "max-age=31536000"}

    def _code(self, *argv):
        with mock.patch.object(cli, "fetch_headers", return_value=("https://example.com/", self.HEADERS, [], 200)), \
                redirect_stdout(io.StringIO()):
            return cli.main(["example.com", "--only", "hsts,referrer-policy", *argv])

    def test_default_only_fails_on_fail(self):
        self.assertEqual(self._code(), 0)
        self.assertEqual(self._code("--fail-on", "fail"), 0)

    def test_fail_on_warn_exits_1_for_a_warning(self):
        self.assertEqual(self._code("--fail-on", "warn"), 1)

    def test_fail_on_warn_passes_a_clean_run(self):
        with mock.patch.object(cli, "fetch_headers", return_value=("https://example.com/", self.HEADERS, [], 200)), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["example.com", "--only", "hsts", "--fail-on", "warn"]), 0)

    def test_skipped_checks_do_not_trip_fail_on_warn(self):
        skipped = cli.Finding("spf", "WARN", "skipped: install the optional DNS support")
        passed = cli.Finding("hsts", "PASS", "ok")
        self.assertEqual(cli.exit_code([passed, skipped], "warn"), 0)
        self.assertEqual(cli.exit_code([passed, cli.Finding("caa", "WARN", "no CAA record")], "warn"), 1)

    def test_fail_on_warn_still_exits_1_on_a_fail(self):
        # warn is a superset of fail: raising the bar to warnings must not stop
        # a FAIL from failing the gate. Guards against warn meaning only {WARN}.
        passed = cli.Finding("hsts", "PASS", "ok")
        failed = cli.Finding("csp", "FAIL", "Content-Security-Policy header is missing")
        self.assertEqual(cli.exit_code([passed, failed], "warn"), 1)

    def test_invalid_level_is_a_usage_error(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["example.com", "--fail-on", "pass"])
        self.assertEqual(ctx.exception.code, 2)


class RetryTest(unittest.TestCase):
    """Transient failures are retried and explained. No network, no real sleeping."""

    OK = ("https://example.com/", {"Strict-Transport-Security": "max-age=31536000"}, [], 200)

    def setUp(self):
        sleep = mock.patch.object(cli.time, "sleep")
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    def _run(self, side_effect, *argv):
        fetch = mock.Mock(side_effect=side_effect)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, "fetch_headers", fetch), redirect_stdout(out), mock.patch("sys.stderr", err):
            code = cli.main(["example.com", "--only", "hsts", *argv])
        return code, fetch.call_count, err.getvalue()

    def test_timeout_then_success_is_retried_once(self):
        code, calls, err = self._run([urllib.error.URLError(TimeoutError("timed out")), self.OK])
        self.assertEqual((code, calls), (0, 2))
        self.assertEqual(err, "")
        self.sleep.assert_called_once_with(cli.RETRY_DELAY_SECONDS)

    def test_connection_reset_is_retried(self):
        code, calls, _ = self._run([urllib.error.URLError(ConnectionResetError(10054, "forcibly closed")), self.OK])
        self.assertEqual((code, calls), (0, 2))

    def test_persistent_timeout_gives_a_clear_message_and_exit_2(self):
        code, calls, err = self._run(urllib.error.URLError(TimeoutError("timed out")), "--timeout", "3", "--retries", "2")
        self.assertEqual((code, calls), (2, 3))
        self.assertIn("did not respond within 3s (3 attempts)", err)
        self.assertIn("try a larger --timeout", err)

    def test_retries_0_tries_once(self):
        code, calls, err = self._run(urllib.error.URLError(ConnectionResetError()), "--retries", "0")
        self.assertEqual((code, calls), (2, 1))
        self.assertIn("closed the connection (1 attempt)", err)

    def test_dns_and_certificate_errors_are_not_retried(self):
        _, calls, err = self._run(urllib.error.URLError(OSError("Name or service not known")))
        self.assertEqual(calls, 1)
        self.assertIn("could not fetch https://example.com: Name or service not known", err)
        _, calls, _ = self._run(_cert_error(10, "certificate has expired"))
        self.assertEqual(calls, 1)
        self.sleep.assert_not_called()

    def test_connection_aborted_is_retried(self):
        # ConnectionAbortedError (WinError 10053) is listed as transient next to
        # ConnectionResetError but was untested; it must be retried too.
        code, calls, _ = self._run([urllib.error.URLError(ConnectionAbortedError(10053, "aborted")), self.OK])
        self.assertEqual((code, calls), (0, 2))

    def test_retries_must_be_between_0_and_5(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["example.com", "--retries", "9"])
        self.assertEqual(ctx.exception.code, 2)


class InsecureTest(unittest.TestCase):
    """--insecure runs the checks after a certificate failure, and only then. No network needed."""

    OK = ("https://bad-cert.example/", {"Strict-Transport-Security": "max-age=31536000"}, [], 200)

    def _run(self, *argv):
        contexts = []

        def fetch(url, timeout, extra_headers=None):
            # Record whether verification was off for this request.
            contexts.append(cli._https_context())
            if contexts[-1] is None:
                raise _cert_error(10, "certificate has expired")
            return self.OK

        out = io.StringIO()
        with mock.patch.object(cli, "fetch_headers", side_effect=fetch), redirect_stdout(out):
            code = cli.main(["bad-cert.example", "--json", *argv])
        return code, json.loads(out.getvalue()), contexts

    def test_without_insecure_nothing_is_fetched_unverified(self):
        code, result, contexts = self._run("--only", "hsts")
        self.assertEqual(contexts, [None])
        self.assertEqual([f["check"] for f in result["findings"]], ["tls-certificate"])
        self.assertIn("--insecure runs them anyway", result["note"])
        self.assertEqual(code, 1)

    def test_insecure_runs_the_checks_without_verification(self):
        code, result, contexts = self._run("--only", "hsts", "--insecure")
        self.assertIsNone(contexts[0])
        self.assertEqual(contexts[1].verify_mode, ssl.CERT_NONE)
        self.assertFalse(contexts[1].check_hostname)
        self.assertEqual([f["check"] for f in result["findings"]], ["tls-certificate", "hsts"])
        self.assertEqual(result["findings"][0]["status"], "FAIL")
        self.assertEqual(result["findings"][1]["status"], "PASS")
        self.assertIn("ran with --insecure", result["note"])
        # The certificate failure keeps the run failing even when every other check passes.
        self.assertEqual(code, 1)

    def test_verification_is_switched_back_on_afterwards(self):
        self._run("--only", "hsts", "--insecure")
        self.assertFalse(cli._INSECURE)
        self.assertIsNone(cli._https_context())

    def test_insecure_does_nothing_for_a_trusted_site(self):
        contexts = []

        def fetch(url, timeout, extra_headers=None):
            contexts.append(cli._https_context())
            return ("https://good.example/", {}, [], 200)

        with mock.patch.object(cli, "fetch_headers", side_effect=fetch), redirect_stdout(io.StringIO()):
            cli.main(["good.example", "--only", "hsts", "--insecure"])
        self.assertEqual(contexts, [None])


if __name__ == "__main__":
    unittest.main()
