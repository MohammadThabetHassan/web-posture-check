import io
import json
import os
import ssl
import tempfile
import threading
import time
import unittest
import urllib.error
from collections.abc import Callable
from contextlib import redirect_stdout
from unittest import mock

from webposture import cli, emailauth, fetch, output, runner
from webposture.findings import Finding


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
        with mock.patch.object(fetch, "fetch_headers", side_effect=_cert_error(10, "certificate has expired")):
            code, out = self._run("expired.example")
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] tls-certificate: certificate has expired", out)
        self.assertIn("other checks skipped", out)

    def test_untrusted_certificate_in_json(self):
        with mock.patch.object(fetch, "fetch_headers", side_effect=_cert_error(62, "Hostname mismatch")):
            code, out = self._run("wrong.example", "--json")
        result = json.loads(out)
        self.assertEqual(code, 1)
        self.assertIsNone(result["status"])
        self.assertEqual(result["findings"][0]["status"], "FAIL")
        self.assertIn("not trusted: Hostname mismatch", result["findings"][0]["detail"])

    def test_certificate_error_json_carries_skip_note(self):
        # --json documents a top-level note explaining that the other checks
        # were skipped. A consumer parsing the output relies on it, so pin it.
        with mock.patch.object(fetch, "fetch_headers", side_effect=_cert_error(10, "certificate has expired")):
            code, out = self._run("expired.example", "--json")
        result = json.loads(out)
        self.assertEqual(code, 1)
        self.assertIn("note", result)
        self.assertIn("other checks skipped", result["note"])

    def test_other_fetch_errors_still_exit_2(self):
        err = urllib.error.URLError(OSError("Name or service not known"))
        with mock.patch.object(fetch, "fetch_headers", side_effect=err), redirect_stdout(io.StringIO()), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
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
            finding = runner.check_dmarc("https://mail.google.com/", 5)
        self.assertEqual(finding.status, "PASS")
        self.assertIn("_dmarc.google.com (p=reject applies to mail.google.com)", finding.detail)


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
            finding = runner.check_dkim("https://example.com/", 5, selectors=["custom"])
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

        def record(name, value):
            called.append(name)
            return value

        patches = [mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", {}, [], 200)),
                   mock.patch.object(fetch, "fetch_final_url",
                                     side_effect=lambda *a, **k: record("https-redirect", "https://example.com/"))]
        for func, name in self.NETWORK.items():
            patches.append(mock.patch.object(
                runner, func, side_effect=lambda *a, _n=name, **k: record(_n, Finding(_n, "PASS", "ok"))))
        out = io.StringIO()
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        with redirect_stdout(out):
            code = cli.main(["example.com", "--json", *argv])
        return code, [f["check"] for f in json.loads(out.getvalue())["findings"]], called

    def test_default_runs_every_check_in_documented_order(self):
        _, checks, _ = self._run()
        self.assertEqual(checks, runner.ALL_CHECKS)

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

    def test_text_has_no_score_when_nothing_was_scored(self):
        result = runner.failed("https://example.com/", "boom")
        result["findings"] = [Finding("spf", "WARN", "skipped: no DNS support")]
        text = output.to_text(result)
        self.assertNotIn("Score:", text)
        self.assertIn("[WARN] spf: skipped: no DNS support", text)

    def test_json_carries_score_and_grade(self):
        out = io.StringIO()
        with mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", {}, [], 200)), \
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
    RESPONSES: dict[str, tuple] = {
        "https://good.example": ("https://good.example/", {"Strict-Transport-Security": "max-age=31536000"}, [], 200),
        "https://bad.example": ("https://bad.example/", {}, [], 200),
    }

    def _fetch(self, url, timeout, extra_headers=None, context=None):
        if url not in self.RESPONSES:
            raise urllib.error.URLError(OSError("Name or service not known"))
        return self.RESPONSES[url]

    def _run(self, *argv):
        out = io.StringIO()
        with mock.patch.object(fetch, "fetch_headers", side_effect=self._fetch), redirect_stdout(out), \
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
        self.assertIn("## Web posture report: `https://good.example/`", out)
        self.assertIn("## Web posture report: `https://bad.example/`", out)

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

    def test_targets_file_may_start_with_a_byte_order_mark(self):
        # Windows editors often save UTF-8 with a BOM; it must not become part of the first target.
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "sites.txt")
            with open(path, "w", encoding="utf-8-sig") as handle:
                handle.write("good.example\n")
            _, out = self._run("--targets-file", path, "--json")
        self.assertEqual(json.loads(out)["url"], "https://good.example/")

    def test_a_targets_file_that_is_not_utf8_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "sites.txt")
            with open(path, "wb") as handle:
                handle.write(b"caf\xe9.example\n")
            err = io.StringIO()
            with mock.patch("sys.stderr", err), self.assertRaises(SystemExit) as ctx:
                cli.main(["--targets-file", path])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("could not read --targets-file: it is not UTF-8 text", err.getvalue())

    def test_json_keeps_every_target_in_input_order_with_its_error(self):
        code, out = self._run("good.example", "down.example", "exa mple.com", "bad.example", "--json")
        results = json.loads(out)["results"]
        self.assertEqual([r["url"] for r in results],
                         ["https://good.example/", "https://down.example", "exa mple.com", "https://bad.example/"])
        self.assertEqual([r.get("error", "")[:18] for r in results], ["", "could not fetch ht", "invalid target 'ex", ""])
        for unscanned in results[1:3]:
            self.assertEqual((unscanned["status"], unscanned["findings"]), (None, []))
            self.assertNotIn("score", unscanned)
        self.assertEqual(code, 2)

    def test_a_single_unreachable_target_is_still_a_json_document(self):
        code, out = self._run("down.example", "--json")
        self.assertEqual(json.loads(out), {"url": "https://down.example", "status": None, "findings": [],
                                           "error": "could not fetch https://down.example: Name or service not known"})
        self.assertEqual(code, 2)

    def test_markdown_says_why_a_target_was_not_scanned(self):
        code, out = self._run("good.example", "down.example", "--format", "markdown")
        self.assertIn("## Web posture report: `https://down.example`\n", out)
        self.assertTrue(out.endswith("\n**Error:** `could not fetch https://down.example: Name or service not known`\n"), out)
        # Only the scanned target has a grade and a table.
        self.assertEqual(out.count("**Grade "), 1)
        self.assertEqual(out.count("| Status | Check | Detail |"), 1)
        self.assertEqual(code, 2)

    def test_text_report_leaves_unscanned_targets_to_stderr(self):
        self.assertEqual(self._run("down.example"), (2, ""))
        _, out = self._run("down.example", "good.example")
        self.assertNotIn("down.example", out)
        self.assertIn("Target: https://good.example/", out)

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
        with mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", self.HEADERS, [], 200)), \
                redirect_stdout(io.StringIO()):
            return cli.main(["example.com", "--only", "hsts,referrer-policy", *argv])

    def test_default_only_fails_on_fail(self):
        self.assertEqual(self._code(), 0)
        self.assertEqual(self._code("--fail-on", "fail"), 0)

    def test_fail_on_warn_exits_1_for_a_warning(self):
        self.assertEqual(self._code("--fail-on", "warn"), 1)

    def test_fail_on_warn_passes_a_clean_run(self):
        with mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", self.HEADERS, [], 200)), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["example.com", "--only", "hsts", "--fail-on", "warn"]), 0)

    def test_skipped_checks_do_not_trip_fail_on_warn(self):
        skipped = Finding("spf", "WARN", "skipped: install the optional DNS support")
        passed = Finding("hsts", "PASS", "ok")
        self.assertEqual(runner.exit_code([passed, skipped], "warn"), 0)
        self.assertEqual(runner.exit_code([passed, Finding("caa", "WARN", "no CAA record")], "warn"), 1)

    def test_fail_on_warn_still_exits_1_on_a_fail(self):
        # warn is a superset of fail: raising the bar to warnings must not stop
        # a FAIL from failing the gate. Guards against warn meaning only {WARN}.
        passed = Finding("hsts", "PASS", "ok")
        failed = Finding("csp", "FAIL", "Content-Security-Policy header is missing")
        self.assertEqual(runner.exit_code([passed, failed], "warn"), 1)

    def test_invalid_level_is_a_usage_error(self):
        with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["example.com", "--fail-on", "pass"])
        self.assertEqual(ctx.exception.code, 2)


class RetryTest(unittest.TestCase):
    """Transient failures are retried and explained. No network, no real sleeping."""

    OK: tuple = ("https://example.com/", {"Strict-Transport-Security": "max-age=31536000"}, [], 200)

    def setUp(self):
        sleep = mock.patch.object(time, "sleep")
        self.sleep = sleep.start()
        self.addCleanup(sleep.stop)

    def _run(self, side_effect, *argv):
        fake_fetch = mock.Mock(side_effect=side_effect)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(fetch, "fetch_headers", fake_fetch), redirect_stdout(out), mock.patch("sys.stderr", err):
            code = cli.main(["example.com", "--only", "hsts", *argv])
        return code, fake_fetch.call_count, err.getvalue()

    def test_timeout_then_success_is_retried_once(self):
        code, calls, err = self._run([urllib.error.URLError(TimeoutError("timed out")), self.OK])
        self.assertEqual((code, calls), (0, 2))
        self.assertEqual(err, "")
        self.sleep.assert_called_once_with(fetch.RETRY_DELAY_SECONDS)

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

    OK: tuple = ("https://bad-cert.example/", {"Strict-Transport-Security": "max-age=31536000"}, [], 200)

    def _run(self, *argv):
        contexts = []

        def fake_fetch(url, timeout, extra_headers=None, context=None):
            # Record whether verification was off for this request.
            contexts.append(context)
            if context is None:
                raise _cert_error(10, "certificate has expired")
            return self.OK

        out = io.StringIO()
        with mock.patch.object(fetch, "fetch_headers", side_effect=fake_fetch), redirect_stdout(out):
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

    def test_insecure_drops_the_duplicate_tls_certificate_finding(self):
        # Under --insecure, check_tls verifies on its own and re-reports the
        # same failure. When tls-certificate is among the checks, that duplicate
        # must be dropped so the report shows the single prepended cert FAIL.
        def fake_fetch(url, timeout, extra_headers=None, context=None):
            if context is None:
                raise _cert_error(10, "certificate has expired")
            return self.OK

        duplicate = Finding("tls-certificate", "FAIL", "certificate has expired")
        out = io.StringIO()
        with mock.patch.object(fetch, "fetch_headers", side_effect=fake_fetch), \
                mock.patch.object(runner, "check_tls", return_value=duplicate), redirect_stdout(out):
            cli.main(["bad-cert.example", "--only", "hsts,tls-certificate", "--insecure", "--json"])
        checks = [f["check"] for f in json.loads(out.getvalue())["findings"]]
        self.assertEqual(checks.count("tls-certificate"), 1)
        self.assertEqual(checks, ["tls-certificate", "hsts"])

    def test_unverified_context_never_reaches_another_target(self):
        # A broken-certificate site scanned with --insecure, then a trusted
        # site in the same run: the trusted site must still be fetched with
        # verification. The context is passed explicitly, never kept globally.
        seen = []

        def fake_fetch(url, timeout, extra_headers=None, context=None):
            seen.append((url, context))
            if url.startswith("https://bad-cert.example") and context is None:
                raise _cert_error(10, "certificate has expired")
            return (url, {}, [], 200)

        with mock.patch.object(fetch, "fetch_headers", side_effect=fake_fetch), redirect_stdout(io.StringIO()):
            cli.main(["bad-cert.example", "good.example", "--only", "hsts", "--insecure"])
        good = [context for url, context in seen if url.startswith("https://good.example")]
        self.assertEqual(good, [None])
        self.assertTrue(any(context is not None for url, context in seen if url.startswith("https://bad-cert.example")))

    def test_insecure_does_nothing_for_a_trusted_site(self):
        contexts = []

        def fake_fetch(url, timeout, extra_headers=None, context=None):
            contexts.append(context)
            return ("https://good.example/", {}, [], 200)

        with mock.patch.object(fetch, "fetch_headers", side_effect=fake_fetch), redirect_stdout(io.StringIO()):
            cli.main(["good.example", "--only", "hsts", "--insecure"])
        self.assertEqual(contexts, [None])

    def test_insecure_context_reaches_security_txt_and_redirect_requests(self):
        # The existing tests only cover fetch_headers (main fetch and CORS probe).
        # The security.txt (fetch_text) and https-redirect (fetch_final_url)
        # requests must get the same unverified context, or they would re-verify
        # on a broken-certificate site and report misleading results.
        seen = {}

        def fake_headers(url, timeout, extra_headers=None, context=None):
            if context is None:
                raise _cert_error(10, "certificate has expired")
            return (url, {}, [], 200)

        def fake_text(url, timeout, limit, context=None):
            seen["security-txt"] = context
            return (404, None, "")

        def fake_final(url, timeout, context=None):
            seen["https-redirect"] = context
            return None

        with mock.patch.object(fetch, "fetch_headers", side_effect=fake_headers), \
                mock.patch.object(fetch, "fetch_text", side_effect=fake_text), \
                mock.patch.object(fetch, "fetch_final_url", side_effect=fake_final), redirect_stdout(io.StringIO()):
            cli.main(["bad-cert.example", "--only", "security-txt,https-redirect", "--insecure"])
        self.assertEqual(seen["security-txt"].verify_mode, ssl.CERT_NONE)
        self.assertEqual(seen["https-redirect"].verify_mode, ssl.CERT_NONE)


class ParallelTest(unittest.TestCase):
    """--jobs scans targets at the same time and keeps the output in input order. No network needed."""

    def _main(self, fake_fetch, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(fetch, "fetch_headers", side_effect=fake_fetch), redirect_stdout(out), \
                mock.patch("sys.stderr", err):
            code = cli.main([*argv, "--only", "hsts", "--retries", "0"])
        return code, out.getvalue(), err.getvalue()

    def test_targets_really_run_at_the_same_time(self):
        # Every fake request waits until all four are in flight. Run one at a
        # time, the first would wait alone until the barrier times out.
        barrier = threading.Barrier(4, timeout=5)

        def fake_fetch(url, timeout, extra_headers=None, context=None):
            barrier.wait()
            return (url, {}, [], 200)

        code, out, _ = self._main(fake_fetch, "a.example", "b.example", "c.example", "d.example", "--json", "--jobs", "4")
        self.assertEqual(len(json.loads(out)["results"]), 4)
        self.assertEqual(code, 1)  # hsts fails on every empty response

    def test_jobs_1_scans_one_at_a_time(self):
        active, peak, lock = [0], [0], threading.Lock()

        def fake_fetch(url, timeout, extra_headers=None, context=None):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
            return (url, {}, [], 200)

        self._main(fake_fetch, "a.example", "b.example", "c.example", "--jobs", "1")
        self.assertEqual(peak[0], 1)

    def test_jobs_caps_concurrency_below_the_target_count(self):
        # The anti-flood guarantee: with more targets than --jobs, no more than
        # --jobs run at once. The serial (jobs 1) and full-width (jobs = count)
        # cases don't cover an intermediate cap.
        active, peak, lock = [0], [0], threading.Lock()

        def fake_fetch(url, timeout, extra_headers=None, context=None):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.05)
            with lock:
                active[0] -= 1
            return (url, {}, [], 200)

        self._main(fake_fetch, "a.example", "b.example", "c.example", "d.example", "e.example", "--jobs", "2")
        self.assertEqual(peak[0], 2)

    def test_results_keep_the_input_order_when_later_targets_finish_first(self):
        delays = {"https://slow.example": 0.3, "https://medium.example": 0.15, "https://fast.example": 0.0}

        def fake_fetch(url, timeout, extra_headers=None, context=None):
            time.sleep(delays[url])
            return (url + "/", {}, [], 200)

        _, out, _ = self._main(fake_fetch, "slow.example", "medium.example", "fast.example", "--json")
        urls = [r["url"] for r in json.loads(out)["results"]]
        self.assertEqual(urls, ["https://slow.example/", "https://medium.example/", "https://fast.example/"])

    def test_errors_are_printed_in_input_order(self):
        delays = {"https://first-down.example": 0.3, "https://second-down.example": 0.0}

        def fake_fetch(url, timeout, extra_headers=None, context=None):
            time.sleep(delays[url])
            raise urllib.error.URLError(OSError(f"cannot resolve {url}"))

        code, _, err = self._main(fake_fetch, "first-down.example", "second-down.example")
        lines = err.strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("first-down.example", lines[0])
        self.assertIn("second-down.example", lines[1])
        self.assertEqual(code, 2)

    def test_insecure_context_stays_with_its_own_target_when_running_in_parallel(self):
        # The broken-certificate target and the trusted one are scanned at the
        # same moment; the trusted one must still be fetched with verification.
        barrier = threading.Barrier(2, timeout=5)
        seen, lock = [], threading.Lock()

        def fake_fetch(url, timeout, extra_headers=None, context=None):
            with lock:
                seen.append((url, context))
            if url.startswith("https://bad-cert.example") and context is None:
                barrier.wait()
                raise _cert_error(10, "certificate has expired")
            if url.startswith("https://good.example"):
                barrier.wait()
            return (url, {}, [], 200)

        self._main(fake_fetch, "bad-cert.example", "good.example", "--insecure", "--jobs", "2")
        good = [context for url, context in seen if url.startswith("https://good.example")]
        self.assertEqual(good, [None])
        self.assertTrue(any(context is not None for url, context in seen if url.startswith("https://bad-cert.example")))

    def test_jobs_must_be_between_1_and_16(self):
        for value in ("0", "17"):
            with mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit) as ctx:
                cli.main(["example.com", "--jobs", value])
            self.assertEqual(ctx.exception.code, 2, value)


class ListChecksAndOutputTest(unittest.TestCase):
    """--list-checks and --output. No network needed."""

    def test_list_checks_prints_every_check_once_in_report_order(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(["--list-checks"])
        names = [line.split()[0] for line in out.getvalue().splitlines()]
        self.assertEqual(names, runner.ALL_CHECKS)
        self.assertEqual(code, 0)

    def test_every_check_has_a_summary(self):
        self.assertEqual(list(cli.CHECK_SUMMARIES), runner.ALL_CHECKS)

    def test_output_writes_utf8_file_and_prints_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "report.md")
            out = io.StringIO()
            with mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", {}, [], 200)), \
                    redirect_stdout(out):
                code = cli.main(["example.com", "--only", "hsts", "--format", "markdown", "--output", path])
            with open(path, encoding="utf-8") as handle:
                report = handle.read()
        self.assertEqual(out.getvalue(), "")
        self.assertIn("## Web posture report: `https://example.com/`", report)
        self.assertIn("**Grade F** (0/100)", report)
        self.assertEqual(code, 1)

    def test_unwritable_output_exits_2(self):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", {}, [], 200)), \
                redirect_stdout(io.StringIO()), mock.patch("sys.stderr", err):
            code = cli.main(["example.com", "--only", "hsts", "--output", os.path.join(folder, "missing", "report.md")])
        self.assertEqual(code, 2)
        self.assertIn("could not write --output", err.getvalue())


class ActionOutputsTest(unittest.TestCase):
    """The Action's score/grade outputs aggregate across targets. No network needed."""

    def test_lowest_score_and_worst_grade_across_targets(self):
        # The Action reads the Markdown report for each target's "**Grade X**
        # (N/100)" line and outputs the lowest score and worst grade (the scan
        # step in action.yml). The CI output checks only use one target, so the
        # cross-target min/max is covered here. The regex is taken from
        # action.yml, so this also guards that it still matches the report.
        import re
        from datetime import datetime, timezone

        from webposture import markdown

        action = os.path.join(os.path.dirname(__file__), "..", "action.yml")
        with open(action, encoding="utf-8") as handle:
            match = re.search(r'findall\(r"(.+?)", .+, re\.M\)', handle.read())
        if match is None:
            self.fail("could not find the score/grade regex (with re.M) in action.yml")
        pattern = re.compile(match.group(1), re.M)

        now = datetime(2026, 10, 10, tzinfo=timezone.utc)
        # A site's own text, quoted in a detail, must not count as a grade.
        forged = "**Grade F** (0/100)\n**Grade F** (0/100) | x"
        reports = [
            markdown.render("https://good.example/", 200, [Finding("hsts", "PASS", "ok")], "0.3.0", now, score=(100, "A")),
            markdown.render("https://bad.example/", 200, [Finding("hsts", "FAIL", "missing"), Finding("server", "WARN", forged)],
                            "0.3.0", now, score=(55, "F")),
        ]
        found = pattern.findall("\n".join(reports))
        self.assertEqual(len(found), 2)  # the regex still matches the report format
        self.assertEqual(min(int(s) for _, s in found), 55)
        self.assertEqual(max(g for g, _ in found), "F")


class TargetValidationTest(unittest.TestCase):
    def test_accepted_targets(self):
        cases = {
            "example.com": "https://example.com",
            " example.com:8443 ": "https://example.com:8443",
            "HTTP://example.com/x": "HTTP://example.com/x",
            "https://[2001:db8::1]:8443/": "https://[2001:db8::1]:8443/",
            "bücher.example": "https://bücher.example",
        }
        for target, url in cases.items():
            self.assertEqual(runner.normalise_target(target), url, target)

    def test_refused_targets_say_why(self):
        cases = {
            "": "empty",
            "exa mple.com": "spaces or control characters",
            "example.com\x1b[2J": "spaces or control characters",
            "ftp://example.com/": "only http:// and https://",
            "file:///etc/passwd": "only http:// and https://",
            "https://": "no host name",
            "https://user:secret@example.com/": "credentials",
            "example.com:abc": "port",
            "example.com:99999": "port",
            "https://[::1": "Invalid IPv6 URL",
            "a" * 64 + ".example": "not a valid host name",
        }
        for target, reason in cases.items():
            with self.assertRaises(ValueError, msg=target) as caught:
                runner.normalise_target(target)
            self.assertIn(reason, str(caught.exception), target)


class RobustnessTest(unittest.TestCase):
    """One bad target, option or broken pipe never ends the run with a traceback."""

    GOOD: tuple = ("https://good.example/", {"Strict-Transport-Security": "max-age=31536000"}, [], 200)

    def test_bad_targets_are_errors_and_good_targets_are_still_reported(self):
        out, err = io.StringIO(), io.StringIO()
        hostile = ["example.com:abc", "https://[::1", "ftp://example.com/", "exa mple.com", "https://user:pw@example.com"]
        with mock.patch.object(fetch, "fetch_headers", return_value=self.GOOD), \
                redirect_stdout(out), mock.patch("sys.stderr", err):
            code = cli.main([*hostile, "good.example", "--only", "hsts", "--json"])
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err.getvalue())
        self.assertEqual(err.getvalue().count("error: invalid target"), len(hostile))
        results = json.loads(out.getvalue())["results"]
        self.assertIn("https://good.example/", [r["url"] for r in results])

    def test_an_unexpected_exception_on_an_invalid_target_keeps_the_target(self):
        with mock.patch.object(runner, "scan", side_effect=RuntimeError("boom")):
            result, code = cli.scan_safely(" bad target ", runner.ScanOptions())
        self.assertEqual((result["url"], code), ("bad target", 2))

    def test_an_unexpected_exception_is_one_targets_error(self):
        with mock.patch.object(runner, "scan", side_effect=RuntimeError("boom")):
            result, code = cli.scan_safely("example.com", runner.ScanOptions())
        self.assertEqual((result["url"], result["findings"], code), ("https://example.com", [], 2))
        self.assertIn("unexpected error while scanning 'example.com': RuntimeError: boom", result["error"])
        self.assertIn("issues", result["error"])

    def test_error_lines_cannot_drive_the_terminal(self):
        err = io.StringIO()
        message = "could not fetch https://evil.example/: \x1b]52;c;ZXZpbA==\x07"
        with mock.patch.object(runner, "scan", return_value=(runner.failed("https://evil.example/", message), 2)), \
                redirect_stdout(io.StringIO()), mock.patch("sys.stderr", err):
            cli.main(["evil.example"])
        self.assertEqual(err.getvalue(), "error: could not fetch https://evil.example/: \\x1b]52;c;ZXZpbA==\\x07\n")

    def test_timeout_must_be_a_positive_finite_number(self):
        for value in ("0", "-1", "nan", "inf", "abc"):
            with self.assertRaises(SystemExit, msg=value), mock.patch("sys.stderr", io.StringIO()):
                cli.main(["example.com", "--timeout", value])
        self.assertEqual(cli.build_parser().parse_args(["x", "--timeout", "2.5"]).timeout, 2.5)

    def test_scan_options_come_from_the_command_line(self):
        args = cli.build_parser().parse_args(["x", "--timeout", "3", "--retries", "0", "--insecure", "--fail-on", "warn",
                                              "--only", "hsts,dkim", "--dkim-selector", "s1", "--dkim-selector", "s2"])
        self.assertEqual(cli.scan_options(args), runner.ScanOptions(
            timeout=3.0, retries=0, insecure=True, only=frozenset({"hsts", "dkim"}), skip=None, fail_on="warn",
            dkim_selectors=("s1", "s2")))
        defaults = cli.scan_options(cli.build_parser().parse_args(["x"]))
        self.assertEqual(defaults, runner.ScanOptions())
        self.assertTrue(defaults.wanted("hsts"))
        skipping = cli.scan_options(cli.build_parser().parse_args(["x", "--skip", "hsts"]))
        self.assertEqual((skipping.wanted("hsts"), skipping.wanted("csp")), (False, True))

    def test_ctrl_c_exits_130_without_waiting_for_running_scans(self):
        # Ctrl-C arrives while another scan is still running and would hold the
        # pool for 30 s. Leaving at once is the point: code that waited for the
        # running scans (a "with ThreadPoolExecutor()" block) would fail here.
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def scan(target, options):
            if target == "slow.example":
                started.set()
                release.wait(30)
                return runner.failed(target, "released"), 2
            started.wait(10)
            raise KeyboardInterrupt

        err = io.StringIO()
        begin = time.monotonic()
        with mock.patch.object(runner, "scan", side_effect=scan), \
                mock.patch.object(cli, "exit_now", side_effect=SystemExit) as exit_now, \
                mock.patch("sys.stderr", err), self.assertRaises(SystemExit):
            cli.main(["fast.example", "slow.example"])
        self.assertLess(time.monotonic() - begin, 10)
        exit_now.assert_called_once_with(130)
        self.assertIn("interrupted", err.getvalue())

    def test_exit_now_flushes_and_leaves_with_the_code(self):
        # exit_now never returns, so the type checker would call the lines after it
        # unreachable; with os._exit mocked it does return.
        exit_now: Callable[[int], object] = cli.exit_now
        with mock.patch.object(os, "_exit") as leave:
            exit_now(130)
        leave.assert_called_once_with(130)

    def test_a_closed_pipe_is_not_a_traceback(self):
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)

        class ClosedPipe:
            def write(self, text):
                raise BrokenPipeError

            def flush(self):
                pass

            def fileno(self):
                return write_end

        with mock.patch.object(fetch, "fetch_headers", return_value=self.GOOD), mock.patch("sys.stdout", ClosedPipe()):
            code = cli.main(["good.example", "--only", "hsts"])
        self.assertEqual(code, 0)

if __name__ == "__main__":
    unittest.main()
