import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from webposture import __version__, cli, fetch, runner, sarif
from webposture.findings import Finding


def _result(url, *findings):
    return {"url": url, "status": 200, "findings": list(findings), "note": None}


def _render(results, errors=(), anchor=None):
    return sarif.render(results, runner.ALL_CHECKS, runner.CHECK_SUMMARIES, errors=errors, anchor=anchor)


class SarifRenderTest(unittest.TestCase):
    def test_log_shape_and_tool(self):
        log = _render([])
        self.assertEqual(log["version"], "2.1.0")
        self.assertEqual(len(log["runs"]), 1)
        driver = log["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "web-posture-check")
        self.assertEqual(driver["version"], __version__)
        self.assertEqual([rule["id"] for rule in driver["rules"]], runner.ALL_CHECKS)
        self.assertEqual(log["runs"][0]["results"], [])
        self.assertEqual(log["runs"][0]["invocations"], [{"executionSuccessful": True}])

    def test_fail_is_error_and_warn_is_warning_and_pass_and_skipped_are_left_out(self):
        log = _render([_result("https://example.com/",
                               Finding("hsts", "FAIL", "missing"),
                               Finding("caa", "WARN", "no CAA record"),
                               Finding("csp", "PASS", "ok"),
                               Finding("spf", "WARN", "skipped: dnspython is not installed"))])
        results = log["runs"][0]["results"]
        self.assertEqual([(r["ruleId"], r["level"]) for r in results], [("hsts", "error"), ("caa", "warning")])

    def test_rule_index_points_at_the_rule(self):
        log = _render([_result("https://example.com/", Finding("dkim", "WARN", "x"))])
        run = log["runs"][0]
        result = run["results"][0]
        self.assertEqual(run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"], "dkim")

    def test_message_names_the_url(self):
        log = _render([_result("https://example.com/login", Finding("hsts", "FAIL", "missing"))])
        self.assertEqual(log["runs"][0]["results"][0]["message"]["text"], "hsts: missing (https://example.com/login)")

    def test_site_text_cannot_form_a_link_in_a_message(self):
        # In SARIF plain text, "[text](target)" is a link (section 3.11.6); the site's brackets are escaped.
        log = _render([_result("https://example.com/", Finding("information-leakage", "WARN", "Server: [fix](https://evil.example) a\\b"))],
                      errors=["could not fetch https://x/: [x](https://evil.example)"])
        run = log["runs"][0]
        self.assertEqual(run["results"][0]["message"]["text"],
                         "information-leakage: Server: \\[fix\\](https://evil.example) a\\\\b (https://example.com/)")
        self.assertEqual(run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"],
                         "could not fetch https://x/: \\[x\\](https://evil.example)")

    def test_location_is_a_relative_path_never_an_https_uri(self):
        # Code scanning rejects a SARIF file whose locations use the https scheme.
        log = _render([_result("https://example.com/login/", Finding("hsts", "FAIL", "missing"))])
        location = log["runs"][0]["results"][0]["locations"][0]
        self.assertEqual(location["physicalLocation"]["artifactLocation"]["uri"], "example.com/login")
        self.assertEqual(location["logicalLocations"], [{"fullyQualifiedName": "https://example.com/login/", "kind": "resource"}])

    def test_anchor_points_every_result_at_that_file(self):
        log = _render([_result("https://example.com/", Finding("hsts", "FAIL", "missing"))],
                      anchor=".github/workflows/posture.yml")
        physical = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(physical, {"artifactLocation": {"uri": ".github/workflows/posture.yml"}, "region": {"startLine": 1}})

    def test_fingerprint_ignores_the_detail_but_not_the_check_or_url(self):
        def fingerprint(check, url, detail):
            log = _render([_result(url, Finding(check, "WARN", detail))])
            return log["runs"][0]["results"][0]["partialFingerprints"]["webPostureCheck/v1"]

        base = fingerprint("tls-certificate", "https://example.com/", "expires in 9 days")
        self.assertEqual(base, fingerprint("tls-certificate", "https://example.com/", "expires in 8 days"))
        self.assertNotEqual(base, fingerprint("caa", "https://example.com/", "expires in 9 days"))
        self.assertNotEqual(base, fingerprint("tls-certificate", "https://example.org/", "expires in 9 days"))

    def test_unreachable_targets_mark_the_invocation_unsuccessful(self):
        log = _render([], errors=["could not reach https://down.invalid/: DNS lookup failed"])
        invocation = log["runs"][0]["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(invocation["toolExecutionNotifications"][0]["message"]["text"],
                         "could not reach https://down.invalid/: DNS lookup failed")

    def test_several_targets_share_one_run(self):
        log = _render([_result("https://a.example/", Finding("hsts", "FAIL", "missing")),
                       _result("https://b.example/", Finding("hsts", "FAIL", "missing"))])
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in log["runs"][0]["results"]]
        self.assertEqual(uris, ["a.example", "b.example"])


class ArtifactUriTest(unittest.TestCase):
    def test_host_and_path(self):
        self.assertEqual(sarif.artifact_uri("https://example.com/"), "example.com")
        self.assertEqual(sarif.artifact_uri("https://example.com/a/b"), "example.com/a/b")

    def test_port_colon_is_encoded_so_it_cannot_read_as_a_scheme(self):
        self.assertEqual(sarif.artifact_uri("https://example.com:8443/a"), "example.com%3A8443/a")

    def test_query_and_fragment_are_dropped(self):
        self.assertEqual(sarif.artifact_uri("https://example.com/a?token=x#top"), "example.com/a")

    def test_only_a_path_inside_the_repository_can_be_the_location(self):
        for path in (".github/workflows/scan.yml", "./scan.yml", "docs/web scan.yml", "a/../b.yml"):
            self.assertIsNone(sarif.location_problem(path), path)
        for path in ("/etc/passwd", "C:\\work\\scan.yml", "https://example.com/x", "../x.yml", "a/../../x", ".", ""):
            self.assertIsNotNone(sarif.location_problem(path), path)

    def test_anchor_path_becomes_a_relative_uri(self):
        self.assertEqual(sarif.anchor_uri(".github/workflows/scan.yml"), ".github/workflows/scan.yml")
        self.assertEqual(sarif.anchor_uri("./.github/workflows/web scan.yml"), ".github/workflows/web%20scan.yml")
        self.assertEqual(sarif.anchor_uri(".github\\workflows\\100%.yml"), ".github/workflows/100%25.yml")

    def test_unsafe_characters_are_percent_encoded(self):
        self.assertEqual(sarif.artifact_uri("https://example.com/a b"), "example.com/a%20b")


class SarifCliTest(unittest.TestCase):
    """--format sarif, --sarif FILE and --sarif-location. No network needed."""

    def _main(self, *args):
        out = io.StringIO()
        with mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", {}, [], 200)), \
                redirect_stdout(out):
            code = cli.main(["example.com", "--only", "hsts", *args])
        return code, out.getvalue()

    def test_format_sarif_prints_the_log(self):
        code, out = self._main("--format", "sarif")
        log = json.loads(out)
        self.assertEqual([r["ruleId"] for r in log["runs"][0]["results"]], ["hsts"])
        self.assertEqual(code, 1)

    def test_sarif_file_is_written_next_to_the_normal_report_from_one_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "scan.sarif")
            with mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", {}, [], 200)) as fetched, \
                    redirect_stdout(io.StringIO()) as out:
                code = cli.main(["example.com", "--only", "hsts", "--sarif", path,
                                 "--sarif-location", ".github/workflows/scan.yml"])
            with open(path, encoding="utf-8") as handle:
                log = json.load(handle)
        self.assertEqual(fetched.call_count, 1)  # one scan, two outputs
        self.assertIn("[FAIL] hsts", out.getvalue())
        uri = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, ".github/workflows/scan.yml")
        self.assertEqual(code, 1)

    def test_unreachable_target_is_in_the_sarif_and_exits_2(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "scan.sarif")
            with mock.patch.object(fetch, "fetch_headers", side_effect=OSError("connection refused")), \
                    redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                code = cli.main(["example.com", "--retries", "0", "--sarif", path])
            with open(path, encoding="utf-8") as handle:
                log = json.load(handle)
        invocation = log["runs"][0]["invocations"][0]
        self.assertFalse(invocation["executionSuccessful"])
        self.assertIn("example.com", invocation["toolExecutionNotifications"][0]["message"]["text"])
        self.assertEqual(code, 2)

    def test_unwritable_sarif_exits_2_and_the_report_is_still_printed(self):
        err, out = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", {}, [], 200)), \
                redirect_stdout(out), mock.patch("sys.stderr", err):
            code = cli.main(["example.com", "--only", "hsts", "--sarif", os.path.join(folder, "missing", "x.sarif")])
        self.assertEqual(code, 2)
        self.assertIn("could not write --sarif", err.getvalue())
        self.assertIn("[FAIL] hsts", out.getvalue())

    def test_unwritable_output_still_writes_the_sarif(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(fetch, "fetch_headers", return_value=("https://example.com/", {}, [], 200)), \
                redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()) as err:
            sarif_path = os.path.join(folder, "x.sarif")
            code = cli.main(["example.com", "--only", "hsts", "--output", os.path.join(folder, "missing", "r.md"),
                             "--sarif", sarif_path])
            with open(sarif_path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["runs"][0]["results"][0]["ruleId"], "hsts")
        self.assertEqual(code, 2)
        self.assertIn("could not write --output", err.getvalue())

    def test_a_sarif_location_outside_the_repository_is_a_usage_error(self):
        for path in ("/etc/passwd", "../outside.yml"):
            err = io.StringIO()
            with mock.patch("sys.stderr", err), self.assertRaises(SystemExit) as ctx:
                cli.main(["example.com", "--format", "sarif", "--sarif-location", path])
            self.assertEqual(ctx.exception.code, 2, path)
            self.assertIn("--sarif-location must", err.getvalue())

    def test_sarif_location_without_sarif_output_is_a_usage_error(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err), self.assertRaises(SystemExit) as ctx:
            cli.main(["example.com", "--sarif-location", ".github/workflows/scan.yml"])
        self.assertEqual(ctx.exception.code, 2)
        self.assertIn("--sarif-location only applies to SARIF output", err.getvalue())
        # With --format sarif it is accepted.
        _, out = self._main("--format", "sarif", "--sarif-location", ".github/workflows/scan.yml")
        location = json.loads(out)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], ".github/workflows/scan.yml")


if __name__ == "__main__":
    unittest.main()
