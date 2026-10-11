"""The compatibility promise in the README, as tests.

These pin what scripts and pipelines rely on: check names, JSON fields,
statuses, exit codes and the Action's inputs and outputs. If one fails, the
change is a compatibility change: update the README's Compatibility section
and the CHANGELOG, and release it in a new minor version.
"""

import io
import json
import os
import re
import ssl
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

from webposture import checks, cli, fetch, findings, output, runner

CHECK_NAMES = [
    "http-status", "hsts", "csp", "x-content-type-options", "clickjacking", "referrer-policy",
    "permissions-policy", "cross-origin-isolation", "x-xss-protection", "information-leakage",
    "cookies", "cors", "tls-certificate", "tls-protocols", "caa", "security-txt",
    "spf", "dmarc", "dkim", "https-redirect",
]


def _json(*argv, headers=None, side_effect=None):
    out = io.StringIO()
    patch = mock.patch.object(fetch, "fetch_headers", side_effect=side_effect,
                              return_value=("https://example.com/", headers or {}, [], 200))
    with patch, redirect_stdout(out), mock.patch("sys.stderr", io.StringIO()):
        code = cli.main([*argv, "--json", "--only", "hsts", "--retries", "0"])
    return code, out.getvalue()


class ContractTest(unittest.TestCase):
    def test_check_names(self):
        self.assertEqual(runner.ALL_CHECKS, CHECK_NAMES)
        self.assertEqual(list(checks.NAMES), CHECK_NAMES)

    def test_check_names_are_the_sarif_rule_ids(self):
        log = json.loads(output.to_sarif([]))
        self.assertEqual([rule["id"] for rule in log["runs"][0]["tool"]["driver"]["rules"]], CHECK_NAMES)

    def test_statuses_and_skipped_prefix(self):
        self.assertEqual((findings.PASS, findings.WARN, findings.FAIL), ("PASS", "WARN", "FAIL"))
        self.assertEqual(findings.SKIPPED_PREFIX, "skipped:")

    def test_single_target_json_fields(self):
        code, out = _json("example.com")
        result = json.loads(out)
        self.assertEqual(set(result), {"url", "status", "findings", "score", "grade"})
        self.assertEqual(set(result["findings"][0]), {"check", "status", "detail"})
        self.assertEqual(code, 1)

    def test_unscanned_target_json_fields(self):
        code, out = _json("example.com", side_effect=OSError("connection refused"))
        self.assertEqual(set(json.loads(out)), {"url", "status", "findings", "error"})
        self.assertEqual(code, 2)

    def test_note_json_field_on_a_skipped_target(self):
        # The promise lists `note`; it appears when a target's other checks were
        # skipped, such as a broken certificate. The field test above covers a
        # normal run, which has none, and `error` is a separate unscanned case.
        cert_error = ssl.SSLCertVerificationError(1, "certificate verify failed")
        cert_error.verify_code, cert_error.verify_message = 10, "certificate has expired"
        code, out = _json("bad.example", side_effect=urllib.error.URLError(cert_error))
        self.assertIn("note", json.loads(out))
        self.assertEqual(code, 1)

    def test_several_targets_json_fields(self):
        _, out = _json("a.example", "b.example")
        self.assertEqual(list(json.loads(out)), ["results"])

    def test_exit_codes(self):
        self.assertEqual(_json("example.com", headers={"Strict-Transport-Security": "max-age=31536000"})[0], 0)
        self.assertEqual(_json("example.com")[0], 1)
        self.assertEqual(_json("example.com", side_effect=OSError("connection refused"))[0], 2)
        # Ctrl-C: 130, the conventional code for an interrupt.
        with mock.patch.object(runner, "scan", side_effect=KeyboardInterrupt), \
                mock.patch.object(cli, "exit_now", side_effect=SystemExit) as exit_now, \
                mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            cli.main(["example.com"])
        exit_now.assert_called_once_with(130)

    def test_action_inputs_and_outputs(self):
        path = os.path.join(os.path.dirname(__file__), "..", "action.yml")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()

        def keys(section):
            body = re.search(rf"^{section}:\n((?:  .*\n|\n)+)", text, re.MULTILINE)
            self.assertIsNotNone(body, section)
            return re.findall(r"^  ([a-z-]+):$", body.group(1) if body else "", re.MULTILINE)

        self.assertEqual(keys("inputs"), ["targets", "args", "dns", "python-version"])
        for name in ("score", "grade", "exit-code", "report", "sarif"):
            self.assertIn(name, keys("outputs"))


if __name__ == "__main__":
    unittest.main()
