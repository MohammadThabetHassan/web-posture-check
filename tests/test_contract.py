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
import unittest
from contextlib import redirect_stdout
from unittest import mock

from webposture import cli, fetch, findings, runner

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

    def test_statuses_and_skipped_prefix(self):
        self.assertEqual((findings.PASS, findings.WARN, findings.FAIL), ("PASS", "WARN", "FAIL"))
        self.assertEqual(findings.SKIPPED_PREFIX, "skipped:")

    def test_single_target_json_fields(self):
        code, out = _json("example.com")
        result = json.loads(out)
        self.assertEqual(set(result), {"url", "status", "findings", "score", "grade"})
        self.assertEqual(set(result["findings"][0]), {"check", "status", "detail"})
        self.assertEqual(code, 1)

    def test_several_targets_json_fields(self):
        _, out = _json("a.example", "b.example")
        self.assertEqual(list(json.loads(out)), ["results"])

    def test_exit_codes(self):
        self.assertEqual(_json("example.com", headers={"Strict-Transport-Security": "max-age=31536000"})[0], 0)
        self.assertEqual(_json("example.com")[0], 1)
        self.assertEqual(_json("example.com", side_effect=OSError("connection refused"))[0], 2)

    def test_action_inputs_and_outputs(self):
        path = os.path.join(os.path.dirname(__file__), "..", "action.yml")
        with open(path, encoding="utf-8") as handle:
            text = handle.read()

        def keys(section):
            body = re.search(rf"^{section}:\n((?:  .*\n|\n)+)", text, re.MULTILINE)
            self.assertIsNotNone(body, section)
            return re.findall(r"^  ([a-z-]+):$", body.group(1) if body else "", re.MULTILINE)

        self.assertEqual(keys("inputs"), ["targets", "args", "dns", "python-version"])
        for output in ("score", "grade", "exit-code", "report"):
            self.assertIn(output, keys("outputs"))


if __name__ == "__main__":
    unittest.main()
