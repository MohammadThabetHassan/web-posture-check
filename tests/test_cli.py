import io
import json
import ssl
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

from webposture import cli


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


if __name__ == "__main__":
    unittest.main()
