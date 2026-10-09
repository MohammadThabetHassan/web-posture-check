import unittest

from webposture import transport
from webposture.findings import PASS, FAIL


class HttpUrlTest(unittest.TestCase):
    def test_keeps_host_path_and_query(self):
        self.assertEqual(transport.http_url_for("https://example.com/login?next=/"), "http://example.com/login?next=/")

    def test_bare_host_gets_root_path(self):
        self.assertEqual(transport.http_url_for("https://example.com"), "http://example.com/")

    def test_drops_https_port(self):
        self.assertEqual(transport.http_url_for("https://example.com:8443/app"), "http://example.com/app")


class HttpsRedirectTest(unittest.TestCase):
    def test_redirect_to_https_passes(self):
        f = transport.check_https_redirect("http://example.com/", "https://example.com/")
        self.assertEqual(f.status, PASS)
        self.assertIn("redirects to https://example.com/", f.detail)

    def test_redirect_to_https_on_other_host_passes(self):
        f = transport.check_https_redirect("http://example.com/", "https://www.example.com/")
        self.assertEqual(f.status, PASS)

    def test_plain_http_response_fails(self):
        f = transport.check_https_redirect("http://example.com/", "http://example.com/")
        self.assertEqual(f.status, FAIL)

    def test_redirect_to_other_http_url_fails(self):
        f = transport.check_https_redirect("http://example.com/", "http://www.example.com/home")
        self.assertEqual(f.status, FAIL)

    def test_unreachable_http_passes(self):
        f = transport.check_https_redirect("http://example.com/", None)
        self.assertEqual(f.status, PASS)
        self.assertIn("not reachable", f.detail)


if __name__ == "__main__":
    unittest.main()
