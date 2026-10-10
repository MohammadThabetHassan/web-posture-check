import unittest

from webposture import transport
from webposture.findings import PASS, WARN, FAIL


class HttpUrlTest(unittest.TestCase):
    def test_keeps_host_path_and_query(self):
        self.assertEqual(transport.http_url_for("https://example.com/login?next=/"), "http://example.com/login?next=/")

    def test_bare_host_gets_root_path(self):
        self.assertEqual(transport.http_url_for("https://example.com"), "http://example.com/")

    def test_drops_https_port(self):
        self.assertEqual(transport.http_url_for("https://example.com:8443/app"), "http://example.com/app")

    def test_ipv6_host_keeps_brackets(self):
        # Without brackets the rebuilt URL is malformed: urlsplit would read the
        # host as "2606" and the plain-HTTP request would fail, wrongly passing
        # the check. The literal must stay bracketed.
        self.assertEqual(
            transport.http_url_for("https://[2606:2800:220:1::1]:8443/app"),
            "http://[2606:2800:220:1::1]/app",
        )

    def test_http_target_keeps_its_port(self):
        # Plain HTTP is served on that port; dropping it would probe port 80.
        self.assertEqual(transport.http_url_for("http://example.com:8080/x?y=1"), "http://example.com:8080/x?y=1")
        self.assertEqual(transport.http_url_for("http://[::1]:8080/"), "http://[::1]:8080/")

    def test_http_target_on_the_default_port_is_unchanged(self):
        self.assertEqual(transport.http_url_for("http://example.com/"), "http://example.com/")

    def test_malformed_port_falls_back_to_the_default_instead_of_raising(self):
        # Reading parts.port raises on a non-numeric or out-of-range port; the
        # helper must not propagate that, it should drop the unusable port.
        self.assertEqual(transport.http_url_for("http://example.com:notaport/x"), "http://example.com/x")
        self.assertEqual(transport.http_url_for("http://example.com:99999999/"), "http://example.com/")


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



class StatusTest(unittest.TestCase):
    def test_success_and_redirect_statuses_pass(self):
        for status in (200, 204, 304):
            f = transport.check_status(status)
            self.assertEqual(f.status, PASS, status)
            self.assertIn(f"HTTP {status}", f.detail)

    def test_error_status_warns_that_findings_describe_the_error_page(self):
        f = transport.check_status(404)
        self.assertEqual(f.status, WARN)
        self.assertIn("describe this error page", f.detail)
        self.assertNotIn("bot protection", f.detail)

    def test_bot_block_statuses_mention_bot_protection(self):
        for status in (403, 429, 503):
            self.assertIn("bot protection", transport.check_status(status).detail, status)

    def test_generic_server_error_warns_without_bot_protection_hint(self):
        # The bot-protection hint is scoped to 403/429/503, not to 5xx as a
        # whole: a 500 or 502 is a server fault, not a client being blocked.
        # Guards against broadening the hint to every 5xx.
        for status in (500, 502):
            f = transport.check_status(status)
            self.assertEqual(f.status, WARN, status)
            self.assertIn("describe this error page", f.detail)
            self.assertNotIn("bot protection", f.detail, status)

    def test_boundary_399_passes_and_400_warns(self):
        self.assertEqual(transport.check_status(399).status, PASS)
        self.assertEqual(transport.check_status(400).status, WARN)


if __name__ == "__main__":
    unittest.main()
