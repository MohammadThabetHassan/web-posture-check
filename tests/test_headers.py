import unittest

from webposture import headers
from webposture.findings import PASS, WARN, FAIL

GOOD = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


class HeaderChecksTest(unittest.TestCase):
    def test_good_headers_all_pass(self):
        self.assertTrue(all(f.status == PASS for f in headers.run(GOOD)))

    def test_header_names_are_case_insensitive(self):
        lowered = {k.lower(): v for k, v in GOOD.items()}
        self.assertTrue(all(f.status == PASS for f in headers.run(lowered)))

    def test_missing_headers(self):
        results = {f.check: f.status for f in headers.run({})}
        self.assertEqual(results["hsts"], FAIL)
        self.assertEqual(results["csp"], FAIL)
        self.assertEqual(results["x-content-type-options"], FAIL)
        self.assertEqual(results["clickjacking"], FAIL)
        self.assertEqual(results["referrer-policy"], WARN)
        self.assertEqual(results["permissions-policy"], WARN)

    def test_short_hsts_max_age_warns(self):
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=300"})
        self.assertEqual(f.status, WARN)

    def test_hsts_without_max_age_fails(self):
        f = headers.check_hsts({"Strict-Transport-Security": "includeSubDomains"})
        self.assertEqual(f.status, FAIL)

    def test_report_only_csp_warns(self):
        f = headers.check_csp({"Content-Security-Policy-Report-Only": "default-src 'self'"})
        self.assertEqual(f.status, WARN)

    def test_x_frame_options_accepted_without_csp(self):
        f = headers.check_framing({"X-Frame-Options": "sameorigin"})
        self.assertEqual(f.status, PASS)

    def test_x_frame_options_allow_from_fails(self):
        f = headers.check_framing({"X-Frame-Options": "ALLOW-FROM https://example.com"})
        self.assertEqual(f.status, FAIL)

    def test_unsafe_url_referrer_policy_fails(self):
        f = headers.check_referrer_policy({"Referrer-Policy": "unsafe-url"})
        self.assertEqual(f.status, FAIL)


if __name__ == "__main__":
    unittest.main()
