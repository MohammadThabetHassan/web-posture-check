import unittest

from webposture import cookies
from webposture.findings import PASS, WARN, FAIL


class ParseSetCookieTest(unittest.TestCase):
    def test_name_and_attributes(self):
        name, attrs = cookies.parse_set_cookie("sid=abc=123; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(name, "sid")
        self.assertEqual(attrs["samesite"], "Lax")
        self.assertIn("secure", attrs)
        self.assertIn("httponly", attrs)

    def test_attribute_names_are_case_insensitive(self):
        _, attrs = cookies.parse_set_cookie("sid=1; SECURE; httponly; samesite=Strict")
        self.assertEqual(set(attrs), {"secure", "httponly", "samesite"})


class CheckCookiesTest(unittest.TestCase):
    def test_no_cookies_passes(self):
        self.assertEqual(cookies.check_cookies([], is_https=True).status, PASS)

    def test_well_flagged_cookie_passes(self):
        f = cookies.check_cookies(["sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, PASS)

    def test_missing_secure_on_https_fails(self):
        f = cookies.check_cookies(["sid=1; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("sid: missing Secure", f.detail)

    def test_missing_secure_over_plain_http_is_not_a_failure(self):
        # Over http:// the Secure flag would stop the cookie being sent at all;
        # the https-redirect check is what reports plain HTTP.
        f = cookies.check_cookies(["sid=1; HttpOnly; SameSite=Lax"], is_https=False)
        self.assertEqual(f.status, PASS)

    def test_missing_httponly_and_samesite_warn(self):
        f = cookies.check_cookies(["prefs=dark; Secure"], is_https=True)
        self.assertEqual(f.status, WARN)
        self.assertIn("missing HttpOnly", f.detail)
        self.assertIn("missing SameSite", f.detail)

    def test_samesite_none_without_secure_fails_even_over_http(self):
        f = cookies.check_cookies(["track=1; HttpOnly; SameSite=None"], is_https=False)
        self.assertEqual(f.status, FAIL)
        self.assertIn("SameSite=None without Secure", f.detail)

    def test_samesite_none_with_secure_passes(self):
        # SameSite=None is legitimate and common for cross-site cookies (SSO,
        # embeds) as long as Secure is set. The SameSite=None failure must stay
        # gated on Secure being absent, so this canonical config must pass.
        f = cookies.check_cookies(["sso=1; Secure; HttpOnly; SameSite=None"], is_https=True)
        self.assertEqual(f.status, PASS)

    def test_worst_status_wins_and_every_cookie_is_listed(self):
        f = cookies.check_cookies(
            ["good=1; Secure; HttpOnly; SameSite=Strict", "a=1; Secure", "b=1; HttpOnly; SameSite=Lax"],
            is_https=True,
        )
        self.assertEqual(f.status, FAIL)
        self.assertIn("a: missing HttpOnly, missing SameSite", f.detail)
        self.assertIn("b: missing Secure", f.detail)
        self.assertNotIn("good:", f.detail)


if __name__ == "__main__":
    unittest.main()
