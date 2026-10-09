import unittest
from datetime import datetime, timezone

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

    def test_max_age_zero_deletion_is_ignored(self):
        f = cookies.check_cookies(["sid=; Max-Age=0; Path=/"], is_https=True)
        self.assertEqual(f.status, PASS)
        self.assertIn("1 deletion(s) ignored", f.detail)

    def test_past_expires_deletion_is_ignored(self):
        now = datetime(2026, 10, 9, tzinfo=timezone.utc)
        f = cookies.check_cookies(["sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"], is_https=True, now=now)
        self.assertEqual(f.status, PASS)

    def test_future_expires_is_still_checked(self):
        now = datetime(2026, 10, 9, tzinfo=timezone.utc)
        f = cookies.check_cookies(["sid=1; Expires=Sat, 09 Oct 2027 14:49:56 GMT"], is_https=True, now=now)
        self.assertEqual(f.status, FAIL)

    def test_max_age_wins_over_expires(self):
        # RFC 6265: a positive Max-Age keeps the cookie even if Expires is past.
        now = datetime(2026, 10, 9, tzinfo=timezone.utc)
        f = cookies.check_cookies(["sid=1; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT"], is_https=True, now=now)
        self.assertEqual(f.status, FAIL)

    def test_deletion_alongside_live_cookie_only_reports_live_one(self):
        f = cookies.check_cookies(["old=; Max-Age=0", "sid=1; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertNotIn("old:", f.detail)
        self.assertIn("sid: missing Secure", f.detail)

    def test_valid_host_prefix_passes(self):
        f = cookies.check_cookies(["__Host-sid=1; Path=/; Secure; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, PASS)

    def test_valid_prefix_still_gets_flag_review(self):
        # A valid prefix does not exempt a cookie from the ordinary flag review:
        # this __Host- cookie satisfies the prefix rules but is missing HttpOnly,
        # so it must still warn (cf. the live __Host-GAPS / __Secure-STRP cases).
        f = cookies.check_cookies(["__Host-sid=1; Path=/; Secure; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, WARN)
        self.assertIn("missing HttpOnly", f.detail)

    def test_host_prefix_with_domain_fails(self):
        f = cookies.check_cookies(["__Host-sid=1; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("__Host-sid: __Host- prefix requires no Domain", f.detail)

    def test_host_prefix_lists_every_violation(self):
        f = cookies.check_cookies(["__Host-sid=1; Path=/app; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("requires Secure, Path=/ (browsers reject it)", f.detail)
        # The prefix message already covers Secure, so it is not repeated.
        self.assertNotIn("missing Secure", f.detail)

    def test_host_prefix_without_path_fails(self):
        f = cookies.check_cookies(["__Host-sid=1; Secure; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("Path=/", f.detail)

    def test_secure_prefix_without_secure_fails_even_over_http(self):
        f = cookies.check_cookies(["__Secure-id=1; HttpOnly; SameSite=Lax"], is_https=False)
        self.assertEqual(f.status, FAIL)
        self.assertIn("__Secure- prefix requires Secure", f.detail)

    def test_secure_prefix_allows_domain_and_any_path(self):
        f = cookies.check_cookies(["__Secure-id=1; Domain=example.com; Path=/app; Secure; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, PASS)

    def test_prefix_match_is_case_insensitive(self):
        f = cookies.check_cookies(["__HOST-sid=1; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax"], is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("__HOST- prefix requires no Domain", f.detail)

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
