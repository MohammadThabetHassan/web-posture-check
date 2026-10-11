import unittest
from datetime import datetime, timezone

from webposture import cookies
from webposture.findings import FAIL, PASS, WARN


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

    def test_host_prefix_with_empty_domain_passes(self):
        # Browsers ignore an empty Domain attribute, so the cookie stays host-only.
        for value in ("__Host-sid=1; Path=/; Domain=; Secure; HttpOnly; SameSite=Lax",
                      "__Host-sid=1; Path=/; Domain; Secure; HttpOnly; SameSite=Lax"):
            f = cookies.check_cookies([value], is_https=True)
            self.assertEqual(f.status, PASS, value)

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



class CookieChainTest(unittest.TestCase):
    """Cookies set across a redirect chain, judged like a browser's cookie store."""

    def test_each_cookie_is_judged_by_the_scheme_of_the_response_that_set_it(self):
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("a=1; HttpOnly; SameSite=Lax", "http://example.com/", redirect=True),
                                   SetCookie("b=1; HttpOnly; SameSite=Lax", "https://example.com/")], is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("b: missing Secure", f.detail)
        self.assertNotIn("a (", f.detail)

    def test_a_later_write_replaces_an_earlier_one(self):
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("sid=1; Path=/", "https://example.com/start", redirect=True),
                                   SetCookie("sid=2; Path=/; Secure; HttpOnly; SameSite=Lax", "https://example.com/")], is_https=True)
        self.assertEqual(f.status, PASS)
        self.assertIn("1 cookie(s)", f.detail)

    def test_a_cookie_deleted_by_the_final_page_is_not_reported(self):
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("sid=1; Path=/", "https://example.com/start", redirect=True),
                                   SetCookie("sid=; Path=/; Max-Age=0", "https://example.com/")], is_https=True)
        self.assertEqual(f.status, PASS)
        self.assertIn("1 deletion(s) ignored", f.detail)

    def test_a_redirect_from_another_host_keeps_its_own_cookie(self):
        # A browser keeps both host-only cookies: the insecure one from 127.0.0.1
        # is not replaced by the good one that localhost sets later.
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("sid=insecure; Path=/", "https://127.0.0.1/", redirect=True),
                                   SetCookie("sid=good; Path=/; Secure; HttpOnly; SameSite=Lax", "https://localhost/")],
                                  is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("sid (set by the redirect at https://127.0.0.1/): missing Secure", f.detail)

    def test_a_deletion_by_another_host_does_not_hide_a_cookie(self):
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("sid=insecure; Path=/", "https://www.example.com/", redirect=True),
                                   SetCookie("sid=; Path=/; Max-Age=0", "https://example.com/")], is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("sid (set by the redirect at https://www.example.com/): missing Secure", f.detail)

    def test_a_domain_cookie_is_shared_by_the_hosts_of_that_domain(self):
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("sid=1; Domain=.Example.com; Path=/", "https://www.example.com/", redirect=True),
                                   SetCookie("sid=; Domain=example.com; Path=/; Max-Age=0", "https://example.com/")],
                                  is_https=True)
        self.assertEqual(f.status, PASS)
        self.assertIn("no cookies set (1 deletion(s) ignored)", f.detail)

    def test_without_path_the_cookie_belongs_to_the_directory_that_set_it(self):
        from webposture.cookies import SetCookie
        good = "Secure; HttpOnly; SameSite=Lax"
        two = cookies.check_cookies([SetCookie(f"sid=1; {good}", "https://example.com/account/login", redirect=True),
                                     SetCookie(f"sid=2; {good}", "https://example.com/")], is_https=True)
        self.assertIn("2 cookie(s)", two.detail)
        # Set at / without Path, then deleted with Path=/: the same cookie, so it is gone.
        gone = cookies.check_cookies([SetCookie("sid=1", "https://example.com/start", redirect=True),
                                      SetCookie("sid=; Path=/; Max-Age=0", "https://example.com/")], is_https=True)
        self.assertEqual(gone.status, PASS)
        self.assertIn("no cookies set", gone.detail)

    def test_only_spaces_and_tabs_are_trimmed_from_attributes(self):
        # RFC 6265 section 5.2: "Secure\xa0" is not the Secure attribute.
        name, attributes = cookies.parse_set_cookie("sid=1;\tSecure\xa0; HttpOnly ;SameSite=Lax")
        self.assertNotIn("secure", attributes)
        self.assertIn("httponly", attributes)
        self.assertEqual((name, attributes["samesite"]), ("sid", "Lax"))

    def test_cookie_identity(self):
        key = cookies.cookie_key
        self.assertEqual(key("a", {}, "https://Example.com/x/y/z"), ("a", "example.com", True, "/x/y"))
        self.assertEqual(key("a", {"path": "nope"}, "https://example.com/x"), ("a", "example.com", True, "/"))
        self.assertEqual(key("a", {"domain": ".EXAMPLE.com", "path": "/p"}, "https://www.example.com/"),
                         ("a", "example.com", False, "/p"))
        self.assertEqual(key("a", {}), ("a", "", True, "/"))
        # An IP address may only name itself, and the cookie is then host-only (as in Chrome).
        self.assertEqual(key("a", {"domain": "127.0.0.1"}, "https://127.0.0.1/"), ("a", "127.0.0.1", True, "/"))

    def test_browsers_reject_a_domain_that_does_not_cover_the_sending_host(self):
        key = cookies.cookie_key
        for domain, url in (("other.net", "https://example.com/"), ("..example.com", "https://www.example.com/"),
                            ("example.com", "https://notexample.com/"), ("0.0.1", "https://127.0.0.1/")):
            self.assertIsNone(key("a", {"domain": domain}, url), domain)

    def test_a_rejected_deletion_leaves_the_cookie_in_place(self):
        # RFC 6265 section 5.3 step 6: app.other.net cannot touch a cookie for example.com (checked in Chrome).
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("sid=bad; Domain=example.com; Path=/", "https://a.example.com/", redirect=True),
                                   SetCookie("sid=; Domain=example.com; Path=/; Max-Age=0", "https://app.other.net/")],
                                  is_https=True)
        self.assertEqual(f.status, FAIL)
        self.assertIn("sid (set by the redirect at https://a.example.com/): missing Secure", f.detail)

    def test_plain_http_cannot_replace_or_delete_a_secure_cookie(self):
        # RFC 6265bis: a non-secure origin cannot overwrite a Secure cookie.
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("sid=1; Secure; Path=/", "https://example.com/", redirect=True),
                                   SetCookie("sid=; Path=/; Max-Age=0", "http://example.com/")], is_https=False)
        self.assertEqual(f.status, WARN)
        self.assertIn("sid (set by the redirect at https://example.com/): missing HttpOnly, missing SameSite", f.detail)

    def test_a_secure_cookie_from_plain_http_is_not_stored(self):
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("sid=1; Secure; HttpOnly; SameSite=Lax", "http://example.com/")], is_https=False)
        self.assertEqual((f.status, f.detail), ("PASS", "no cookies set"))

    def test_same_name_with_another_path_is_another_cookie(self):
        from webposture.cookies import SetCookie
        f = cookies.check_cookies([SetCookie("sid=1; Path=/a; Secure; HttpOnly; SameSite=Lax", "https://example.com/"),
                                   SetCookie("sid=2; Path=/b; Secure; HttpOnly; SameSite=Lax", "https://example.com/")], is_https=True)
        self.assertIn("2 cookie(s)", f.detail)

if __name__ == "__main__":
    unittest.main()
