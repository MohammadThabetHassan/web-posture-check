import unittest

from webposture import checks, headers
from webposture.findings import FAIL, PASS, WARN
from webposture.headermap import HeaderMap

GOOD = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
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
        self.assertEqual(results["cross-origin-isolation"], WARN)
        self.assertEqual(results["x-xss-protection"], PASS)
        self.assertEqual(results["information-leakage"], PASS)

    def test_short_hsts_max_age_warns(self):
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=300"})
        self.assertEqual(f.status, WARN)

    def test_hsts_without_max_age_fails(self):
        f = headers.check_hsts({"Strict-Transport-Security": "includeSubDomains"})
        self.assertEqual(f.status, FAIL)

    def test_hsts_detail_reports_directives(self):
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload"})
        self.assertEqual(f.status, PASS)
        self.assertEqual(f.detail, "max-age=63072000; includeSubDomains; preload")

    def test_hsts_preload_without_include_subdomains_warns(self):
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=31536000; preload"})
        self.assertEqual(f.status, WARN)
        self.assertIn("includeSubDomains", f.detail)

    def test_hsts_preload_with_short_max_age_warns(self):
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=15552000; includeSubDomains; preload"})
        self.assertEqual(f.status, WARN)
        self.assertIn("1 year", f.detail)

    def test_hsts_preload_at_minimum_requirements_passes(self):
        # Exactly one year plus includeSubDomains is the minimum the preload
        # list accepts, so it must PASS. Guards the max-age comparison against
        # an off-by-one (< vs <=) that would warn on compliant sites.
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"})
        self.assertEqual(f.status, PASS)
        self.assertEqual(f.detail, "max-age=31536000; includeSubDomains; preload")

    def test_hsts_directives_are_case_insensitive(self):
        f = headers.check_hsts({"Strict-Transport-Security": "MAX-AGE=31536000; INCLUDESUBDOMAINS; PRELOAD"})
        self.assertEqual(f.status, PASS)

    def test_report_only_csp_warns(self):
        f = headers.check_csp({"Content-Security-Policy-Report-Only": "default-src 'self'"})
        self.assertEqual(f.status, WARN)

    def test_csp_unsafe_inline_in_script_src_warns(self):
        f = headers.check_csp({"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("script-src allows 'unsafe-inline'", f.detail)

    def test_csp_unsafe_inline_with_nonce_passes(self):
        f = headers.check_csp({"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'nonce-abc123'"})
        self.assertEqual(f.status, PASS)

    def test_csp_unsafe_inline_with_hash_passes(self):
        f = headers.check_csp({"Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'sha256-AbCd='"})
        self.assertEqual(f.status, PASS)

    def test_csp_falls_back_to_default_src(self):
        f = headers.check_csp({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("default-src", f.detail)

    def test_csp_script_src_overrides_default_src(self):
        f = headers.check_csp({"Content-Security-Policy": "default-src 'self' 'unsafe-inline'; script-src 'self'"})
        self.assertEqual(f.status, PASS)

    def test_csp_duplicate_script_src_uses_first_occurrence(self):
        # Browsers honour the first occurrence of a directive and ignore later
        # duplicates, so a later safe script-src must not mask an earlier unsafe
        # one. Guards against a last-wins regression that would be a silent
        # false negative on a real XSS exposure.
        f = headers.check_csp({"Content-Security-Policy": "script-src 'unsafe-inline'; script-src 'self'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("'unsafe-inline'", f.detail)

    def test_csp_unsafe_eval_warns_even_with_nonce(self):
        f = headers.check_csp({"Content-Security-Policy": "script-src 'nonce-abc123' 'unsafe-eval'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("'unsafe-eval'", f.detail)

    def test_csp_reports_both_problems(self):
        f = headers.check_csp({"Content-Security-Policy": "script-src 'unsafe-inline' 'unsafe-eval'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("'unsafe-inline'", f.detail)
        self.assertIn("'unsafe-eval'", f.detail)

    def test_csp_wildcard_script_source_warns(self):
        f = headers.check_csp({"Content-Security-Policy": "script-src 'self' *"})
        self.assertEqual(f.status, WARN)
        self.assertIn("script-src allows scripts from any host (*)", f.detail)

    def test_csp_scheme_only_script_sources_warn(self):
        f = headers.check_csp({"Content-Security-Policy": "default-src 'self' https: data:"})
        self.assertEqual(f.status, WARN)
        self.assertIn("default-src allows scripts from any HTTPS host and data: URLs (https:, data:)", f.detail)

    def test_csp_specific_hosts_pass(self):
        f = headers.check_csp({"Content-Security-Policy": "script-src 'self' https://cdn.example.com *.example.org"})
        self.assertEqual(f.status, PASS)

    def test_csp_strict_dynamic_ignores_broad_sources(self):
        f = headers.check_csp({"Content-Security-Policy": "script-src 'nonce-abc123' 'strict-dynamic' https: 'unsafe-inline'"})
        self.assertEqual(f.status, PASS)

    def test_csp_strict_dynamic_does_not_silence_unsafe_eval(self):
        # 'strict-dynamic' tells browsers to ignore host and scheme sources, but
        # it has no effect on 'unsafe-eval'. The exemption must stay scoped to
        # broad sources, so a policy that pairs the two must still warn about
        # 'unsafe-eval' even though the https: source is correctly ignored.
        f = headers.check_csp({"Content-Security-Policy": "script-src 'nonce-abc123' 'strict-dynamic' https: 'unsafe-eval'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("'unsafe-eval'", f.detail)
        self.assertNotIn("https:", f.detail)

    def test_csp_that_restricts_no_scripts_warns(self):
        # A policy with neither script-src nor default-src lets any script run, so
        # it is no protection against XSS; a PASS here would be a false pass.
        f = headers.check_csp({"Content-Security-Policy": "frame-ancestors 'none'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("does not restrict scripts", f.detail)

    def test_server_with_version_warns(self):
        for server in ("nginx/1.18.0", "Apache/2.4.41 (Ubuntu)", "Microsoft-IIS/10.0", "Apache/2"):
            f = headers.check_information_leakage({"Server": server})
            self.assertEqual(f.status, WARN, server)
            self.assertIn(server, f.detail)

    def test_server_without_version_passes(self):
        for server in ("nginx", "cloudflare", "AmazonS3", "ECS (dcb/7F84)"):
            f = headers.check_information_leakage({"Server": server})
            self.assertEqual(f.status, PASS, server)

    def test_stack_disclosure_headers_warn(self):
        f = headers.check_information_leakage({"X-Powered-By": "PHP/8.1.2", "x-aspnet-version": "4.0.30319"})
        self.assertEqual(f.status, WARN)
        self.assertIn("X-Powered-By: PHP/8.1.2", f.detail)
        self.assertIn("X-AspNet-Version: 4.0.30319", f.detail)

    def test_x_powered_by_without_version_still_warns(self):
        f = headers.check_information_leakage({"X-Powered-By": "Express"})
        self.assertEqual(f.status, WARN)

    def test_information_leakage_is_warn_only_and_keeps_exit_code(self):
        # The check is WARN-only by design so it never changes the exit code.
        # Run it through the full pipeline on an otherwise-secure response that
        # only leaks a server version: information-leakage must warn, and no
        # finding may be FAIL, since cli returns 1 only when something fails.
        leaking = dict(GOOD, Server="nginx/1.18.0")
        results = headers.run(leaking)
        leak = next(f for f in results if f.check == "information-leakage")
        self.assertEqual(leak.status, WARN)
        self.assertFalse(any(f.status == FAIL for f in results))

    def test_coop_and_corp_set_passes_without_coep(self):
        f = headers.check_cross_origin_isolation({"Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Resource-Policy": "same-site"})
        self.assertEqual(f.status, PASS)
        self.assertIn("COEP=unset", f.detail)
        self.assertNotIn("cross-origin isolated", f.detail)

    def test_coop_unsafe_none_warns(self):
        f = headers.check_cross_origin_isolation({"Cross-Origin-Opener-Policy": "unsafe-none", "Cross-Origin-Resource-Policy": "same-origin"})
        self.assertEqual(f.status, WARN)
        self.assertIn("Cross-Origin-Opener-Policy", f.detail)
        self.assertNotIn("Cross-Origin-Resource-Policy is missing", f.detail)

    def test_missing_corp_warns(self):
        f = headers.check_cross_origin_isolation({"Cross-Origin-Opener-Policy": "same-origin-allow-popups"})
        self.assertEqual(f.status, WARN)
        self.assertIn("Cross-Origin-Resource-Policy is missing", f.detail)

    def test_coop_same_origin_allow_popups_does_not_warn(self):
        # same-origin-allow-popups still severs a cross-origin opener's handle,
        # so it is an acceptable COOP value (sites that open OAuth popups rely on
        # it). With CORP set the check must pass and raise no COOP warning;
        # guards against tightening the test to require exactly "same-origin".
        f = headers.check_cross_origin_isolation({
            "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
            "Cross-Origin-Resource-Policy": "same-origin",
        })
        self.assertEqual(f.status, PASS)
        self.assertNotIn("Cross-Origin-Opener-Policy", f.detail)

    def test_unrecognised_coop_value_is_treated_as_missing(self):
        f = headers.check_cross_origin_isolation({
            "Cross-Origin-Opener-Policy": "same-orgin",
            "Cross-Origin-Resource-Policy": "same-origin",
        })
        self.assertEqual(f.status, WARN)
        self.assertIn("value 'same-orgin' is not recognised", f.detail)
        self.assertIn("COOP=unset", f.detail)

    def test_unrecognised_corp_value_is_treated_as_missing(self):
        f = headers.check_cross_origin_isolation({
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "sameorigin",
        })
        self.assertEqual(f.status, WARN)
        self.assertIn("Cross-Origin-Resource-Policy is missing", f.detail)

    def test_unrecognised_coep_value_warns_and_prevents_isolation(self):
        f = headers.check_cross_origin_isolation({
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require_corp",
        })
        self.assertEqual(f.status, WARN)
        self.assertNotIn("cross-origin isolated", f.detail)

    def test_coop_report_to_parameter_is_ignored(self):
        f = headers.check_cross_origin_isolation({
            "Cross-Origin-Opener-Policy": 'same-origin; report-to="coop"',
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": 'require-corp; report-to="coep"',
        })
        self.assertEqual(f.status, PASS)
        self.assertIn("cross-origin isolated", f.detail)

    def test_credentialless_coep_counts_as_isolated(self):
        f = headers.check_cross_origin_isolation({
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "credentialless",
        })
        self.assertIn("cross-origin isolated", f.detail)

    def test_x_xss_protection_disabled_passes(self):
        for value in ("0", " 0 "):
            self.assertEqual(headers.check_x_xss_protection({"X-XSS-Protection": value}).status, PASS, value)

    def test_x_xss_protection_disabled_with_params_passes(self):
        # Disabling is read from the first token, so leftover parameters (e.g.
        # from a site migrating 1; mode=block to 0; mode=block) still count as
        # disabled. Guards the 0 branch against a whole-value comparison that
        # would wrongly flag it as invalid.
        f = headers.check_x_xss_protection({"X-XSS-Protection": "0; mode=block"})
        self.assertEqual(f.status, PASS)
        self.assertNotIn("not a valid value", f.detail)

    def test_x_xss_protection_enabled_warns(self):
        for value in ("1", "1; mode=block", "1; report=https://example.com/r"):
            f = headers.check_x_xss_protection({"x-xss-protection": value})
            self.assertEqual(f.status, WARN, value)
            self.assertIn("legacy XSS auditor", f.detail)

    def test_x_xss_protection_invalid_value_warns(self):
        f = headers.check_x_xss_protection({"X-XSS-Protection": "yes"})
        self.assertEqual(f.status, WARN)
        self.assertIn("not a valid value", f.detail)

    def test_x_frame_options_accepted_without_csp(self):
        f = headers.check_framing({"X-Frame-Options": "sameorigin"})
        self.assertEqual(f.status, PASS)

    def test_x_frame_options_allow_from_fails(self):
        f = headers.check_framing({"X-Frame-Options": "ALLOW-FROM https://example.com"})
        self.assertEqual(f.status, FAIL)

    def test_unsafe_url_referrer_policy_fails(self):
        f = headers.check_referrer_policy({"Referrer-Policy": "unsafe-url"})
        self.assertEqual(f.status, FAIL)



class CatalogTest(unittest.TestCase):
    def test_every_header_check_is_in_the_catalog_in_report_order(self):
        names = [finding.check for finding in headers.run(HeaderMap())]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual([name for name in checks.NAMES if name in names], names)


class HstsStandardTest(unittest.TestCase):
    """RFC 6797: which header counts, what max-age=0 means, and plain HTTP."""

    def test_only_the_first_header_counts(self):
        # Section 8.1: browsers process only the first header, so a later weak one changes nothing.
        f = headers.check_hsts(HeaderMap([("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
                                          ("Strict-Transport-Security", "max-age=10")]))
        self.assertEqual(f.status, PASS)
        self.assertIn("first of 2 Strict-Transport-Security headers", f.detail)

    def test_a_weak_first_header_is_not_rescued_by_a_later_one(self):
        f = headers.check_hsts(HeaderMap([("Strict-Transport-Security", "max-age=10"),
                                          ("Strict-Transport-Security", "max-age=31536000")]))
        self.assertEqual(f.status, WARN)

    def test_max_age_zero_fails(self):
        # Section 6.1.1: max-age=0 tells browsers to forget the host, the same as no HSTS.
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=0"})
        self.assertEqual(f.status, FAIL)
        self.assertIn("stop enforcing HTTPS", f.detail)

    def test_empty_directives_are_skipped(self):
        # A trailing or doubled semicolon is common in the wild and harmless.
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=31536000;; includeSubDomains;"})
        self.assertEqual((f.status, f.detail), (PASS, "max-age=31536000; includeSubDomains"))

    def test_quoted_max_age_is_read(self):
        self.assertEqual(headers.check_hsts({"Strict-Transport-Security": 'max-age="31536000"'}).status, PASS)

    def test_non_numeric_max_age_fails(self):
        for value in ("max-age=abc", "max-age=-5", "max-age", "max-age=1e9"):
            self.assertEqual(headers.check_hsts({"Strict-Transport-Security": value}).status, FAIL, value)

    def test_a_repeated_max_age_or_include_subdomains_makes_the_header_invalid(self):
        # Chromium and Firefox reject these headers (RFC 6797 section 6.1 allows each directive once).
        for value, repeated in (("max-age=31536000; max-age=10", "max-age"),
                                ("max-age=31536000; includeSubDomains; INCLUDESUBDOMAINS", "INCLUDESUBDOMAINS")):
            f = headers.check_hsts({"Strict-Transport-Security": value})
            self.assertEqual(f.status, FAIL, value)
            self.assertIn(f"not valid (it repeats {repeated}), so browsers ignore it", f.detail)

    def test_unknown_directives_are_ignored_even_when_repeated(self):
        # Browsers skip directives they do not know; preload is one of them.
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=31536000; includeSubdomains; preload; preload; x=1"})
        self.assertEqual((f.status, f.detail), (PASS, "max-age=31536000; includeSubDomains; preload"))

    def test_include_subdomains_takes_no_value(self):
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=31536000; includeSubDomains=true"})
        self.assertEqual(f.status, FAIL)
        self.assertIn("includeSubDomains takes no value", f.detail)

    def test_any_directive_outside_the_grammar_makes_the_header_invalid(self):
        # Chromium's parser (net/http/http_security_headers.cc) rejects the header when
        # any directive's name, or unquoted value, is not a token, known directive or not.
        for value in ("max-age=31536000; include Sub Domains", 'max-age=31536000; x="unterminated',
                      "max-age=31536000; x=a b", "max-age=31536000; (x)", "max-age=31536000; =x",
                      "max-age=31536000; report-uri=https://r.example/x", 'max-age=31536000; x="oops; includeSubDomains'):
            f = headers.check_hsts({"Strict-Transport-Security": value})
            self.assertEqual(f.status, FAIL, value)
            self.assertIn("is not valid", f.detail, value)

    def test_an_empty_value_is_accepted(self):
        # Chromium accepts "x=" and "includeSubDomains=" (no value), but not includeSubDomains="".
        self.assertEqual(headers.check_hsts({"Strict-Transport-Security": "max-age=31536000; x="}).status, PASS)
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=31536000; includeSubDomains="})
        self.assertEqual((f.status, f.detail), (PASS, "max-age=31536000; includeSubDomains"))
        f = headers.check_hsts({"Strict-Transport-Security": 'max-age=31536000; includeSubDomains=""'})
        self.assertEqual(f.status, FAIL)
        self.assertIn("includeSubDomains takes no value", f.detail)

    def test_a_malformed_max_age_or_include_subdomains_is_ignored_by_every_browser(self):
        for value in ("max-age=1 2", "max-age=31536000; includeSubDomains=true", "max-age=(1)"):
            f = headers.check_hsts({"Strict-Transport-Security": value})
            self.assertEqual(f.status, FAIL, value)
            self.assertIn("so browsers ignore it", f.detail, value)
        # A header that is invalid either way keeps its FAIL.
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=0; x=a b"})
        self.assertEqual(f.status, FAIL)
        # A quoted value may contain ";" (the grammar's quoted-string).
        for value in ('max-age=31536000; x="a; b"', 'max-age="31536000"; x="a \\" b"'):
            self.assertEqual(headers.check_hsts({"Strict-Transport-Security": value}).status, PASS, value)

    def test_untrusted_certificate_is_named_in_a_pass(self):
        # RFC 6797 section 8.1: browsers ignore the header on a connection whose certificate is not trusted.
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=31536000"}, verified=False)
        self.assertEqual(f.status, PASS)
        self.assertIn("browsers ignore it while the certificate is not trusted", f.detail)
        missing = headers.check_hsts({}, verified=False)
        self.assertNotIn("certificate", missing.detail)

    def test_a_directive_name_is_not_matched_inside_another(self):
        # The old regex found "max-age=" inside "xmax-age=", which is an unknown directive.
        self.assertEqual(headers.check_hsts({"Strict-Transport-Security": "xmax-age=31536000"}).status, FAIL)

    def test_hsts_on_plain_http_fails(self):
        # Section 8.1: browsers ignore the header on a response that did not come over HTTPS.
        f = headers.check_hsts({"Strict-Transport-Security": "max-age=31536000"}, https=False)
        self.assertEqual(f.status, FAIL)
        self.assertIn("plain HTTP", f.detail)
        run = {f.check: f for f in headers.run({"Strict-Transport-Security": "max-age=31536000"}, https=False)}
        self.assertEqual(run["hsts"].status, FAIL)


class CspStandardTest(unittest.TestCase):
    """CSP3: every header and every comma-separated policy is enforced."""

    def test_empty_policy_fails(self):
        for value in ("", "   ", ";", " , "):
            f = headers.check_csp({"Content-Security-Policy": value})
            self.assertEqual(f.status, FAIL, repr(value))
            self.assertIn("empty", f.detail)

    def test_a_second_header_that_restricts_scripts_is_enforced(self):
        # Two headers: one restricts scripts, one sets frame-ancestors. Both apply.
        f = headers.check_csp(HeaderMap([("Content-Security-Policy", "script-src 'self'"),
                                         ("Content-Security-Policy", "frame-ancestors 'none'")]))
        self.assertEqual(f.status, PASS)
        self.assertIn("2 policies", f.detail)

    def test_a_weakness_counts_only_when_every_policy_shares_it(self):
        # 'unsafe-inline' is allowed by the first policy but blocked by the second, so inline scripts never run.
        f = headers.check_csp(HeaderMap([("Content-Security-Policy", "script-src 'self' 'unsafe-inline'"),
                                         ("Content-Security-Policy", "script-src 'self'")]))
        self.assertEqual(f.status, PASS)

    def test_a_weakness_every_policy_shares_is_reported(self):
        f = headers.check_csp(HeaderMap([("Content-Security-Policy", "script-src 'unsafe-eval' https:"),
                                         ("Content-Security-Policy", "default-src 'unsafe-eval' data:")]))
        self.assertEqual(f.status, WARN)
        self.assertIn("'unsafe-eval' in all 2 policies", f.detail)
        self.assertNotIn("https:", f.detail)

    def test_comma_separated_policies_in_one_header_are_each_enforced(self):
        f = headers.check_csp({"Content-Security-Policy": "script-src 'unsafe-inline', script-src 'self'"})
        self.assertEqual(f.status, PASS)

    def test_strict_dynamic_switches_off_unsafe_inline(self):
        # CSP3 section 6.7.3.3: 'strict-dynamic' disables 'unsafe-inline' for scripts, like a nonce or hash.
        f = headers.check_csp({"Content-Security-Policy": "script-src 'strict-dynamic' 'unsafe-inline'"})
        self.assertEqual(f.status, PASS)


class HttpWhitespaceTest(unittest.TestCase):
    """Fetch strips only tab, space, CR and LF from header values; other characters stay part of the value."""

    def test_a_no_break_space_is_part_of_the_value(self):
        self.assertEqual(headers.check_content_type_options({"X-Content-Type-Options": "nosniff\xa0"}).status, FAIL)
        self.assertEqual(headers.check_content_type_options({"X-Content-Type-Options": " nosniff\t"}).status, PASS)
        self.assertEqual(headers.check_framing({"X-Frame-Options": "DENY\x85"}).status, FAIL)
        self.assertEqual(headers.check_hsts({"Strict-Transport-Security": "max-age=31536000\x1f"}).status, FAIL)

    def test_repeated_cross_origin_policies_are_not_recognised(self):
        # Browsers combine them into "same-origin, same-origin", which no browser accepts.
        f = headers.check_cross_origin_isolation(HeaderMap([
            ("Cross-Origin-Opener-Policy", "same-origin"), ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cross-Origin-Resource-Policy", "same-origin"), ("Cross-Origin-Resource-Policy", "same-origin")]))
        self.assertEqual(f.status, WARN)
        self.assertIn("Cross-Origin-Resource-Policy value 'same-origin, same-origin' is not recognised", f.detail)
        self.assertIn("COOP=unset, CORP=unset", f.detail)

    def test_an_empty_cross_origin_policy_is_unset(self):
        f = headers.check_cross_origin_isolation({"Cross-Origin-Opener-Policy": "", "Cross-Origin-Resource-Policy": "same-site"})
        self.assertIn("COOP=unset, CORP=same-site", f.detail)
        self.assertNotIn("not recognised", f.detail)

    def test_x_xss_protection_is_decided_by_its_first_character(self):
        # Blink and WebKit read only the first character of the combined value.
        f = headers.check_x_xss_protection(HeaderMap([("X-XSS-Protection", "0"), ("X-XSS-Protection", "0")]))
        self.assertEqual((f.status, f.detail), (PASS, "0 (legacy XSS auditor disabled) (sent as '0, 0')"))
        self.assertEqual(headers.check_x_xss_protection({"X-XSS-Protection": "1, 0"}).status, WARN)
        self.assertIn("not a valid value", headers.check_x_xss_protection({"X-XSS-Protection": "on"}).detail)

    def test_cross_origin_policy_values_are_case_sensitive(self):
        # Chrome: Same-Origin / Require-Corp do not make the page cross-origin isolated.
        f = headers.check_cross_origin_isolation({"Cross-Origin-Opener-Policy": "Same-Origin",
                                                  "Cross-Origin-Resource-Policy": "same-origin",
                                                  "Cross-Origin-Embedder-Policy": "Require-Corp"})
        self.assertEqual(f.status, WARN)
        self.assertIn("Cross-Origin-Opener-Policy value 'Same-Origin' is not recognised", f.detail)
        self.assertNotIn("cross-origin isolated", f.detail)


class CspParsingTest(unittest.TestCase):
    """CSP3 section 2.2.1: only ASCII whitespace separates sources, and browsers drop a directive with any other character."""

    def test_a_directive_with_a_non_ascii_character_is_dropped(self):
        # A no-break space (byte 0xA0, often pasted in) is not ASCII whitespace: Chrome drops
        # script-src, so default-src governs scripts.
        f = headers.check_csp({"Content-Security-Policy": "default-src * 'unsafe-inline'; script-src 'self'\xa0'nonce-abc'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("default-src allows 'unsafe-inline'", f.detail)

    def test_a_directive_with_a_control_character_is_dropped(self):
        f = headers.check_csp({"Content-Security-Policy": "script-src * 'unsafe-inline'\x1f'strict-dynamic'"})
        self.assertEqual(f.status, FAIL)
        self.assertIn("has no directive browsers accept", f.detail)
        f = headers.check_csp({"Content-Security-Policy": "frame-ancestors 'none'; script-src * 'unsafe-inline'\x1f'strict-dynamic'"})
        self.assertEqual(f.status, WARN)
        self.assertIn("does not restrict scripts", f.detail)

    def test_ascii_whitespace_separates_sources(self):
        # Tab and form feed are ASCII whitespace; vertical tab is not.
        self.assertEqual(headers.check_csp({"Content-Security-Policy": "script-src\t'self'\x0c'nonce-abc123'"}).status, PASS)
        f = headers.check_csp({"Content-Security-Policy": "default-src *; script-src 'self'\x0b'nonce-abc123'"})
        self.assertIn("default-src allows scripts from any host", f.detail)

    def test_a_dropped_frame_ancestors_protects_nothing(self):
        self.assertEqual(headers.check_framing({"Content-Security-Policy": "frame-ancestors 'none'\xa0"}).status, FAIL)

    def test_a_wildcard_right_under_a_top_level_domain_is_any_host(self):
        # Anyone can register a name under .com.
        for source in ("https://*.com", "*.net"):
            f = headers.check_csp({"Content-Security-Policy": f"script-src 'self' {source}"})
            self.assertEqual(f.status, WARN, source)
            self.assertIn(f"({source})", f.detail)
        # Nobody can register under a special-use name.
        for source in ("*.localhost", "https://*.test", "*.internal"):
            self.assertEqual(headers.check_csp({"Content-Security-Policy": f"script-src 'self' {source}"}).status, PASS, source)


class CspScriptModelTest(unittest.TestCase):
    """What a policy lets scripts do, as browsers decide it (CSP3 sections 4.4, 6.7.2 and 6.7.3)."""

    def _csp(self, *values):
        return headers.check_csp(HeaderMap([("Content-Security-Policy", value) for value in values]))

    def test_broad_sources_count_whatever_their_spelling(self):
        # A script must pass every policy. '*' and 'https:' are spelled differently,
        # but both allow any HTTPS host, so together they still do.
        cases = [
            (("default-src * 'unsafe-inline' 'unsafe-eval' data: blob:", "script-src 'self' https:"), "any HTTPS host"),
            (("script-src *", "script-src https:"), "any HTTPS host"),
            (("script-src http:", "script-src https:"), "any HTTPS host"),
            (("script-src *", "script-src http:"), "any host"),
        ]
        for values, expected in cases:
            f = self._csp(*values)
            self.assertEqual(f.status, WARN, values)
            self.assertIn(f"scripts from {expected} in all 2 policies", f.detail, values)
        f = self._csp(*cases[0][0])
        self.assertIn("default-src and script-src allow scripts from any HTTPS host in all 2 policies (default-src *; script-src https:)",
                      f.detail)

    def test_a_policy_with_only_specific_hosts_removes_the_broad_reach(self):
        self.assertEqual(self._csp("script-src *", "script-src https://cdn.example.com").status, PASS)

    def test_wildcard_host_sources_allow_any_host(self):
        for source in ("https://*", "http://*", "*:*", "https://*:443", "*:8443", "https://*/js/"):
            f = self._csp(f"script-src 'self' {source}")
            self.assertEqual(f.status, WARN, source)
            self.assertIn("allows scripts from any", f.detail, source)
            self.assertIn(f"({source})", f.detail, source)

    def test_data_urls_alone_are_named(self):
        f = self._csp("script-src 'self' data:")
        self.assertEqual(f.status, WARN)
        self.assertIn("script-src allows scripts from data: URLs (data:)", f.detail)

    def test_subdomain_wildcards_and_non_web_schemes_are_not_any_host(self):
        for source in ("*.example.com", "https://*.example.com", "blob:", "wss://*", "chrome-extension:"):
            self.assertEqual(self._csp(f"script-src 'self' {source}").status, PASS, source)

    def test_only_a_well_formed_nonce_or_hash_switches_off_unsafe_inline(self):
        # A nonce or hash must match the grammar; an empty one or an unfilled
        # template placeholder is not one, so 'unsafe-inline' still applies.
        for source in ("'nonce-'", "'nonce-{{NONCE}}'", "'sha256-'", "'nonce-<%=nonce%>'"):
            f = self._csp(f"script-src 'self' 'unsafe-inline' {source}")
            self.assertEqual(f.status, WARN, source)
            self.assertIn("'unsafe-inline'", f.detail, source)
        for source in ("'nonce-abc123'", "'nonce-a_b-c'", "'sha384-AbC+/d=='", "'NONCE-Xy9='"):
            self.assertEqual(self._csp(f"script-src 'self' 'unsafe-inline' {source}").status, PASS, source)

    def test_script_src_elem_governs_script_elements(self):
        f = self._csp("script-src 'self'; script-src-elem * 'unsafe-inline'")
        self.assertEqual(f.status, WARN)
        self.assertIn("script-src-elem allows 'unsafe-inline' without a nonce or hash", f.detail)
        self.assertIn("script-src-elem allows scripts from any host (*)", f.detail)

    def test_script_src_attr_governs_event_handlers(self):
        f = self._csp("default-src 'self'; script-src-attr 'unsafe-inline'")
        self.assertEqual(f.status, WARN)
        self.assertIn("script-src-attr allows 'unsafe-inline'", f.detail)

    def test_script_src_elem_alone_leaves_event_handlers_and_eval_unrestricted(self):
        f = self._csp("script-src-elem 'self'")
        self.assertEqual(f.status, WARN)
        self.assertIn("nothing restricts inline event handlers", f.detail)
        self.assertIn("nothing restricts eval()", f.detail)

    def test_handlers_inherit_script_src_when_elements_have_their_own_directive(self):
        f = self._csp("script-src 'self' 'unsafe-inline'; script-src-elem 'self'")
        self.assertEqual(f.status, WARN)
        self.assertIn("script-src allows 'unsafe-inline'", f.detail)
        self.assertNotIn("script-src-elem allows", f.detail)

    def test_one_message_when_elements_and_handlers_share_a_directive(self):
        f = self._csp("script-src 'unsafe-inline'")
        self.assertEqual(f.detail.count("'unsafe-inline'"), 1)

    def test_strict_policies_pass(self):
        for value in ("script-src 'strict-dynamic' 'nonce-abc123' https: 'unsafe-inline'",
                      "script-src 'self'; script-src-elem 'self' https://cdn.example.com; script-src-attr 'none'",
                      "default-src 'none'; script-src 'sha256-AbCd='"):
            self.assertEqual(self._csp(value).status, PASS, value)


class FramingStandardTest(unittest.TestCase):
    """The HTML standard's X-Frame-Options processing model, and CSP frame-ancestors."""

    def test_frame_ancestors_that_allows_any_site_fails(self):
        for value in ("*", "https:", "http: https:", "https://*", "*:443", "'self' *"):
            f = headers.check_framing({"Content-Security-Policy": f"default-src 'self'; frame-ancestors {value}"})
            self.assertEqual(f.status, FAIL, value)
            self.assertIn("allows any site", f.detail)

    def test_restrictive_frame_ancestors_pass(self):
        for value in ("'none'", "'self'", "https://partner.example", "*.example.com", "", "'self' chrome-extension:"):
            f = headers.check_framing({"Content-Security-Policy": f"frame-ancestors {value}"})
            self.assertEqual(f.status, PASS, value)
        self.assertIn("'none'", headers.check_framing({"Content-Security-Policy": "frame-ancestors"}).detail)

    def test_frame_ancestors_overrides_x_frame_options(self):
        # HTML: an enforced frame-ancestors makes browsers ignore X-Frame-Options, so DENY does not help.
        f = headers.check_framing({"Content-Security-Policy": "frame-ancestors *", "X-Frame-Options": "DENY"})
        self.assertEqual(f.status, FAIL)
        self.assertIn("X-Frame-Options is ignored", f.detail)

    def test_one_restrictive_policy_protects(self):
        f = headers.check_framing(HeaderMap([("Content-Security-Policy", "frame-ancestors *"),
                                             ("Content-Security-Policy", "frame-ancestors 'self'")]))
        self.assertEqual(f.status, PASS)

    def test_report_only_frame_ancestors_does_not_count(self):
        f = headers.check_framing({"Content-Security-Policy-Report-Only": "frame-ancestors 'none'"})
        self.assertEqual(f.status, FAIL)

    def test_repeated_identical_x_frame_options_is_that_value(self):
        # A proxy that adds the header again produces "SAMEORIGIN, SAMEORIGIN"; browsers read SAMEORIGIN.
        for headers_in in ({"X-Frame-Options": "SAMEORIGIN, SAMEORIGIN"},
                           HeaderMap([("X-Frame-Options", "SAMEORIGIN"), ("X-Frame-Options", "sameorigin")])):
            f = headers.check_framing(headers_in)
            self.assertEqual(f.status, PASS)
            self.assertIn("SAMEORIGIN", f.detail)

    def test_conflicting_x_frame_options_block_framing(self):
        # HTML: several different values including deny, sameorigin or allowall block framing outright.
        for value in ("DENY, SAMEORIGIN", "SAMEORIGIN, ALLOWALL"):
            f = headers.check_framing({"X-Frame-Options": value})
            self.assertEqual(f.status, PASS, value)
            self.assertIn("treat as DENY", f.detail)

    def test_unknown_x_frame_options_values_fail(self):
        for value in ("ALLOWALL", "foo", "", "foo, bar"):
            self.assertEqual(headers.check_framing({"X-Frame-Options": value}).status, FAIL, value)


class ListedHeaderValuesTest(unittest.TestCase):
    """Headers the Fetch standard reads by combining and splitting on commas."""

    def test_nosniff_repeated_passes(self):
        # Fetch, "determine nosniff": the first value decides.
        for headers_in in ({"X-Content-Type-Options": "nosniff, nosniff"},
                           HeaderMap([("X-Content-Type-Options", "nosniff"), ("X-Content-Type-Options", "nosniff")]),
                           {"X-Content-Type-Options": "NoSniff"}):
            f = headers.check_content_type_options(headers_in)
            self.assertEqual(f.status, PASS)

    def test_nosniff_must_come_first(self):
        f = headers.check_content_type_options({"X-Content-Type-Options": "foo, nosniff"})
        self.assertEqual(f.status, FAIL)

    def test_referrer_policy_uses_the_last_recognised_value(self):
        # Referrer Policy section 8.1: a list names fallbacks; the last recognised token applies.
        f = headers.check_referrer_policy({"Referrer-Policy": "no-referrer, unsafe-url"})
        self.assertEqual(f.status, FAIL)
        f = headers.check_referrer_policy({"Referrer-Policy": "unsafe-url, strict-origin-when-cross-origin"})
        self.assertEqual(f.status, PASS)
        self.assertIn("strict-origin-when-cross-origin", f.detail)
        f = headers.check_referrer_policy({"Referrer-Policy": "strict-origin-when-cross-origin, made-up-future-value"})
        self.assertEqual(f.status, PASS)

    def test_referrer_policy_across_repeated_headers(self):
        f = headers.check_referrer_policy(HeaderMap([("Referrer-Policy", "no-referrer"), ("Referrer-Policy", "unsafe-url")]))
        self.assertEqual(f.status, FAIL)

    def test_referrer_policy_with_no_recognised_value_warns(self):
        f = headers.check_referrer_policy({"Referrer-Policy": "nope"})
        self.assertEqual(f.status, WARN)
        self.assertIn("no recognised value", f.detail)

    def test_no_referrer_when_downgrade_warns(self):
        f = headers.check_referrer_policy({"Referrer-Policy": "no-referrer-when-downgrade"})
        self.assertEqual(f.status, WARN)
        self.assertIn("full URL", f.detail)

    def test_empty_permissions_policy_warns(self):
        self.assertEqual(headers.check_permissions_policy({"Permissions-Policy": " "}).status, WARN)

    def test_every_server_header_is_checked(self):
        f = headers.check_information_leakage(HeaderMap([("Server", "cloudflare"), ("Server", "nginx/1.25.3")]))
        self.assertEqual(f.status, WARN)
        self.assertIn("nginx/1.25.3", f.detail)


if __name__ == "__main__":
    unittest.main()
