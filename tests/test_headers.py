import unittest

from webposture import headers
from webposture.findings import PASS, WARN, FAIL

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
        self.assertIn("allows scripts from *", f.detail)

    def test_csp_scheme_only_script_sources_warn(self):
        f = headers.check_csp({"Content-Security-Policy": "default-src 'self' https: data:"})
        self.assertEqual(f.status, WARN)
        self.assertIn("default-src allows scripts from https:, data:", f.detail)

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

    def test_csp_without_script_directives_says_scripts_unrestricted(self):
        f = headers.check_csp({"Content-Security-Policy": "frame-ancestors 'none'"})
        self.assertEqual(f.status, PASS)
        self.assertIn("not restricted", f.detail)

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
