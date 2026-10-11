import sys
import unittest
from unittest import mock

from webposture import emailauth
from webposture.findings import FAIL, PASS, WARN

try:
    import dns.resolver  # noqa: F401
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False


class MailDomainTest(unittest.TestCase):
    def test_strips_www_and_trailing_dot(self):
        self.assertEqual(emailauth.mail_domain("www.Example.com."), "example.com")
        self.assertEqual(emailauth.mail_domain("shop.example.com"), "shop.example.com")


class CheckSpfTest(unittest.TestCase):
    def check(self, *txt):
        return emailauth.check_spf("example.com", list(txt))

    def test_hard_and_soft_fail_pass(self):
        for record in ("v=spf1 -all", "v=spf1 include:_spf.google.com ~all", "V=SPF1 mx -ALL"):
            self.assertEqual(self.check(record).status, PASS, record)

    def test_other_txt_records_are_ignored(self):
        f = self.check("google-site-verification=abc", "v=spf1 -all", "v=spf10 nonsense")
        self.assertEqual(f.status, PASS)

    def test_missing_record_warns(self):
        f = self.check("google-site-verification=abc")
        self.assertEqual(f.status, WARN)
        self.assertIn("no SPF record", f.detail)

    def test_multiple_records_fail(self):
        f = self.check("v=spf1 -all", "v=spf1 include:x ~all")
        self.assertEqual(f.status, FAIL)
        self.assertIn("2 SPF records", f.detail)

    def test_plus_all_fails(self):
        for record in ("v=spf1 +all", "v=spf1 include:x all"):
            f = self.check(record)
            self.assertEqual(f.status, FAIL, record)
            self.assertIn("every server", f.detail)

    def test_neutral_all_warns(self):
        self.assertIn("neutral", self.check("v=spf1 mx ?all").detail)

    def test_no_all_mechanism_warns(self):
        f = self.check("v=spf1 mx include:x")
        self.assertEqual(f.status, WARN)
        self.assertIn("no 'all' mechanism", f.detail)

    def test_redirect_without_all_passes(self):
        f = self.check("v=spf1 redirect=_spf.example.net")
        self.assertEqual(f.status, PASS)
        self.assertIn("redirect=_spf.example.net", f.detail)


class LookupTxtTest(unittest.TestCase):
    def test_missing_dnspython_is_reported_as_skipped(self):
        blocked = {"dns": None, "dns.resolver": None, "dns.exception": None}
        with mock.patch.dict(sys.modules, blocked):
            txt, problem = emailauth.lookup_txt("example.com", 5)
        self.assertEqual(txt, [])
        self.assertIn("web-posture-check[dns]", str(problem))

    @unittest.skipUnless(HAVE_DNSPYTHON, "needs the optional dns extra")
    def test_split_txt_strings_are_joined_without_spaces(self):
        # RFC 7208 section 3.3: a TXT record split into several strings must be
        # concatenated with no separator. Long SPF records (many includes) are
        # split past 255 bytes, often mid-token, so a space-join would corrupt
        # a domain like _spf.google.com into "_spf.goog le.com".
        record = type("Txt", (), {"strings": (b"v=spf1 include:_spf.goog", b"le.com ~all")})
        with mock.patch("dns.resolver.resolve", return_value=[record()]):
            txt, problem = emailauth.lookup_txt("example.com", 5)
        self.assertIsNone(problem)
        self.assertEqual(txt, ["v=spf1 include:_spf.google.com ~all"])



class DmarcTest(unittest.TestCase):
    def test_candidates_walk_up_to_two_labels(self):
        self.assertEqual(emailauth.dmarc_candidates("a.b.example.com"), ["a.b.example.com", "b.example.com", "example.com"])
        self.assertEqual(emailauth.dmarc_candidates("example.com"), ["example.com"])

    def test_reject_and_quarantine_pass(self):
        for record in ("v=DMARC1; p=reject; rua=mailto:r@example.com", "v=DMARC1;p=quarantine;pct=100", "V=DMARC1; P=REJECT"):
            self.assertEqual(emailauth.check_dmarc("example.com", [record]).status, PASS, record)

    def test_missing_record_warns(self):
        f = emailauth.check_dmarc(None, [])
        self.assertEqual(f.status, WARN)
        self.assertIn("no DMARC record", f.detail)

    def test_p_none_warns(self):
        f = emailauth.check_dmarc("example.com", ["v=DMARC1; p=none; rua=mailto:r@example.com"])
        self.assertEqual(f.status, WARN)
        self.assertIn("only monitors", f.detail)

    def test_missing_or_invalid_p_warns(self):
        for record in ("v=DMARC1; rua=mailto:r@example.com", "v=DMARC1; p=block"):
            f = emailauth.check_dmarc("example.com", [record])
            self.assertEqual(f.status, WARN, record)
            self.assertIn("treat it as p=none", f.detail)

    def test_partial_pct_warns(self):
        f = emailauth.check_dmarc("example.com", ["v=DMARC1; p=reject; pct=25"])
        self.assertEqual(f.status, WARN)
        self.assertIn("pct=25", f.detail)

    def test_multiple_records_fail(self):
        f = emailauth.check_dmarc("example.com", ["v=DMARC1; p=reject", "v=DMARC1; p=none"])
        self.assertEqual(f.status, FAIL)

    def test_non_dmarc_txt_is_ignored(self):
        f = emailauth.check_dmarc("example.com", ["some-verification=abc", "v=DMARC1; p=reject"])
        self.assertEqual(f.status, PASS)



class DkimTest(unittest.TestCase):
    def test_dmarc_parts_without_a_value_are_ignored(self):
        self.assertEqual(emailauth.parse_dmarc_tags("v=DMARC1; p=reject; junk; ;"), {"v": "DMARC1", "p": "reject"})

    def test_parse_key_ignores_non_dkim_txt(self):
        self.assertIsNone(emailauth.parse_dkim_key(["google-site-verification=abc"]))
        self.assertEqual(emailauth.parse_dkim_key(["v=DKIM1; k=rsa; p=MIGf MA0"]), "MIGfMA0")
        self.assertEqual(emailauth.parse_dkim_key(["v=DKIM1; p="]), "")

    def test_active_key_passes_and_names_selectors(self):
        f = emailauth.check_dkim("example.com", {"google": "MIIB", "selector1": None}, explicit=False)
        self.assertEqual(f.status, PASS)
        self.assertIn("under: google", f.detail)

    def test_nothing_found_under_common_selectors_is_unknown_not_a_failure(self):
        f = emailauth.check_dkim("example.com", {"google": None, "k1": None}, explicit=False)
        self.assertEqual(f.status, WARN)
        self.assertIn("may still use another selector", f.detail)

    def test_only_revoked_keys_warns(self):
        f = emailauth.check_dkim("example.com", {"google": "", "k1": None}, explicit=False)
        self.assertEqual(f.status, WARN)
        self.assertIn("only revoked keys", f.detail)

    def test_explicit_selector_missing_or_revoked_is_reported(self):
        f = emailauth.check_dkim("example.com", {"mysel": None, "old": ""}, explicit=True)
        self.assertEqual(f.status, WARN)
        self.assertIn("no DKIM key at mysel._domainkey.example.com", f.detail)
        self.assertIn("old._domainkey.example.com is revoked", f.detail)

    def test_explicit_selector_found_passes(self):
        self.assertEqual(emailauth.check_dkim("example.com", {"mysel": "MIIB"}, explicit=True).status, PASS)



class DmarcSubdomainPolicyTest(unittest.TestCase):
    """RFC 7489 section 6.3: a subdomain inherits sp= from its organizational domain, else p=."""

    def test_sp_applies_to_a_subdomain(self):
        f = emailauth.check_dmarc("example.com", ["v=DMARC1; p=reject; sp=none"], domain="shop.example.com")
        self.assertEqual(f.status, WARN)
        self.assertIn("sp=none (the policy shop.example.com inherits as a subdomain)", f.detail)

    def test_strict_sp_passes_a_subdomain_even_with_a_lax_p(self):
        f = emailauth.check_dmarc("example.com", ["v=DMARC1; p=none; sp=reject"], domain="shop.example.com")
        self.assertEqual(f.status, PASS)
        self.assertIn("sp=reject applies to shop.example.com", f.detail)

    def test_p_applies_to_a_subdomain_without_sp(self):
        f = emailauth.check_dmarc("example.com", ["v=DMARC1; p=quarantine"], domain="shop.example.com")
        self.assertEqual(f.status, PASS)
        self.assertIn("p=quarantine applies to shop.example.com", f.detail)

    def test_the_domain_itself_uses_p(self):
        f = emailauth.check_dmarc("example.com", ["v=DMARC1; p=reject; sp=none"], domain="example.com")
        self.assertEqual(f.status, PASS)

    def test_invalid_sp_is_treated_as_p_none(self):
        f = emailauth.check_dmarc("example.com", ["v=DMARC1; p=reject; sp=strict"], domain="shop.example.com")
        self.assertEqual(f.status, WARN)
        self.assertIn("not a valid policy", f.detail)

    def test_invalid_sp_spoils_the_record_for_the_domain_itself_too(self):
        # Section 6.6.3 step 6 applies to the whole record, not only to subdomains.
        for domain in ("example.com", None):
            f = emailauth.check_dmarc("example.com", ["v=DMARC1; p=reject; sp=bogus"], domain=domain)
            self.assertEqual(f.status, WARN, domain)
            self.assertIn("sp='bogus' is not a valid policy, so receivers treat the record as p=none", f.detail)

if __name__ == "__main__":
    unittest.main()
