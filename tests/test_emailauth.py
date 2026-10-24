import base64
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

    def test_rsa_key_size_is_read_from_the_key(self):
        self.assertEqual(emailauth.rsa_key_bits(_spki(_rsa_key(1024))), 1024)
        self.assertEqual(emailauth.rsa_key_bits(_spki(_rsa_key(2048))), 2048)

    def test_keys_that_are_not_rsa_have_no_size(self):
        ed25519_spki = _spki(_der(0x03, b"\0" + bytes(32)), oid=bytes.fromhex("2b6570"))
        self.assertIsNone(emailauth.rsa_key_bits(ed25519_spki))
        # RFC 8463 publishes Ed25519 keys bare, not as a SubjectPublicKeyInfo.
        self.assertIsNone(emailauth.rsa_key_bits("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="))
        self.assertIsNone(emailauth.rsa_key_bits("MIIB"))
        self.assertIsNone(emailauth.rsa_key_bits("not base64!"))

    def test_rsa_key_under_2048_bits_warns(self):
        f = emailauth.check_dkim("example.com", {"google": _spki(_rsa_key(1024)), "k1": _spki(_rsa_key(2048))}, explicit=False)
        self.assertEqual(f.status, WARN)
        self.assertIn("under: google (1024-bit)", f.detail)
        self.assertNotIn("k1", f.detail)

    def test_rsa_key_of_2048_bits_passes(self):
        self.assertEqual(emailauth.check_dkim("example.com", {"google": _spki(_rsa_key(2048))}, explicit=False).status, PASS)


def _der(tag, body):
    n = len(body)
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + (bytes([n]) if n < 0x80 else bytes([0x80 | len(size)]) + size) + body


def _rsa_key(bits):
    """A BIT STRING holding an RSAPublicKey whose modulus is exactly bits long."""
    modulus = b"\0" + ((1 << (bits - 1)) | 1).to_bytes(bits // 8, "big")
    return _der(0x03, b"\0" + _der(0x30, _der(0x02, modulus) + _der(0x02, b"\x01\x00\x01")))


def _spki(key, oid=emailauth.RSA_ENCRYPTION_OID):
    return base64.b64encode(_der(0x30, _der(0x30, _der(0x06, oid)) + key)).decode()



class SpfLookupLimitTest(unittest.TestCase):
    """RFC 7208 section 4.6.4: more than 10 DNS-querying terms make SPF a permerror."""

    def _lookup(self, records):
        def lookup(name):
            if name == "broken.example":
                return [], "DNS lookup for broken.example failed: Timeout"
            return records.get(name, []), None
        return lookup

    def _check(self, record, records=None):
        return emailauth.check_spf("example.com", [record], lookup=self._lookup(records or {}))

    def test_ten_lookups_pass_and_eleven_fail(self):
        ten = "v=spf1 a mx ptr exists:e.example a:x.example a:w.example mx:y.example/24 a/24 mx/24 include:i.example ip4:192.0.2.1 -all"
        f = self._check(ten, {"i.example": ["v=spf1 ip6:2001:db8::1 -all"]})
        self.assertEqual(f.status, PASS)
        self.assertIn("(10 of 10 DNS lookups)", f.detail)
        f = self._check(ten.replace("-all", "exists:z.example -all"), {"i.example": ["v=spf1 -all"]})
        self.assertEqual(f.status, FAIL)
        self.assertIn("more than 10 DNS lookups", f.detail)

    def test_included_records_count(self):
        records = {f"i{n}.example": [f"v=spf1 include:i{n + 1}.example a ~all"] for n in range(6)}
        f = self._check("v=spf1 include:i0.example -all", records)
        self.assertEqual(f.status, FAIL)

    def test_a_loop_runs_into_the_limit(self):
        f = self._check("v=spf1 include:loop.example -all", {"loop.example": ["v=spf1 include:loop.example -all"]})
        self.assertEqual(f.status, FAIL)
        self.assertIn("more than 10", f.detail)

    def test_redirect_counts_only_without_all(self):
        records = {"r.example": ["v=spf1 a -all"]}
        self.assertIn("(2 of 10 DNS lookups)", self._check("v=spf1 redirect=r.example", records).detail)
        self.assertNotIn("DNS lookups", self._check("v=spf1 -all redirect=r.example", records).detail)
        self.assertNotIn("DNS lookups", self._check("v=spf1 ip4:192.0.2.0/24 exp=explain.example -all").detail)

    def test_an_include_without_one_spf_record_is_a_permerror(self):
        f = self._check("v=spf1 include:none.example -all")
        self.assertEqual(f.status, FAIL)
        self.assertIn("includes none.example (no SPF record)", f.detail)
        f = self._check("v=spf1 include:two.example -all", {"two.example": ["v=spf1 -all", "v=spf1 ~all"]})
        self.assertIn("includes two.example (2 SPF records)", f.detail)

    def test_a_failed_lookup_means_the_limit_was_not_verified(self):
        f = self._check("v=spf1 include:broken.example -all")
        self.assertEqual(f.status, WARN)
        self.assertIn("the 10-lookup limit could not be checked: DNS lookup for broken.example failed", f.detail)
        # A finding that already warns keeps its own status.
        self.assertEqual(self._check("v=spf1 include:broken.example ?all").status, WARN)

    def test_a_macro_include_is_counted_once_as_a_lower_bound(self):
        f = self._check("v=spf1 include:%{i}._ip.%{d}._spf.example -all")
        self.assertEqual(f.status, PASS)
        self.assertIn("(at least 1 of 10 DNS lookups)", f.detail)

    def test_terms_after_all_are_ignored(self):
        # RFC 7208 section 5.1: they are never evaluated, so they neither count nor get looked up.
        f = self._check("v=spf1 ip4:192.0.2.1 -all include:gone.example")
        self.assertEqual((f.status, f.detail), (PASS, "example.com: v=spf1 ip4:192.0.2.1 -all include:gone.example"))
        many = " ".join(f"include:i{n}.example" for n in range(12))
        self.assertEqual(self._check(f"v=spf1 a -all {many}", {f"i{n}.example": ["v=spf1 -all"] for n in range(12)}).status, PASS)

    def test_a_redirect_without_one_spf_record_says_redirect(self):
        f = self._check("v=spf1 redirect=none.example")
        self.assertEqual(f.status, FAIL)
        self.assertIn("redirects to none.example (no SPF record)", f.detail)

    def test_a_repeated_redirect_or_exp_is_a_permerror(self):
        for record in ("v=spf1 redirect=a.example redirect=b.example", "v=spf1 -all exp=a.example exp=b.example"):
            f = emailauth.check_spf("example.com", [record])
            self.assertEqual(f.status, FAIL, record)
            self.assertIn("repeats a redirect= or exp= modifier", f.detail)

    def test_a_record_that_already_fails_is_not_counted(self):
        f = self._check("v=spf1 include:i.example +all")
        self.assertEqual(f.status, FAIL)
        self.assertIn("authorises every server", f.detail)


class DmarcCandidatesTest(unittest.TestCase):
    def test_the_walk_stops_at_the_organizational_domain(self):
        self.assertEqual(emailauth.dmarc_candidates("shop.example.co.uk"), ["shop.example.co.uk", "example.co.uk"])
        self.assertEqual(emailauth.dmarc_candidates("a.b.example.com"), ["a.b.example.com", "b.example.com", "example.com"])
        self.assertEqual(emailauth.dmarc_candidates("example.com"), ["example.com"])
        self.assertEqual(emailauth.dmarc_candidates("user.github.io"), ["user.github.io"])
        # A public suffix is asked only when it is the domain itself.
        self.assertEqual(emailauth.dmarc_candidates("co.uk"), ["co.uk"])


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
