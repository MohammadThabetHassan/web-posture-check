import sys
import unittest
from unittest import mock

from webposture import caa
from webposture.findings import PASS, WARN

try:
    import dns.resolver  # noqa: F401
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False


class CheckCaaTest(unittest.TestCase):
    def test_no_record_warns(self):
        f = caa.check_caa(None, [])
        self.assertEqual(f.status, WARN)
        self.assertIn("any certificate authority", f.detail)

    def test_issue_lists_allowed_cas(self):
        f = caa.check_caa("example.com", [
            (0, "issue", "letsencrypt.org"),
            (0, "issue", "pki.goog; cansignhttpexchanges=yes"),
            (0, "iodef", "mailto:s@example.com"),
        ])
        self.assertEqual(f.status, PASS)
        self.assertIn("allows: letsencrypt.org, pki.goog", f.detail)
        self.assertNotIn("wildcards", f.detail)

    def test_issuewild_is_reported_separately(self):
        f = caa.check_caa("example.com", [(0, "issue", "digicert.com"), (0, "issuewild", ";")])
        self.assertEqual(f.status, PASS)
        self.assertIn("wildcards: no CA", f.detail)

    def test_empty_issue_means_no_ca_may_issue(self):
        f = caa.check_caa("example.com", [(0, "issue", ";")])
        self.assertEqual(f.status, PASS)
        self.assertIn("allows: no CA", f.detail)

    def test_only_issuewild_leaves_normal_certificates_open(self):
        f = caa.check_caa("example.com", [(0, "issuewild", "letsencrypt.org"), (0, "iodef", "mailto:s@example.com")])
        self.assertEqual(f.status, WARN)
        self.assertIn("no 'issue' property", f.detail)

    def test_unknown_critical_tag_warns(self):
        f = caa.check_caa("example.com", [(128, "futuretag", "x"), (0, "issue", "letsencrypt.org")])
        self.assertEqual(f.status, WARN)
        self.assertIn("unknown critical tag(s) futuretag", f.detail)

    def test_known_critical_tag_and_tag_case_are_fine(self):
        f = caa.check_caa("example.com", [(128, "ISSUE", "letsencrypt.org")])
        self.assertEqual(f.status, PASS)


class LookupCaaTest(unittest.TestCase):
    def test_missing_dnspython_is_reported_as_skipped(self):
        blocked = {"dns": None, "dns.resolver": None, "dns.exception": None}
        with mock.patch.dict(sys.modules, blocked):
            found_on, _records, problem = caa.lookup_caa("example.com", 5)
        self.assertIsNone(found_on)
        self.assertIn("web-posture-check[dns]", str(problem))

    @unittest.skipUnless(HAVE_DNSPYTHON, "needs the optional dns extra")
    def test_climbs_to_parent_when_host_has_no_caa(self):
        # RFC 8659 section 3: the host has no CAA RRset, so the lookup must climb
        # to the parent and report the record it finds there, naming the parent.
        import dns.resolver

        class _Caa:
            def __init__(self, flags, tag, value):
                self.flags, self.tag, self.value = flags, tag, value

        def fake_resolve(name, rdtype, lifetime=None):
            if name == "example.com":
                return [_Caa(0, b"issue", b"letsencrypt.org")]
            raise dns.resolver.NoAnswer()

        with mock.patch("dns.resolver.resolve", side_effect=fake_resolve):
            found_on, records, problem = caa.lookup_caa("www.example.com", 5)
        self.assertIsNone(problem)
        self.assertEqual(found_on, "example.com")
        self.assertEqual(records, [(0, "issue", "letsencrypt.org")])


    def test_candidates_climb_to_the_top_level_domain(self):
        # RFC 8659 section 3: the climb stops at the root, so the TLD is checked too.
        self.assertEqual(caa.caa_candidates("www.example.com."), ["www.example.com", "example.com", "com"])
        self.assertEqual(caa.caa_candidates("example.com"), ["example.com", "com"])

    @unittest.skipUnless(HAVE_DNSPYTHON, "needs the optional dns extra")
    def test_a_record_on_the_tld_applies(self):
        import dns.resolver

        class _Caa:
            def __init__(self, flags, tag, value):
                self.flags, self.tag, self.value = flags, tag, value

        def fake_resolve(name, rdtype, lifetime=None):
            if name == "com":
                return [_Caa(0, b"issue", b"ca.example")]
            raise dns.resolver.NoAnswer()

        with mock.patch("dns.resolver.resolve", side_effect=fake_resolve):
            self.assertEqual(caa.lookup_caa("www.example.com", 5), ("com", [(0, "issue", "ca.example")], None))

if __name__ == "__main__":
    unittest.main()
