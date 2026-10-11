"""The Public Suffix List and how the checks use it. No network needed."""

import unittest

from webposture import publicsuffix

# The list's official test vectors (tests/test_psl.txt at github.com/publicsuffix/list,
# dedicated to the public domain): (name, its registrable domain or None).
PSL_TEST_VECTORS = [
    ('COM', None),
    ('example.COM', 'example.com'),
    ('WwW.example.COM', 'example.com'),
    ('.com', None),
    ('.example', None),
    ('.example.com', None),
    ('.example.example', None),
    ('example', None),
    ('example.example', 'example.example'),
    ('b.example.example', 'example.example'),
    ('a.b.example.example', 'example.example'),
    ('biz', None),
    ('domain.biz', 'domain.biz'),
    ('b.domain.biz', 'domain.biz'),
    ('a.b.domain.biz', 'domain.biz'),
    ('com', None),
    ('example.com', 'example.com'),
    ('b.example.com', 'example.com'),
    ('a.b.example.com', 'example.com'),
    ('uk.com', None),
    ('example.uk.com', 'example.uk.com'),
    ('b.example.uk.com', 'example.uk.com'),
    ('a.b.example.uk.com', 'example.uk.com'),
    ('test.ac', 'test.ac'),
    ('mm', None),
    ('c.mm', None),
    ('b.c.mm', 'b.c.mm'),
    ('a.b.c.mm', 'b.c.mm'),
    ('jp', None),
    ('test.jp', 'test.jp'),
    ('www.test.jp', 'test.jp'),
    ('ac.jp', None),
    ('test.ac.jp', 'test.ac.jp'),
    ('www.test.ac.jp', 'test.ac.jp'),
    ('kyoto.jp', None),
    ('test.kyoto.jp', 'test.kyoto.jp'),
    ('ide.kyoto.jp', None),
    ('b.ide.kyoto.jp', 'b.ide.kyoto.jp'),
    ('a.b.ide.kyoto.jp', 'b.ide.kyoto.jp'),
    ('c.kobe.jp', None),
    ('b.c.kobe.jp', 'b.c.kobe.jp'),
    ('a.b.c.kobe.jp', 'b.c.kobe.jp'),
    ('city.kobe.jp', 'city.kobe.jp'),
    ('www.city.kobe.jp', 'city.kobe.jp'),
    ('ck', None),
    ('test.ck', None),
    ('b.test.ck', 'b.test.ck'),
    ('a.b.test.ck', 'b.test.ck'),
    ('www.ck', 'www.ck'),
    ('www.www.ck', 'www.ck'),
    ('us', None),
    ('test.us', 'test.us'),
    ('www.test.us', 'test.us'),
    ('ak.us', None),
    ('test.ak.us', 'test.ak.us'),
    ('www.test.ak.us', 'test.ak.us'),
    ('k12.ak.us', None),
    ('test.k12.ak.us', 'test.k12.ak.us'),
    ('www.test.k12.ak.us', 'test.k12.ak.us'),
    ('食狮.com.cn', '食狮.com.cn'),
    ('食狮.公司.cn', '食狮.公司.cn'),
    ('www.食狮.公司.cn', '食狮.公司.cn'),
    ('shishi.公司.cn', 'shishi.公司.cn'),
    ('公司.cn', None),
    ('食狮.中国', '食狮.中国'),
    ('www.食狮.中国', '食狮.中国'),
    ('shishi.中国', 'shishi.中国'),
    ('中国', None),
    ('xn--85x722f.com.cn', 'xn--85x722f.com.cn'),
    ('xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn'),
    ('www.xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn'),
    ('shishi.xn--55qx5d.cn', 'shishi.xn--55qx5d.cn'),
    ('xn--55qx5d.cn', None),
    ('xn--85x722f.xn--fiqs8s', 'xn--85x722f.xn--fiqs8s'),
    ('www.xn--85x722f.xn--fiqs8s', 'xn--85x722f.xn--fiqs8s'),
    ('shishi.xn--fiqs8s', 'shishi.xn--fiqs8s'),
    ('xn--fiqs8s', None),
]


class OfficialVectorsTest(unittest.TestCase):
    def test_every_official_vector(self):
        for name, expected in PSL_TEST_VECTORS:
            # The vectors give Unicode answers for Unicode names; the module answers in ASCII.
            want = publicsuffix.to_ascii(expected) if expected else None
            self.assertEqual(publicsuffix.registrable_domain(name), want, name)


class BrowserCasesTest(unittest.TestCase):
    """Names whose cookie Domain Chromium, Firefox and WebKit all refuse or all accept."""

    def test_public_suffixes(self):
        for name in ("com", "co.uk", "github.io", "herokuapp.com", "foo.ck", "zzunknowntld", "xn--55qx5d.cn", "\u516c\u53f8.cn"):
            self.assertTrue(publicsuffix.is_public_suffix(name), name)

    def test_registrable_names(self):
        for name in ("b.co.uk", "www.ck", "b.zzunknowntld", "example.com", "x.github.io", "CO.UK.example.com"):
            self.assertFalse(publicsuffix.is_public_suffix(name), name)

    def test_wildcard_parents_and_names_below(self):
        # Chromium, Firefox and libpsl count the name under a wildcard rule as a suffix.
        self.assertTrue(publicsuffix.is_public_suffix("kawasaki.jp"))
        self.assertTrue(publicsuffix.has_suffix_below("amazonaws.com"))
        self.assertFalse(publicsuffix.has_suffix_below("salesforce.com"))
        self.assertFalse(publicsuffix.has_suffix_below("example.com"))

    def test_a_huge_name_is_cheap(self):
        # A hostile 64 KB header value must not burn CPU: only the last labels are looked at.
        import time
        name = ".".join(["a"] * 32000) + ".com"
        start = time.perf_counter()
        self.assertEqual(publicsuffix.public_suffix(name), "com")
        self.assertLess(time.perf_counter() - start, 1.0)

    def test_suffixes_and_registrable_domains(self):
        self.assertEqual(publicsuffix.public_suffix("a.b.co.uk"), "co.uk")
        self.assertEqual(publicsuffix.public_suffix("www.ck"), "ck")  # the exception rule !www.ck
        self.assertEqual(publicsuffix.public_suffix("a.foo.ck"), "foo.ck")  # the wildcard rule *.ck
        self.assertEqual(publicsuffix.registrable_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(publicsuffix.registrable_domain("example.com."), "example.com")
        self.assertIsNone(publicsuffix.registrable_domain("github.io"))


if __name__ == "__main__":
    unittest.main()
