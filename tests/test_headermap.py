import unittest
from email.message import Message

from webposture.headermap import HeaderMap, split_list


class HeaderMapTest(unittest.TestCase):
    def test_names_are_case_insensitive_and_every_occurrence_is_kept_in_order(self):
        hm = HeaderMap([("Set-Cookie", "a=1"), ("set-cookie", "b=2"), ("X-Other", "x")])
        self.assertEqual(hm.get_all("SET-COOKIE"), ["a=1", "b=2"])
        self.assertEqual(hm.get("set-cookie"), "a=1")
        self.assertEqual(len(hm), 3)
        self.assertIn("x-other", hm)
        self.assertNotIn("missing", hm)
        self.assertNotIn(42, hm)

    def test_absent_and_empty_are_different(self):
        hm = HeaderMap({"X-Empty": ""})
        self.assertIsNone(hm.get("X-Absent"))
        self.assertIsNone(hm.combined("X-Absent"))
        self.assertIsNone(hm.split("X-Absent"))
        self.assertEqual(hm.get("X-Empty"), "")
        self.assertEqual(hm.split("X-Empty"), [""])

    def test_built_from_a_mapping_a_message_or_another_map(self):
        message = Message()
        message["Vary"] = "Origin"
        message["Vary"] = "Accept"
        self.assertEqual(HeaderMap(message).get_all("vary"), ["Origin", "Accept"])
        original = HeaderMap({"A": "1"})
        self.assertEqual(HeaderMap(original).items(), [("A", "1")])
        self.assertEqual(repr(HeaderMap({"A": "1"})), "HeaderMap([('A', '1')])")

    def test_combined_and_split_follow_fetch(self):
        hm = HeaderMap([("X-Frame-Options", " SAMEORIGIN "), ("X-Frame-Options", "DENY")])
        self.assertEqual(hm.combined("x-frame-options"), "SAMEORIGIN, DENY")
        self.assertEqual(hm.split("x-frame-options"), ["SAMEORIGIN", "DENY"])


class SplitListTest(unittest.TestCase):
    def test_commas_inside_quotes_do_not_split(self):
        self.assertEqual(split_list('a, "b, c", d'), ["a", '"b, c"', "d"])

    def test_escaped_quote_inside_quotes(self):
        self.assertEqual(split_list(r'"x\", y", z'), [r'"x\", y"', "z"])

    def test_empty_items_are_kept(self):
        self.assertEqual(split_list("a,,b"), ["a", "", "b"])
        self.assertEqual(split_list("\ta ,b\t"), ["a", "b"])


if __name__ == "__main__":
    unittest.main()
