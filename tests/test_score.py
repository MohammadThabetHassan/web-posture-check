import unittest

from webposture import score
from webposture.findings import Finding, PASS, WARN, FAIL


def findings(passes=0, warns=0, fails=0):
    return ([Finding(f"p{i}", PASS, "ok") for i in range(passes)]
            + [Finding(f"w{i}", WARN, "meh") for i in range(warns)]
            + [Finding(f"f{i}", FAIL, "bad") for i in range(fails)])


class ScoreTest(unittest.TestCase):
    def test_all_pass_is_a_perfect_a(self):
        self.assertEqual(score.compute(findings(passes=20)), (100, "A"))

    def test_warn_counts_half(self):
        self.assertEqual(score.compute(findings(passes=1, warns=1)), (75, "C"))

    def test_grade_boundaries(self):
        # 8 PASS + 2 WARN = 90 -> A (boundary); 7 + 3 WARN = 85 -> B
        self.assertEqual(score.compute(findings(passes=8, warns=2)), (90, "A"))
        self.assertEqual(score.compute(findings(passes=7, warns=3)), (85, "B"))
        self.assertEqual(score.compute(findings(passes=6, fails=4)), (60, "D"))
        self.assertEqual(score.compute(findings(passes=5, fails=5)), (50, "F"))

    def test_any_fail_caps_the_grade_at_b(self):
        # 19 PASS + 1 FAIL scores 95 but must not be an A.
        self.assertEqual(score.compute(findings(passes=19, fails=1)), (95, "B"))

    def test_skipped_findings_are_not_scored(self):
        skipped = Finding("spf", WARN, 'skipped: install the optional DNS support')
        self.assertEqual(score.compute(findings(passes=4) + [skipped]), (100, "A"))

    def test_nothing_to_score(self):
        self.assertIsNone(score.compute([]))
        self.assertIsNone(score.compute([Finding("spf", WARN, "skipped: x")]))


if __name__ == "__main__":
    unittest.main()
