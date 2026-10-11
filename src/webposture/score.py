"""Overall score and letter grade for a set of findings.

Formula (also documented in the README):
- Each scored finding is worth 1 for PASS, 0.5 for WARN and 0 for FAIL.
- score = round(100 * points / number of scored findings).
- Grade by score: A >= 90, B >= 80, C >= 70, D >= 60, otherwise F.
- A needs zero FAILs: a run with any FAIL is capped at B, so one serious
  problem cannot hide behind many passes.
- Findings reported as skipped (e.g. DNS checks without the optional extra)
  are not results, so they are left out of the score.

Because the score is an average, it works the same for any --only/--skip
selection.
"""

from __future__ import annotations

from collections.abc import Iterable

from .findings import FAIL, PASS, SKIPPED_PREFIX, WARN, Finding

POINTS = {PASS: 1.0, WARN: 0.5, FAIL: 0.0}
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))


def compute(findings: Iterable[Finding]) -> tuple[int, str] | None:
    """Return (score, grade), or None when there is nothing to score."""
    scored = [f for f in findings if f.status in POINTS and not f.detail.startswith(SKIPPED_PREFIX)]
    if not scored:
        return None
    score = round(100 * sum(POINTS[f.status] for f in scored) / len(scored))
    grade = next((letter for minimum, letter in GRADES if score >= minimum), "F")
    if grade == "A" and any(f.status == FAIL for f in scored):
        grade = "B"
    return score, grade
