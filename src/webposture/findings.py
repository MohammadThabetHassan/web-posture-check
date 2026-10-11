from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TypedDict

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

# Detail prefix for a check that could not run (e.g. a missing optional
# dependency). Such findings are shown but not scored.
SKIPPED_PREFIX = "skipped:"


@dataclass
class Finding:
    check: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class _ResultFields(TypedDict):
    # The final URL after redirects (or the target, when it could not be scanned).
    url: str
    # The final HTTP status, or None when nothing answered.
    status: int | None
    findings: list[Finding]
    # Why checks were skipped or ran with --insecure, if they were.
    note: str | None


class ScanResult(_ResultFields, total=False):
    """One target's result, as runner.scan returns it and every output format reads it."""

    # Why the target could not be (fully) scanned.
    error: str
