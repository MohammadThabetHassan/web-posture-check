from dataclasses import asdict, dataclass

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

    def to_dict(self):
        return asdict(self)
