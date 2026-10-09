from dataclasses import dataclass, asdict

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"


@dataclass
class Finding:
    check: str
    status: str
    detail: str

    def to_dict(self):
        return asdict(self)
