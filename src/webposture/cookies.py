"""Cookie flag checks.

Takes the raw Set-Cookie header values (a response can carry several, so they
must not be folded into one) and returns a Finding. No network access.
"""

from .findings import Finding, PASS, WARN, FAIL

_RANK = {PASS: 0, WARN: 1, FAIL: 2}


def parse_set_cookie(value):
    """Return (name, attributes) where attributes maps lower-cased names to values."""
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attributes = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, attr_value = part.partition("=")
        attributes[key.strip().lower()] = attr_value.strip()
    return name, attributes


def _problems(attributes, is_https):
    """Return a list of (status, message) for one cookie."""
    problems = []
    samesite = attributes.get("samesite")
    if "secure" not in attributes:
        if samesite is not None and samesite.lower() == "none":
            # Browsers reject SameSite=None without Secure, so the cookie is dropped.
            problems.append((FAIL, "SameSite=None without Secure (browsers reject it)"))
        elif is_https:
            problems.append((FAIL, "missing Secure"))
    if "httponly" not in attributes:
        problems.append((WARN, "missing HttpOnly"))
    if samesite is None:
        problems.append((WARN, "missing SameSite"))
    return problems


def check_cookies(set_cookie_values, is_https):
    if not set_cookie_values:
        return Finding("cookies", PASS, "no cookies set")
    status = PASS
    notes = []
    for value in set_cookie_values:
        name, attributes = parse_set_cookie(value)
        problems = _problems(attributes, is_https)
        if problems:
            notes.append(f"{name}: " + ", ".join(msg for _, msg in problems))
            status = max([status] + [s for s, _ in problems], key=_RANK.get)
    if not notes:
        return Finding("cookies", PASS, f"{len(set_cookie_values)} cookie(s), no flag problems found")
    return Finding("cookies", status, "; ".join(notes))
