"""Cookie flag checks.

Takes the raw Set-Cookie header values (a response can carry several, so they
must not be folded into one) and returns a Finding. No network access.
"""

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .findings import FAIL, PASS, WARN, Finding

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


def _prefix_violations(name, attributes):
    """Return the rules a __Host- or __Secure- cookie breaks, or [] if none.

    Browsers drop such cookies outright, so a broken prefix means the cookie
    never gets set. Prefixes are matched case-insensitively, as current
    browsers do (draft-ietf-httpbis-rfc6265bis).
    """
    lower = name.lower()
    violations = []
    if lower.startswith("__host-"):
        if "secure" not in attributes:
            violations.append("Secure")
        if attributes.get("path") != "/":
            violations.append("Path=/")
        # An empty Domain= is ignored by browsers (RFC 6265, section 5.2.3),
        # so only a Domain with a value breaks the __Host- rule.
        if attributes.get("domain"):
            violations.append("no Domain")
    elif lower.startswith("__secure-") and "secure" not in attributes:
        violations.append("Secure")
    return violations


def _problems(name, attributes, is_https):
    """Return a list of (status, message) for one cookie."""
    problems = []
    samesite = attributes.get("samesite")
    violations = _prefix_violations(name, attributes)
    if violations:
        prefix = name.split("-", 1)[0] + "-"
        problems.append((FAIL, f"{prefix} prefix requires " + ", ".join(violations) + " (browsers reject it)"))
    if "secure" not in attributes and "Secure" not in violations:
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


def is_deletion(attributes, now):
    """True when the Set-Cookie only removes a cookie (Max-Age <= 0 or Expires in the past).

    Sites clear cookies this way, often without repeating the flags, and the
    browser discards the cookie, so there is nothing to protect.
    Max-Age takes precedence over Expires (RFC 6265, section 5.3).
    """
    if "max-age" in attributes:
        try:
            return int(attributes["max-age"]) <= 0
        except ValueError:
            pass
    if "expires" in attributes:
        try:
            expires = parsedate_to_datetime(attributes["expires"])
        except (TypeError, ValueError, IndexError):
            return False
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires <= now
    return False


def check_cookies(set_cookie_values, is_https, now=None):
    now = now or datetime.now(timezone.utc)
    live = []
    for value in set_cookie_values:
        name, attributes = parse_set_cookie(value)
        if not is_deletion(attributes, now):
            live.append((name, attributes))
    ignored = len(set_cookie_values) - len(live)
    suffix = f" ({ignored} deletion(s) ignored)" if ignored else ""
    if not live:
        return Finding("cookies", PASS, "no cookies set" + suffix)
    status = PASS
    notes = []
    for name, attributes in live:
        problems = _problems(name, attributes, is_https)
        if problems:
            notes.append(f"{name}: " + ", ".join(msg for _, msg in problems))
            status = max([status] + [s for s, _ in problems], key=_RANK.get)
    if not notes:
        return Finding("cookies", PASS, f"{len(live)} cookie(s), no flag problems found" + suffix)
    return Finding("cookies", status, "; ".join(notes))
