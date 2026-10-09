"""security.txt check (RFC 9116).

The CLI fetches /.well-known/security.txt; check_security_txt takes the
status, content type and body and returns a Finding. No network access.
"""

from datetime import datetime, timedelta

from .findings import Finding, PASS, WARN

PATH = "/.well-known/security.txt"

# RFC 9116 section 2.5.5 recommends an Expires less than a year away.
MAX_EXPIRES_AHEAD = timedelta(days=365)


def parse_fields(body):
    """Return {lower-case field name: [values]} from a security.txt body.

    Comments and blank lines are skipped. In a PGP-signed file, lines that
    start with "- " are dash-escaped (RFC 4880) and the prefix is removed.
    """
    fields = {}
    for raw in body.splitlines():
        line = raw[2:] if raw.startswith("- ") else raw
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, _, value = line.partition(":")
        fields.setdefault(name.strip().lower(), []).append(value.strip())
    return fields


def parse_expires(value):
    """Parse an RFC 3339 date-time such as 2027-01-01T00:00:00.000Z. Returns None if invalid."""
    text = value.strip()
    if text[-1:] in ("z", "Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # RFC 3339 requires a time zone offset.
    if parsed.tzinfo is None:
        return None
    return parsed


def check_security_txt(status, content_type, body, now):
    """WARN only: a missing or stale security.txt is a gap in disclosure, not a vulnerability."""
    if status is None or status == 404:
        return Finding("security-txt", WARN, f"no {PATH}, so researchers have no published way to report vulnerabilities")
    if status != 200:
        return Finding("security-txt", WARN, f"{PATH} returned HTTP {status}")
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type != "text/plain":
        # Catch-all routes often answer 200 with an HTML page for any path.
        return Finding("security-txt", WARN, f"{PATH} is served as {media_type or 'an unknown type'}, not text/plain, so it is probably not a real security.txt")

    fields = parse_fields(body)
    problems = []
    contacts = fields.get("contact", [])
    if not contacts:
        problems.append("missing the required Contact field")
    expires_values = fields.get("expires", [])
    expires = None
    if not expires_values:
        problems.append("missing the required Expires field")
    elif len(expires_values) > 1:
        problems.append("Expires must appear only once")
    else:
        expires = parse_expires(expires_values[0])
        if expires is None:
            problems.append(f"Expires '{expires_values[0]}' is not a valid RFC 3339 date-time")
        elif expires <= now:
            problems.append(f"expired on {expires.date()}")
        elif expires - now > MAX_EXPIRES_AHEAD:
            problems.append(f"Expires {expires.date()} is more than a year away (RFC 9116 recommends less, to avoid stale contacts)")
    if problems:
        return Finding("security-txt", WARN, f"{PATH}: " + "; ".join(problems))
    return Finding("security-txt", PASS, f"Contact: {contacts[0]}; expires {expires.date()}")
