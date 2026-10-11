"""CORS misconfiguration check.

The CLI requests the page again with an Origin header for a domain that
cannot exist, then passes the response's CORS headers here. No network access.
"""

from __future__ import annotations

from .findings import FAIL, PASS, WARN, Finding

# .invalid is reserved (RFC 2606), so no real site can legitimately be allowed.
PROBE_ORIGIN = "https://web-posture-check.invalid"


def check_cors(allow_origin: str | None, allow_credentials: str | None, probe_origin: str = PROBE_ORIGIN) -> Finding:
    """allow_origin / allow_credentials are the Access-Control-Allow-* values, or None."""
    if allow_origin is None:
        return Finding("cors", PASS, "no Access-Control-Allow-Origin for a foreign origin")
    origin = allow_origin.strip()
    # The Fetch standard enables credentials only for the exact, case-sensitive
    # value "true" (surrounding whitespace is trimmed), so "TRUE" does not count.
    credentials = (allow_credentials or "").strip() == "true"
    if origin == probe_origin:
        if credentials:
            return Finding("cors", FAIL, "reflects any Origin with credentials allowed: any website can read authenticated responses")
        return Finding("cors", WARN, "reflects any Origin (without credentials)")
    if origin == "null" and credentials:
        # Sandboxed iframes and local files send Origin: null, so this is open to anyone.
        # Browsers match the value exactly (Fetch standard), so "NULL" does not count.
        return Finding("cors", FAIL, "allows Origin null with credentials: any website can read authenticated responses from a sandboxed iframe")
    if origin == "*" and credentials:
        return Finding("cors", WARN, "'*' with credentials allowed: browsers reject this combination, which suggests a misconfigured CORS policy")
    if origin == "*":
        return Finding("cors", PASS, "allows any origin without credentials (public resource)")
    return Finding("cors", PASS, f"allows only {origin}")
