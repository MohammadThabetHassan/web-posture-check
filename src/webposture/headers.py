"""HTTP security header checks.

Each check takes the response headers (a case-insensitive mapping) and
returns a Finding. Checks never make network calls, so they are easy to test.
"""

import re

from .findings import Finding, PASS, WARN, FAIL

# Six months: the common scanner baseline. The HSTS preload list requires one year.
HSTS_MIN_MAX_AGE = 15552000
HSTS_PRELOAD_MIN_MAX_AGE = 31536000


def _get(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value.strip()
    return None


def check_hsts(headers):
    value = _get(headers, "Strict-Transport-Security")
    if value is None:
        return Finding("hsts", FAIL, "Strict-Transport-Security header is missing")
    match = re.search(r"max-age\s*=\s*\"?(\d+)\"?", value, re.IGNORECASE)
    if not match:
        return Finding("hsts", FAIL, "Strict-Transport-Security has no valid max-age")
    max_age = int(match.group(1))
    directives = {d.strip().lower() for d in value.split(";")}
    subdomains = "includesubdomains" in directives
    preload = "preload" in directives
    detail = f"max-age={max_age}" + ("; includeSubDomains" if subdomains else "") + ("; preload" if preload else "")
    if max_age < HSTS_MIN_MAX_AGE:
        return Finding("hsts", WARN, f"max-age={max_age} is below {HSTS_MIN_MAX_AGE} (6 months)")
    if preload:
        # The preload list (hstspreload.org) rejects sites that ask for preload
        # without meeting its requirements, so the directive does nothing.
        missing = []
        if max_age < HSTS_PRELOAD_MIN_MAX_AGE:
            missing.append(f"max-age of at least {HSTS_PRELOAD_MIN_MAX_AGE} (1 year)")
        if not subdomains:
            missing.append("includeSubDomains")
        if missing:
            return Finding("hsts", WARN, f"{detail}: preload is set but the preload list also requires " + " and ".join(missing))
    return Finding("hsts", PASS, detail)


def check_csp(headers):
    value = _get(headers, "Content-Security-Policy")
    if value is None:
        if _get(headers, "Content-Security-Policy-Report-Only") is not None:
            return Finding("csp", WARN, "only Content-Security-Policy-Report-Only is set, nothing is enforced")
        return Finding("csp", FAIL, "Content-Security-Policy header is missing")
    return Finding("csp", PASS, "Content-Security-Policy is set")


def check_content_type_options(headers):
    value = _get(headers, "X-Content-Type-Options")
    if value is None:
        return Finding("x-content-type-options", FAIL, "X-Content-Type-Options header is missing")
    if value.lower() != "nosniff":
        return Finding("x-content-type-options", FAIL, f"expected 'nosniff', got '{value}'")
    return Finding("x-content-type-options", PASS, "nosniff")


def check_framing(headers):
    csp = _get(headers, "Content-Security-Policy") or ""
    if re.search(r"(^|;)\s*frame-ancestors\s", csp, re.IGNORECASE):
        return Finding("clickjacking", PASS, "CSP frame-ancestors is set")
    xfo = _get(headers, "X-Frame-Options")
    if xfo is not None and xfo.upper() in ("DENY", "SAMEORIGIN"):
        return Finding("clickjacking", PASS, f"X-Frame-Options: {xfo.upper()}")
    return Finding("clickjacking", FAIL, "neither CSP frame-ancestors nor X-Frame-Options DENY/SAMEORIGIN is set")


def check_referrer_policy(headers):
    value = _get(headers, "Referrer-Policy")
    if value is None:
        return Finding("referrer-policy", WARN, "Referrer-Policy header is missing (browser default applies)")
    if value.lower() == "unsafe-url":
        return Finding("referrer-policy", FAIL, "unsafe-url leaks full URLs to other origins")
    return Finding("referrer-policy", PASS, value)


def check_permissions_policy(headers):
    if _get(headers, "Permissions-Policy") is None:
        return Finding("permissions-policy", WARN, "Permissions-Policy header is missing")
    return Finding("permissions-policy", PASS, "Permissions-Policy is set")


ALL_CHECKS = [
    check_hsts,
    check_csp,
    check_content_type_options,
    check_framing,
    check_referrer_policy,
    check_permissions_policy,
]


def run(headers):
    return [check(headers) for check in ALL_CHECKS]
