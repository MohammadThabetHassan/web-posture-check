"""HTTP security header checks.

Each check takes the response headers (a case-insensitive mapping) and
returns a Finding. Checks never make network calls, so they are easy to test.
"""

import re

from .findings import Finding, PASS, WARN, FAIL

# Six months: the common scanner baseline. The HSTS preload list requires one year.
HSTS_MIN_MAX_AGE = 15552000
HSTS_PRELOAD_MIN_MAX_AGE = 31536000

# Script sources that allow loading code from any host (or from data: URLs),
# which lets an attacker who can inject a <script src> tag run their own code.
BROAD_SCRIPT_SOURCES = ("*", "https:", "http:", "data:")


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
    sources, directive = _script_sources(value)
    if sources is None:
        return Finding("csp", PASS, "Content-Security-Policy is set (no script-src or default-src, scripts are not restricted)")
    problems = []
    # Browsers ignore 'unsafe-inline' when a nonce or hash is present (CSP Level 2+),
    # so it is only a problem on its own.
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in sources)
    if "'unsafe-inline'" in sources and not has_nonce_or_hash:
        problems.append(f"{directive} allows 'unsafe-inline' without a nonce or hash")
    if "'unsafe-eval'" in sources:
        problems.append(f"{directive} allows 'unsafe-eval'")
    # With 'strict-dynamic', CSP Level 3 browsers ignore host and scheme sources,
    # so broad sources only matter without it.
    if "'strict-dynamic'" not in sources:
        broad = [src for src in sources if src in BROAD_SCRIPT_SOURCES]
        if broad:
            problems.append(f"{directive} allows scripts from " + ", ".join(broad))
    if problems:
        return Finding("csp", WARN, "; ".join(problems))
    return Finding("csp", PASS, "Content-Security-Policy is set")


def _script_sources(policy):
    """Return (sources, directive name) that govern scripts, or (None, None).

    script-src applies when present, otherwise default-src is the fallback.
    The first occurrence of a directive wins, as in browsers.
    """
    directives = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens and tokens[0].lower() not in directives:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    for name in ("script-src", "default-src"):
        if name in directives:
            return directives[name], name
    return None, None


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


# Headers that exist only to name the server-side stack. Any value helps an
# attacker match the site to known vulnerabilities, so their presence is reported.
STACK_DISCLOSURE_HEADERS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")

# A version number such as nginx/1.18.0, Microsoft-IIS/10.0 or Apache/2.
# "/7F84" style build IDs are not versions, so a digit run must end the token.
SERVER_VERSION = re.compile(r"\d+\.\d+|/v?\d+\b")


def check_information_leakage(headers):
    leaks = []
    server = _get(headers, "Server")
    if server and SERVER_VERSION.search(server):
        leaks.append(f"Server: {server}")
    for name in STACK_DISCLOSURE_HEADERS:
        value = _get(headers, name)
        if value is not None:
            leaks.append(f"{name}: {value}")
    if leaks:
        return Finding("information-leakage", WARN, "response discloses the server stack (" + "; ".join(leaks) + ")")
    return Finding("information-leakage", PASS, "no server version or stack headers")


ALL_CHECKS = [
    check_hsts,
    check_csp,
    check_content_type_options,
    check_framing,
    check_referrer_policy,
    check_permissions_policy,
    check_information_leakage,
]


def run(headers):
    return [check(headers) for check in ALL_CHECKS]
