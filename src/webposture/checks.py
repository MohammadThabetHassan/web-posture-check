"""The checks: every name, in report order, with a one-line summary.

This is the one list that --only and --skip are validated against, that
--list-checks prints and that SARIF turns into rules. The runner runs the
checks in this order; tests keep the two in step (the header checks in
test_headers, the whole run in test_cli.CheckSelectionTest).
"""

from __future__ import annotations

from typing import NamedTuple


class Check(NamedTuple):
    name: str
    # One line, for --list-checks and the SARIF rule.
    summary: str
    # How serious a problem found by this check is, 0.0 to 10.0, as GitHub code scanning
    # reads it from a SARIF rule (security-severity): 9.0 and above is critical, 7.0 high,
    # 4.0 medium, below that low. Defaults for the worst case of each check; tune them here.
    severity: float


CATALOG: tuple[Check, ...] = (
    Check("http-status", "the final response is not an error page (bot protection, 4xx, 5xx)", 1.0),
    Check("hsts", "Strict-Transport-Security max-age, includeSubDomains and preload", 6.5),
    Check("csp", "Content-Security-Policy is set and its script policy is not unsafe", 5.5),
    Check("x-content-type-options", "X-Content-Type-Options: nosniff", 3.0),
    Check("clickjacking", "CSP frame-ancestors or X-Frame-Options", 4.5),
    Check("referrer-policy", "Referrer-Policy is set and not unsafe-url", 2.5),
    Check("permissions-policy", "Permissions-Policy is set", 2.0),
    Check("cross-origin-isolation", "Cross-Origin-Opener, -Resource and -Embedder policies", 2.0),
    Check("x-xss-protection", "the legacy XSS auditor is not turned on", 2.0),
    Check("information-leakage", "no server version or stack headers", 3.0),
    Check("cookies", "Secure, HttpOnly, SameSite and __Host- / __Secure- prefixes", 6.0),
    Check("cors", "no credentialed access for any origin (probe request)", 8.0),
    Check("tls-certificate", "trusted and not close to expiry", 7.5),
    Check("tls-protocols", "TLS 1.0 and 1.1 are refused", 5.5),
    Check("caa", "a CAA record limits which CAs may issue", 2.5),
    Check("security-txt", "/.well-known/security.txt (RFC 9116)", 1.0),
    Check("spf", "a single SPF record that does not allow everyone", 5.0),
    Check("dmarc", "a DMARC policy that quarantines or rejects", 5.5),
    Check("dkim", "a DKIM key under common or given selectors", 3.5),
    Check("https-redirect", "plain HTTP redirects to HTTPS", 6.5),
)

# Every check name, in report order.
NAMES: tuple[str, ...] = tuple(check.name for check in CATALOG)

# Each check's summary, in report order.
SUMMARIES: dict[str, str] = {check.name: check.summary for check in CATALOG}

# Each check's security-severity for SARIF, in report order.
SEVERITIES: dict[str, float] = {check.name: check.severity for check in CATALOG}
