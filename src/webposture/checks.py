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


CATALOG: tuple[Check, ...] = (
    Check("http-status", "the final response is not an error page (bot protection, 4xx, 5xx)"),
    Check("hsts", "Strict-Transport-Security max-age, includeSubDomains and preload"),
    Check("csp", "Content-Security-Policy is set and its script policy is not unsafe"),
    Check("x-content-type-options", "X-Content-Type-Options: nosniff"),
    Check("clickjacking", "CSP frame-ancestors or X-Frame-Options"),
    Check("referrer-policy", "Referrer-Policy is set and not unsafe-url"),
    Check("permissions-policy", "Permissions-Policy is set"),
    Check("cross-origin-isolation", "Cross-Origin-Opener, -Resource and -Embedder policies"),
    Check("x-xss-protection", "the legacy XSS auditor is not turned on"),
    Check("information-leakage", "no server version or stack headers"),
    Check("cookies", "Secure, HttpOnly, SameSite and __Host- / __Secure- prefixes"),
    Check("cors", "no credentialed access for any origin (probe request)"),
    Check("tls-certificate", "trusted and not close to expiry"),
    Check("tls-protocols", "TLS 1.0 and 1.1 are refused"),
    Check("caa", "a CAA record limits which CAs may issue"),
    Check("security-txt", "/.well-known/security.txt (RFC 9116)"),
    Check("spf", "a single SPF record that does not allow everyone"),
    Check("dmarc", "a DMARC policy that quarantines or rejects"),
    Check("dkim", "a DKIM key under common or given selectors"),
    Check("https-redirect", "plain HTTP redirects to HTTPS"),
)

# Every check name, in report order.
NAMES: tuple[str, ...] = tuple(check.name for check in CATALOG)

# Each check's summary, in report order.
SUMMARIES: dict[str, str] = {check.name: check.summary for check in CATALOG}
