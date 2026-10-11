"""HTTP security header checks.

Each check takes the response headers and returns a Finding. Checks never make
network calls, so they are easy to test.

A response can repeat a header, and each header has its own rule for what that
means, so the checks read a HeaderMap, which keeps every occurrence, and apply
the rule of the standard behind that header. Any mapping of header names to
values also works, which keeps tests short.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from .findings import FAIL, PASS, WARN, Finding
from .headermap import HeaderMap, HeaderSource

# Six months: the common scanner baseline. The HSTS preload list requires one year.
HSTS_MIN_MAX_AGE = 15552000
HSTS_PRELOAD_MIN_MAX_AGE = 31536000

# Script sources that allow loading code from any host (or from data: URLs),
# which lets an attacker who can inject a <script src> tag run their own code.
BROAD_SCRIPT_SOURCES = ("*", "https:", "http:", "data:")

# Source expressions that switch off 'unsafe-inline' for scripts (CSP3 section
# 6.7.3.3, "Does a source list allow all inline behavior for type?").
_NONCE_OR_HASH = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")

# The values of Referrer-Policy (Referrer Policy, section 3).
REFERRER_POLICIES = (
    "no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin",
    "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url",
)


def _headers(headers: HeaderSource) -> HeaderMap:
    return headers if isinstance(headers, HeaderMap) else HeaderMap(headers)


# --- Strict-Transport-Security ------------------------------------------------------------------


def _hsts_directives(value: str) -> dict[str, str | None] | None:
    """Directive name (lower case) -> value with quotes removed, or None for a bare directive.

    Returns None for the whole header when a directive appears twice: RFC 6797
    section 6.1 allows each directive once, and browsers ignore such a header.
    """
    directives: dict[str, str | None] = {}
    for part in value.split(";"):
        name, sep, raw = part.partition("=")
        name = name.strip().lower()
        if not name:
            continue
        if name in directives:
            return None
        text = raw.strip()
        if len(text) >= 2 and text[0] == text[-1] == '"':
            text = text[1:-1]
        directives[name] = text if sep else None
    return directives


def check_hsts(headers: HeaderSource, https: bool = True) -> Finding:
    """Strict-Transport-Security, read as browsers read it (RFC 6797).

    https is False when the final response came over plain HTTP, where browsers
    ignore the header entirely (section 8.1).
    """
    values = _headers(headers).get_all("Strict-Transport-Security")
    if not values:
        return Finding("hsts", FAIL, "Strict-Transport-Security header is missing")
    if not https:
        return Finding("hsts", FAIL, "the final response is plain HTTP, where browsers ignore Strict-Transport-Security (RFC 6797 section 8.1)")
    # Section 8.1: with several Strict-Transport-Security headers, only the first is processed.
    value = values[0].strip()
    extra = f" (first of {len(values)} Strict-Transport-Security headers; browsers use only the first)" if len(values) > 1 else ""
    directives = _hsts_directives(value)
    if directives is None:
        return Finding("hsts", FAIL, f"Strict-Transport-Security repeats a directive, so browsers ignore it: '{value}'{extra}")
    raw_max_age = directives.get("max-age")
    if raw_max_age is None or not re.fullmatch(r"[0-9]+", raw_max_age):
        return Finding("hsts", FAIL, f"Strict-Transport-Security has no valid max-age{extra}")
    max_age = int(raw_max_age)
    if max_age == 0:
        # Section 6.1.1: max-age=0 tells browsers to stop treating the host as an HSTS host.
        return Finding("hsts", FAIL, f"max-age=0 tells browsers to stop enforcing HTTPS for this host{extra}")
    subdomains = "includesubdomains" in directives
    preload = "preload" in directives
    detail = f"max-age={max_age}" + ("; includeSubDomains" if subdomains else "") + ("; preload" if preload else "")
    if max_age < HSTS_MIN_MAX_AGE:
        return Finding("hsts", WARN, f"max-age={max_age} is below {HSTS_MIN_MAX_AGE} (6 months){extra}")
    if preload:
        # The preload list (hstspreload.org) rejects sites that ask for preload
        # without meeting its requirements, so the directive does nothing.
        missing = []
        if max_age < HSTS_PRELOAD_MIN_MAX_AGE:
            missing.append(f"max-age of at least {HSTS_PRELOAD_MIN_MAX_AGE} (1 year)")
        if not subdomains:
            missing.append("includeSubDomains")
        if missing:
            return Finding("hsts", WARN, f"{detail}: preload is set but the preload list also requires " + " and ".join(missing) + extra)
    return Finding("hsts", PASS, detail + extra)


# --- Content-Security-Policy ----------------------------------------------------------------------


def _csp_policies(header_values: list[str]) -> list[dict[str, list[str]]]:
    """Parse Content-Security-Policy headers into policies, each a {directive: [sources]} dict.

    Every header is enforced, and one header can carry several policies separated
    by commas (CSP3 section 2.2.2). Within a policy the first occurrence of a
    directive wins and later ones are ignored, as in browsers. Directive names and
    source expressions are compared in lower case. Policies with no directives are
    dropped, since they enforce nothing.
    """
    policies = []
    for header in header_values:
        for serialized in header.split(","):
            directives: dict[str, list[str]] = {}
            for part in serialized.split(";"):
                tokens = part.split()
                if tokens and tokens[0].lower() not in directives:
                    directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
            if directives:
                policies.append(directives)
    return policies


def _script_directive(policy: dict[str, list[str]]) -> tuple[str, list[str]] | None:
    """The directive that governs scripts in one policy: script-src, else default-src, else None."""
    for name in ("script-src", "default-src"):
        if name in policy:
            return name, policy[name]
    return None


def _script_weaknesses(sources: list[str]) -> list[str]:
    """The unsafe things a script source list allows: 'unsafe-inline', 'unsafe-eval' and broad sources."""
    weak = []
    # A nonce, a hash or 'strict-dynamic' makes browsers ignore 'unsafe-inline' (CSP3 section 6.7.3.3).
    if "'unsafe-inline'" in sources and not any(s.startswith(_NONCE_OR_HASH) or s == "'strict-dynamic'" for s in sources):
        weak.append("'unsafe-inline'")
    if "'unsafe-eval'" in sources:
        weak.append("'unsafe-eval'")
    # With 'strict-dynamic', CSP Level 3 browsers ignore host and scheme sources.
    if "'strict-dynamic'" not in sources:
        weak += [s for s in sources if s in BROAD_SCRIPT_SOURCES]
    return weak


def check_csp(headers: HeaderSource) -> Finding:
    hm = _headers(headers)
    enforced = hm.get_all("Content-Security-Policy")
    if not enforced:
        if hm.get_all("Content-Security-Policy-Report-Only"):
            return Finding("csp", WARN, "only Content-Security-Policy-Report-Only is set, nothing is enforced")
        return Finding("csp", FAIL, "Content-Security-Policy header is missing")
    policies = _csp_policies(enforced)
    if not policies:
        return Finding("csp", FAIL, "Content-Security-Policy is empty, so it enforces nothing")
    governing = [found for found in map(_script_directive, policies) if found is not None]
    if not governing:
        return Finding("csp", WARN, "Content-Security-Policy does not restrict scripts (no script-src or default-src), so it does not stop injected scripts")
    # Every policy is enforced, so a script runs only if every policy that governs
    # scripts allows it: a weakness counts only when all of those policies share it.
    directive = governing[0][0]
    shared = _script_weaknesses(governing[0][1])
    for _, sources in governing[1:]:
        others = set(_script_weaknesses(sources))
        shared = [w for w in shared if w in others]
    scope = f" in all {len(governing)} policies" if len(governing) > 1 else ""
    problems = []
    if "'unsafe-inline'" in shared:
        problems.append(f"{directive} allows 'unsafe-inline' without a nonce or hash{scope}")
    if "'unsafe-eval'" in shared:
        problems.append(f"{directive} allows 'unsafe-eval'{scope}")
    broad = [w for w in shared if w in BROAD_SCRIPT_SOURCES]
    if broad:
        problems.append(f"{directive} allows scripts from " + ", ".join(broad) + scope)
    if problems:
        return Finding("csp", WARN, "; ".join(problems))
    return Finding("csp", PASS, "Content-Security-Policy is set" + (f" ({len(policies)} policies, all enforced)" if len(policies) > 1 else ""))


# --- Clickjacking -------------------------------------------------------------------------------


def _allows_any_ancestor(sources: list[str]) -> bool:
    """True when a frame-ancestors source list lets every site frame the page.

    That is '*', a scheme on its own such as https:, or a host-source whose host
    is '*' (https://*). An empty list means 'none'.
    """
    for source in sources:
        if source == "*" or re.fullmatch(r"[a-z][a-z0-9+.\-]*:", source):
            return True
        rest = source.split("://", 1)[1] if "://" in source else source
        if re.split(r"[:/]", rest, maxsplit=1)[0] == "*":
            return True
    return False


def check_framing(headers: HeaderSource) -> Finding:
    """Clickjacking protection, following the HTML standard's X-Frame-Options processing model.

    An enforced CSP frame-ancestors directive takes precedence and makes browsers
    ignore X-Frame-Options altogether, so a permissive frame-ancestors fails even
    when X-Frame-Options says DENY.
    """
    hm = _headers(headers)
    ancestors = [policy["frame-ancestors"] for policy in _csp_policies(hm.get_all("Content-Security-Policy"))
                 if "frame-ancestors" in policy]
    if ancestors:
        # Every policy is enforced, so framing is blocked if any of them restricts it.
        protective = [sources for sources in ancestors if not _allows_any_ancestor(sources)]
        if protective:
            # An empty source list means 'none'.
            shown = " ".join(protective[0]) or "'none'"
            return Finding("clickjacking", PASS, f"CSP frame-ancestors {shown}")
        ignored = "; X-Frame-Options is ignored when frame-ancestors is set" if hm.get_all("X-Frame-Options") else ""
        return Finding("clickjacking", FAIL, f"CSP frame-ancestors {' '.join(ancestors[0])} allows any site to frame this page{ignored}")
    values = hm.split("X-Frame-Options")
    if values is None:
        return Finding("clickjacking", FAIL, "neither CSP frame-ancestors nor X-Frame-Options DENY/SAMEORIGIN is set")
    raw = hm.combined("X-Frame-Options")
    options = {value.lower() for value in values}
    if len(options) > 1:
        # HTML: several different values that include deny, sameorigin or allowall block framing outright.
        if options & {"deny", "sameorigin", "allowall"}:
            return Finding("clickjacking", PASS, f"X-Frame-Options '{raw}' has conflicting values, which browsers treat as DENY")
        return Finding("clickjacking", FAIL, f"X-Frame-Options '{raw}' is not a value browsers understand, so it gives no protection")
    option = next(iter(options))
    sent_as = f" (sent as '{raw}')" if len(values) > 1 else ""
    if option in ("deny", "sameorigin"):
        return Finding("clickjacking", PASS, f"X-Frame-Options: {option.upper()}{sent_as}")
    if option.startswith("allow-from"):
        return Finding("clickjacking", FAIL, "X-Frame-Options ALLOW-FROM is not supported by current browsers, so it gives no protection")
    return Finding("clickjacking", FAIL, f"X-Frame-Options '{raw}' is not a value browsers understand, so it gives no protection")


# --- Other response headers ---------------------------------------------------------------------


def check_content_type_options(headers: HeaderSource) -> Finding:
    hm = _headers(headers)
    values = hm.split("X-Content-Type-Options")
    if values is None:
        return Finding("x-content-type-options", FAIL, "X-Content-Type-Options header is missing")
    raw = hm.combined("X-Content-Type-Options")
    # Fetch, "determine nosniff": the first value decides, compared case-insensitively.
    if values[0].lower() == "nosniff":
        return Finding("x-content-type-options", PASS, "nosniff" + (f" (sent as '{raw}')" if (raw or "").lower() != "nosniff" else ""))
    return Finding("x-content-type-options", FAIL, f"expected 'nosniff', got '{raw}'")


def check_referrer_policy(headers: HeaderSource) -> Finding:
    hm = _headers(headers)
    tokens = hm.split("Referrer-Policy")
    if tokens is None:
        return Finding("referrer-policy", WARN, "Referrer-Policy header is missing (browser default applies)")
    raw = hm.combined("Referrer-Policy") or ""
    # Referrer Policy, section 8.1: the last recognised value wins, so a list can
    # name fallbacks for older browsers before the policy it means.
    policy = next((token.lower() for token in reversed(tokens) if token.lower() in REFERRER_POLICIES), None)
    if policy is None:
        return Finding("referrer-policy", WARN, f"Referrer-Policy '{raw}' has no recognised value, so the browser default applies")
    shown = policy if raw.lower() == policy else f"{policy} (the value that applies in '{raw}')"
    if policy == "unsafe-url":
        return Finding("referrer-policy", FAIL, f"{shown}: unsafe-url sends the full URL, including path and query, to every site, even over plain HTTP")
    if policy == "no-referrer-when-downgrade":
        return Finding("referrer-policy", WARN, f"{shown}: sends the full URL, including path and query, to every HTTPS site")
    return Finding("referrer-policy", PASS, shown)


def check_permissions_policy(headers: HeaderSource) -> Finding:
    value = _headers(headers).combined("Permissions-Policy")
    if value is None:
        return Finding("permissions-policy", WARN, "Permissions-Policy header is missing")
    if not value.strip(" ,"):
        return Finding("permissions-policy", WARN, "Permissions-Policy is empty, so it restricts no browser feature")
    return Finding("permissions-policy", PASS, "Permissions-Policy is set")


def check_x_xss_protection(headers: HeaderSource) -> Finding:
    """X-XSS-Protection drove the old browser XSS auditor, which every current browser
    has removed. In browsers that still have it, enabling it ('1', '1; mode=block')
    could be abused to detect or block content on the page (XS-Leaks), so OWASP
    recommends '0' or omitting the header and relying on Content-Security-Policy.
    """
    value = _headers(headers).get("X-XSS-Protection")
    if value is None:
        return Finding("x-xss-protection", PASS, "not set (rely on Content-Security-Policy)")
    token = value.split(";", 1)[0].strip()
    if token == "0":
        return Finding("x-xss-protection", PASS, "0 (legacy XSS auditor disabled)")
    if token == "1":
        return Finding("x-xss-protection", WARN, f"'{value}' enables the legacy XSS auditor, which can be abused for XS-Leaks; set it to 0 or remove it")
    return Finding("x-xss-protection", WARN, f"'{value}' is not a valid value; set it to 0 or remove it")


def _policy_token(value: str | None) -> str | None:
    """First token of a policy header, e.g. 'same-origin; report-to="x"' -> 'same-origin'."""
    return value.split(";", 1)[0].strip().lower() if value else None


# Values browsers understand. Anything else is ignored, which means no protection.
COOP_VALUES = ("unsafe-none", "same-origin-allow-popups", "same-origin", "noopener-allow-popups")
CORP_VALUES = ("same-site", "same-origin", "cross-origin")
COEP_VALUES = ("unsafe-none", "require-corp", "credentialless")


def _known_policy(hm: HeaderMap, name: str, allowed: tuple[str, ...]) -> tuple[str | None, str | None]:
    """Return (value, None) for a recognised value or None, or (None, raw) for an unknown one."""
    value = _policy_token(hm.get(name))
    if value is None or value in allowed:
        return value, None
    return None, value


def check_cross_origin_isolation(headers: HeaderSource) -> Finding:
    """Report COOP, CORP and COEP. WARN only: they harden against XS-Leaks, not core flaws.

    COEP is only needed for cross-origin isolation (e.g. SharedArrayBuffer),
    so a missing COEP is reported in the detail but never warned about.
    """
    hm = _headers(headers)
    coop, coop_bad = _known_policy(hm, "Cross-Origin-Opener-Policy", COOP_VALUES)
    corp, corp_bad = _known_policy(hm, "Cross-Origin-Resource-Policy", CORP_VALUES)
    coep, coep_bad = _known_policy(hm, "Cross-Origin-Embedder-Policy", COEP_VALUES)
    problems = [f"{name} value '{value}' is not recognised, so browsers ignore it"
                for name, value in (("Cross-Origin-Opener-Policy", coop_bad),
                                    ("Cross-Origin-Resource-Policy", corp_bad),
                                    ("Cross-Origin-Embedder-Policy", coep_bad)) if value]
    if coop in (None, "unsafe-none"):
        problems.append("Cross-Origin-Opener-Policy is missing or unsafe-none, so a page that opens this one keeps a handle to its window")
    if corp is None:
        problems.append("Cross-Origin-Resource-Policy is missing, so other sites can embed this response")
    isolated = coop == "same-origin" and coep in ("require-corp", "credentialless")
    state = f"COOP={coop or 'unset'}, CORP={corp or 'unset'}, COEP={coep or 'unset'}" + ("; cross-origin isolated" if isolated else "")
    if problems:
        return Finding("cross-origin-isolation", WARN, "; ".join(problems) + f" ({state})")
    return Finding("cross-origin-isolation", PASS, state)


# Headers that exist only to name the server-side stack. Any value helps an
# attacker match the site to known vulnerabilities, so their presence is reported.
STACK_DISCLOSURE_HEADERS = ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")

# A version number such as nginx/1.18.0, Microsoft-IIS/10.0 or Apache/2.
# "/7F84" style build IDs are not versions, so a digit run must end the token.
SERVER_VERSION = re.compile(r"\d+\.\d+|/v?\d+\b")


def check_information_leakage(headers: HeaderSource) -> Finding:
    hm = _headers(headers)
    leaks = [f"Server: {server.strip()}" for server in hm.get_all("Server") if SERVER_VERSION.search(server)]
    for name in STACK_DISCLOSURE_HEADERS:
        leaks += [f"{name}: {value.strip()}" for value in hm.get_all(name)]
    if leaks:
        return Finding("information-leakage", WARN, "response discloses the server stack (" + "; ".join(leaks) + ")")
    return Finding("information-leakage", PASS, "no server version or stack headers")


# Every header check, in report order. check_hsts also takes https; run() passes it.
ALL_CHECKS: list[Callable[[HeaderSource], Finding]] = [
    check_hsts,
    check_csp,
    check_content_type_options,
    check_framing,
    check_referrer_policy,
    check_permissions_policy,
    check_cross_origin_isolation,
    check_x_xss_protection,
    check_information_leakage,
]


def run(headers: HeaderSource, https: bool = True) -> list[Finding]:
    """Every header check on one response. https says whether that response came over HTTPS."""
    hm = _headers(headers)
    return [check_hsts(hm, https=https) if check is check_hsts else check(hm) for check in ALL_CHECKS]
