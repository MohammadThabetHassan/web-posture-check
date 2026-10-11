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
from .headermap import HTTP_WHITESPACE, HeaderMap, HeaderSource, split_list

# Six months: the common scanner baseline. The HSTS preload list requires one year.
HSTS_MIN_MAX_AGE = 15552000
HSTS_PRELOAD_MIN_MAX_AGE = 31536000

# A nonce-source or hash-source (CSP3 section 2.3.1), matched on a lower-cased
# source list. One that does not match the grammar, such as 'nonce-' or an
# unfilled template placeholder, is not a nonce, so it switches nothing off.
_NONCE_OR_HASH = re.compile(r"'(?:nonce|sha256|sha384|sha512)-[a-z0-9+/_-]+={0,2}'")

# A host-source whose host is "*", or a wildcard right under a top-level domain
# (*.com, where anyone can register a name), with any scheme, port and path
# (CSP3 section 2.3.1): https://*, *:443, *:*, http://*/js/, https://*.com.
_ANY_HOST_SOURCE = re.compile(r"(?:(?P<scheme>[a-z][a-z0-9+.-]*)://)?\*(?:\.(?P<tld>[a-z0-9-]+))?(?::(?:[0-9]+|\*))?(?:/.*)?")

# Special-use names nobody can register (RFC 2606, RFC 6761, RFC 6762, ICANN's .internal).
_RESERVED_TLDS = frozenset({"localhost", "test", "invalid", "example", "local", "internal"})

# For each part of script loading, the directives that govern it, most specific
# first: the first one a policy has is the one that applies (CSP3 section 6.8.4,
# and section 4.4 for eval).
_SCRIPT_DIRECTIVES = {
    "elements": ("script-src-elem", "script-src", "default-src"),
    "handlers": ("script-src-attr", "script-src", "default-src"),
    "eval": ("script-src", "default-src"),
}

# The values of Referrer-Policy (Referrer Policy, section 3).
REFERRER_POLICIES = (
    "no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin",
    "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url",
)


def _headers(headers: HeaderSource) -> HeaderMap:
    return headers if isinstance(headers, HeaderMap) else HeaderMap(headers)


# --- Strict-Transport-Security ------------------------------------------------------------------


# RFC 9110 token, and quoted-string with its escapes.
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_QUOTED_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')


def _hsts_directives(value: str) -> dict[str, str | None] | str:
    """Directive name (lower case) -> value with quotes removed, or None for a bare directive.

    Returns why browsers ignore the whole header instead, as Chromium's parser
    (net/http/http_security_headers.cc) and RFC 6797 section 6.1 decide: a
    directive name that is not a token, a value that is neither a token nor a
    quoted string (an empty value is accepted), a repeated max-age or
    includeSubDomains, or an includeSubDomains with a value. Other directives,
    preload among them, may repeat and are otherwise ignored.
    """
    directives: dict[str, str | None] = {}
    for part in split_list(value, ";"):
        if not part:
            continue
        name, sep, raw = part.partition("=")
        name, raw = name.strip(" \t"), raw.strip(" \t")
        if not _TOKEN.fullmatch(name):
            return f"'{name}' is not a valid directive"
        quoted = raw.startswith('"')
        valid_value = _QUOTED_STRING.fullmatch(raw) if quoted else not raw or _TOKEN.fullmatch(raw)
        if not valid_value:
            return f"the value of {name} is not valid"
        if quoted:
            raw = re.sub(r"\\(.)", r"\1", raw[1:-1])
        lower = name.lower()
        if lower in ("max-age", "includesubdomains") and lower in directives:
            return f"it repeats {name}"
        if lower == "includesubdomains" and (raw or quoted):
            return "includeSubDomains takes no value"
        directives[lower] = raw if sep else None
    return directives


def check_hsts(headers: HeaderSource, https: bool = True, verified: bool = True) -> Finding:
    """Strict-Transport-Security, read as browsers read it (RFC 6797).

    https is False when the final response came over plain HTTP, and verified is
    False when its certificate is not trusted (a scan with --insecure). Browsers
    ignore the header in both cases (section 8.1): over plain HTTP that is a
    FAIL; with --insecure the header is judged as configured, with a note.
    """
    finding = _check_hsts(headers, https)
    if not verified and finding.status != FAIL:
        return Finding("hsts", finding.status, finding.detail + "; browsers ignore it while the certificate is not trusted (RFC 6797 section 8.1)")
    return finding


def _check_hsts(headers: HeaderSource, https: bool) -> Finding:
    values = _headers(headers).get_all("Strict-Transport-Security")
    if not values:
        return Finding("hsts", FAIL, "Strict-Transport-Security header is missing")
    if not https:
        return Finding("hsts", FAIL, "the final response is plain HTTP, where browsers ignore Strict-Transport-Security (RFC 6797 section 8.1)")
    # Section 8.1: with several Strict-Transport-Security headers, only the first is processed.
    value = values[0].strip(HTTP_WHITESPACE)
    extra = f" (first of {len(values)} Strict-Transport-Security headers; browsers use only the first)" if len(values) > 1 else ""
    directives = _hsts_directives(value)
    if isinstance(directives, str):
        return Finding("hsts", FAIL, f"Strict-Transport-Security is not valid ({directives}), so browsers ignore it: '{value}'{extra}")
    return _judge_hsts(directives, extra)


def _judge_hsts(directives: dict[str, str | None], extra: str) -> Finding:
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


# ASCII whitespace, the only characters that separate a directive's name and sources.
_ASCII_WHITESPACE = "\t\n\f\r "

# A directive browsers keep: ASCII whitespace and printable ASCII only. CSP3 section
# 2.2.1 drops a directive with a non-ASCII character, and Chromium also drops one
# with a control character ("contains an invalid character").
_VALID_DIRECTIVE = re.compile(r"[\t\n\f\r\x20-\x7e]*")


def _csp_policies(header_values: list[str]) -> list[dict[str, list[str]]]:
    """Parse Content-Security-Policy headers into policies, each a {directive: [sources]} dict.

    Every header is enforced, and one header can carry several policies separated
    by commas (CSP3 section 2.2.3). Within a policy the first occurrence of a
    directive wins and later ones are ignored, and a directive with a character
    browsers do not accept is dropped, as in section 2.2.1. Directive names and
    source expressions are compared in lower case. Policies with no directives are
    dropped, since they enforce nothing.
    """
    policies = []
    for header in header_values:
        for serialized in split_list(header):
            directives: dict[str, list[str]] = {}
            for token in serialized.split(";"):
                token = token.strip(_ASCII_WHITESPACE)
                if not token or not _VALID_DIRECTIVE.fullmatch(token):
                    continue
                name, *sources = re.split(r"[\t\n\f\r ]+", token)
                if name.lower() not in directives:
                    directives[name.lower()] = [source.lower() for source in sources]
            if directives:
                policies.append(directives)
    return policies


def _reach(sources: list[str]) -> set[str]:
    """Where a source list lets anything be loaded from any host: "http" and "https" for
    any web host over that scheme, "data" for data: URLs.

    * and http: also match https (CSP3 sections 6.7.2.6 and 6.7.2.8), so the
    spelling does not matter: *, http:, https:, https://* and *:443 all let
    an attacker load code from a host of their own.
    """
    reach: set[str] = set()
    for source in sources:
        if source in ("*", "http:"):
            reach |= {"http", "https"}
        elif source in ("https:", "data:"):
            reach.add(source[:-1])
        else:
            match = _ANY_HOST_SOURCE.fullmatch(source)
            if match and match["tld"] in _RESERVED_TLDS:
                continue
            if match and match["scheme"] in (None, "http"):
                reach |= {"http", "https"}
            elif match and match["scheme"] == "https":
                reach.add("https")
    return reach


def _script_reach(sources: list[str]) -> set[str]:
    """_reach for scripts: with 'strict-dynamic', browsers ignore host and scheme sources."""
    return set() if "'strict-dynamic'" in sources else _reach(sources)


def _allows_inline(sources: list[str]) -> bool:
    """CSP3 section 6.7.3.3: 'unsafe-inline' applies unless a nonce, a hash or 'strict-dynamic' is present."""
    if any(source == "'strict-dynamic'" or _NONCE_OR_HASH.fullmatch(source) for source in sources):
        return False
    return "'unsafe-inline'" in sources


def _describe_reach(reach: set[str]) -> str:
    parts = []
    if {"http", "https"} <= reach:
        parts.append("any host")
    elif "https" in reach:
        parts.append("any HTTPS host")
    if "data" in reach:
        parts.append("data: URLs")
    return " and ".join(parts)


def _governing(policies: list[dict[str, list[str]]], part: str) -> list[tuple[str, list[str]]]:
    """(directive, sources) for each policy that governs this part of script loading."""
    found = []
    for policy in policies:
        name = next((name for name in _SCRIPT_DIRECTIVES[part] if name in policy), None)
        if name is not None:
            found.append((name, policy[name]))
    return found


def _subject(governing: list[tuple[str, list[str]]]) -> str:
    """'script-src allows', or with several policies 'default-src and script-src allow ... in all 2 policies'."""
    names = list(dict.fromkeys(name for name, _ in governing))
    return f"{' and '.join(names)} {'allows' if len(names) == 1 else 'allow'}"


def _scope(governing: list[tuple[str, list[str]]]) -> str:
    return f" in all {len(governing)} policies" if len(governing) > 1 else ""


def _script_problems(policies: list[dict[str, list[str]]]) -> list[str]:
    """What the policies let scripts do that they should not, as sentences.

    Every policy is enforced, so a script runs only if every policy that governs
    it allows it: a weakness counts when all of those policies have it, whatever
    the spelling (CSP3 section 2.2.2). A policy that does not govern something
    does not restrict it.
    """
    problems: list[str] = []

    def add(problem: str) -> None:
        if problem not in problems:
            problems.append(problem)

    for part in ("elements", "handlers"):
        governing = _governing(policies, part)
        if governing and all(_allows_inline(sources) for _, sources in governing):
            add(f"{_subject(governing)} 'unsafe-inline' without a nonce or hash{_scope(governing)}")
    elements = _governing(policies, "elements")
    shared = set.intersection(*(_script_reach(sources) for _, sources in elements)) if elements else set()
    if shared:
        # The sources to remove, per policy.
        per_policy = [(name, [source for source in sources if _reach([source]) & shared]) for name, sources in elements]
        shown = ", ".join(per_policy[0][1]) if len(elements) == 1 else "; ".join(f"{name} {' '.join(tokens)}" for name, tokens in per_policy)
        add(f"{_subject(elements)} scripts from {_describe_reach(shared)}{_scope(elements)} ({shown})")
    if not _governing(policies, "handlers"):
        add("nothing restricts inline event handlers (no script-src-attr, script-src or default-src)")
    evaluating = _governing(policies, "eval")
    if not evaluating:
        add("nothing restricts eval() (no script-src or default-src)")
    elif all("'unsafe-eval'" in sources for _, sources in evaluating):
        add(f"{_subject(evaluating)} 'unsafe-eval'{_scope(evaluating)}")
    return problems


def check_csp(headers: HeaderSource) -> Finding:
    hm = _headers(headers)
    enforced = hm.get_all("Content-Security-Policy")
    if not enforced:
        if hm.get_all("Content-Security-Policy-Report-Only"):
            return Finding("csp", WARN, "only Content-Security-Policy-Report-Only is set, nothing is enforced")
        return Finding("csp", FAIL, "Content-Security-Policy header is missing")
    policies = _csp_policies(enforced)
    if not policies:
        if any(value.strip(_ASCII_WHITESPACE + ",;") for value in enforced):
            return Finding("csp", FAIL, "Content-Security-Policy has no directive browsers accept (a character outside "
                                        "the CSP syntax makes them drop it), so it enforces nothing")
        return Finding("csp", FAIL, "Content-Security-Policy is empty, so it enforces nothing")
    if not _governing(policies, "elements"):
        return Finding("csp", WARN, "Content-Security-Policy does not restrict scripts (no script-src or default-src), so it does not stop injected scripts")
    problems = _script_problems(policies)
    if problems:
        return Finding("csp", WARN, "; ".join(problems))
    return Finding("csp", PASS, "Content-Security-Policy is set" + (f" ({len(policies)} policies, all enforced)" if len(policies) > 1 else ""))


# --- Clickjacking -------------------------------------------------------------------------------


def _allows_any_ancestor(sources: list[str]) -> bool:
    """True when a frame-ancestors source list lets every website frame the page.

    That is *, http: or https:, or a host-source whose host is * (https://*).
    Other schemes, such as chrome-extension:, are not websites. An empty list means 'none'.
    """
    return bool(_reach(sources) & {"http", "https"})


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
    value = _headers(headers).combined("X-XSS-Protection")
    if value is None:
        return Finding("x-xss-protection", PASS, "not set (rely on Content-Security-Policy)")
    # Blink and WebKit decided on the first character of the (combined) value:
    # 0 turned the auditor off, 1 turned it on, anything else was invalid.
    first = value.lstrip(HTTP_WHITESPACE)[:1]
    if first == "0":
        return Finding("x-xss-protection", PASS, "0 (legacy XSS auditor disabled)" + (f" (sent as '{value}')" if value != "0" else ""))
    if first == "1":
        return Finding("x-xss-protection", WARN, f"'{value}' enables the legacy XSS auditor, which can be abused for XS-Leaks; set it to 0 or remove it")
    return Finding("x-xss-protection", WARN, f"'{value}' is not a valid value; set it to 0 or remove it")


def _policy_token(value: str | None) -> str | None:
    """First token of a policy header, e.g. 'same-origin; report-to="x"' -> 'same-origin'; None when empty.

    The case is kept: browsers compare these values case-sensitively, so Same-Origin is not same-origin.
    """
    return value.split(";", 1)[0].strip(HTTP_WHITESPACE) or None if value else None


# Values browsers understand. Anything else is ignored, which means no protection.
COOP_VALUES = ("unsafe-none", "same-origin-allow-popups", "same-origin", "noopener-allow-popups")
CORP_VALUES = ("same-site", "same-origin", "cross-origin")
COEP_VALUES = ("unsafe-none", "require-corp", "credentialless")


def _known_policy(hm: HeaderMap, name: str, allowed: tuple[str, ...]) -> tuple[str | None, str | None]:
    """Return (value, None) for a recognised value or None, or (None, raw) for one browsers ignore.

    Browsers combine a repeated header, so two copies ("same-origin, same-origin")
    are not a value they recognise either (the Fetch standard notes this for CORP).
    """
    combined = hm.combined(name)
    value = _policy_token(combined)
    if value is None or value in allowed:
        return value, None
    return None, combined


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


def run(headers: HeaderSource, https: bool = True, verified: bool = True) -> list[Finding]:
    """Every header check on one response.

    https says whether that response came over HTTPS, and verified whether its
    certificate was verified (False with --insecure).
    """
    hm = _headers(headers)
    return [check_hsts(hm, https=https, verified=verified) if check is check_hsts else check(hm) for check in ALL_CHECKS]
