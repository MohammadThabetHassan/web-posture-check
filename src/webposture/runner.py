"""Scanning one target: fetch it, run the selected checks, decide the exit code.

scan() keeps no state between targets and does no printing, so several
targets can be scanned at once on different threads.

Requests go through the fetch module by attribute (fetch.fetch_headers, ...),
so a test that patches the fetch module intercepts every caller.
"""

from __future__ import annotations

import ipaddress
import ssl
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlsplit

from . import caa, checks, cookies, cors, emailauth, fetch, headers, securitytxt, tls, transport
from .findings import FAIL, SKIPPED_PREFIX, WARN, Finding, ScanResult
from .headermap import HeaderMap

# Every check name in report order, and each one's summary (kept here for
# callers that used runner.ALL_CHECKS and runner.CHECK_SUMMARIES).
ALL_CHECKS = list(checks.NAMES)
CHECK_SUMMARIES = checks.SUMMARIES

# What scanning one target gives: its result and the exit code.
Outcome = tuple[ScanResult, int]


@dataclass(frozen=True)
class ScanOptions:
    """How to scan each target. The command line builds it (cli.scan_options)."""

    timeout: float = 10.0
    # Extra attempts for the first request after a timeout or a dropped connection.
    retries: int = 1
    # Run the other checks without certificate verification when the certificate is not trusted.
    insecure: bool = False
    # Check names to run (only) or to leave out (skip); None means no restriction.
    only: frozenset[str] | None = None
    skip: frozenset[str] | None = None
    # The lowest status that makes the exit code 1.
    fail_on: Literal["fail", "warn"] = "fail"
    # DKIM selectors to look up; empty means the common ones.
    dkim_selectors: tuple[str, ...] = ()

    def wanted(self, name: str) -> bool:
        """Whether check name is selected by only and skip."""
        if self.only is not None:
            return name in self.only
        return self.skip is None or name not in self.skip


def normalise_target(target: str) -> str:
    """Turn a target into the URL to fetch, or raise ValueError saying why it cannot be checked.

    A bare domain or host:port is fetched over https://. Only http:// and https://
    URLs with a valid host name and port are accepted; a URL with credentials in
    it is refused, so they never end up in a request log or a report.
    """
    target = target.strip()
    if not target:
        raise ValueError("it is empty")
    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in target):
        raise ValueError("it contains spaces or control characters")
    url = target if "://" in target else "https://" + target
    parts = urlsplit(url)  # raises ValueError for a malformed IPv6 literal
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("only http:// and https:// URLs can be checked")
    if not parts.hostname:
        raise ValueError("it has no host name")
    if "@" in parts.netloc:
        raise ValueError("credentials in the URL are not supported")
    try:
        parts.port  # noqa: B018 -- reading it validates the port
    except ValueError:
        raise ValueError("its port is not a number from 0 to 65535") from None
    try:
        parts.hostname.encode("idna")
    except UnicodeError:
        raise ValueError(f"{parts.hostname} is not a valid host name") from None
    return url


def probe_cors(url: str, timeout: float, context: ssl.SSLContext | None = None) -> Finding:
    """Request url as if from a foreign origin and check what CORS allows."""
    try:
        _, probe_headers, _, _ = fetch.fetch_headers(url, timeout, {"Origin": cors.PROBE_ORIGIN}, context=context)
    except fetch.FETCH_ERRORS as err:
        return Finding("cors", WARN, f"could not run the CORS probe: {err}")
    # Fetch, "CORS check": repeated headers are combined, so "x, x" is not a match for x.
    allowed = HeaderMap(probe_headers)
    return cors.check_cors(allowed.combined("Access-Control-Allow-Origin"), allowed.combined("Access-Control-Allow-Credentials"))


def check_tls(url: str, timeout: float) -> Finding:
    """Check the certificate of the host that served the final URL (always verifying)."""
    parts = urlsplit(url)
    # (A fetched https:// URL always has a host name; the test is for the type checker.)
    if parts.scheme != "https" or not parts.hostname:
        return Finding("tls-certificate", WARN, "the final URL is not HTTPS, so there is no certificate to check")
    try:
        not_after, verify_code, verify_message = tls.fetch_certificate(parts.hostname, parts.port or 443, timeout)
    except OSError as err:
        return Finding("tls-certificate", WARN, f"could not check the certificate: {err}")
    return tls.check_certificate(not_after, verify_code, verify_message, now=datetime.now(timezone.utc))


def check_legacy_tls(url: str, timeout: float) -> Finding:
    """Check whether the host that served the final URL still accepts TLS 1.0 or 1.1."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return Finding("tls-protocols", WARN, "the final URL is not HTTPS, so TLS versions were not checked")
    return tls.check_legacy_protocols(tls.probe_legacy_protocols(parts.hostname, parts.port or 443, timeout))


def check_security_txt(url: str, timeout: float, context: ssl.SSLContext | None = None) -> Finding:
    """Fetch /.well-known/security.txt from the final URL's origin and check it."""
    parts = urlsplit(url)
    # A real security.txt is a few KB.
    status, content_type, body = fetch.fetch_text(f"{parts.scheme}://{parts.netloc}{securitytxt.PATH}", timeout, 64 * 1024, context=context)
    return securitytxt.check_security_txt(status, content_type, body, now=datetime.now(timezone.utc))


def check_https_redirect(http_url: str, timeout: float, context: ssl.SSLContext | None = None) -> Finding:
    """Request the site over plain HTTP and check where the redirects end."""
    try:
        final_url = fetch.fetch_final_url(http_url, timeout, context=context)
    except fetch.UNREADABLE as err:
        # Something answered, so "nothing is served over plain HTTP" would be a false pass.
        return Finding("https-redirect", WARN, f"{http_url} answered with a response that could not be read "
                                               f"({type(err).__name__}: {str(err).strip()}), so the redirect was not checked")
    return transport.check_https_redirect(http_url, final_url)


def dns_not_applicable(url: str) -> str | None:
    """Why the DNS checks do not apply to url's host, as a skipped detail, or None when they do.

    An IP address has no domain to look up, and a name without a dot (localhost,
    an intranet host) is not a public domain with mail or certificate records.
    """
    host = (urlsplit(url).hostname or "").rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return f"{SKIPPED_PREFIX} {host} is an IP address, so there is no domain to look up"
    if "." not in host:
        return f"{SKIPPED_PREFIX} {host or 'the host'} is not a public domain name"
    return None


def check_spf(url: str, timeout: float) -> Finding:
    """Check the SPF record of the site's mail domain (www. stripped from the host)."""
    skipped = dns_not_applicable(url)
    if skipped:
        return Finding("spf", WARN, skipped)
    domain = emailauth.mail_domain(urlsplit(url).hostname)
    txt, problem = emailauth.lookup_txt(domain, timeout)
    if problem:
        return Finding("spf", WARN, problem)
    return emailauth.check_spf(domain, txt)


def check_dmarc(url: str, timeout: float) -> Finding:
    """Find the DMARC record that applies to the site's mail domain and check it."""
    skipped = dns_not_applicable(url)
    if skipped:
        return Finding("dmarc", WARN, skipped)
    domain = emailauth.mail_domain(urlsplit(url).hostname)
    for candidate in emailauth.dmarc_candidates(domain):
        txt, problem = emailauth.lookup_txt(f"_dmarc.{candidate}", timeout)
        if problem:
            return Finding("dmarc", WARN, problem)
        if emailauth.dmarc_records(txt):
            return emailauth.check_dmarc(candidate, txt, domain=domain)
    return emailauth.check_dmarc(None, [])


def check_dkim(url: str, timeout: float, selectors: Sequence[str] | None = None) -> Finding:
    """Look for DKIM keys under the given selectors, or under common ones when none are given."""
    skipped = dns_not_applicable(url)
    if skipped:
        return Finding("dkim", WARN, skipped)
    domain = emailauth.mail_domain(urlsplit(url).hostname)
    explicit = bool(selectors)
    keys: dict[str, str | None] = {}
    for selector in selectors or emailauth.COMMON_DKIM_SELECTORS:
        txt, problem = emailauth.lookup_txt(f"{selector}._domainkey.{domain}", timeout)
        if problem:
            return Finding("dkim", WARN, problem)
        keys[selector] = emailauth.parse_dkim_key(txt)
    return emailauth.check_dkim(domain, keys, explicit)


def check_caa(url: str, timeout: float) -> Finding:
    """Check which CAs may issue for the host that served the final URL."""
    skipped = dns_not_applicable(url)
    if skipped:
        return Finding("caa", WARN, skipped)
    found_on, records, problem = caa.lookup_caa((urlsplit(url).hostname or "").rstrip("."), timeout)
    if problem:
        return Finding("caa", WARN, problem)
    return caa.check_caa(found_on, records)


def failed(url: str, error: str) -> ScanResult:
    """The result for a target that could not be scanned: no status, no findings, and why."""
    return {"url": url, "status": None, "findings": [], "note": None, "error": error}


def scan(target: str, options: ScanOptions) -> Outcome:
    """Run the selected checks on one target and return (result, exit code).

    A target that could not be (fully) scanned has an "error" in its result
    and exit code 2. Nothing is printed, so the caller can report targets
    scanned in parallel in a stable order.
    """
    try:
        url = normalise_target(target)
    except ValueError as err:
        return failed(target.strip(), f"invalid target {target!r}: {err}"), 2
    try:
        fetched = fetch.fetch_with_retries(url, options.timeout, options.retries)
    except fetch.FETCH_ERRORS as err:
        reason = getattr(err, "reason", err)
        if isinstance(reason, ssl.SSLCertVerificationError):
            # A broken certificate is itself the most important finding, so
            # report it instead of aborting.
            finding = tls.check_certificate(None, reason.verify_code, reason.verify_message, now=datetime.now(timezone.utc))
            if options.insecure:
                return _scan_insecure(url, options, finding)
            return {"url": url, "status": None, "findings": [finding],
                    "note": "other checks skipped: no trusted HTTPS connection (--insecure runs them anyway)"}, 1
        return failed(url, fetch.describe_fetch_error(url, err, options.timeout, options.retries + 1)), 2
    return run_checks(url, fetched, options)


def _scan_insecure(url: str, options: ScanOptions, cert_finding: Finding) -> Outcome:
    """Run the checks without certificate verification after the certificate failed.

    The unverified context is created here and passed down explicitly, so it
    only ever applies to this target's requests. The certificate failure stays
    in the report, first and whatever --only or --skip say, and the run still
    exits at least 1. If even the unverified request fails, the target could
    not be scanned: that is an error, exit code 2, like any other target that
    could not be reached.
    """
    context = fetch.unverified_context()
    try:
        fetched = fetch.fetch_with_retries(url, options.timeout, options.retries, context=context)
    except fetch.FETCH_ERRORS as err:
        return {"url": url, "status": None, "findings": [cert_finding],
                "note": "other checks skipped: the target could not be fetched even without certificate verification",
                "error": fetch.describe_fetch_error(url, err, options.timeout, options.retries + 1)}, 2
    result, code = run_checks(url, fetched, options, context=context)
    # check_tls verifies on its own and would repeat the same failure.
    others = [f for f in result["findings"] if f.check != "tls-certificate"]
    result["findings"] = [cert_finding, *others]
    result["note"] = "certificate not trusted; the other checks ran with --insecure (no certificate verification)"
    return result, max(code, 1)


def run_checks(url: str, fetched: fetch.FetchResult, options: ScanOptions,
               context: ssl.SSLContext | None = None) -> tuple[ScanResult, int]:
    """Run the selected checks on a fetched target. Returns (result, exit code)."""
    final_url, response_headers, set_cookies, status = fetched
    # urlsplit lower-cases the scheme, so HTTPS://example.com counts as HTTPS too.
    https = urlsplit(final_url).scheme == "https"

    # Checks that need their own requests are wrapped in lambdas, so a check
    # left out with --only/--skip never touches the network.
    http_url = transport.http_url_for(url)
    later: list[tuple[str, Callable[[], Finding]]] = [
        ("cookies", lambda: cookies.check_cookies(set_cookies, https)),
        ("cors", lambda: probe_cors(final_url, options.timeout, context=context)),
        ("tls-certificate", lambda: check_tls(final_url, options.timeout)),
        ("tls-protocols", lambda: check_legacy_tls(final_url, options.timeout)),
        ("caa", lambda: check_caa(final_url, options.timeout)),
        ("security-txt", lambda: check_security_txt(final_url, options.timeout, context=context)),
        ("spf", lambda: check_spf(final_url, options.timeout)),
        ("dmarc", lambda: check_dmarc(final_url, options.timeout)),
        ("dkim", lambda: check_dkim(final_url, options.timeout, options.dkim_selectors)),
        ("https-redirect", lambda: check_https_redirect(http_url, options.timeout, context=context)),
    ]
    # The status goes first: when it is an error page, every finding below describes that page.
    findings = [transport.check_status(status)] if options.wanted("http-status") else []
    # With --insecure (a context), the certificate was not verified.
    findings += [f for f in headers.run(response_headers, https=https, verified=context is None) if options.wanted(f.check)]
    findings += [run() for name, run in later if options.wanted(name)]
    return {"url": final_url, "status": status, "findings": findings, "note": None}, exit_code(findings, options.fail_on)


def exit_code(findings: Iterable[Finding], fail_on: str) -> int:
    """1 if any finding is at or above the --fail-on level, else 0.

    With --fail-on warn, findings reported as skipped (a check that could not
    run, e.g. without the optional DNS extra) do not count: they say nothing
    about the site.
    """
    levels = {FAIL} if fail_on == "fail" else {FAIL, WARN}
    failing = any(f.status in levels and not f.detail.startswith(SKIPPED_PREFIX) for f in findings)
    return 1 if failing else 0
