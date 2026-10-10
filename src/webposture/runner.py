"""Scanning one target: fetch it, run the selected checks, decide the exit code.

Requests go through the fetch module by attribute (fetch.fetch_headers, ...),
so a test that patches the fetch module intercepts every caller.
"""

import ssl
import sys
import urllib.error
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import caa, cookies, cors, emailauth, fetch, headers, securitytxt, tls, transport
from .findings import FAIL, SKIPPED_PREFIX, WARN, Finding

# Every check name, in report order. Header check names come from the
# headers module itself so the list cannot drift from it.
HEADER_CHECKS = [f.check for f in headers.run({})]
ALL_CHECKS = [
    "http-status", *HEADER_CHECKS,
    "cookies", "cors", "tls-certificate", "tls-protocols", "caa",
    "security-txt", "spf", "dmarc", "dkim", "https-redirect",
]


def normalise_target(target):
    if "://" not in target:
        target = "https://" + target
    return target


def probe_cors(url, timeout, context=None):
    """Request url as if from a foreign origin and check what CORS allows."""
    try:
        _, probe_headers, _, _ = fetch.fetch_headers(url, timeout, {"Origin": cors.PROBE_ORIGIN}, context=context)
    except (urllib.error.URLError, OSError) as err:
        return Finding("cors", WARN, f"could not run the CORS probe: {err}")
    lowered = {k.lower(): v for k, v in probe_headers.items()}
    return cors.check_cors(lowered.get("access-control-allow-origin"), lowered.get("access-control-allow-credentials"))


def check_tls(url, timeout):
    """Check the certificate of the host that served the final URL (always verifying)."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        return Finding("tls-certificate", WARN, "the final URL is not HTTPS, so there is no certificate to check")
    try:
        result = tls.fetch_certificate(parts.hostname, parts.port or 443, timeout)
    except OSError as err:
        return Finding("tls-certificate", WARN, f"could not check the certificate: {err}")
    return tls.check_certificate(*result, now=datetime.now(timezone.utc))


def check_legacy_tls(url, timeout):
    """Check whether the host that served the final URL still accepts TLS 1.0 or 1.1."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        return Finding("tls-protocols", WARN, "the final URL is not HTTPS, so TLS versions were not checked")
    return tls.check_legacy_protocols(tls.probe_legacy_protocols(parts.hostname, parts.port or 443, timeout))


def check_security_txt(url, timeout, context=None):
    """Fetch /.well-known/security.txt from the final URL's origin and check it."""
    parts = urlsplit(url)
    # A real security.txt is a few KB.
    status, content_type, body = fetch.fetch_text(f"{parts.scheme}://{parts.netloc}{securitytxt.PATH}", timeout, 64 * 1024, context=context)
    return securitytxt.check_security_txt(status, content_type, body, now=datetime.now(timezone.utc))


def check_spf(url, timeout):
    """Check the SPF record of the site's mail domain (www. stripped from the host)."""
    domain = emailauth.mail_domain(urlsplit(url).hostname)
    txt, problem = emailauth.lookup_txt(domain, timeout)
    if problem:
        return Finding("spf", WARN, problem)
    return emailauth.check_spf(domain, txt)


def check_dmarc(url, timeout):
    """Find the DMARC record that applies to the site's mail domain and check it."""
    domain = emailauth.mail_domain(urlsplit(url).hostname)
    for candidate in emailauth.dmarc_candidates(domain):
        txt, problem = emailauth.lookup_txt(f"_dmarc.{candidate}", timeout)
        if problem:
            return Finding("dmarc", WARN, problem)
        if emailauth.dmarc_records(txt):
            return emailauth.check_dmarc(candidate, txt)
    return emailauth.check_dmarc(None, [])


def check_dkim(url, timeout, selectors=None):
    """Look for DKIM keys under the given selectors, or under common ones when none are given."""
    domain = emailauth.mail_domain(urlsplit(url).hostname)
    explicit = bool(selectors)
    keys = {}
    for selector in selectors or emailauth.COMMON_DKIM_SELECTORS:
        txt, problem = emailauth.lookup_txt(f"{selector}._domainkey.{domain}", timeout)
        if problem:
            return Finding("dkim", WARN, problem)
        keys[selector] = emailauth.parse_dkim_key(txt)
    return emailauth.check_dkim(domain, keys, explicit)


def check_caa(url, timeout):
    """Check which CAs may issue for the host that served the final URL."""
    found_on, records, problem = caa.lookup_caa(urlsplit(url).hostname.rstrip("."), timeout)
    if problem:
        return Finding("caa", WARN, problem)
    return caa.check_caa(found_on, records)


def scan(target, args):
    """Run the selected checks on one target. Returns (result or None, exit code)."""
    url = normalise_target(target)
    try:
        fetched = fetch.fetch_with_retries(url, args.timeout, args.retries)
    except (urllib.error.URLError, OSError) as err:
        reason = getattr(err, "reason", err)
        if isinstance(reason, ssl.SSLCertVerificationError):
            # A broken certificate is itself the most important finding, so
            # report it instead of aborting.
            finding = tls.check_certificate(None, reason.verify_code, reason.verify_message, now=datetime.now(timezone.utc))
            if args.insecure:
                return _scan_insecure(url, args, finding)
            return {"url": url, "status": None, "findings": [finding],
                    "note": "other checks skipped: no trusted HTTPS connection (--insecure runs them anyway)"}, 1
        print(f"error: {fetch.describe_fetch_error(url, err, args.timeout, args.retries + 1)}", file=sys.stderr)
        return None, 2
    return run_checks(url, fetched, args)


def _scan_insecure(url, args, cert_finding):
    """Run the checks without certificate verification after the certificate failed.

    The unverified context is created here and passed down explicitly, so it
    only ever applies to this target's requests. The certificate failure stays
    in the report, first and whatever --only or --skip say, and the run still
    exits at least 1.
    """
    context = fetch.unverified_context()
    try:
        fetched = fetch.fetch_with_retries(url, args.timeout, args.retries, context=context)
    except (urllib.error.URLError, OSError) as err:
        print(f"error: {fetch.describe_fetch_error(url, err, args.timeout, args.retries + 1)}", file=sys.stderr)
        return {"url": url, "status": None, "findings": [cert_finding],
                "note": "other checks skipped: the target could not be fetched even without certificate verification"}, 1
    result, code = run_checks(url, fetched, args, context=context)
    # check_tls verifies on its own and would repeat the same failure.
    others = [f for f in result["findings"] if f.check != "tls-certificate"]
    result["findings"] = [cert_finding, *others]
    result["note"] = "certificate not trusted; the other checks ran with --insecure (no certificate verification)"
    return result, max(code, 1)


def run_checks(url, fetched, args, context=None):
    """Run the selected checks on a fetched target. Returns (result, exit code)."""
    final_url, response_headers, set_cookies, status = fetched

    def wanted(name):
        if args.only is not None:
            return name in args.only
        return args.skip is None or name not in args.skip

    # Checks that need their own requests are wrapped in lambdas, so a check
    # left out with --only/--skip never touches the network.
    http_url = transport.http_url_for(url)
    later = [
        ("cookies", lambda: cookies.check_cookies(set_cookies, final_url.startswith("https://"))),
        ("cors", lambda: probe_cors(final_url, args.timeout, context=context)),
        ("tls-certificate", lambda: check_tls(final_url, args.timeout)),
        ("tls-protocols", lambda: check_legacy_tls(final_url, args.timeout)),
        ("caa", lambda: check_caa(final_url, args.timeout)),
        ("security-txt", lambda: check_security_txt(final_url, args.timeout, context=context)),
        ("spf", lambda: check_spf(final_url, args.timeout)),
        ("dmarc", lambda: check_dmarc(final_url, args.timeout)),
        ("dkim", lambda: check_dkim(final_url, args.timeout, args.dkim_selector)),
        ("https-redirect", lambda: transport.check_https_redirect(
            http_url, fetch.fetch_final_url(http_url, args.timeout, context=context))),
    ]
    # The status goes first: when it is an error page, every finding below describes that page.
    findings = [transport.check_status(status)] if wanted("http-status") else []
    findings += [f for f in headers.run(response_headers) if wanted(f.check)]
    findings += [run() for name, run in later if wanted(name)]
    return {"url": final_url, "status": status, "findings": findings, "note": None}, exit_code(findings, args.fail_on)


def exit_code(findings, fail_on):
    """1 if any finding is at or above the --fail-on level, else 0.

    With --fail-on warn, findings reported as skipped (a check that could not
    run, e.g. without the optional DNS extra) do not count: they say nothing
    about the site.
    """
    levels = {FAIL} if fail_on == "fail" else {FAIL, WARN}
    failing = any(f.status in levels and not f.detail.startswith(SKIPPED_PREFIX) for f in findings)
    return 1 if failing else 0
