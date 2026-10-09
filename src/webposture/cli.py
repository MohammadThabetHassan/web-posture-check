import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import __version__, caa, cookies, cors, emailauth, headers, securitytxt, tls, transport
from .findings import FAIL, WARN, Finding

USER_AGENT = f"web-posture-check/{__version__}"


def fetch_headers(url, timeout, extra_headers=None):
    """Return (final URL, headers dict, list of Set-Cookie values, HTTP status).

    Set-Cookie is returned separately because a response can carry several,
    and folding headers into a dict keeps only one of them.
    """
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT, **(extra_headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.geturl(), dict(response.headers.items()), response.headers.get_all("Set-Cookie") or [], response.status
    except urllib.error.HTTPError as err:
        # Error pages still carry the site's headers, so check them anyway.
        return err.geturl(), dict(err.headers.items()), err.headers.get_all("Set-Cookie") or [], err.code


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    """Remember the last redirect target, so it is known even if fetching it fails."""

    def __init__(self):
        super().__init__()
        self.last_url = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.last_url = newurl
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_final_url(url, timeout):
    """Follow redirects from url and return where they end, or None if nothing answered."""
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    recorder = _RedirectRecorder()
    opener = urllib.request.build_opener(recorder)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.geturl()
    except urllib.error.HTTPError as err:
        # An error page is still a response served at that URL.
        return err.geturl()
    except (urllib.error.URLError, OSError):
        # The server answered with a redirect but the target failed, e.g. an
        # https:// URL with a broken certificate. The redirect still happened,
        # so report where it pointed rather than "not reachable".
        return recorder.last_url


def probe_cors(url, timeout):
    """Request url as if from a foreign origin and check what CORS allows."""
    try:
        _, probe_headers, _, _ = fetch_headers(url, timeout, {"Origin": cors.PROBE_ORIGIN})
    except (urllib.error.URLError, OSError) as err:
        return Finding("cors", WARN, f"could not run the CORS probe: {err}")
    lowered = {k.lower(): v for k, v in probe_headers.items()}
    return cors.check_cors(lowered.get("access-control-allow-origin"), lowered.get("access-control-allow-credentials"))


def check_tls(url, timeout):
    """Check the certificate of the host that served the final URL."""
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


def check_security_txt(url, timeout):
    """Fetch /.well-known/security.txt from the final URL's origin and check it."""
    parts = urlsplit(url)
    txt_url = f"{parts.scheme}://{parts.netloc}{securitytxt.PATH}"
    request = urllib.request.Request(txt_url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # A real security.txt is a few KB; cap the read so a huge page cannot stall the run.
            body = response.read(64 * 1024).decode("utf-8", errors="replace")
            status, content_type = response.status, response.headers.get("Content-Type")
    except urllib.error.HTTPError as err:
        status, content_type, body = err.code, err.headers.get("Content-Type"), ""
    except (urllib.error.URLError, OSError):
        status, content_type, body = None, None, ""
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


def normalise_target(target):
    if "://" not in target:
        target = "https://" + target
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="web-posture-check",
        description="Check a website's security posture: security headers, cookies, CORS, TLS, "
                    "security.txt, DNS (CAA, SPF, DMARC, DKIM) and the HTTPS redirect.",
    )
    parser.add_argument("target", help="domain or URL, e.g. example.com or https://example.com/login")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default 10)")
    parser.add_argument("--dkim-selector", action="append", metavar="SELECTOR",
                        help="DKIM selector to check (repeatable); by default common selectors are tried")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    url = normalise_target(args.target)
    try:
        final_url, response_headers, set_cookies, status = fetch_headers(url, args.timeout)
    except (urllib.error.URLError, OSError) as err:
        reason = getattr(err, "reason", err)
        if isinstance(reason, ssl.SSLCertVerificationError):
            # A broken certificate is itself the most important finding, so
            # report it instead of aborting. Without a trusted connection there
            # is no response to run the other checks on.
            finding = tls.check_certificate(None, reason.verify_code, reason.verify_message, now=datetime.now(timezone.utc))
            report(args, url, None, [finding], note="other checks skipped: no trusted HTTPS connection")
            return 1
        print(f"error: could not fetch {url}: {err}", file=sys.stderr)
        return 2

    # The status goes first: when it is an error page, every finding below describes that page.
    findings = [transport.check_status(status)]
    findings += headers.run(response_headers)
    findings.append(cookies.check_cookies(set_cookies, final_url.startswith("https://")))
    findings.append(probe_cors(final_url, args.timeout))
    findings.append(check_tls(final_url, args.timeout))
    findings.append(check_legacy_tls(final_url, args.timeout))
    findings.append(check_caa(final_url, args.timeout))
    findings.append(check_security_txt(final_url, args.timeout))
    findings.append(check_spf(final_url, args.timeout))
    findings.append(check_dmarc(final_url, args.timeout))
    findings.append(check_dkim(final_url, args.timeout, args.dkim_selector))
    http_url = transport.http_url_for(url)
    findings.append(transport.check_https_redirect(http_url, fetch_final_url(http_url, args.timeout)))

    report(args, final_url, status, findings)
    return 1 if any(f.status == FAIL for f in findings) else 0


def report(args, url, status, findings, note=None):
    if args.json:
        result = {"url": url, "status": status, "findings": [f.to_dict() for f in findings]}
        if note:
            result["note"] = note
        print(json.dumps(result, indent=2))
        return
    print(f"Target: {url} ({f'HTTP {status}' if status is not None else 'no HTTP response'})")
    for f in findings:
        print(f"  [{f.status:4}] {f.check}: {f.detail}")
    if note:
        print(f"  ({note})")


if __name__ == "__main__":
    sys.exit(main())
