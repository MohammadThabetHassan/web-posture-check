import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import __version__, cookies, cors, headers, tls, transport
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


def normalise_target(target):
    if "://" not in target:
        target = "https://" + target
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="web-posture-check",
        description="Check a website's security posture (security headers, cookies, CORS and HTTPS redirect).",
    )
    parser.add_argument("target", help="domain or URL, e.g. example.com or https://example.com/login")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default 10)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    url = normalise_target(args.target)
    try:
        final_url, response_headers, set_cookies, status = fetch_headers(url, args.timeout)
    except (urllib.error.URLError, OSError) as err:
        print(f"error: could not fetch {url}: {err}", file=sys.stderr)
        return 2

    # The status goes first: when it is an error page, every finding below describes that page.
    findings = [transport.check_status(status)]
    findings += headers.run(response_headers)
    findings.append(cookies.check_cookies(set_cookies, final_url.startswith("https://")))
    findings.append(probe_cors(final_url, args.timeout))
    findings.append(check_tls(final_url, args.timeout))
    http_url = transport.http_url_for(url)
    findings.append(transport.check_https_redirect(http_url, fetch_final_url(http_url, args.timeout)))

    if args.json:
        print(json.dumps({"url": final_url, "status": status, "findings": [f.to_dict() for f in findings]}, indent=2))
    else:
        print(f"Target: {final_url} (HTTP {status})")
        for f in findings:
            print(f"  [{f.status:4}] {f.check}: {f.detail}")

    return 1 if any(f.status == FAIL for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
