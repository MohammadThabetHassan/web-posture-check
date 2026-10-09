import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import __version__, caa, cookies, cors, emailauth, headers, markdown, score, securitytxt, tls, transport
from .findings import FAIL, WARN, SKIPPED_PREFIX, Finding

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


# Every check name, in report order. Header check names come from the
# headers module itself so the list cannot drift from it.
HEADER_CHECKS = [f.check for f in headers.run({})]
ALL_CHECKS = (["http-status"] + HEADER_CHECKS
              + ["cookies", "cors", "tls-certificate", "tls-protocols", "caa",
                 "security-txt", "spf", "dmarc", "dkim", "https-redirect"])


def parse_check_names(value):
    """argparse type for --only/--skip: comma-separated check names, validated."""
    names = [n.strip() for n in value.split(",") if n.strip()]
    unknown = [n for n in names if n not in ALL_CHECKS]
    if unknown or not names:
        problem = f"unknown check name(s): {', '.join(unknown)}" if unknown else "no check names given"
        raise argparse.ArgumentTypeError(f"{problem}; valid names: {', '.join(ALL_CHECKS)}")
    return names


def read_targets_file(path):
    """One target per line; blank lines and lines starting with # are ignored."""
    with open(path, encoding="utf-8") as handle:
        lines = [line.strip() for line in handle]
    return [line for line in lines if line and not line.startswith("#")]


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="web-posture-check",
        description="Check a website's security posture: security headers, cookies, CORS, TLS, "
                    "security.txt, DNS (CAA, SPF, DMARC, DKIM) and the HTTPS redirect.",
    )
    parser.add_argument("targets", nargs="*", metavar="target",
                        help="domain or URL, e.g. example.com or https://example.com/login (several allowed)")
    parser.add_argument("--targets-file", metavar="FILE",
                        help="read more targets from FILE, one per line (# starts a comment)")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--format", choices=("text", "json", "markdown"), default="text",
                        help="output format (default text); markdown is a table for tickets and pull requests")
    output.add_argument("--json", action="store_const", const="json", dest="format",
                        help="same as --format json")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default 10)")
    parser.add_argument("--fail-on", choices=("fail", "warn"), default="fail",
                        help="exit 1 on any FAIL (default), or with 'warn' on any WARN or FAIL")
    parser.add_argument("--dkim-selector", action="append", metavar="SELECTOR",
                        help="DKIM selector to check (repeatable); by default common selectors are tried")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--only", type=parse_check_names, metavar="NAMES",
                           help="run only these checks (comma-separated names, e.g. tls-certificate,caa)")
    selection.add_argument("--skip", type=parse_check_names, metavar="NAMES",
                           help="run every check except these (comma-separated names)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    targets = list(args.targets)
    if args.targets_file:
        try:
            targets += read_targets_file(args.targets_file)
        except OSError as err:
            parser.error(f"could not read --targets-file: {err}")
    if not targets:
        parser.error("give at least one target, or --targets-file")

    results, codes = [], []
    for target in targets:
        result, code = scan(target, args)
        codes.append(code)
        if result is not None:
            results.append(result)
    report(args, results, single=len(targets) == 1)
    # The worst outcome wins: 2 (a target could not be reached) over 1 (a FAIL) over 0.
    return max(codes)


def scan(target, args):
    """Run the selected checks on one target. Returns (result or None, exit code)."""

    def wanted(name):
        if args.only is not None:
            return name in args.only
        return args.skip is None or name not in args.skip

    url = normalise_target(target)
    try:
        final_url, response_headers, set_cookies, status = fetch_headers(url, args.timeout)
    except (urllib.error.URLError, OSError) as err:
        reason = getattr(err, "reason", err)
        if isinstance(reason, ssl.SSLCertVerificationError):
            # A broken certificate is itself the most important finding, so
            # report it instead of aborting. Without a trusted connection there
            # is no response to run the other checks on.
            finding = tls.check_certificate(None, reason.verify_code, reason.verify_message, now=datetime.now(timezone.utc))
            return {"url": url, "status": None, "findings": [finding],
                    "note": "other checks skipped: no trusted HTTPS connection"}, 1
        print(f"error: could not fetch {url}: {err}", file=sys.stderr)
        return None, 2

    # Checks that need their own requests are wrapped in lambdas, so a check
    # left out with --only/--skip never touches the network.
    http_url = transport.http_url_for(url)
    later = [
        ("cookies", lambda: cookies.check_cookies(set_cookies, final_url.startswith("https://"))),
        ("cors", lambda: probe_cors(final_url, args.timeout)),
        ("tls-certificate", lambda: check_tls(final_url, args.timeout)),
        ("tls-protocols", lambda: check_legacy_tls(final_url, args.timeout)),
        ("caa", lambda: check_caa(final_url, args.timeout)),
        ("security-txt", lambda: check_security_txt(final_url, args.timeout)),
        ("spf", lambda: check_spf(final_url, args.timeout)),
        ("dmarc", lambda: check_dmarc(final_url, args.timeout)),
        ("dkim", lambda: check_dkim(final_url, args.timeout, args.dkim_selector)),
        ("https-redirect", lambda: transport.check_https_redirect(http_url, fetch_final_url(http_url, args.timeout))),
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


def to_json(result):
    data = {"url": result["url"], "status": result["status"], "findings": [f.to_dict() for f in result["findings"]]}
    result_score = score.compute(result["findings"])
    if result_score:
        data["score"], data["grade"] = result_score
    if result["note"]:
        data["note"] = result["note"]
    return data


def to_text(result):
    status = result["status"]
    lines = [f"Target: {result['url']} ({f'HTTP {status}' if status is not None else 'no HTTP response'})"]
    result_score = score.compute(result["findings"])
    if result_score:
        lines.append(f"Score: {result_score[0]}/100 (grade {result_score[1]})")
    lines += [f"  [{f.status:4}] {f.check}: {f.detail}" for f in result["findings"]]
    if result["note"]:
        lines.append(f"  ({result['note']})")
    return "\n".join(lines)


def report(args, results, single):
    """Print every result. With one target the output is exactly as before."""
    if args.format == "json":
        if single:
            if results:
                print(json.dumps(to_json(results[0]), indent=2))
        else:
            print(json.dumps({"results": [to_json(r) for r in results]}, indent=2))
        return
    if args.format == "markdown":
        now = datetime.now(timezone.utc)
        print("\n".join(markdown.render(r["url"], r["status"], r["findings"], __version__, now, note=r["note"],
                                         score=score.compute(r["findings"])) for r in results), end="")
        return
    if results:
        print("\n\n".join(to_text(r) for r in results))


if __name__ == "__main__":
    sys.exit(main())
