"""Command-line entry point: parse arguments, scan every target, print the report.

The work itself lives in fetch (HTTP requests), runner (one target's checks)
and output (text, JSON and Markdown).
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__, output, runner

# More than this many simultaneous scans gains little and looks like a flood to the sites.
MAX_JOBS = 16


def parse_check_names(value):
    """argparse type for --only/--skip: comma-separated check names, validated."""
    names = [n.strip() for n in value.split(",") if n.strip()]
    unknown = [n for n in names if n not in runner.ALL_CHECKS]
    if unknown or not names:
        problem = f"unknown check name(s): {', '.join(unknown)}" if unknown else "no check names given"
        raise argparse.ArgumentTypeError(f"{problem}; valid names: {', '.join(runner.ALL_CHECKS)}")
    return names


# One line per check for --list-checks, in report order.
CHECK_SUMMARIES = {
    "http-status": "the final response is not an error page (bot protection, 4xx, 5xx)",
    "hsts": "Strict-Transport-Security max-age, includeSubDomains and preload",
    "csp": "Content-Security-Policy is set and its script policy is not unsafe",
    "x-content-type-options": "X-Content-Type-Options: nosniff",
    "clickjacking": "CSP frame-ancestors or X-Frame-Options",
    "referrer-policy": "Referrer-Policy is set and not unsafe-url",
    "permissions-policy": "Permissions-Policy is set",
    "cross-origin-isolation": "Cross-Origin-Opener, -Resource and -Embedder policies",
    "x-xss-protection": "the legacy XSS auditor is not turned on",
    "information-leakage": "no server version or stack headers",
    "cookies": "Secure, HttpOnly, SameSite and __Host- / __Secure- prefixes",
    "cors": "no credentialed access for any origin (probe request)",
    "tls-certificate": "trusted and not close to expiry",
    "tls-protocols": "TLS 1.0 and 1.1 are refused",
    "caa": "a CAA record limits which CAs may issue",
    "security-txt": "/.well-known/security.txt (RFC 9116)",
    "spf": "a single SPF record that does not allow everyone",
    "dmarc": "a DMARC policy that quarantines or rejects",
    "dkim": "a DKIM key under common or given selectors",
    "https-redirect": "plain HTTP redirects to HTTPS",
}


def read_targets_file(path):
    """One target per line; blank lines and lines starting with # are ignored."""
    with open(path, encoding="utf-8") as handle:
        lines = [line.strip() for line in handle]
    return [line for line in lines if line and not line.startswith("#")]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="web-posture-check",
        description="Check a website's security posture: security headers, cookies, CORS, TLS, "
                    "security.txt, DNS (CAA, SPF, DMARC, DKIM) and the HTTPS redirect.",
    )
    parser.add_argument("targets", nargs="*", metavar="target",
                        help="domain or URL, e.g. example.com or https://example.com/login (several allowed)")
    parser.add_argument("--targets-file", metavar="FILE",
                        help="read more targets from FILE, one per line (# starts a comment)")
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--format", choices=("text", "json", "markdown"), default="text",
                              help="output format (default text); markdown is a table for tickets and pull requests")
    output_group.add_argument("--json", action="store_const", const="json", dest="format",
                              help="same as --format json")
    parser.add_argument("--output", metavar="FILE",
                        help="write the report to FILE (UTF-8) instead of printing it")
    parser.add_argument("--list-checks", action="store_true", help="print every check name with a short description and exit")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default 10)")
    parser.add_argument("--insecure", action="store_true",
                        help="if a target's certificate is not trusted, still run the other checks without verification "
                             "(the certificate is reported as FAIL)")
    parser.add_argument("--retries", type=int, default=1, choices=range(6), metavar="N",
                        help="retry a target's first request up to N times after a timeout or dropped connection (default 1, max 5)")
    parser.add_argument("--jobs", type=int, default=4, choices=range(1, MAX_JOBS + 1), metavar="N",
                        help=f"scan up to N targets at the same time (default 4, max {MAX_JOBS}); results keep the input order")
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
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        width = max(len(name) for name in runner.ALL_CHECKS)
        print("\n".join(f"{name.ljust(width)}  {CHECK_SUMMARIES[name]}" for name in runner.ALL_CHECKS))
        return 0

    targets = list(args.targets)
    if args.targets_file:
        try:
            targets += read_targets_file(args.targets_file)
        except OSError as err:
            parser.error(f"could not read --targets-file: {err}")
    if not targets:
        parser.error("give at least one target, or --targets-file")

    # map() returns the outcomes in input order, however the scans finish.
    with ThreadPoolExecutor(max_workers=min(args.jobs, len(targets))) as pool:
        outcomes = list(pool.map(lambda target: runner.scan(target, args), targets))
    results, codes = [], []
    for result, code, error in outcomes:
        codes.append(code)
        if error:
            print(f"error: {error}", file=sys.stderr)
        if result is not None:
            results.append(result)
    text = output.render(args.format, results, single=len(targets) == 1)
    if args.output:
        try:
            # Written as UTF-8 whatever the console encoding is (Windows consoles are often not UTF-8).
            with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError as err:
            print(f"error: could not write --output: {err}", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(text)
    # The worst outcome wins: 2 (a target could not be reached) over 1 (a FAIL) over 0.
    return max(codes)


if __name__ == "__main__":
    sys.exit(main())
