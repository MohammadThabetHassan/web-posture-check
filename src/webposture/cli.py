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
    output.report(args.format, results, single=len(targets) == 1)
    # The worst outcome wins: 2 (a target could not be reached) over 1 (a FAIL) over 0.
    return max(codes)


if __name__ == "__main__":
    sys.exit(main())
