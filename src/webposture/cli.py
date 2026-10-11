"""Command-line entry point: parse arguments, scan every target, print the report.

The work itself lives in fetch (HTTP requests), runner (one target's checks)
and output (text, JSON and Markdown).
"""

import argparse
import math
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from . import __version__, output, runner
from .textsafe import printable

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


# Kept here too for callers that used cli.CHECK_SUMMARIES.
CHECK_SUMMARIES = runner.CHECK_SUMMARIES


ISSUES_URL = "https://github.com/MohammadThabetHassan/web-posture-check/issues"


def positive_seconds(value):
    """argparse type for --timeout: a finite number of seconds above zero."""
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number of seconds") from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be a number of seconds greater than 0")
    return seconds


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
    output_group.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text",
                              help="output format (default text); markdown is a table for tickets and pull requests, "
                                   "sarif is for GitHub code scanning")
    output_group.add_argument("--json", action="store_const", const="json", dest="format",
                              help="same as --format json")
    parser.add_argument("--output", metavar="FILE",
                        help="write the report to FILE (UTF-8) instead of printing it")
    parser.add_argument("--sarif", metavar="FILE",
                        help="also write a SARIF 2.1.0 log to FILE, from the same scan (for GitHub code scanning)")
    parser.add_argument("--sarif-location", metavar="PATH",
                        help="repository file every SARIF result points to, e.g. the workflow that runs the scan "
                             "(default: a path made from the URL, such as example.com/login)")
    parser.add_argument("--list-checks", action="store_true", help="print every check name with a short description and exit")
    parser.add_argument("--timeout", type=positive_seconds, default=10.0, metavar="SECONDS",
                        help="request timeout in seconds, above 0 (default 10)")
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


def write_file(path, text, option):
    """Write text to path as UTF-8; on failure print why and return False."""
    try:
        # UTF-8 whatever the console encoding is (Windows consoles are often not UTF-8).
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except OSError as err:
        print(f"error: could not write {option}: {err}", file=sys.stderr)
        return False
    return True


def scan_safely(target, args):
    """runner.scan, but a bug while scanning one target becomes that target's error, exit code 2.

    Without this, an unexpected exception in one thread would abort every other
    target's report and print a traceback.
    """
    try:
        return runner.scan(target, args)
    except Exception as err:
        return None, 2, f"unexpected error while scanning {target!r}: {type(err).__name__}: {err} (please report it at {ISSUES_URL})"


def display_url(target):
    """The URL a target was scanned as, or the target itself when it is not a valid one."""
    try:
        return runner.normalise_target(target)
    except ValueError:
        return target.strip()


def write_stdout(text):
    """Print the report; if the reader has gone (e.g. piped into head), stop quietly instead of a traceback."""
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:
        # Point stdout at devnull so the interpreter's own flush at exit is quiet too.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)


def exit_now(code):
    """Leave immediately, without waiting for worker threads that cannot be interrupted."""
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_checks:
        width = max(len(name) for name in runner.ALL_CHECKS)
        print("\n".join(f"{name.ljust(width)}  {runner.CHECK_SUMMARIES[name]}" for name in runner.ALL_CHECKS))
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
    pool = ThreadPoolExecutor(max_workers=min(args.jobs, len(targets)))
    try:
        outcomes = list(pool.map(lambda target: scan_safely(target, args), targets))
    except KeyboardInterrupt:
        # Running scans cannot be stopped, and waiting for them could take
        # minutes, so leave at once with the conventional code for Ctrl-C.
        pool.shutdown(wait=False, cancel_futures=True)
        print("interrupted", file=sys.stderr)
        exit_now(130)
    pool.shutdown()
    # Every target gets an entry, in input order; one that could not be scanned carries its error.
    results, codes, errors = [], [], []
    for target, (result, code, error) in zip(targets, outcomes):
        codes.append(code)
        if error:
            errors.append(error)
            print(f"error: {printable(error)}", file=sys.stderr)
            result = output.failed(display_url(target), error) if result is None else {**result, "error": error}
        results.append(result)
    text = output.render(args.format, results, single=len(targets) == 1, errors=errors, sarif_anchor=args.sarif_location)
    if args.sarif and not write_file(args.sarif, output.to_sarif(results, errors, args.sarif_location), "--sarif"):
        return 2
    if args.output:
        if not write_file(args.output, text, "--output"):
            return 2
    else:
        write_stdout(text)
    # The worst outcome wins: 2 (a target could not be reached) over 1 (a FAIL) over 0.
    return max(codes)


if __name__ == "__main__":
    sys.exit(main())
