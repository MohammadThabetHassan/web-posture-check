import argparse
import json
import sys
import urllib.error
import urllib.request

from . import __version__, headers
from .findings import FAIL

USER_AGENT = f"web-posture-check/{__version__}"


def fetch_headers(url, timeout):
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.geturl(), dict(response.headers.items())
    except urllib.error.HTTPError as err:
        # Error pages still carry the site's headers, so check them anyway.
        return err.geturl(), dict(err.headers.items())


def normalise_target(target):
    if "://" not in target:
        target = "https://" + target
    return target


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="web-posture-check",
        description="Check a website's security posture (HTTP security headers).",
    )
    parser.add_argument("target", help="domain or URL, e.g. example.com or https://example.com/login")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds (default 10)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    url = normalise_target(args.target)
    try:
        final_url, response_headers = fetch_headers(url, args.timeout)
    except (urllib.error.URLError, OSError) as err:
        print(f"error: could not fetch {url}: {err}", file=sys.stderr)
        return 2

    findings = headers.run(response_headers)

    if args.json:
        print(json.dumps({"url": final_url, "findings": [f.to_dict() for f in findings]}, indent=2))
    else:
        print(f"Target: {final_url}")
        for f in findings:
            print(f"  [{f.status:4}] {f.check}: {f.detail}")

    return 1 if any(f.status == FAIL for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
