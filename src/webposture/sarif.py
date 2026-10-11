"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF viewers.

render takes the scan results and returns a SARIF log as a dict; it does no
I/O, so it can be tested directly.

- Every check is a rule, listed in report order, so rule indexes stay stable.
- FAIL becomes level "error" and WARN "warning". PASS and skipped findings
  are not results: SARIF lists problems, and code scanning closes an alert
  when its result stops appearing.
- A website has no file or line, but code scanning needs a location in the
  repository for every result and rejects "https:" URIs. The location is
  the URL's host and path as a relative path ("example.com/login"), or
  with --sarif-location a real file, such as the workflow that runs the
  scan. The full URL is always kept as a logical location.
- partialFingerprints use the check and the URL, not the detail text, which
  can change from run to run (for example days until a certificate expires),
  so a problem stays one alert across runs.
- Targets that could not be scanned are reported as tool execution
  notifications, and the invocation is marked as not successful.
"""

import hashlib
import posixpath
from typing import Any
from urllib.parse import quote, urlsplit

from . import __version__
from .findings import FAIL, SKIPPED_PREFIX, WARN

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/MohammadThabetHassan/web-posture-check"
LEVELS = {FAIL: "error", WARN: "warning"}


def _rule(name, summary):
    return {
        "id": name,
        "shortDescription": {"text": f"{name}: {summary}"},
        "fullDescription": {"text": f"web-posture-check rule {name}: {summary}."},
        "helpUri": f"{INFORMATION_URI}#checks",
        "help": {
            "text": f"{summary}. See {INFORMATION_URI}#checks for when this check fails or warns.",
            "markdown": f"{summary}. See [the check reference]({INFORMATION_URI}#checks) for when this check fails or warns.",
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "web-posture"]},
    }


def artifact_uri(url):
    """The URL's host, port and path as a relative URI: https://example.com:8443/a -> example.com%3A8443/a.

    The colon is encoded, since "host:port/..." would otherwise read as a URI scheme.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host += f":{parts.port}"
    path = parts.path.rstrip("/")
    return quote(host + path, safe="/%-._~!$&'()*+,;=@")


def anchor_uri(path):
    """A repository file path as a relative URI: / separators, no ./ segments, percent-encoded.

    --sarif-location takes a path, not a URI, so a space or a % in it is
    encoded, and Windows separators become / as in every repository path.
    """
    return quote(posixpath.normpath(path.replace("\\", "/")), safe="/-._~!$&'()*+,;=@")


def _location(url, anchor):
    physical = {"artifactLocation": {"uri": anchor_uri(anchor)}, "region": {"startLine": 1}} if anchor \
        else {"artifactLocation": {"uri": artifact_uri(url)}}
    return {"physicalLocation": physical, "logicalLocations": [{"fullyQualifiedName": url, "kind": "resource"}]}


def _fingerprint(check, url):
    return hashlib.sha256(f"{check}\n{url}".encode()).hexdigest()


def render(results, checks, summaries, errors=(), anchor=None):
    """Return a SARIF log (a dict) for results.

    checks is every check name in report order and summaries maps each name
    to its one-line description. errors are messages for targets that could
    not be scanned. anchor, if given, is a repository file every result
    points to instead of a path made from the URL.
    """
    index = {name: i for i, name in enumerate(checks)}
    sarif_results = []
    for result in results:
        for finding in result["findings"]:
            if finding.status not in LEVELS or finding.detail.startswith(SKIPPED_PREFIX):
                continue
            sarif_results.append({
                "ruleId": finding.check,
                "ruleIndex": index[finding.check],
                "level": LEVELS[finding.status],
                "message": {"text": f"{finding.check}: {finding.detail} ({result['url']})"},
                "locations": [_location(result["url"], anchor)],
                "partialFingerprints": {"webPostureCheck/v1": _fingerprint(finding.check, result["url"])},
            })
    invocation: dict[str, Any] = {"executionSuccessful": not errors}
    if errors:
        invocation["toolExecutionNotifications"] = [
            {"level": "error", "message": {"text": message}} for message in errors
        ]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "web-posture-check",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFORMATION_URI,
                "rules": [_rule(name, summaries[name]) for name in checks],
            }},
            "invocations": [invocation],
            "results": sarif_results,
        }],
    }
