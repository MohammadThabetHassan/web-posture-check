"""Transport checks: is the site only reachable over HTTPS, and did it answer normally?

The check functions take request results (a final URL or a status code) and
return a Finding, so they can be tested without network access.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from .findings import FAIL, PASS, WARN, Finding


def http_url_for(url: str) -> str:
    """Return the http:// version of a URL, keeping host, path and query.

    For an https:// URL an explicit port is dropped, because it belongs to the
    HTTPS service and plain HTTP is expected on the default port. For an
    http:// URL the port is kept: that port is where plain HTTP is served, and
    dropping it would probe port 80 instead and could wrongly report
    "not reachable".
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        # An IPv6 literal must keep its brackets, or the rebuilt URL is
        # malformed and the plain-HTTP request silently fails.
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        # A non-numeric or out-of-range port cannot be probed; fall back to the
        # default port instead of raising.
        port = None
    if parts.scheme == "http" and port:
        host = f"{host}:{port}"
    return urlunsplit(("http", host, parts.path or "/", parts.query, ""))


def check_https_redirect(http_url: str, final_url: str | None) -> Finding:
    """Check where a request to http_url ended up after following redirects.

    final_url is None when nothing answered on plain HTTP (connection refused
    or timed out), which is acceptable: no content is served without TLS.
    """
    if final_url is None:
        return Finding("https-redirect", PASS, f"{http_url} is not reachable, nothing is served over plain HTTP")
    scheme = urlsplit(final_url).scheme.lower()
    if scheme == "https":
        return Finding("https-redirect", PASS, f"{http_url} redirects to {final_url}")
    if scheme == "http":
        if final_url.rstrip("/") == http_url.rstrip("/"):
            return Finding("https-redirect", FAIL, f"{http_url} is served over plain HTTP without redirecting to HTTPS")
        return Finding("https-redirect", FAIL, f"{http_url} redirects to {final_url}, which is still plain HTTP")
    return Finding("https-redirect", FAIL, f"{http_url} redirects to {final_url}, which is not HTTPS")


def check_status(status: int) -> Finding:
    """Flag an error response, because every other check then describes the error page.

    Bot protection often answers unknown clients with 403 or 429 while browsers
    get the real page, so the header results may not match what users receive.
    """
    if status < 400:
        return Finding("http-status", PASS, f"final response is HTTP {status}")
    hint = " (often bot protection blocking automated clients)" if status in (403, 429, 503) else ""
    return Finding("http-status", WARN, f"final response is HTTP {status}{hint}; the other findings describe this error page, not the site's normal pages")
