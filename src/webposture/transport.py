"""Transport checks: is the site only reachable over HTTPS?

The check functions take the result of a plain-HTTP request and return a
Finding, so they can be tested without network access.
"""

from urllib.parse import urlsplit, urlunsplit

from .findings import Finding, PASS, FAIL


def http_url_for(url):
    """Return the http:// version of a URL on the default port, keeping host, path and query.

    An explicit port is dropped because it belongs to the HTTPS service.
    """
    parts = urlsplit(url)
    return urlunsplit(("http", parts.hostname or "", parts.path or "/", parts.query, ""))


def check_https_redirect(http_url, final_url):
    """Check where a request to http_url ended up after following redirects.

    final_url is None when nothing answered on plain HTTP (connection refused
    or timed out), which is acceptable: no content is served without TLS.
    """
    if final_url is None:
        return Finding("https-redirect", PASS, f"{http_url} is not reachable, nothing is served over plain HTTP")
    if urlsplit(final_url).scheme == "https":
        return Finding("https-redirect", PASS, f"{http_url} redirects to {final_url}")
    return Finding("https-redirect", FAIL, f"{http_url} is served over plain HTTP without redirecting to HTTPS")
