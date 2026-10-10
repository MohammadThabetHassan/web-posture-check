"""HTTP requests: fetching a target, following redirects, retrying, explaining failures.

Every function that makes an HTTPS request takes an optional `context`. None
means the default, verifying TLS context. Only a target whose certificate has
already failed, scanned with --insecure, is given an unverified one, and it is
passed explicitly so it can never leak into another target's requests.
"""

import socket
import ssl
import time
import urllib.error
import urllib.request

from . import __version__

USER_AGENT = f"web-posture-check/{__version__}"

# A short pause gives a rate limiter or a busy server a moment before the retry.
RETRY_DELAY_SECONDS = 1.0


def unverified_context():
    """A TLS context that skips certificate verification, for --insecure only."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def fetch_headers(url, timeout, extra_headers=None, context=None):
    """Return (final URL, headers dict, list of Set-Cookie values, HTTP status).

    Set-Cookie is returned separately because a response can carry several,
    and folding headers into a dict keeps only one of them.
    """
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT, **(extra_headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.geturl(), dict(response.headers.items()), response.headers.get_all("Set-Cookie") or [], response.status
    except urllib.error.HTTPError as err:
        # Error pages still carry the site's headers, so check them anyway.
        return err.geturl(), dict(err.headers.items()), err.headers.get_all("Set-Cookie") or [], err.code


def fetch_text(url, timeout, limit, context=None):
    """Return (status, content type, body) for a small text resource; status is None if nothing answered."""
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            # Cap the read so a huge page cannot stall the run.
            body = response.read(limit).decode("utf-8", errors="replace")
            return response.status, response.headers.get("Content-Type"), body
    except urllib.error.HTTPError as err:
        return err.code, err.headers.get("Content-Type"), ""
    except (urllib.error.URLError, OSError):
        return None, None, ""


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    """Remember the last redirect target, so it is known even if fetching it fails."""

    def __init__(self):
        super().__init__()
        self.last_url = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.last_url = newurl
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_final_url(url, timeout, context=None):
    """Follow redirects from url and return where they end, or None if nothing answered."""
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    recorder = _RedirectRecorder()
    opener = urllib.request.build_opener(recorder, urllib.request.HTTPSHandler(context=context))
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


def _reason(err):
    return getattr(err, "reason", err)


def is_transient(err):
    """Timeouts and dropped connections often succeed on a second try; DNS and TLS errors do not."""
    reason = _reason(err)
    return isinstance(reason, (socket.timeout, TimeoutError, ConnectionResetError, ConnectionAbortedError))


def fetch_with_retries(url, timeout, retries, context=None):
    """fetch_headers, retried up to `retries` more times after a transient failure."""
    for attempt in range(retries + 1):
        try:
            return fetch_headers(url, timeout, context=context)
        except (urllib.error.URLError, OSError) as err:
            if attempt == retries or not is_transient(err):
                raise
            time.sleep(RETRY_DELAY_SECONDS)


def describe_fetch_error(url, err, timeout, attempts):
    """A plain-language reason for why the target could not be fetched."""
    reason = _reason(err)
    tries = f"{attempts} attempt{'s' if attempts != 1 else ''}"
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return f"{url} did not respond within {timeout:g}s ({tries}); the site may be down or slow, try a larger --timeout"
    if isinstance(reason, (ConnectionResetError, ConnectionAbortedError)):
        return f"{url} closed the connection ({tries}); this is often rate limiting or a firewall"
    return f"could not fetch {url}: {reason}"
