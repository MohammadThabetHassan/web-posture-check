"""HTTP requests: fetching a target, following redirects, retrying, explaining failures.

Every function that makes an HTTPS request takes an optional `context`. None
means the default, verifying TLS context. Only a target whose certificate has
already failed, scanned with --insecure, is given an unverified one, and it is
passed explicitly so it can never leak into another target's requests.

Requests only ever use http:// and https://. The opener is built from the HTTP
handlers alone, so a target or a redirect can never make the tool read a local
file:// path or speak FTP to an address a server chose.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import time
import urllib.error
import urllib.request
from email.message import Message
from typing import IO, Any, NamedTuple
from urllib.parse import urljoin, urlsplit

from . import __version__
from .cookies import SetCookie
from .headermap import HeaderMap

USER_AGENT = f"web-posture-check/{__version__}"

# A short pause gives a rate limiter or a busy server a moment before the retry.
RETRY_DELAY_SECONDS = 1.0

# Every way a request can fail: refused, timed out, reset, a TLS or DNS error
# (URLError and OSError), a malformed response (HTTPException) or a URL or host
# name urllib cannot use (ValueError, which includes IDNA errors).
FETCH_ERRORS = (urllib.error.URLError, OSError, http.client.HTTPException, ValueError)

# The ones that mean something answered, but not with a response that can be
# read: a malformed status line or header block, or a Location that is not a URL.
UNREADABLE = (http.client.HTTPException, ValueError)

_SCHEMES = ("http", "https")


class FetchResult(NamedTuple):
    """The final response after redirects. A NamedTuple, so it also unpacks as (url, headers, cookies, status)."""

    url: str
    headers: HeaderMap
    # Every Set-Cookie of the redirect chain, in order, each with the URL that sent it.
    cookies: list[SetCookie]
    status: int


def unverified_context() -> ssl.SSLContext:
    """A TLS context that skips certificate verification, for --insecure only."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class _Recorder(urllib.request.HTTPRedirectHandler):
    """Follows redirects, remembering where they pointed and the cookies each one set.

    A redirect to anything but http:// or https:// is refused: browsers do not
    follow it, and the tool must not make the requests a server asks for there.
    The check runs before urllib's own, which would still follow ftp://.
    """

    def __init__(self) -> None:
        super().__init__()
        self.last_url: str | None = None
        self.cookies: list[SetCookie] = []
        # The URL of a redirect that was refused because it is not http(s), if any.
        self.refused: str | None = None

    def redirect_request(self, req: urllib.request.Request, fp: IO[bytes], code: int, msg: str,
                         headers: http.client.HTTPMessage, newurl: str) -> urllib.request.Request | None:
        # Python 3.9 and 3.10 do not follow 308 (3.11 does). RFC 9110 defines it
        # like 307 with the method kept, which for these GET requests is the same.
        return super().redirect_request(req, fp, 307 if code == 308 else code, msg, headers, newurl)

    def http_error_302(self, req: urllib.request.Request, fp: IO[bytes], code: int, msg: str,
                       headers: http.client.HTTPMessage) -> Any:
        self.cookies += [SetCookie(value, req.full_url, redirect=True) for value in headers.get_all("Set-Cookie") or []]
        location = headers.get("Location") or headers.get("URI")
        if location:
            newurl = urljoin(req.full_url, location.strip())
            self.last_url = newurl
            if urlsplit(newurl).scheme.lower() not in _SCHEMES:
                self.refused = newurl
                raise urllib.error.HTTPError(req.full_url, code, f"redirect to {newurl} refused: not an http(s) URL", headers, fp)
        return super().http_error_302(req, fp, code, msg, headers)

    # 301, 303, 307 and 308 go through the same checks (urllib follows 308 from Python 3.11).
    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _opener(recorder: _Recorder, context: ssl.SSLContext | None) -> urllib.request.OpenerDirector:
    """An opener that speaks only HTTP and HTTPS (and honours *_proxy settings)."""
    opener = urllib.request.OpenerDirector()
    for handler in (urllib.request.ProxyHandler(), urllib.request.UnknownHandler(), urllib.request.HTTPHandler(),
                    urllib.request.HTTPSHandler(context=context), urllib.request.HTTPDefaultErrorHandler(),
                    recorder, urllib.request.HTTPErrorProcessor()):
        opener.add_handler(handler)
    return opener


def _request(url: str, extra_headers: dict[str, str] | None = None) -> urllib.request.Request:
    if urlsplit(url).scheme.lower() not in _SCHEMES:
        raise urllib.error.URLError(f"unsupported URL scheme in {url}; only http:// and https:// can be checked")
    return urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT, **(extra_headers or {})})


def _redirect_problem(err: urllib.error.HTTPError, recorder: _Recorder) -> urllib.error.URLError | None:
    """A redirect that went nowhere, as a fetch error; None for an ordinary error response.

    That is a redirect the recorder refused (not http or https), or one urllib
    gave up on (a loop, or more hops than it follows). A 3xx response that is not
    followed, such as a 300 or a 302 without Location, is a normal final response.
    """
    if recorder.refused:
        return urllib.error.URLError(f"redirected to {recorder.refused}, which is not an http(s) URL")
    if str(err.msg).startswith(_Recorder.inf_msg):
        return urllib.error.URLError(f"redirect loop or too many redirects (last: HTTP {err.code} at {err.geturl()})")
    return None


def _result(url: str, headers: Message, status: int, recorder: _Recorder) -> FetchResult:
    final_cookies = [SetCookie(value, url) for value in headers.get_all("Set-Cookie") or []]
    return FetchResult(url, HeaderMap(headers), recorder.cookies + final_cookies, status)


def fetch_headers(url: str, timeout: float, extra_headers: dict[str, str] | None = None,
                  context: ssl.SSLContext | None = None) -> FetchResult:
    """Fetch url, following redirects, and return the final response's URL, headers, cookies and status.

    The body is not read. Raises one of FETCH_ERRORS when nothing usable answered.
    """
    recorder = _Recorder()
    try:
        with _opener(recorder, context).open(_request(url, extra_headers), timeout=timeout) as response:
            return _result(response.geturl(), response.headers, response.status, recorder)
    except urllib.error.HTTPError as err:
        # An HTTPError holds the open response; closing it releases the connection.
        with err:
            problem = _redirect_problem(err, recorder)
            if problem:
                raise problem from err
            # Error pages still carry the site's headers, so check them anyway.
            return _result(err.geturl(), err.headers, err.code, recorder)


def fetch_text(url: str, timeout: float, limit: int, context: ssl.SSLContext | None = None) -> tuple[int | None, str | None, str]:
    """Return (status, content type, body) for a small text resource; status is None if nothing answered."""
    recorder = _Recorder()
    try:
        with _opener(recorder, context).open(_request(url), timeout=timeout) as response:
            # Cap the read so a huge page cannot stall the run.
            body = response.read(limit).decode("utf-8", errors="replace")
            return response.status, response.headers.get("Content-Type"), body
    except urllib.error.HTTPError as err:
        with err:
            if _redirect_problem(err, recorder):
                return None, None, ""
            return err.code, err.headers.get("Content-Type"), ""
    except FETCH_ERRORS:
        return None, None, ""


def fetch_final_url(url: str, timeout: float, context: ssl.SSLContext | None = None) -> str | None:
    """Follow redirects from url and return where they end, or None if nothing answered.

    Raises one of UNREADABLE when a server answered, before any redirect, with a
    response that cannot be read.
    """
    recorder = _Recorder()
    try:
        with _opener(recorder, context).open(_request(url), timeout=timeout) as response:
            return str(response.geturl())
    except urllib.error.HTTPError as err:
        # An error page is still a response served at that URL; a refused or
        # looping redirect still pointed somewhere, which is what is reported.
        with err:
            return recorder.last_url if _redirect_problem(err, recorder) and recorder.last_url else str(err.geturl())
    except OSError:
        # Nothing answered (refused, timed out, closed without a response), or a
        # redirect was followed and its target failed, e.g. an https:// URL with a
        # broken certificate. The redirect still happened, so report where it pointed.
        return recorder.last_url
    except UNREADABLE:
        if recorder.last_url:
            return recorder.last_url
        raise


def _reason(err: BaseException) -> Any:
    return getattr(err, "reason", err)


def is_transient(err: BaseException) -> bool:
    """Timeouts and dropped connections often succeed on a second try; DNS and TLS errors do not."""
    reason = _reason(err)
    return isinstance(reason, (socket.timeout, TimeoutError, ConnectionResetError, ConnectionAbortedError))


def fetch_with_retries(url: str, timeout: float, retries: int, context: ssl.SSLContext | None = None) -> FetchResult:
    """fetch_headers, retried up to `retries` more times after a transient failure."""
    for attempt in range(retries + 1):
        try:
            return fetch_headers(url, timeout, context=context)
        except FETCH_ERRORS as err:
            if attempt == retries or not is_transient(err):
                raise
            time.sleep(RETRY_DELAY_SECONDS)
    raise AssertionError("unreachable: the last attempt returns or raises")  # pragma: no cover


def describe_fetch_error(url: str, err: BaseException, timeout: float, attempts: int) -> str:
    """A plain-language reason for why the target could not be fetched."""
    reason = _reason(err)
    tries = f"{attempts} attempt{'s' if attempts != 1 else ''}"
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return f"{url} did not respond within {timeout:g}s ({tries}); the site may be down or slow, try a larger --timeout"
    if isinstance(reason, (ConnectionResetError, ConnectionAbortedError)):
        return f"{url} closed the connection ({tries}); this is often rate limiting or a firewall"
    if isinstance(reason, http.client.HTTPException):
        # These carry little text of their own (BadStatusLine, IncompleteRead, LineTooLong).
        return f"could not fetch {url}: the server sent a malformed response ({type(reason).__name__}: {str(reason).strip()})"
    return f"could not fetch {url}: {reason or type(reason).__name__}"
