"""Cookie flag checks.

Takes the raw Set-Cookie header values (a response can carry several, so they
must not be folded into one) and returns a Finding. No network access.

Cookies are often set on a redirect (a login, or www. to the bare domain), and
those count too: the fetch collects the Set-Cookie headers of every response in
the redirect chain, each with the URL that sent it.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import NamedTuple
from urllib.parse import urlsplit

from .findings import FAIL, PASS, WARN, Finding

_RANK = {PASS: 0, WARN: 1, FAIL: 2}


class SetCookie(NamedTuple):
    """One Set-Cookie header value and the response that sent it."""

    value: str
    # The URL of the response that carried the header; its scheme decides whether Secure is required.
    url: str
    # True when that response was a redirect rather than the final page.
    redirect: bool = False


def parse_set_cookie(value: str) -> tuple[str, dict[str, str]]:
    """Return (name, attributes) where attributes maps lower-cased names to values."""
    # RFC 6265 section 5.2 trims only spaces and tabs (WSP); "Secure\xa0" is not Secure.
    parts = [p.strip(" \t") for p in value.split(";")]
    name = parts[0].split("=", 1)[0].strip(" \t")
    attributes = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, attr_value = part.partition("=")
        attributes[key.strip(" \t").lower()] = attr_value.strip(" \t")
    return name, attributes


def _prefix_violations(name: str, attributes: dict[str, str]) -> list[str]:
    """Return the rules a __Host- or __Secure- cookie breaks, or [] if none.

    Browsers drop such cookies outright, so a broken prefix means the cookie
    never gets set. Prefixes are matched case-insensitively, as current
    browsers do (draft-ietf-httpbis-rfc6265bis).
    """
    lower = name.lower()
    violations = []
    if lower.startswith("__host-"):
        if "secure" not in attributes:
            violations.append("Secure")
        if attributes.get("path") != "/":
            violations.append("Path=/")
        # An empty Domain= is ignored by browsers (RFC 6265, section 5.2.3),
        # so only a Domain with a value breaks the __Host- rule.
        if attributes.get("domain"):
            violations.append("no Domain")
    elif lower.startswith("__secure-") and "secure" not in attributes:
        violations.append("Secure")
    return violations


def _problems(name: str, attributes: dict[str, str], is_https: bool) -> list[tuple[str, str]]:
    """Return a list of (status, message) for one cookie."""
    problems = []
    samesite = attributes.get("samesite")
    violations = _prefix_violations(name, attributes)
    if violations:
        prefix = name.split("-", 1)[0] + "-"
        problems.append((FAIL, f"{prefix} prefix requires " + ", ".join(violations) + " (browsers reject it)"))
    if "secure" not in attributes and "Secure" not in violations:
        if samesite is not None and samesite.lower() == "none":
            # Browsers reject SameSite=None without Secure, so the cookie is dropped.
            problems.append((FAIL, "SameSite=None without Secure (browsers reject it)"))
        elif is_https:
            problems.append((FAIL, "missing Secure"))
    if "httponly" not in attributes:
        problems.append((WARN, "missing HttpOnly"))
    if samesite is None:
        problems.append((WARN, "missing SameSite"))
    return problems


def is_deletion(attributes: dict[str, str], now: datetime) -> bool:
    """True when the Set-Cookie only removes a cookie (Max-Age <= 0 or Expires in the past).

    Sites clear cookies this way, often without repeating the flags, and the
    browser discards the cookie, so there is nothing to protect.
    Max-Age takes precedence over Expires (RFC 6265, section 5.3).
    """
    # A Max-Age that is not a whole number (optionally signed, as Chrome accepts "+0") is ignored.
    if re.fullmatch(r"[+-]?[0-9]+", attributes.get("max-age", "")):
        return int(attributes["max-age"]) <= 0
    if "expires" in attributes:
        try:
            expires = parsedate_to_datetime(attributes["expires"])
        except (TypeError, ValueError, IndexError):
            return False
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires <= now
    return False


def _default_path(url: str) -> str:
    """RFC 6265 section 5.1.4: the directory of the request path (/account/login -> /account)."""
    path = urlsplit(url).path
    if not path.startswith("/") or path.count("/") == 1:
        return "/"
    return path[:path.rindex("/")]


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _domain_match(host: str, domain: str) -> bool:
    """RFC 6265 section 5.1.3: host is domain, or a name under it (never for an IP address)."""
    return host == domain or (host.endswith("." + domain) and not _is_ip(host))


def secure_origin(url: str) -> bool:
    """Whether browsers treat url as a secure origin for Secure cookies: https://, or a loopback host
    (localhost, *.localhost, 127.0.0.0/8, ::1), which Chrome and Firefox trust over plain HTTP too."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme == "https" or host == "localhost" or host.endswith(".localhost"):
        return True
    return _is_ip(host) and ipaddress.ip_address(host).is_loopback


def _path_match(path: str, cookie_path: str) -> bool:
    """RFC 6265 section 5.1.4."""
    return path == cookie_path or (path.startswith(cookie_path) and (cookie_path.endswith("/") or path[len(cookie_path)] == "/"))


def cookie_key(name: str, attributes: dict[str, str], url: str = "") -> tuple[str, str, bool, str] | None:
    """How a browser's cookie store identifies a cookie: (name, domain, host-only, path).

    The domain is the Domain attribute (lower case, one leading dot removed),
    or else the host that set the cookie, which makes it host-only. The path is
    the Path attribute if it starts with "/", or else the default path of the URL
    that set it (RFC 6265 sections 5.2.3, 5.2.4 and 5.3; host-only is part of
    the identity in RFC 6265bis and in browsers). url is "" when unknown.

    None when the browser rejects the cookie because its Domain does not cover
    the host that set it (section 5.3, step 6). An IP address can set a Domain
    of itself only, which browsers then treat as host-only.
    """
    domain = attributes.get("domain", "").lower()
    domain = domain[1:] if domain.startswith(".") else domain
    host = (urlsplit(url).hostname or "") if url else ""
    if domain and host:
        if domain == host and _is_ip(host):
            domain = ""
        elif not _domain_match(host, domain):
            return None
    path = attributes.get("path", "")
    if not path.startswith("/"):
        path = _default_path(url) if url else "/"
    return name, domain or host, not domain, path


def _overwrites_secure(key: tuple[str, str, bool, str], jar: dict[tuple[str, str, bool, str], tuple[str, dict[str, str], bool, str | None]],
                       now: datetime) -> bool:
    """True when a cookie from plain HTTP would replace a live Secure cookie (RFC 6265bis, section 5.7)."""
    name, domain, _, path = key
    for (other_name, other_domain, _, other_path), (_, attributes, _, _) in jar.items():
        if (other_name == name and "secure" in attributes and not is_deletion(attributes, now)
                and (_domain_match(domain, other_domain) or _domain_match(other_domain, domain))
                and _path_match(path, other_path)):
            return True
    return False


def check_cookies(set_cookies: Sequence[str | SetCookie], is_https: bool, now: datetime | None = None) -> Finding:
    """Check every cookie the response chain leaves in the browser.

    set_cookies are SetCookie entries, or plain Set-Cookie values sent by the
    final response, whose scheme is_https gives. A later Set-Cookie for the same
    cookie (cookie_key) replaces an earlier one, as in a browser's cookie store
    (RFC 6265 section 5.3, step 11), so a cookie set on a redirect and deleted or
    re-set by the final page is judged by its last version, while a cookie of the
    same name set by another host or for another path is a cookie of its own.

    A Set-Cookie the browser rejects changes nothing: a Domain that does not
    cover the host that sent it, a Secure cookie sent over plain HTTP, or a
    cookie from plain HTTP that would replace a Secure one (RFC 6265bis; plain
    HTTP to a loopback host counts as secure, as in browsers).
    """
    now = now or datetime.now(timezone.utc)
    jar: dict[tuple[str, str, bool, str], tuple[str, dict[str, str], bool, str | None]] = {}
    for item in set_cookies:
        if isinstance(item, SetCookie):
            value, url, https, via = item.value, item.url, urlsplit(item.url).scheme == "https", item.url if item.redirect else None
            trusted = secure_origin(item.url)
        else:
            value, url, https, via, trusted = item, "", is_https, None, is_https
        name, attributes = parse_set_cookie(value)
        key = cookie_key(name, attributes, url)
        if key is None or (not trusted and ("secure" in attributes or _overwrites_secure(key, jar, now))):
            continue
        jar.pop(key, None)  # keep the report in the order of the last write
        jar[key] = (name, attributes, https, via)
    live = [entry for entry in jar.values() if not is_deletion(entry[1], now)]
    deletions = len(jar) - len(live)
    suffix = f" ({deletions} deletion(s) ignored)" if deletions else ""
    if not live:
        return Finding("cookies", PASS, "no cookies set" + suffix)
    status = PASS
    notes = []
    for name, attributes, https, via in live:
        problems = _problems(name, attributes, https)
        if problems:
            label = f"{name} (set by the redirect at {via})" if via else name
            notes.append(f"{label}: " + ", ".join(msg for _, msg in problems))
            status = max([status] + [s for s, _ in problems], key=lambda s: _RANK[s])
    if not notes:
        return Finding("cookies", PASS, f"{len(live)} cookie(s), no flag problems found" + suffix)
    return Finding("cookies", status, "; ".join(notes))
