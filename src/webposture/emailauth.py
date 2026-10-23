"""Email authentication checks (SPF, DMARC and DKIM), read from DNS.

The standard library cannot query TXT records, so lookups use the optional
dnspython package (pip install "web-posture-check[dns]"). Without it the check
is reported as skipped. The check_* functions take the TXT strings and need no
network access.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import NamedTuple

from . import publicsuffix
from .findings import FAIL, PASS, SKIPPED_PREFIX, WARN, Finding

INSTALL_HINT = 'install the optional DNS support with: pip install "web-posture-check[dns]"'


def mail_domain(host: str | None) -> str:
    """The domain to check for a web host: www.example.com -> example.com."""
    host = (host or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def spf_records(txt_strings: Iterable[str]) -> list[str]:
    """Return the TXT values that are SPF records (they start with 'v=spf1', RFC 7208 section 4.5)."""
    return [t for t in txt_strings if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


# RFC 7208 section 4.6.4: at most 10 terms that query DNS in one evaluation.
SPF_LOOKUP_LIMIT = 10
_LOOKUP_MECHANISMS = frozenset({"include", "a", "mx", "ptr", "exists"})

# A TXT lookup: name -> (TXT strings, None) or ([], why it failed), as lookup_txt returns.
TxtLookup = Callable[[str], "tuple[list[str], str | None]"]


class SpfLookups(NamedTuple):
    """What counting an SPF record's DNS lookups found."""

    # Terms that query DNS, across the record and those it includes or redirects to;
    # counting stops once it passes the limit.
    lookups: int
    # An included or redirected domain with no SPF record, or several: a permerror of its own.
    broken: str | None = None
    # Why a record needed for counting could not be read (the count is then a lower bound).
    problem: str | None = None
    # True when an include or redirect uses a macro (%{...}), which depends on the sender.
    macro: bool = False


def _spf_terms(record: str) -> Iterator[tuple[str, str, bool]]:
    """(lower-case name, value, is_modifier) for each term after "v=spf1"."""
    for term in record.split()[1:]:
        name, sep, value = term.partition("=")
        if sep and ":" not in name and "/" not in name:
            yield name.lower(), value, True
            continue
        body = term.lstrip("+-~?")
        name, _, value = body.partition(":")
        yield name.split("/", 1)[0].lower(), value, False


def spf_lookups(record: str, lookup: TxtLookup, limit: int = SPF_LOOKUP_LIMIT) -> SpfLookups:
    """Count the terms that query DNS (include, a, mx, ptr, exists, and redirect when there
    is no "all") in record and in every record it includes or redirects to (RFC 7208
    section 4.6.4). A loop counts until it passes the limit, as it does for a receiver.
    """
    count = 0
    broken: str | None = None
    problem: str | None = None
    macro = False

    def walk(text: str) -> None:
        nonlocal count, broken, problem, macro
        terms = list(_spf_terms(text))
        has_all = any(name == "all" and not modifier for name, _, modifier in terms)
        for name, value, modifier in terms:
            # RFC 7208 section 5.1: mechanisms after "all" are never evaluated.
            if name == "all" and not modifier:
                break
            counted = name in _LOOKUP_MECHANISMS if not modifier else name == "redirect" and not has_all
            if not counted:
                continue
            count += 1
            if count > limit:
                return
            # Only include and redirect pull in another record; once the answer is known, stop asking DNS.
            if name not in ("include", "redirect") or broken or problem:
                continue
            if "%{" in value:
                macro = True
                continue
            txt, failure = lookup(value)
            if failure:
                problem = failure
                continue
            records = spf_records(txt)
            if len(records) != 1:
                verb = "includes" if name == "include" else "redirects to"
                broken = f"{verb} {value} ({'no SPF record' if not records else f'{len(records)} SPF records'})"
                continue
            walk(records[0])
            if count > limit:
                return

    walk(record)
    return SpfLookups(count, broken, problem, macro)


def check_spf(domain: str, txt_strings: Iterable[str], lookup: TxtLookup | None = None) -> Finding:
    """Check a domain's SPF record. With lookup, also count its DNS lookups (RFC 7208 section 4.6.4)."""
    finding = _check_spf_record(domain, txt_strings)
    if lookup is None or finding.status == FAIL or not spf_records(txt_strings):
        return finding
    record = spf_records(txt_strings)[0]
    found = spf_lookups(record, lookup)
    if found.lookups > SPF_LOOKUP_LIMIT:
        return Finding("spf", FAIL, f"{domain} SPF needs more than {SPF_LOOKUP_LIMIT} DNS lookups (RFC 7208 section 4.6.4), "
                                    f"so receivers return permerror and ignore it: {record}")
    if found.broken:
        return Finding("spf", FAIL, f"{domain} SPF {found.broken}, so receivers that reach it return "
                                    f"permerror and ignore SPF: {record}")
    if found.problem:
        return Finding("spf", WARN if finding.status == PASS else finding.status,
                       f"{finding.detail}; the {SPF_LOOKUP_LIMIT}-lookup limit could not be checked: {found.problem}")
    if found.lookups:
        at_least = "at least " if found.macro else ""
        return Finding("spf", finding.status, f"{finding.detail} ({at_least}{found.lookups} of {SPF_LOOKUP_LIMIT} DNS lookups)")
    return finding


def _check_spf_record(domain: str, txt_strings: Iterable[str]) -> Finding:
    records = spf_records(txt_strings)
    if not records:
        return Finding("spf", WARN, f"{domain} has no SPF record, so anyone can send mail claiming to be from it (a domain that sends no mail should publish 'v=spf1 -all')")
    if len(records) > 1:
        # RFC 7208 section 4.5: more than one record is a permanent error and receivers ignore SPF.
        return Finding("spf", FAIL, f"{domain} has {len(records)} SPF records; receivers treat that as an error and ignore SPF")
    record = records[0]
    modifiers = [name for name, _, modifier in _spf_terms(record) if modifier]
    if modifiers.count("redirect") > 1 or modifiers.count("exp") > 1:
        # RFC 7208 section 6: each may appear once; more is a permanent error.
        return Finding("spf", FAIL, f"{domain} SPF repeats a redirect= or exp= modifier, so receivers return permerror "
                                    f"and ignore it: {record}")
    terms = record.split()[1:]
    for term in terms:
        lower = term.lower()
        if lower in ("all", "+all"):
            return Finding("spf", FAIL, f"{domain} SPF ends with '{term}', which authorises every server on the internet: {record}")
        if lower in ("-all", "~all"):
            return Finding("spf", PASS, f"{domain}: {record}")
        if lower == "?all":
            return Finding("spf", WARN, f"{domain} SPF ends with '?all' (neutral), so receivers get no instruction to reject spoofed mail: {record}")
    redirect = next((t for t in terms if t.lower().startswith("redirect=")), None)
    if redirect:
        # With no 'all', the policy comes from the redirected record (RFC 7208 section 6.1).
        return Finding("spf", PASS, f"{domain} SPF delegates its policy with {redirect}: {record}")
    return Finding("spf", WARN, f"{domain} SPF has no 'all' mechanism, so mail from unlisted servers is treated as neutral: {record}")


def lookup_txt(domain: str, timeout: float) -> tuple[list[str], str | None]:
    """Return (TXT strings, None), or ([], reason) when the lookup could not be done."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return [], f"{SKIPPED_PREFIX} {INSTALL_HINT}"
    try:
        answer = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except dns.exception.DNSException as err:
        return [], f"DNS lookup for {domain} failed: {err.__class__.__name__}"
    # A TXT record can be split into several strings; they are joined without spaces (RFC 7208 section 3.3).
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answer], None


def dmarc_candidates(domain: str) -> list[str]:
    """Domains whose _dmarc record applies, most specific first.

    Receivers fall back from a subdomain to its organizational domain, the
    registrable domain by the Public Suffix List (RFC 7489 sections 3.2 and
    6.6.3): shop.example.co.uk, then example.co.uk, never co.uk. The parents in
    between are asked too, as the DNS tree walk of DMARCbis does.
    """
    domain = publicsuffix.to_ascii(domain).rstrip(".")
    organizational = publicsuffix.registrable_domain(domain) or domain
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(max(len(labels) - organizational.count("."), 1))]


def dmarc_records(txt_strings: Iterable[str]) -> list[str]:
    return [t for t in txt_strings if t.replace(" ", "").lower().startswith("v=dmarc1")]


def parse_dmarc_tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(found_on: str | None, txt_strings: Iterable[str], domain: str | None = None) -> Finding:
    """found_on is the domain whose _dmarc record was read, or None if no domain had one.

    domain is the mail domain being checked. When the record was found on a
    parent of it (an organizational domain), the subdomain policy sp= applies,
    falling back to p= when sp= is absent (RFC 7489 section 6.3).
    """
    if found_on is None:
        return Finding("dmarc", WARN, "no DMARC record, so receivers get no instruction for mail that fails SPF and DKIM")
    records = dmarc_records(txt_strings)
    if len(records) > 1:
        # RFC 7489 section 6.6.3: with more than one record, no DMARC policy is applied.
        return Finding("dmarc", FAIL, f"_dmarc.{found_on} has {len(records)} DMARC records, so receivers apply no DMARC policy")
    record = records[0]
    tags = parse_dmarc_tags(record)
    inherited = domain is not None and domain != found_on
    tag = "sp" if inherited and "sp" in tags else "p"
    applies = f" (the policy {domain} inherits as a subdomain)" if inherited else ""
    policy = tags.get(tag, "").lower()
    policies = ("none", "quarantine", "reject")
    problems = []
    # Section 6.6.3, step 6: a record without a valid p=, or with an invalid sp=,
    # is handled as if it said p=none, whichever domain it applies to.
    if tags.get("p", "").lower() not in policies:
        problems.append(f"no valid p= tag ('{tags.get('p', '')}'), so receivers treat it as p=none")
    elif "sp" in tags and tags["sp"].lower() not in policies:
        problems.append(f"sp={tags['sp']!r} is not a valid policy, so receivers treat the record as p=none")
    elif policy == "none":
        problems.append(f"{tag}=none{applies} only monitors; spoofed mail is still delivered")
    pct = tags.get("pct")
    if pct is not None and pct != "100":
        problems.append(f"pct={pct} applies the policy to only part of the failing mail")
    if problems:
        return Finding("dmarc", WARN, f"_dmarc.{found_on}: " + "; ".join(problems) + f": {record}")
    return Finding("dmarc", PASS, f"_dmarc.{found_on}{f' ({tag}={policy} applies to {domain})' if inherited else ''}: {record}")


# Selectors used by common mail providers: Google Workspace, Microsoft 365
# (selector1/2), Mailchimp/Mandrill (k1), SendGrid (s1/s2), Cloudflare Email
# Routing (cf2024-1) and frequent self-hosted defaults.
COMMON_DKIM_SELECTORS = ("google", "selector1", "selector2", "k1", "s1", "s2", "default", "dkim", "mail", "cf2024-1")


def parse_dkim_key(txt_strings: Iterable[str]) -> str | None:
    """Return the p= value of the first DKIM key record, or None if there is none.

    Only records with a p= tag count, so unrelated TXT records (or wildcard
    TXT answers) are not mistaken for a key. An empty p= means a revoked key.
    """
    for txt in txt_strings:
        tags = parse_dmarc_tags(txt)
        if "p" in tags:
            return tags["p"].replace(" ", "")
    return None


RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1


def _der_item(der: bytes, i: int) -> tuple[int, int]:
    """Return the content start and end of the DER element at offset i."""
    length, i = der[i + 1], i + 2
    if length & 0x80:
        size = length & 0x7F
        length, i = int.from_bytes(der[i:i + size], "big"), i + size
    return i, i + length


def rsa_key_bits(key: str) -> int | None:
    """Return the modulus size of a DKIM p= value holding an RSA public key.

    The value is a base64 SubjectPublicKeyInfo (RFC 6376 section 3.6.1).
    Anything else, such as an Ed25519 key (RFC 8463) or a value that does not
    decode, gives None, so only RSA keys are judged by size.
    """
    try:
        der = base64.b64decode(key, validate=True)
        spki, _ = _der_item(der, 0)
        algorithm, algorithm_end = _der_item(der, spki)
        oid, oid_end = _der_item(der, algorithm)
        if der[oid:oid_end] != RSA_ENCRYPTION_OID:
            return None
        bit_string, _ = _der_item(der, algorithm_end)
        rsa_key, _ = _der_item(der, bit_string + 1)  # skip the unused-bits byte
        modulus, modulus_end = _der_item(der, rsa_key)
    except (ValueError, IndexError):
        return None
    return int.from_bytes(der[modulus:modulus_end], "big").bit_length()


def check_dkim(domain: str, keys: Mapping[str, str | None], explicit: bool) -> Finding:
    """keys maps each selector tried to its p= value ('' revoked) or None (no key).

    explicit is True when the user named the selectors, so a missing one is
    reported directly. Otherwise only common selectors were guessed, and not
    finding a key does not prove DKIM is absent.
    """
    active = [sel for sel, key in keys.items() if key]
    revoked = [sel for sel, key in keys.items() if key == ""]
    missing = [sel for sel, key in keys.items() if key is None]
    if explicit and (missing or revoked):
        problems = [f"no DKIM key at {sel}._domainkey.{domain}" for sel in missing]
        problems += [f"the key at {sel}._domainkey.{domain} is revoked (empty p=)" for sel in revoked]
        return Finding("dkim", WARN, "; ".join(problems))
    if active:
        sizes = {sel: rsa_key_bits(keys[sel] or "") for sel in active}
        weak = [f"{sel} ({bits}-bit)" for sel, bits in sizes.items() if bits is not None and bits < 2048]
        if weak:
            return Finding("dkim", WARN, f"RSA key shorter than 2048 bits for {domain} under: {', '.join(weak)}; RFC 8301 asks signers for 2048 bits, and receivers ignore signatures from keys under 1024 bits")
        return Finding("dkim", PASS, f"DKIM key published for {domain} under: {', '.join(active)}")
    tried = ", ".join(keys)
    if revoked:
        return Finding("dkim", WARN, f"only revoked keys (empty p=) under common selectors ({', '.join(revoked)}); fine if {domain} sends no mail, otherwise its active key uses another selector, which --dkim-selector can check")
    return Finding("dkim", WARN, f"no DKIM key under common selectors ({tried}); DKIM may still use another selector, which --dkim-selector can check")
