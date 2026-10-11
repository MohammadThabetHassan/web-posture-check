"""Email authentication checks (SPF, DMARC and DKIM), read from DNS.

The standard library cannot query TXT records, so lookups use the optional
dnspython package (pip install "web-posture-check[dns]"). Without it the check
is reported as skipped. The check_* functions take the TXT strings and need no
network access.
"""

from .findings import FAIL, PASS, SKIPPED_PREFIX, WARN, Finding

INSTALL_HINT = 'install the optional DNS support with: pip install "web-posture-check[dns]"'


def mail_domain(host):
    """The domain to check for a web host: www.example.com -> example.com."""
    host = (host or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def spf_records(txt_strings):
    """Return the TXT values that are SPF records (they start with 'v=spf1', RFC 7208 section 4.5)."""
    return [t for t in txt_strings if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


def check_spf(domain, txt_strings):
    records = spf_records(txt_strings)
    if not records:
        return Finding("spf", WARN, f"{domain} has no SPF record, so anyone can send mail claiming to be from it (a domain that sends no mail should publish 'v=spf1 -all')")
    if len(records) > 1:
        # RFC 7208 section 4.5: more than one record is a permanent error and receivers ignore SPF.
        return Finding("spf", FAIL, f"{domain} has {len(records)} SPF records; receivers treat that as an error and ignore SPF")
    record = records[0]
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


def lookup_txt(domain, timeout):
    """Return (list of TXT strings, None), or (None, reason) when the lookup could not be done."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return None, f"{SKIPPED_PREFIX} {INSTALL_HINT}"
    try:
        answer = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except dns.exception.DNSException as err:
        return None, f"DNS lookup for {domain} failed: {err.__class__.__name__}"
    # A TXT record can be split into several strings; they are joined without spaces (RFC 7208 section 3.3).
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answer], None


def dmarc_candidates(domain):
    """Domains whose _dmarc record applies, most specific first.

    Receivers fall back from a subdomain to the organizational domain
    (RFC 7489 section 6.6.3). Without the Public Suffix List this walks up to
    two labels, which matches it for names like shop.example.com.
    """
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(max(len(labels) - 1, 1))]


def dmarc_records(txt_strings):
    return [t for t in txt_strings if t.replace(" ", "").lower().startswith("v=dmarc1")]


def parse_dmarc_tags(record):
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(found_on, txt_strings, domain=None):
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
    problems = []
    if tag == "sp" and policy not in ("none", "quarantine", "reject"):
        # Section 6.6.3: a record whose sp= is invalid is handled as if it said p=none.
        problems.append(f"sp={tags.get('sp', '')!r} is not a valid policy, so receivers treat the record as p=none")
    elif policy not in ("none", "quarantine", "reject"):
        problems.append(f"no valid p= tag ('{tags.get('p', '')}'), so receivers treat it as p=none")
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


def parse_dkim_key(txt_strings):
    """Return the p= value of the first DKIM key record, or None if there is none.

    Only records with a p= tag count, so unrelated TXT records (or wildcard
    TXT answers) are not mistaken for a key. An empty p= means a revoked key.
    """
    for txt in txt_strings:
        tags = parse_dmarc_tags(txt)
        if "p" in tags:
            return tags["p"].replace(" ", "")
    return None


def check_dkim(domain, keys, explicit):
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
        return Finding("dkim", PASS, f"DKIM key published for {domain} under: {', '.join(active)}")
    tried = ", ".join(keys)
    if revoked:
        return Finding("dkim", WARN, f"only revoked keys (empty p=) under common selectors ({', '.join(revoked)}); fine if {domain} sends no mail, otherwise its active key uses another selector, which --dkim-selector can check")
    return Finding("dkim", WARN, f"no DKIM key under common selectors ({tried}); DKIM may still use another selector, which --dkim-selector can check")
