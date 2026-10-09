"""Email authentication checks (SPF), read from DNS.

The standard library cannot query TXT records, so lookups use the optional
dnspython package (pip install "web-posture-check[dns]"). Without it the check
is reported as skipped. check_spf itself takes the TXT strings and needs no
network access.
"""

from .findings import Finding, PASS, WARN, FAIL

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
        return None, f"skipped: {INSTALL_HINT}"
    try:
        answer = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except dns.exception.DNSException as err:
        return None, f"DNS lookup for {domain} failed: {err.__class__.__name__}"
    # A TXT record can be split into several strings; they are joined without spaces (RFC 7208 section 3.3).
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answer], None
