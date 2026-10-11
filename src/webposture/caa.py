"""CAA check (RFC 8659): which certificate authorities may issue for the host.

Lookups use the optional dnspython package, like the email checks.
check_caa takes the records and needs no network access.
"""

from .emailauth import INSTALL_HINT
from .findings import PASS, SKIPPED_PREFIX, WARN, Finding

# Property tags defined by RFC 8659 and RFC 9495. A CA must refuse to issue
# when it sees a critical flag on a tag it does not understand.
KNOWN_TAGS = {"issue", "issuewild", "iodef", "issuemail", "contactemail", "contactphone"}
CRITICAL_FLAG = 128


def _issuers(records, tag):
    """CA domains named by a tag; an empty value (';') names none."""
    names = []
    for _, record_tag, value in records:
        if record_tag == tag:
            ca = value.split(";", 1)[0].strip()
            if ca:
                names.append(ca)
    return sorted(set(names))


def check_caa(found_on, records):
    """records is a list of (flags, tag, value) from the CAA RRset at found_on, or empty."""
    if not found_on:
        return Finding("caa", WARN, "no CAA record, so any certificate authority may issue certificates for this host")
    records = [(flags, tag.lower(), value) for flags, tag, value in records]
    critical = sorted({tag for flags, tag, _ in records if flags & CRITICAL_FLAG and tag not in KNOWN_TAGS})
    if critical:
        return Finding("caa", WARN, f"CAA on {found_on} has unknown critical tag(s) {', '.join(critical)}, so every CA must refuse to issue")
    if not any(tag == "issue" for _, tag, _ in records):
        return Finding("caa", WARN, f"CAA on {found_on} has no 'issue' property, so any CA may issue non-wildcard certificates")
    issue = _issuers(records, "issue")
    detail = f"CAA on {found_on} allows: {', '.join(issue) if issue else 'no CA'}"
    if any(tag == "issuewild" for _, tag, _ in records):
        wild = _issuers(records, "issuewild")
        detail += f"; wildcards: {', '.join(wild) if wild else 'no CA'}"
    return Finding("caa", PASS, detail)


def caa_candidates(host):
    """The names whose CAA RRset can apply to host, most specific first.

    RFC 8659 section 3: a CA climbs from the host towards the root, stopping at
    the first name with a CAA RRset, and the top-level domain is one of those
    names (www.example.com -> www.example.com, example.com, com).
    """
    labels = host.rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(len(labels))]


def lookup_caa(host, timeout):
    """Return (found_on, records, problem). Climbs from host to its parent domains (RFC 8659 section 3)."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return None, [], f"{SKIPPED_PREFIX} {INSTALL_HINT}"
    for name in caa_candidates(host):
        try:
            answer = dns.resolver.resolve(name, "CAA", lifetime=timeout)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.exception.DNSException as err:
            return None, [], f"CAA lookup for {name} failed: {err.__class__.__name__}"
        records = [(r.flags, r.tag.decode("ascii", errors="replace"), r.value.decode("utf-8", errors="replace")) for r in answer]
        return name, records, None
    return None, [], None
