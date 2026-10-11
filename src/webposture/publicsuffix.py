"""The Public Suffix List: the names under which anyone can register a domain.

Browsers refuse a cookie whose Domain is a public suffix (co.uk, github.io),
DMARC finds a mail domain's organizational domain with it, and a CSP wildcard
right under a public suffix (*.co.uk) matches hosts anyone can own. The list
ships with the package as public_suffix_list.dat, unchanged from
publicsuffix.org and under the Mozilla Public License 2.0 (its header says so).
It is read once, on first use. Both of its sections count, the ICANN domains
and the private ones such as github.io, as they do in browsers. To refresh it:

    curl -fsSL https://publicsuffix.org/list/public_suffix_list.dat -o src/webposture/public_suffix_list.dat
"""

from __future__ import annotations

import functools
from importlib import resources


def to_ascii(name: str) -> str:
    """A name in lower case and its ASCII (IDNA) form; unchanged when it has no IDNA form."""
    name = name.lower()
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


@functools.lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """The list's rules as (normal, wildcard, exception) sets, each in ASCII.

    A wildcard rule "*.ck" is stored as "ck" and an exception rule "!www.ck" as "www.ck".
    """
    text = resources.files(__package__).joinpath("public_suffix_list.dat").read_text(encoding="utf-8")
    normal: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for line in text.splitlines():
        # A rule is the first word of a line; "//" starts a comment.
        words = line.split()
        if not words or words[0].startswith("//"):
            continue
        rule = words[0]
        if rule.startswith("!"):
            exception.add(to_ascii(rule[1:]))
        elif rule.startswith("*."):
            wildcard.add(to_ascii(rule[2:]))
        else:
            normal.add(to_ascii(rule))
    return frozenset(normal), frozenset(wildcard), frozenset(exception)


def public_suffix(name: str) -> str:
    """The public suffix of a host or domain name, by the list's algorithm.

    An exception rule wins; otherwise the matching rule with the most labels;
    otherwise the implicit rule "*", which makes the last label the suffix.
    """
    labels = to_ascii(name).rstrip(".").split(".")
    normal, wildcard, exception = _rules()
    for i in range(len(labels)):
        if ".".join(labels[i:]) in exception:
            return ".".join(labels[i + 1:])
    # From the longest candidate down, so the first match is the longest rule.
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in normal or ".".join(labels[i + 1:]) in wildcard:
            return candidate
    return labels[-1]


def is_public_suffix(name: str) -> bool:
    """True when name is itself a public suffix (com, co.uk, github.io, or an unknown top-level name)."""
    return public_suffix(name) == to_ascii(name).rstrip(".")


def registrable_domain(name: str) -> str | None:
    """The public suffix and one more label (shop.example.co.uk -> example.co.uk).

    None for a public suffix, or for a name with an empty label (".example.com").
    """
    labels = to_ascii(name).rstrip(".").split(".")
    suffix_labels = public_suffix(name).count(".") + 1
    if len(labels) <= suffix_labels or "" in labels:
        return None
    return ".".join(labels[-suffix_labels - 1:])
