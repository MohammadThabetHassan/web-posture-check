"""Response headers as browsers read them: names are case-insensitive and every occurrence is kept.

A plain dict keeps one value per name, but a response can repeat a header, and
each header has its own rule for what repeating it means: only the first counts
for HSTS (RFC 6797), every one is enforced for Content-Security-Policy (CSP3),
and the values are joined and split on commas for X-Content-Type-Options,
X-Frame-Options and Referrer-Policy (the Fetch standard's "get, decode, and
split"). HeaderMap keeps every occurrence in order so each check can apply the
rule that its header follows.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from email.message import Message
from typing import Union

# Fetch's HTTP whitespace: tab, space, CR and LF. str.strip() would also remove
# characters such as U+00A0, which browsers keep, so "nosniff\xa0" is not "nosniff".
HTTP_WHITESPACE = " \t\r\n"

# Anything a check accepts as response headers: a HeaderMap, the http.client
# message urllib returns, a plain mapping (handy in tests), or (name, value) pairs.
HeaderSource = Union["HeaderMap", Message, Mapping[str, str], Iterable[tuple[str, str]]]


def split_list(value: str, separator: str = ",") -> list[str]:
    """Split a header value on commas (or separator) that are not inside a quoted string, trimming spaces and tabs.

    With commas this is the splitting half of the Fetch standard's "get, decode,
    and split". Quoted strings keep their quotes, as in the standard.
    """
    values: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in value:
        if quoted:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            current.append(char)
        elif char == separator:
            values.append("".join(current).strip(" \t"))
            current = []
        else:
            current.append(char)
    values.append("".join(current).strip(" \t"))
    return values


class HeaderMap:
    """Response headers: case-insensitive names, every occurrence kept in the order received."""

    __slots__ = ("_items",)

    def __init__(self, headers: HeaderSource = ()) -> None:
        pairs: Iterable[tuple[str, str]]
        if isinstance(headers, HeaderMap):
            pairs = headers._items
        elif isinstance(headers, Message):
            # items() of an email Message returns every header, repeats included.
            pairs = headers.items()
        elif isinstance(headers, Mapping):
            pairs = headers.items()
        else:
            pairs = headers
        self._items: tuple[tuple[str, str], ...] = tuple((str(name), str(value)) for name, value in pairs)

    def get_all(self, name: str) -> list[str]:
        """Every value of a header, in order; [] when it is absent."""
        wanted = name.lower()
        return [value for key, value in self._items if key.lower() == wanted]

    def get(self, name: str) -> str | None:
        """The first value of a header without surrounding HTTP whitespace, or None when it is absent."""
        values = self.get_all(name)
        return values[0].strip(HTTP_WHITESPACE) if values else None

    def combined(self, name: str) -> str | None:
        """Every value of a header joined with ", ", as the Fetch standard combines them; None when absent."""
        values = self.get_all(name)
        return ", ".join(value.strip(HTTP_WHITESPACE) for value in values) if values else None

    def split(self, name: str) -> list[str] | None:
        """The Fetch standard's "get, decode, and split": every occurrence combined, then split on commas.

        None when the header is absent, so an absent header and an empty one can be told apart.
        """
        combined = self.combined(name)
        return None if combined is None else split_list(combined)

    def items(self) -> list[tuple[str, str]]:
        """Every (name, value) pair, in the order received."""
        return list(self._items)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and bool(self.get_all(name))

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"HeaderMap({list(self._items)!r})"
