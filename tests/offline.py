"""Run the whole test suite with the network blocked: python tests/offline.py

Every test must pass on a machine without internet access, and must not reach
real sites on a machine that has it. Run this way, tests may use the loopback
interface only. A name lookup for anything but localhost or a loopback
address fails, and so does a connection or datagram to any other address or
to a DNS port (port 53, even on loopback, where a local resolver forwards to
the internet). Every attempt is also recorded, and the run fails if there was
one, so a test cannot pass by catching the error. CI runs the suite this way;
extra arguments are passed to unittest discover (e.g. -p "test_fetch.py").
"""

from __future__ import annotations

import ipaddress
import os
import socket
import sys
import unittest
from typing import Any

DNS_PORT = 53

# What the tests tried to reach, in order.
blocked: list[str] = []


class NetworkBlocked(OSError):
    """A test tried to use the network."""


def _is_loopback(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", errors="replace")
    if not isinstance(host, str):
        return False
    if host.rstrip(".").lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _check(address: Any) -> None:
    # AF_UNIX addresses are paths (str or bytes): local, so always allowed.
    if isinstance(address, tuple) and not (_is_loopback(address[0]) and address[1] != DNS_PORT):
        blocked.append(f"{address[0]} port {address[1]}")
        raise NetworkBlocked(f"network access blocked during tests: {address[0]} port {address[1]}")


def install() -> None:
    """Block everything but loopback for the rest of the process."""
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host is not None and not _is_loopback(host):
            blocked.append(f"name lookup for {host!r}")
            raise socket.gaierror(socket.EAI_NONAME, f"name lookup blocked during tests: {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    def connect(self: Any, address: Any) -> None:
        _check(address)
        real_connect(self, address)

    def connect_ex(self: Any, address: Any) -> int:
        _check(address)
        return real_connect_ex(self, address)

    def sendto(self: Any, data: Any, *flags_and_address: Any) -> int:
        _check(flags_and_address[-1])
        return real_sendto(self, data, *flags_and_address)

    socket.getaddrinfo = getaddrinfo
    socket.socket.connect = connect  # type: ignore[method-assign]
    socket.socket.connect_ex = connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = sendto  # type: ignore[method-assign]


def main(argv: list[str]) -> int:
    install()
    tests = os.path.dirname(os.path.abspath(__file__))
    program = unittest.main(module=None, argv=[argv[0], "discover", "-s", tests, *argv[1:]], exit=False)
    if blocked:
        print("\nTests tried to use the network (all blocked):", *sorted(set(blocked)), sep="\n  ", file=sys.stderr)
        return 1
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
