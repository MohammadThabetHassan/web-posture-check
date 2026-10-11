"""Run the whole test suite with the network blocked: python tests/offline.py

Every test must pass on a machine without internet access, and must not reach
real sites on a machine that has it. Run this way, tests may use the loopback
interface only. A name lookup for anything but localhost or a loopback
address fails, and so does a connection or datagram to any other address or
to a DNS port (port 53, even on loopback, where a local resolver forwards to
the internet). Every attempt is also recorded, and the run fails if there was
one, so a test cannot pass by catching the error. The run also fails when no
test ran, for example after a typo in a -p pattern. CI runs the suite this way;
extra arguments are passed to unittest discover (e.g. -p "test_fetch.py").

The guard covers this Python process: name lookups (getaddrinfo, gethostbyname,
gethostbyname_ex, gethostbyaddr, getnameinfo) and every way a socket sends to
an address (connect, connect_ex, sendto, sendmsg). Subprocesses are not
covered; the only one the tests start is the local openssl command.
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


def _guard_lookup(name: str) -> None:
    """Replace socket.<name>(host, ...) with a version that only looks up loopback names."""
    real = getattr(socket, name)

    def lookup(host: Any, *args: Any, **kwargs: Any) -> Any:
        # getnameinfo takes a socket address, the others a host name or address.
        target = host[0] if isinstance(host, tuple) else host
        if target is not None and not _is_loopback(target):
            blocked.append(f"{name} for {target!r}")
            raise socket.gaierror(socket.EAI_NONAME, f"name lookup blocked during tests: {target!r}")
        return real(host, *args, **kwargs)

    setattr(socket, name, lookup)


def install() -> None:
    """Block everything but loopback for the rest of the process."""
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo"):
        _guard_lookup(name)
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_sendto = socket.socket.sendto

    def connect(self: Any, address: Any) -> None:
        _check(address)
        real_connect(self, address)

    def connect_ex(self: Any, address: Any) -> int:
        _check(address)
        return real_connect_ex(self, address)

    def sendto(self: Any, data: Any, *flags_and_address: Any) -> int:
        _check(flags_and_address[-1])
        return real_sendto(self, data, *flags_and_address)

    socket.socket.connect = connect  # type: ignore[method-assign]
    socket.socket.connect_ex = connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = sendto  # type: ignore[method-assign]
    # Windows sockets have no sendmsg.
    if hasattr(socket.socket, "sendmsg"):
        real_sendmsg = socket.socket.sendmsg

        def sendmsg(self: Any, buffers: Any, *rest: Any) -> int:
            # sendmsg(buffers[, ancdata[, flags[, address]]])
            if len(rest) >= 3 and rest[2] is not None:
                _check(rest[2])
            return real_sendmsg(self, buffers, *rest)

        socket.socket.sendmsg = sendmsg  # type: ignore[method-assign]


def main(argv: list[str]) -> int:
    install()
    tests = os.path.dirname(os.path.abspath(__file__))
    program = unittest.main(module=None, argv=[argv[0], "discover", "-s", tests, *argv[1:]], exit=False)
    if blocked:
        print("\nTests tried to use the network (all blocked):", *sorted(set(blocked)), sep="\n  ", file=sys.stderr)
        return 1
    if program.result.testsRun == 0:
        print("\nNo tests ran: check the -s and -p arguments.", file=sys.stderr)
        return 1
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
