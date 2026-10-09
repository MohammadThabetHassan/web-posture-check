"""TLS certificate checks.

fetch_certificate does the network part; check_certificate takes its result
and returns a Finding, so the rules can be tested without network access.
"""

import socket
import ssl
import warnings
from datetime import datetime, timezone

from .findings import Finding, PASS, WARN, FAIL

# Renewal automation (e.g. ACME clients) normally renews 30 days ahead, so a
# certificate this close to expiry usually means renewal is failing.
EXPIRY_WARN_DAYS = 14

# OpenSSL's X509_V_ERR_CERT_HAS_EXPIRED.
VERIFY_CODE_EXPIRED = 10


def fetch_certificate(host, port=443, timeout=10.0):
    """Return (not_after, verify_code, verify_message).

    not_after is a UTC datetime when the certificate verifies. When it does not,
    not_after is None and the OpenSSL verify code and message are returned.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as err:
        return None, err.verify_code, err.verify_message
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    return not_after, None, None


def check_certificate(not_after, verify_code, verify_message, now):
    if verify_code == VERIFY_CODE_EXPIRED:
        return Finding("tls-certificate", FAIL, "certificate has expired")
    if not_after is None:
        # Wrong host, self-signed, untrusted chain, not yet valid: browsers show
        # a full-page certificate error, so visitors cannot reach the site.
        return Finding("tls-certificate", FAIL, f"certificate is not trusted: {verify_message}")
    date = not_after.strftime("%Y-%m-%d")
    days = (not_after - now).total_seconds() / 86400
    if days < 0:
        return Finding("tls-certificate", FAIL, f"certificate expired on {date}")
    if days < EXPIRY_WARN_DAYS:
        # Under a day, "in 0 day(s)" reads like a bug on the most urgent warning.
        when = "in less than a day" if days < 1 else f"in {int(days)} day(s)"
        return Finding("tls-certificate", WARN, f"certificate expires {when}, on {date}; check that renewal is working")
    return Finding("tls-certificate", PASS, f"certificate valid until {date} ({int(days)} days)")


# Outcomes of trying one protocol version.
ACCEPTED = "accepted"
REFUSED = "refused"
UNTESTABLE = "untestable"

# OpenSSL errors raised by our own side before the server is asked anything:
# the local library will not offer that version, so nothing was learned.
_LOCAL_REASONS = {"NO_CIPHERS_AVAILABLE", "NO_PROTOCOLS_AVAILABLE", "NO_SUITABLE_SIGNATURE_ALGORITHM"}


def _legacy_versions():
    # TLSv1 and TLSv1_1 are deprecated names in the ssl module; that is the point.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]


def classify_handshake_error(err):
    """Map a failed legacy handshake to REFUSED (server said no) or UNTESTABLE (we could not ask)."""
    if isinstance(err, ssl.SSLError):
        return UNTESTABLE if getattr(err, "reason", None) in _LOCAL_REASONS else REFUSED
    if isinstance(err, (socket.timeout, TimeoutError)):
        return UNTESTABLE
    # Many servers simply reset or close the connection on an old ClientHello.
    return REFUSED


def probe_version(host, port, version, timeout=10.0):
    """Try a handshake that only allows one TLS version. Returns ACCEPTED, REFUSED or UNTESTABLE."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Only the protocol version matters here; the certificate is checked elsewhere.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
        # OpenSSL 3 refuses TLS 1.0/1.1 at its default security level, which
        # would look like the server refusing. Lower it for this probe only.
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return UNTESTABLE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return ACCEPTED
    except OSError as err:
        return classify_handshake_error(err)


def check_legacy_protocols(results):
    """results maps a label such as 'TLS 1.0' to ACCEPTED, REFUSED or UNTESTABLE."""
    accepted = [label for label, outcome in results.items() if outcome == ACCEPTED]
    untestable = [label for label, outcome in results.items() if outcome == UNTESTABLE]
    if accepted:
        return Finding("tls-protocols", FAIL, f"server accepts {', '.join(accepted)}, which are deprecated (RFC 8996)")
    if untestable:
        return Finding("tls-protocols", WARN, f"could not test {', '.join(untestable)} from this machine (the local OpenSSL will not offer it), so support is unknown")
    return Finding("tls-protocols", PASS, f"server refuses {', '.join(results)}")


def probe_legacy_protocols(host, port=443, timeout=10.0):
    return {label: probe_version(host, port, version, timeout) for label, version in _legacy_versions()}
