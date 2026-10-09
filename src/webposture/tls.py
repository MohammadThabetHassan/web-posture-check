"""TLS certificate checks.

fetch_certificate does the network part; check_certificate takes its result
and returns a Finding, so the rules can be tested without network access.
"""

import socket
import ssl
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
        # Other verification failures (wrong host, untrusted chain) are a
        # separate problem; this check only reports expiry.
        return Finding("tls-certificate", WARN, f"certificate could not be verified ({verify_message}), so its expiry was not checked")
    date = not_after.strftime("%Y-%m-%d")
    days = (not_after - now).total_seconds() / 86400
    if days < 0:
        return Finding("tls-certificate", FAIL, f"certificate expired on {date}")
    if days < EXPIRY_WARN_DAYS:
        # Under a day, "in 0 day(s)" reads like a bug on the most urgent warning.
        when = "in less than a day" if days < 1 else f"in {int(days)} day(s)"
        return Finding("tls-certificate", WARN, f"certificate expires {when}, on {date}; check that renewal is working")
    return Finding("tls-certificate", PASS, f"certificate valid until {date} ({int(days)} days)")
