"""A throwaway certificate authority for tests that need real TLS handshakes.

make_certificates writes, with the openssl command, a CA and a certificate for
localhost and 127.0.0.1 signed by it. Tests that use it skip when openssl is
not installed (OPENSSL is None). Nothing here touches the network.
"""

import os
import shutil
import subprocess

OPENSSL = shutil.which("openssl")
# How long the server certificate is valid.
CERT_DAYS = 60


def _openssl(folder, *args):
    # A minimal config of our own, so a missing or unusual system openssl.cnf does not matter.
    env = dict(os.environ, OPENSSL_CONF=os.path.join(folder, "openssl.cnf"))
    done = subprocess.run([OPENSSL or "openssl", *args], cwd=folder, env=env, capture_output=True, text=True)
    if done.returncode:
        raise RuntimeError(f"openssl {args[0]} failed: {done.stderr}")


def make_certificates(folder):
    """Write ca.pem, and server.pem/server.key for localhost signed by it; return their paths."""
    with open(os.path.join(folder, "openssl.cnf"), "w", encoding="ascii") as handle:
        handle.write("[req]\ndistinguished_name = dn\n[dn]\n")
    _openssl(folder, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
             "-days", "2", "-subj", "/CN=web-posture-check test CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    _openssl(folder, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr",
             "-subj", "/CN=localhost")
    with open(os.path.join(folder, "server.ext"), "w", encoding="ascii") as handle:
        handle.write("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                     "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                     "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    _openssl(folder, "x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
             "-out", "server.pem", "-days", str(CERT_DAYS), "-extfile", "server.ext")
    return tuple(os.path.join(folder, name) for name in ("ca.pem", "server.pem", "server.key"))
