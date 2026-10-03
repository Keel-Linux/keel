# Copyright (c) 2026 KeelLinux maintainers
"""The self signed certificate of one invite (decision 0048)

Each invite gets a key pair and a certificate of its own, made by
`openssl req -x509` (openssl is a dependency of keel), so nothing about
it outlives the invite. The token carries the SHA-256 of the
certificate's DER form; the new node pins that fingerprint instead of
trusting any authority. The key stays in the invite's file, mode 0600,
and is never printed.
"""

import base64
import hashlib
import re
import subprocess

OPENSSL = "openssl"
TIMEOUT = 30
SUBJECT = "/CN=keel-mesh-invite"
# a day: the invite itself expires within the hour; keel checks that
DAYS = "1"
PEM_RE = re.compile(
    r"-----BEGIN (?P<label>[A-Z ]+)-----\n(?P<body>[A-Za-z0-9+/=\n]+)"
    r"-----END (?P=label)-----\n")


class CertificateError(Exception):
    """openssl could not make the invite's certificate"""


def make() -> tuple[str, str]:
    """(key, certificate), both PEM; raises CertificateError

    Both come back on openssl's standard output, so no key file is
    written outside the invite's own.
    """
    argv = [OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:prime256v1", "-nodes", "-subj", SUBJECT,
            "-days", DAYS, "-keyout", "-", "-out", "-"]
    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              check=False, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CertificateError(f"openssl could not be run: {e}") from None
    blocks = {found.group("label"): found.group(0)
              for found in PEM_RE.finditer(done.stdout)}
    key, certificate = blocks.get("PRIVATE KEY"), blocks.get("CERTIFICATE")
    if done.returncode != 0 or key is None or certificate is None:
        raise CertificateError(
            f"openssl req exited {done.returncode} without a key and a"
            f" certificate: {done.stderr.strip()[-200:]}")
    return key, certificate


def fingerprint(certificate: str) -> bytes:
    """SHA-256 of the DER form of a certificate make() returned, as the
    token carries it"""
    body = PEM_RE.search(certificate).group("body")
    return hashlib.sha256(base64.b64decode(body)).digest()
