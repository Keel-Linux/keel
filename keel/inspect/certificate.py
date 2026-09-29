# Copyright (c) 2026 KeelLinux maintainers
"""The certificate a machine serves, read from its PEM text

tls.acme is only true of a machine when the certificate in use was issued
for the configured domains (keel#35); a domains file alone says what was
asked for, not what was obtained. The text is parsed by `openssl x509`
on standard input: openssl is on every appliance (turnkey-ssl depends on
it), keel needs no Python dependency for X.509, and since only the bytes
of a file are parsed, it answers the same under --root as on the live
system.
"""

import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

BEGIN = "-----BEGIN CERTIFICATE-----"
END = "-----END CERTIFICATE-----"
OPENSSL = (
    "openssl", "x509", "-noout", "-subject", "-issuer", "-enddate",
    "-ext", "subjectAltName", "-nameopt", "RFC2253",
)
DATE_FORMAT = "%b %d %H:%M:%S %Y GMT"


@dataclass(frozen=True)
class Certificate:
    subject: str
    issuer: str
    names: tuple[str, ...]
    not_after: datetime

    @property
    def self_signed(self) -> bool:
        return self.subject == self.issuer


def read_certificate(text: str) -> tuple[Certificate | None, str | None]:
    """The first certificate in `text`, or None and why"""
    block = first_block(text)
    if block is None:
        return None, "no certificate in it"
    try:
        out = subprocess.run(list(OPENSSL), input=block, capture_output=True,
                             text=True, check=False)
    except OSError as e:
        return None, f"openssl could not be run ({e.strerror})"
    if out.returncode != 0:
        return None, "openssl could not parse the certificate"
    return parse(out.stdout), None


def first_block(text: str) -> str | None:
    start = text.find(BEGIN)
    end = text.find(END, start)
    if start < 0 or end < 0:
        return None
    return text[start:end + len(END)] + "\n"


def parse(output: str) -> Certificate:
    fields: dict[str, str] = {}
    names: list[str] = []
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("subject", "issuer", "notAfter"):
            fields[key] = value.strip()
        names += re.findall(r"DNS:([^,\s]+)", line)
    not_after = datetime.strptime(
        " ".join(fields["notAfter"].split()), DATE_FORMAT
    ).replace(tzinfo=timezone.utc)
    return Certificate(fields["subject"], fields["issuer"], tuple(names),
                       not_after)


def covers(cert: Certificate, domain: str) -> bool:
    """Whether the certificate is valid for `domain`, a wildcard for one label"""
    wanted = domain.lower().rstrip(".")
    for name in (n.lower() for n in cert.names):
        if name == wanted:
            return True
        if name.startswith("*.") and "." in wanted:
            label, rest = wanted.split(".", 1)
            if label and rest == name[2:]:
                return True
    return False
