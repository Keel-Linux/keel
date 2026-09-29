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
    "openssl", "x509", "-noout", "-subject", "-issuer", "-enddate", "-ext",
    "subjectAltName,subjectKeyIdentifier,authorityKeyIdentifier,"
    "basicConstraints",
    "-nameopt", "RFC2253",
)
DATE_FORMAT = "%b %d %H:%M:%S %Y GMT"
# a hostile cert.pem on an offline root must not hold inspect up
TIMEOUT = 10
MAX_BLOCKS = 8
EXTENSION_HEADERS = {
    "X509v3 Subject Key Identifier": "ski",
    "X509v3 Authority Key Identifier": "aki",
    "X509v3 Basic Constraints": "basic",
}


@dataclass(frozen=True)
class Certificate:
    subject: str
    issuer: str
    names: tuple[str, ...]
    not_after: datetime
    ski: str | None = None
    aki: str | None = None
    is_ca: bool = False

    @property
    def self_signed(self) -> bool:
        """Its own name as issuer, and signed by its own key

        The name alone is not enough: a private CA can issue a leaf under
        its own DN. A self-signed certificate names its own key as the
        authority, or names none.
        """
        return self.subject == self.issuer and (
            self.aki is None or self.aki == self.ski
        )


def read_certificate(text: str) -> tuple[Certificate | None, str | None]:
    """The leaf in `text`, or None and why

    The leaf is the first certificate that is not a CA; a file holding
    only CA certificates is read from its first, which is what a lone
    self-signed certificate made with `openssl req -x509` is.
    """
    blocks = pem_blocks(text)
    if not blocks:
        return None, "no certificate in it"
    parsed: list[Certificate] = []
    for block in blocks[:MAX_BLOCKS]:
        cert, problem = parse_block(block)
        if cert is None:
            return None, problem
        if not cert.is_ca:
            return cert, None
        parsed.append(cert)
    return parsed[0], None


def parse_block(block: str) -> tuple[Certificate | None, str | None]:
    try:
        out = subprocess.run(list(OPENSSL), input=block, capture_output=True,
                             text=True, check=False, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, f"openssl did not answer within {TIMEOUT} s"
    except OSError as e:
        return None, f"openssl could not be run ({e.strerror})"
    if out.returncode != 0:
        return None, "openssl could not parse the certificate"
    return parse(out.stdout), None


def pem_blocks(text: str) -> list[str]:
    blocks, start = [], text.find(BEGIN)
    while start >= 0:
        end = text.find(END, start)
        if end < 0:
            break
        blocks.append(text[start:end + len(END)] + "\n")
        start = text.find(BEGIN, end)
    return blocks


def parse(output: str) -> Certificate:
    fields: dict[str, str] = {}
    names: list[str] = []
    extension = None
    for line in output.splitlines():
        header = line.strip().removesuffix(": critical").rstrip(":").strip()
        if header in EXTENSION_HEADERS:
            extension = EXTENSION_HEADERS[header]
            continue
        if extension and line[:1].isspace():
            fields[extension] = line.strip().removeprefix("keyid:").upper()
            extension = None
            continue
        extension = None
        key, sep, value = line.partition("=")
        if sep and key in ("subject", "issuer", "notAfter"):
            fields[key] = value.strip()
        names += re.findall(r"DNS:([^,\s]+)", line)
    not_after = datetime.strptime(
        " ".join(fields["notAfter"].split()), DATE_FORMAT
    ).replace(tzinfo=timezone.utc)
    return Certificate(
        fields["subject"], fields["issuer"], tuple(names), not_after,
        ski=fields.get("ski"), aki=fields.get("aki"),
        is_ca="CA:TRUE" in fields.get("basic", ""),
    )


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
