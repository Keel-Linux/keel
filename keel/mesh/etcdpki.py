# Copyright (c) 2026 KeelLinux maintainers
"""The mesh's etcd CA: a root, an intermediate per member, leaves

etcd uses its own TLS, peer and client (0048, second round, point 3),
with a CA the first node makes; every member holds an intermediate CA
of its own, signed by its inviter, and the root's key stays on the
first node (0048, third round, point 1). Each member issues its own
leaves with its intermediate: its member certificate and keel's client
certificate.

All P-256, made with `openssl` (a dependency of keel) on the machine
itself, never in an image. A key is made on standard output and written
by the caller to its state, 0600, so no key is ever in a temporary
file; a signing key is handed to openssl by its path. What a request
asks for is ignored: the issuer takes only its public key, after
checking the request's own signature, and sets the subject and every
extension itself, so a request that asks for `CA:TRUE` or another
address gets none of it.
"""

import hashlib
import ipaddress
import os
import re
import secrets
import subprocess
import tempfile
from datetime import datetime, timezone

OPENSSL = "openssl"
TIMEOUT = 30
CA, MEMBER, CLIENT = "ca", "member", "client"
# the root outlives every intermediate it signs, and an intermediate
# the leaves; a leaf is renewed with a third of its life left
ROOT_DAYS = 7300
CA_DAYS = 3650
LEAF_DAYS = 365
PEM_RE = re.compile(r"-----BEGIN (?P<label>[A-Z ]+)-----\n[A-Za-z0-9+/=\n]+"
                    r"-----END (?P=label)-----\n")
EXTENSIONS = {
    CA: ("basicConstraints=critical,CA:TRUE\n"
         "keyUsage=critical,keyCertSign,cRLSign\n"),
    MEMBER: ("basicConstraints=critical,CA:FALSE\n"
             "keyUsage=critical,digitalSignature\n"
             "extendedKeyUsage=serverAuth,clientAuth\n"),
    CLIENT: ("basicConstraints=critical,CA:FALSE\n"
             "keyUsage=critical,digitalSignature\n"
             "extendedKeyUsage=clientAuth\n"),
}
IDS = "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"


class PkiError(Exception):
    """openssl could not make, read or check a key or a certificate"""


def openssl(*argv: str, data: str | None = None) -> str:
    """openssl's standard output; raises PkiError"""
    try:
        done = subprocess.run([OPENSSL, *argv], input=data,
                              capture_output=True, text=True, check=False,
                              timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PkiError(f"openssl could not be run: {e}") from None
    if done.returncode != 0:
        raise PkiError(f"openssl {argv[0]} exited {done.returncode}:"
                       f" {done.stderr.strip()[-200:]}")
    return done.stdout


def blocks(text: str) -> list[str]:
    """The PEM blocks of `text`, in order"""
    return [found.group(0) for found in PEM_RE.finditer(text)]


def new_key() -> str:
    """A P-256 private key, PEM, on standard output: the caller writes
    it, 0600"""
    found = openssl("genpkey", "-algorithm", "EC", "-pkeyopt",
                    "ec_paramgen_curve:P-256")
    if "PRIVATE KEY" not in found:
        raise PkiError("openssl genpkey gave no private key")
    return found


def key_public(path: str) -> str:
    """The public key of the private key at `path`, PEM"""
    return openssl("pkey", "-in", path, "-pubout")


def request(path: str) -> str:
    """A certificate request for the key at `path`; its subject is not
    read by any issuer"""
    return openssl("req", "-new", "-key", path, "-subj", "/CN=keel")


def request_key(csr: str) -> str:
    """The public key of a request whose signature is its own key's;
    raises PkiError for anything else"""
    if len(blocks(csr)) != 1 or "CERTIFICATE REQUEST" not in csr:
        raise PkiError("not a certificate request")
    openssl("req", "-noout", "-verify", data=csr)
    return openssl("req", "-noout", "-pubkey", data=csr)


def root(path: str, mesh_id: str) -> str:
    """The mesh's root CA, self signed with the key at `path`"""
    return openssl(
        "req", "-x509", "-new", "-key", path, "-subj",
        f"/CN=keel mesh {mesh_id[:16]} etcd root", "-days", str(ROOT_DAYS),
        "-set_serial", f"0x{secrets.token_hex(16)}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash")


def issue(kind: str, issuer_key: str, issuer: str, csr: str, name: str,
          addresses: tuple[str, ...] = (), days: int | None = None) -> str:
    """A certificate of `kind` for the key of `csr`, named `name`, signed
    with the key at `issuer_key` whose certificate is `issuer`; a member
    certificate carries `addresses` as its IP SANs. Raises PkiError"""
    request_key(csr)
    extensions = EXTENSIONS[kind] + IDS
    if addresses:
        extensions += "subjectAltName=" + ",".join(
            f"IP:{ipaddress.ip_address(one)}" for one in addresses) + "\n"
    lasts = days or (CA_DAYS if kind == CA else LEAF_DAYS)
    with tempfile.TemporaryDirectory(prefix="keel-etcd-") as scratch:
        files = {}
        for label, text in (("csr", csr), ("issuer", issuer),
                            ("ext", extensions)):
            files[label] = os.path.join(scratch, label)
            with open(files[label], "w") as fob:
                fob.write(text)
        return openssl(
            "x509", "-req", "-in", files["csr"], "-CA", files["issuer"],
            "-CAkey", issuer_key, "-set_serial",
            f"0x{secrets.token_hex(16)}", "-days", str(lasts), "-subj",
            f"/CN={name}", "-extfile", files["ext"])


def text(certificate: str) -> str:
    return openssl("x509", "-noout", "-text", data=certificate)


def is_ca(certificate: str) -> bool:
    try:
        return "CA:TRUE" in text(certificate)
    except PkiError:
        return False


def addresses(certificate: str) -> tuple[str, ...]:
    """The IP SANs of a certificate, in its order"""
    try:
        found = text(certificate)
    except PkiError:
        return ()
    return tuple(str(ipaddress.ip_address(one))
                 for one in re.findall(r"IP Address:([0-9A-Fa-f:.]+)",
                                       found))


def subject(certificate: str) -> str:
    found = openssl("x509", "-noout", "-subject", "-nameopt", "multiline",
                    data=certificate)
    return found.split("commonName", 1)[1].split("=", 1)[1].strip()


def public(certificate: str) -> str:
    """The public key a certificate certifies, PEM"""
    return openssl("x509", "-noout", "-pubkey", data=certificate)


def not_after(certificate: str) -> datetime:
    found = openssl("x509", "-noout", "-enddate", "-dateopt", "iso_8601",
                    data=certificate)
    return datetime.strptime(found.strip().split("=", 1)[1],
                             "%Y-%m-%d %H:%M:%SZ").replace(
        tzinfo=timezone.utc)


def fingerprint(certificate: str) -> str:
    """SHA-256 of the DER form, in hex: how a root is named"""
    der = subprocess.run([OPENSSL, "x509", "-outform", "DER"],
                         input=certificate.encode(), capture_output=True,
                         check=False, timeout=TIMEOUT).stdout
    return hashlib.sha256(der).hexdigest()


def verified(certificate: str, chain: list[str], trusted: str) -> bool:
    """Whether `certificate` chains to `trusted` through `chain`"""
    with tempfile.TemporaryDirectory(prefix="keel-etcd-") as scratch:
        files = {}
        for label, body in (("leaf", certificate), ("chain", "".join(chain)),
                            ("root", trusted)):
            files[label] = os.path.join(scratch, label)
            with open(files[label], "w") as fob:
                fob.write(body)
        argv = ["verify", "-CAfile", files["root"]]
        if chain:
            argv += ["-untrusted", files["chain"]]
        try:
            openssl(*argv, files["leaf"])
        except PkiError:
            return False
    return True
