# Copyright (c) 2026 KeelLinux maintainers
"""The mesh's etcd CA: a root, and the leaves it signs itself

etcd uses its own TLS, peer and client (0048, second round, point 3),
with a CA the first node makes, whose key stays on that node, the
root's holder. The root signs every certificate etcd is shown itself
(keel#83, amending 0048's third round, point 1, and 0051's intermediate
per member): a member's certificate, which names the member by its mesh
identity in its CN (keel.mesh.etcdstate.name, from its overlay address)
and carries its /128 and ::1 as its IP SANs, and the holder's admin
certificate, CN `root`, which only the holder holds. No member holds a
CA key, so no member can make a certificate etcd takes, and etcd's
users, which are the CNs of client certificates, mean what they say
(keel.mesh.etcdauth). A member's certificate is its peer, server and
client certificate alike: keel asks etcd with it.

All P-256, made with `openssl` (a dependency of keel) on the machine
itself, never in an image. A key is made on standard output and written
by the caller to its state, 0600, so no key is ever in a temporary
file; a signing key is handed to openssl by its path. What a request
asks for is ignored: the issuer takes only its public key, after
checking the request's own signature, and sets the subject and every
extension itself, so a request that asks for `CA:TRUE`, another name or
another address gets none of it.

Short lives, so that a key that leaks stops working by itself: a leaf
lasts 30 days and is renewed by the root, asked over the members'
channel, with a third left (`keel mesh etcd tend`); while the root's
holder cannot be reached a renewal waits, and is alerted.

Revocation is a CRL the root signs (`crl`), which etcd checks against
every certificate a peer or a client presents, chain included; the
intermediates of the layout before keel#83 are revoked by it once every
member holds a certificate the root signed (keel.mesh.etcdreissue).
"""

import base64
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
MEMBER, CLIENT = "member", "client"
# the root outlives every leaf it signs; a leaf is renewed with a third
# of its life left
ROOT_DAYS = 7300
LEAF_DAYS = 30
CRL_DAYS = 30
PEM_RE = re.compile(r"-----BEGIN (?P<label>[A-Z0-9 ]+)-----\n[A-Za-z0-9+/=\n]+"
                    r"-----END (?P=label)-----\n")
EXTENSIONS = {
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
    """A leaf of `kind` for the key of `csr`, its CN `name`, signed with
    the key at `issuer_key` whose certificate is `issuer` (the root); a
    member certificate carries `addresses` as its IP SANs. Never a CA.
    Raises PkiError"""
    request_key(csr)
    if kind not in EXTENSIONS or not name or "/" in name or \
            any(ord(one) < 0x20 for one in name):
        raise PkiError(f"not a certificate keel issues: {kind} {name!r}")
    extensions = EXTENSIONS[kind] + IDS
    if addresses:
        extensions += "subjectAltName=" + ",".join(
            f"IP:{ipaddress.ip_address(one)}" for one in addresses) + "\n"
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
            f"0x{secrets.token_hex(16)}", "-days", str(days or LEAF_DAYS),
            "-subj", f"/CN={name}", "-extfile", files["ext"])


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
    try:
        done = subprocess.run([OPENSSL, "x509", "-outform", "DER"],
                              input=certificate.encode(), capture_output=True,
                              check=False, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PkiError(f"openssl could not be run: {e}") from None
    if done.returncode != 0 or not done.stdout:
        raise PkiError("not a certificate")
    return hashlib.sha256(done.stdout).hexdigest()


def verified(certificate: str, chain: list[str], anchor: str) -> bool:
    """Whether `certificate` chains to `anchor` through `chain`"""
    with tempfile.TemporaryDirectory(prefix="keel-etcd-") as scratch:
        files = {}
        for label, body in (("leaf", certificate), ("chain", "".join(chain)),
                            ("root", anchor)):
            files[label] = os.path.join(scratch, label)
            with open(files[label], "w") as fob:
                fob.write(body)
        argv = ["verify", "-CAfile", files["root"]]
        if chain:
            argv += ["-unanchor", files["chain"]]
        try:
            openssl(*argv, files["leaf"])
        except PkiError:
            return False
    return True


def serial(certificate: str) -> str:
    """The serial number, in upper case hex as a CRL names it"""
    found = openssl("x509", "-noout", "-serial", data=certificate)
    return found.strip().split("=", 1)[1].upper()


def sign(key: str, data: bytes) -> str:
    """The signature of `data` with the key at `key`, in base64"""
    with tempfile.TemporaryDirectory(prefix="keel-etcd-") as scratch:
        inside, out = (os.path.join(scratch, one) for one in ("in", "sig"))
        with open(inside, "wb") as fob:
            fob.write(data)
        openssl("dgst", "-sha256", "-sign", key, "-out", out, inside)
        with open(out, "rb") as fob:
            return base64.b64encode(fob.read()).decode()


def verified_by(certificate: str, data: bytes, signature: str) -> bool:
    """Whether `signature` is the certified key's over `data`"""
    try:
        raw = base64.b64decode(signature, validate=True)
        key = public(certificate)
    except (ValueError, PkiError):
        return False
    with tempfile.TemporaryDirectory(prefix="keel-etcd-") as scratch:
        files = {}
        for label, body in (("in", data), ("sig", raw),
                            ("key", key.encode())):
            files[label] = os.path.join(scratch, label)
            with open(files[label], "wb") as fob:
                fob.write(body)
        try:
            openssl("dgst", "-sha256", "-verify", files["key"],
                    "-signature", files["sig"], files["in"])
        except PkiError:
            return False
    return True


def crl(key: str, issuer: str, revoked: dict[str, tuple[str, str]],
        number: int) -> str:
    """A CRL signed with the key at `key` whose certificate is `issuer`:
    `revoked` maps a serial to (its expiry, when it was revoked), both
    as openssl's index writes them (YYMMDDHHMMSSZ)"""
    with tempfile.TemporaryDirectory(prefix="keel-etcd-") as scratch:
        index = os.path.join(scratch, "index.txt")
        with open(index, "w") as fob:
            for one, (expiry, when) in sorted(revoked.items()):
                fob.write(f"R\t{expiry}\t{when}\t{one}\tunknown\t/CN=x\n")
        with open(os.path.join(scratch, "crlnumber"), "w") as fob:
            fob.write(f"{number:02X}\n")
        conf = os.path.join(scratch, "ca.cnf")
        with open(conf, "w") as fob:
            fob.write(f"[ca]\ndefault_ca=c\n[c]\ndatabase={index}\n"
                      f"crlnumber={scratch}/crlnumber\ndefault_md=sha256\n"
                      f"default_crl_days={CRL_DAYS}\n")
        with open(os.path.join(scratch, "issuer"), "w") as fob:
            fob.write(issuer)
        return openssl("ca", "-config", conf, "-gencrl", "-batch",
                       "-keyfile", key, "-cert",
                       os.path.join(scratch, "issuer"))


def crl_number(found: str) -> int:
    text = openssl("crl", "-noout", "-crlnumber", data=found)
    return int(text.strip().split("=", 1)[1], 16)


def crl_serials(found: str) -> set[str]:
    text = openssl("crl", "-noout", "-text", data=found)
    return {one.upper() for one in re.findall(
        r"Serial Number: ([0-9A-Fa-f]+)", text)}


def crl_verified(found: str, anchor: str) -> bool:
    """Whether `found` is one CRL, signed by the root `anchor`"""
    if len(blocks(found)) != 1 or "X509 CRL" not in found:
        return False
    with tempfile.TemporaryDirectory(prefix="keel-etcd-") as scratch:
        root_file = os.path.join(scratch, "root")
        with open(root_file, "w") as fob:
            fob.write(anchor)
        try:
            openssl("crl", "-noout", "-CAfile", root_file, data=found)
        except PkiError:
            return False
    return True


def stamp(when: datetime) -> str:
    """A time as openssl's index writes it"""
    return when.astimezone(timezone.utc).strftime("%y%m%d%H%M%SZ")
