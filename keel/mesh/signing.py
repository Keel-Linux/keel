# Copyright (c) 2026 KeelLinux maintainers
"""This node's signing key: Ed25519, long-term, made on the machine

What a member signs is admission evidence: that it admitted a node, by
which invite, with which keys, at which address (keel.mesh.trust). The
key pair is made by `openssl genpkey` (openssl is a dependency of keel)
on the machine itself, never in an image, and kept in
/var/lib/keel/mesh/node.key, 0600; it is never printed. Its public half,
32 bytes in base64 as WireGuard writes its keys, travels in the join's
authenticated answer and in each roster.

openssl signs and verifies Ed25519 only from files (`pkeyutl -rawin`),
so the message, the signature and a public key are written to a
private temporary directory for the call.
"""

import base64
import os
import subprocess
import tempfile

from keel.mesh import DIR
from keel.mesh.invites import locked
from keel.network.marker import path, write_private
from keel.network.wireguard import key_bytes

KEY = f"{DIR}/node.key"
OPENSSL = "openssl"
TIMEOUT = 30
# the DER of an Ed25519 SubjectPublicKeyInfo, before the 32 key bytes
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
SIGNATURE_BYTES = 64


class SigningError(Exception):
    """openssl could not make, read or use this node's signing key"""


def openssl(*argv: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run([OPENSSL, *argv], capture_output=True,
                              check=False, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SigningError(f"openssl could not be run: {e}") from None


def ensure(root: str) -> str:
    """This node's public signing key, the pair made under the mesh's
    lock when there is none; raises SigningError"""
    with locked(root):
        if not os.path.exists(path(root, KEY)):
            made = openssl("genpkey", "-algorithm", "ed25519")
            if made.returncode != 0 or b"PRIVATE KEY" not in made.stdout:
                raise SigningError(f"openssl genpkey exited"
                                   f" {made.returncode}: "
                                   f"{made.stderr.decode()[-200:]}")
            write_private(root, KEY, made.stdout.decode())
    return public(root)


def public(root: str) -> str:
    """This node's public signing key; raises SigningError without one"""
    if not os.path.exists(path(root, KEY)):
        raise SigningError(f"no signing key at /{KEY}: this node holds"
                           " none yet")
    found = openssl("pkey", "-in", path(root, KEY), "-pubout",
                    "-outform", "DER")
    if found.returncode != 0 or not found.stdout.startswith(SPKI_PREFIX):
        raise SigningError(f"/{KEY} does not hold an Ed25519 key")
    return base64.b64encode(found.stdout[len(SPKI_PREFIX):]).decode()


def sign(root: str, message: bytes) -> str:
    """The signature of `message` with this node's key, in base64"""
    with tempfile.TemporaryDirectory(prefix="keel-sign-") as scratch:
        inside = os.path.join(scratch, "message")
        out = os.path.join(scratch, "signature")
        with open(inside, "wb") as fob:
            fob.write(message)
        done = openssl("pkeyutl", "-sign", "-inkey", path(root, KEY),
                       "-rawin", "-in", inside, "-out", out)
        if done.returncode != 0:
            raise SigningError(f"openssl could not sign with /{KEY}:"
                               f" {done.stderr.decode()[-200:]}")
        with open(out, "rb") as fob:
            return base64.b64encode(fob.read()).decode()


def verified(key: str, message: bytes, signature: str) -> bool:
    """Whether `signature` is `key`'s over `message`; never raises for a
    malformed key or signature, which are no signature"""
    raw = key_bytes(key)
    try:
        sig = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError):
        return False
    if raw is None or len(sig) != SIGNATURE_BYTES:
        return False
    with tempfile.TemporaryDirectory(prefix="keel-verify-") as scratch:
        files = {}
        for name, data in (("key", SPKI_PREFIX + raw), ("message", message),
                           ("signature", sig)):
            files[name] = os.path.join(scratch, name)
            with open(files[name], "wb") as fob:
                fob.write(data)
        try:
            done = openssl("pkeyutl", "-verify", "-pubin", "-keyform",
                           "DER", "-inkey", files["key"], "-rawin", "-in",
                           files["message"], "-sigfile", files["signature"])
        except SigningError:
            return False
        return done.returncode == 0
