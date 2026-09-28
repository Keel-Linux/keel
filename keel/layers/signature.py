# Copyright (c) 2026 KeelLinux maintainers
"""Verify a clear signed file against a keyring, and return nothing else

`gpgv` is the verifier, because it refuses to do anything but verify: it
cannot be talked into importing a key, consulting a trust database or
asking an agent for anything. It is **not** assumed to be present. On
Debian 13 apt verifies with `sqv` and `gpgv` is a package of its own, so
the keel package depends on it rather than trusting that apt dragged it
in. A machine without it gets a refusal naming the program, never a
verification that quietly did not happen.

Two of its properties decide the shape of this module, and both were
measured rather than assumed:

* **It writes the plain text of a document whose signature it refused.**
  `gpgv --output` produced the body of a tampered pointer and of one
  signed by a key that is not in the keyring, in both cases alongside a
  non zero exit. So the output file is read only after the exit status
  and the status lines have been accepted, and a refusal raises rather
  than returning text a caller might use.
* **Its exit status does not mean the key is good, and neither does
  `VALIDSIG`.** A signature by a revoked primary, by a revoked signing
  subkey under a live primary, or by an expired key each give exit 0, a
  `VALIDSIG` line and `Good signature from` on stderr. `GOODSIG` is the
  one line gpgv withholds, substituting `REVKEYSIG` or `EXPKEYSIG`. This
  module therefore requires `GOODSIG` and refuses outright on the
  retirement lines, because revocation is the only answer to the theft of
  the online key that signs a channel, and a verifier that accepts
  `VALIDSIG` makes revocation do nothing.
* **It reads a binary keyring only.** An ASCII armored keyring, which is
  the form this project publishes its keys in, gives `NO_PUBKEY` and
  exit 2. An armored keyring is therefore dearmored here, in memory,
  into a temporary file gpgv can read.
* **It accepts SHA-1 unless told not to**, so `--weak-digest SHA1` is
  passed.

The accepted signers are a second gate, for the case of one keyring that
holds several project keys: the key that may move a channel is not the
key that says a release was made by a person, and a keyring cannot tell
them apart.
"""

import base64
import os
import subprocess
import tempfile
from dataclasses import dataclass

from keel.layers.constants import (
    ARMOR_END,
    ARMOR_START,
    GOODSIG_RE,
    RETIRED_RE,
    VALIDSIG_RE,
    VERIFIER,
)
from keel.layers.errors import SignatureError


@dataclass(frozen=True)
class Verified:
    """The text the verifier stood behind, and the key that signed it"""

    text: str
    fingerprints: tuple[str, ...]


def dearmor(data: bytes) -> bytes:
    """An armored keyring as its binary form; binary data is returned as is

    Every armored block in the file is decoded and the results are
    concatenated, which is what a keyring of several exported keys looks
    like, and anything before the first armor header is kept as it is, so
    a file holding binary keys followed by an armored one does not lose
    the binary ones. The CRC line is dropped; a corrupt body is caught by
    gpgv, which is the only thing that can judge a key anyway.

    Nothing fetched ever reaches this function. Its input is only ever
    the local path named by --channel-keyring or $KEEL_CHANNEL_KEYRING,
    so a crafted armored blob is not a way in: an attacker who can write
    the keyring has already won without it.
    """
    if ARMOR_START not in data:
        return data
    blocks = data.split(ARMOR_START)
    out = blocks[0]
    for block in blocks[1:]:
        body = block.split(ARMOR_END)[0]
        lines = []
        for line in body.decode("ascii", errors="replace").splitlines():
            line = line.strip()
            if not line or ":" in line or line.startswith("="):
                continue
            lines.append(line)
        try:
            out += base64.b64decode("".join(lines), validate=True)
        except (ValueError, TypeError) as e:
            raise SignatureError(
                f"the armored keyring cannot be decoded: {e}"
            ) from e
    if not out:
        raise SignatureError(
            "the armored keyring holds no OpenPGP key"
        )
    return out


def read_keyring(path: str) -> bytes:
    try:
        with open(path, "rb") as fob:
            return dearmor(fob.read())
    except OSError as e:
        raise SignatureError(f"keyring {path}: {e.strerror or e}") from e


def verify(
    path: str, keyring: str, signers: tuple[str, ...] = ()
) -> Verified:
    """The verified text of a clear signed file; raises SignatureError

    `signers` is the fingerprints that may have signed it, primary or
    subkey; empty means every key in the keyring is accepted.
    """
    try:
        with open(path, "rb") as fob:
            data = fob.read()
    except OSError as e:
        raise SignatureError(f"{path}: {e.strerror or e}") from e
    return verify_bytes(path, data, keyring, signers)


def verify_bytes(
    label: str, data: bytes, keyring: str, signers: tuple[str, ...] = ()
) -> Verified:
    """verify() for a document fetched over the network rather than read

    The bytes are written into the same temporary directory as the
    keyring, because the verifier takes a file and nothing else.
    """
    binary = read_keyring(keyring)
    with tempfile.TemporaryDirectory(prefix="keel-verify.") as work:
        ring = os.path.join(work, "keyring.gpg")
        with open(ring, "wb") as fob:
            fob.write(binary)
        document = os.path.join(work, "document")
        with open(document, "wb") as fob:
            fob.write(data)
        plain = os.path.join(work, "plain")
        status, problem = _run(ring, plain, document)
        if problem is None:
            problem = _status_problem(status)
        if problem is not None:
            raise SignatureError(f"{label}: {problem}")
        fingerprints = _fingerprints(status)
        if not fingerprints:
            raise SignatureError(
                f"{label}: {VERIFIER[0]} said nothing about a valid signature"
            )
        _check_signers(label, fingerprints, signers)
        with open(plain, encoding="utf-8") as fob:
            return Verified(fob.read(), fingerprints)


def _status_problem(status: str) -> str | None:
    """Why the status lines refuse the signature, or None

    Checked before anything is read out of the verifier's output, and
    before the fingerprints are looked at, because a retired key still
    produces a VALIDSIG line naming itself.
    """
    retired = [
        line for line in status.splitlines() if RETIRED_RE.match(line)
    ]
    if retired:
        kind = RETIRED_RE.match(retired[0]).group(1)
        return (
            f"signed by a key that is revoked or expired ({kind}), which"
            f" {VERIFIER[0]} reports with exit 0 and a VALIDSIG line"
        )
    if not any(GOODSIG_RE.match(line) for line in status.splitlines()):
        return (
            f"{VERIFIER[0]} did not call the signature good: no GOODSIG"
            " line, so the key is not one this machine may believe"
        )
    return None


def _run(ring: str, plain: str, path: str) -> tuple[str, str | None]:
    """Run the verifier; the second value is why it was refused, or None"""
    argv = [*VERIFIER, "--status-fd", "1", "--keyring", ring,
            "--output", plain, path]
    try:
        done = subprocess.run(argv, capture_output=True, text=True)
    except OSError as e:
        return "", f"cannot run {VERIFIER[0]}: {e}"
    if done.returncode != 0:
        detail = (done.stderr or "").strip().splitlines()
        reason = detail[-1] if detail else f"exit {done.returncode}"
        return done.stdout, f"signature does not verify: {reason}"
    return done.stdout, None


def _fingerprints(status: str) -> tuple[str, ...]:
    """The fingerprints a VALIDSIG line names: the key and its primary"""
    found: list[str] = []
    for line in status.splitlines():
        match = VALIDSIG_RE.match(line)
        if not match:
            continue
        for value in (match.group("signer"), match.group("primary")):
            if value and value.upper() not in found:
                found.append(value.upper())
    return tuple(found)


def _check_signers(
    path: str, fingerprints: tuple[str, ...], signers: tuple[str, ...]
) -> None:
    if not signers:
        return
    allowed = {value.upper() for value in signers}
    if allowed & set(fingerprints):
        return
    raise SignatureError(
        f"{path}: signed by {', '.join(fingerprints)}, which is not the key"
        f" that may move a channel ({', '.join(sorted(allowed))})"
    )
