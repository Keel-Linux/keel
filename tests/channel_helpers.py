# Copyright (c) 2026 KeelLinux maintainers
"""Shared helpers for the channel tests: real keys, real signatures

A channel pointer is the one mutable object in the mirror and the whole
of its trust, so the tests sign with a real OpenPGP key and verify with
the real verifier. Two keys are made once per run in a throwaway
GNUPGHOME: the channel key a mirror is supposed to be signed with, and
another key that stands for any key that is not it.
"""

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from os.path import abspath, dirname, join

sys.path.insert(0, dirname(dirname(abspath(__file__))))

from layers_helpers import build_source, sha256, write  # noqa: E402

from keel.layers import layout  # noqa: E402

CHANNEL_UID = "Keel Test Channel Key <channel@example.invalid>"
OTHER_UID = "Keel Test Other Key <other@example.invalid>"

KEY_TEMPLATE = """%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: cert,sign
Name-Real: {real}
Name-Email: {email}
Expire-Date: 0
%commit
"""

TOOLS = ("gpg", "gpgv")

_keys = None


def tools_missing() -> str | None:
    """The first tool the channel tests need and this machine lacks"""
    for tool in TOOLS:
        if shutil.which(tool) is None:
            return tool
    return None


class Keys:
    """A throwaway GNUPGHOME with a channel key and one other key"""

    def __init__(self):
        self.home = tempfile.mkdtemp(prefix="keel-channel-keys.")
        os.chmod(self.home, 0o700)
        self.channel = self._generate(CHANNEL_UID)
        self.other = self._generate(OTHER_UID)
        self.keyring = join(self.home, "channel-keyring.gpg")
        self.keyring_armored = join(self.home, "channel-keyring.asc")
        self.export(self.keyring, self.channel)
        self.export(self.keyring_armored, self.channel, armored=True)
        self.both = join(self.home, "both-keyring.gpg")
        self.export(self.both, self.channel, self.other)

    def _gpg(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["gpg", "--batch", "--quiet", "--homedir", self.home, *args],
            capture_output=True, text=True, check=True,
        )

    def _generate(self, uid: str) -> str:
        real, _, email = uid.partition(" <")
        with tempfile.NamedTemporaryFile(
            "w", dir=self.home, suffix=".conf", delete=False
        ) as fob:
            fob.write(
                KEY_TEMPLATE.format(real=real, email=email.rstrip(">"))
            )
            path = fob.name
        self._gpg("--generate-key", path)
        return self.fingerprint(uid)

    def fingerprint(self, uid: str) -> str:
        out = self._gpg("--with-colons", "--list-keys", uid).stdout
        for line in out.splitlines():
            parts = line.split(":")
            if parts[0] == "fpr":
                return parts[9]
        raise AssertionError(f"no fingerprint for {uid}")

    def export(self, path: str, *fprs: str, armored: bool = False) -> str:
        args = ["--output", path, "--yes"]
        if armored:
            args.append("--armor")
        self._gpg(*args, "--export", *fprs)
        return path

    def clearsign(self, body: str, fpr: str | None = None) -> str:
        """Clear sign `body` with a key; the channel key by default"""
        with tempfile.NamedTemporaryFile(
            "w", dir=self.home, delete=False
        ) as fob:
            fob.write(body)
            source = fob.name
        target = source + ".asc"
        self._gpg(
            "--local-user", fpr or self.channel, "--yes", "--output", target,
            "--clearsign", source,
        )
        with open(target, encoding="utf-8") as fob:
            return fob.read()

    def close(self) -> None:
        subprocess.run(
            ["gpgconf", "--homedir", self.home, "--kill", "all"],
            capture_output=True, check=False,
        )
        shutil.rmtree(self.home, ignore_errors=True)


def keys() -> Keys:
    """The keys of this test run, made on first use and kept"""
    global _keys
    if _keys is None:
        _keys = Keys()
        atexit.register(_keys.close)
    return _keys


def stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def channel_body(
    name: str = "stable",
    release: str = "2026-09-28",
    rev: int = 1,
    signed_at: datetime | None = None,
    expires_at: datetime | None = None,
    digests: dict[str, str] | None = None,
    extra: str = "",
) -> str:
    """The body of a channel pointer, as bin/keel-channel writes it"""
    signed_at = signed_at or now()
    expires_at = (
        signed_at + timedelta(days=7) if expires_at is None else expires_at
    )
    text = (
        f"channel {name}\n"
        f"release {release}\n"
        f"rev {rev}\n"
        f"signed_at {stamp(signed_at)}\n"
        f"expires_at {stamp(expires_at)}\n"
    )
    if digests is None:
        digests = {"core": "a" * 64}
    for layer, digest in digests.items():
        text += f"layer {layer} {digest}\n"
    return text + extra


def manifest_digest(text: str) -> str:
    return sha256(text.encode("utf-8"))


def build_mirror(
    root: str,
    release: str = "2026-09-28",
    rev: int = 1,
    channel: str = "stable",
    flat: bool = True,
    **channel_fields,
) -> dict:
    """A mirror tree in the new layout, and the flat one beside it

    Returns the manifest fields of core and lamp with the channel text
    and the manifest digests the channel names, so a test can rewrite
    any one of them.
    """
    fields = build_source(root)
    tarballs = {
        name: read_bytes(join(root, layer["tarball"]))
        for name, layer in fields.items()
    }
    digests = {}
    for name, layer in fields.items():
        text = "".join(f"{key} {value}\n" for key, value in layer.items())
        digests[name] = manifest_digest(text)
        write(_release_manifest(root, release, rev, name), text)
    blobs = join(root, layout.BLOB_DIR)
    os.makedirs(blobs, exist_ok=True)
    for name, layer in fields.items():
        write(join(blobs, layer["sha256"]), tarballs[name])
    if not flat:
        for name, layer in fields.items():
            os.remove(join(root, f"{name}.manifest"))
            os.remove(join(root, layer["tarball"]))
    body = channel_body(
        name=channel, release=release, rev=rev, digests=digests,
        **channel_fields,
    )
    write(join(root, channel), keys().clearsign(body))
    return {"fields": fields, "digests": digests, "body": body}


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as fob:
        return fob.read()


def _release_manifest(root: str, release: str, rev: int, name: str) -> str:
    path = join(root, layout.manifest_path(release, rev, name))
    os.makedirs(dirname(path), exist_ok=True)
    return path


def write_channel(root: str, name: str, body: str, fpr: str | None = None):
    """Replace a channel pointer with one signed over `body`"""
    return write(join(root, name), keys().clearsign(body, fpr))
