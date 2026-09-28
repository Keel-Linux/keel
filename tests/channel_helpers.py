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
REVOKED_UID = "Keel Test Revoked Key <revoked@example.invalid>"
EXPIRED_UID = "Keel Test Expired Key <expired@example.invalid>"
SUBKEY_UID = "Keel Test Revoked Subkey <subkey@example.invalid>"

# When the expired key was made and signed. Far enough back that its
# thirty day life is long over, whatever day the suite runs on.
PAST = "20240101T000000"

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
    """The first tool the channel tests need and this machine lacks

    In CI this raises instead of reporting, so the suite fails rather than
    skipping: without a verifier the signature module is never run, and a
    coverage gate that passes over unrun verification code is exactly the
    shape this project keeps having to fix. Measured: with gpg and gpgv
    off PATH the gate passed at 97 percent with signature.py at 15.
    tests/test_hook_bats.py does the same for bats.
    """
    for tool in TOOLS:
        if shutil.which(tool) is None:
            if os.environ.get("CI"):
                raise AssertionError(
                    f"{tool} is not installed. The channel tests verify real"
                    " signatures; skipping them would leave"
                    " keel/layers/signature.py unrun and still pass the"
                    " coverage gate. Install gnupg and gpgv."
                )
            return tool
    return None


class Keys:
    """A throwaway GNUPGHOME with the keys the refusals need

    Four keys, because gpgv exits 0 and still prints VALIDSIG for three of
    them: the channel key, another key, a key revoked after it signed, and
    a key that has expired. The last two are what prove the verifier
    refuses a retired key rather than trusting the exit status.
    """

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
        self.revoked = self._generate(REVOKED_UID)
        # A revoked key cannot sign, so the secret is copied to a second
        # home first and signing happens there. That is the real shape of
        # the threat too: the thief holds a key the project has revoked.
        self.home_stolen = tempfile.mkdtemp(prefix="keel-stolen-keys.")
        os.chmod(self.home_stolen, 0o700)
        secret = join(self.home, "stolen.key")
        self._gpg(
            "--passphrase", "", "--pinentry-mode", "loopback", "--yes",
            "--output", secret, "--export-secret-keys", self.revoked,
        )
        subprocess.run(
            ["gpg", "--batch", "--quiet", "--homedir", self.home_stolen,
             "--import", secret],
            capture_output=True, text=True, check=True,
        )
        self._revoke(self.revoked)
        self.keyring_revoked = join(self.home, "revoked-keyring.gpg")
        self.export(self.keyring_revoked, self.revoked)
        # A live primary with a revoked signing subkey: the shape
        # apt/keys/keel-archive-keyring.asc already has, and the one where
        # pinning the primary as the accepted signer still matches, because
        # VALIDSIG's last field is the primary fingerprint.
        self.subkey_primary = self._generate(SUBKEY_UID)
        self.subkey_signature = self.clearsign(
            channel_body(), self.subkey_primary
        )
        self._revoke_subkey(self.subkey_primary)
        self.keyring_subkey = join(self.home, "subkey-keyring.gpg")
        self.export(self.keyring_subkey, self.subkey_primary)
        self.expired = self._generate_expired(EXPIRED_UID)
        self.expired_signature = self.clearsign(
            channel_body(), self.expired, at=PAST
        )
        self.keyring_expired = join(self.home, "expired-keyring.gpg")
        self.export(self.keyring_expired, self.expired)

    def _revoke(self, fpr: str) -> None:
        """Import the revocation certificate gpg wrote when the key was made

        The pre-generated certificate in openpgp-revocs.d carries a colon
        before its armor line so it cannot be used by accident; stripping
        it is what the file itself tells the reader to do. --gen-revoke
        refuses to run in batch mode, so this is the only way to revoke a
        key without a terminal.
        """
        source = join(self.home, "openpgp-revocs.d", f"{fpr}.rev")
        target = join(self.home, f"{fpr}.revocation.asc")
        with open(source, encoding="utf-8") as fob:
            text = fob.read()
        with open(target, "w", encoding="utf-8") as fob:
            fob.write(
                "".join(
                    line[1:] if line.startswith(":") else line
                    for line in text.splitlines(keepends=True)
                )
            )
        self._gpg("--import", target)

    def _revoke_subkey(self, fpr: str) -> None:
        """Revoke the signing subkey, leaving the primary alone

        --edit-key does take a command stream in batch mode, unlike
        --gen-revoke, so this one needs no second home: the primary can
        still certify, and it is only the subkey that stops signing.
        """
        subprocess.run(
            ["gpg", "--batch", "--yes", "--quiet", "--homedir", self.home,
             "--command-fd", "0", "--passphrase", "",
             "--pinentry-mode", "loopback", "--edit-key", fpr],
            input="key 1\nrevkey\ny\n0\n\ny\nsave\n",
            capture_output=True, text=True, check=True,
        )

    def _generate_expired(self, uid: str) -> str:
        """A key made in the past with a short life, so it is expired now"""
        real, _, email = uid.partition(" <")
        self._gpg(
            "--faked-system-time", PAST, "--passphrase", "",
            "--pinentry-mode", "loopback", "--quick-generate-key", uid,
            "ed25519", "cert", "30d",
        )
        fpr = self.fingerprint(email.rstrip(">"))
        self._gpg(
            "--faked-system-time", PAST, "--passphrase", "",
            "--pinentry-mode", "loopback", "--quick-add-key", fpr,
            "ed25519", "sign", "30d",
        )
        return fpr

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

    def sign_revoked(self, body: str) -> str:
        """Clear sign with the key the project has since revoked"""
        return self.clearsign(body, self.revoked, home=self.home_stolen)

    def clearsign(
        self, body: str, fpr: str | None = None, at: str | None = None,
        digest: str | None = None, home: str | None = None,
    ) -> str:
        """Clear sign `body` with a key; the channel key by default

        `at` signs with gpg's clock moved, which is how a signature by a
        key that has since expired is made. `digest` picks the hash, for
        the weak-digest case.
        """
        with tempfile.NamedTemporaryFile(
            "w", dir=self.home, delete=False
        ) as fob:
            fob.write(body)
            source = fob.name
        target = source + ".asc"
        when = ["--faked-system-time", at] if at else []
        algo = ["--digest-algo", digest] if digest else []
        subprocess.run(
            ["gpg", "--batch", "--quiet", "--homedir", home or self.home,
             *when, *algo, "--passphrase", "", "--pinentry-mode", "loopback",
             "--local-user", fpr or self.channel, "--yes", "--output", target,
             "--clearsign", source],
            capture_output=True, text=True, check=True,
        )
        with open(target, encoding="utf-8") as fob:
            return fob.read()

    def close(self) -> None:
        for home in (self.home, getattr(self, "home_stolen", None)):
            if home is None:
                continue
            subprocess.run(
                ["gpgconf", "--homedir", home, "--kill", "all"],
                capture_output=True, check=False,
            )
            shutil.rmtree(home, ignore_errors=True)


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
    signed = keys().clearsign(body)
    write(join(root, channel), signed)
    # The same signed bytes archived inside the revision, which is what
    # gives a rollback something to verify against. The publisher does
    # this in mirror_channel_script.
    write(_release_manifest(root, release, rev, "x").replace(
        "x.manifest", layout.REVISION_POINTER), signed)
    return {"fields": fields, "digests": digests, "body": body,
            "signed": signed}


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
