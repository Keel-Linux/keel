# Copyright (c) 2026 KeelLinux maintainers
"""The waiting enrolments, under /var/lib/keel/access/invites (0098)

One file per enrolment, `<id>.json`, mode 0600 in a directory of mode
0700, written through a temporary file and a rename: the computer's
name and reserved /128, the expiry, the TCP port, the TLS key and
certificate of the listener, and the HMAC key the proof is checked
with. That key is derived from the one-use secret of the command
(derive); the secret itself is never stored, so the file cannot be
turned back into the command. State, not configuration: never in the
spec, never backed up.

The proof is computable on the computer with `openssl dgst` alone, on
Linux (OpenSSL 3) and on macOS (LibreSSL): the key is the hex SHA-256 of
`keel-access:<secret>`, used as text, and the proof the hex HMAC-SHA256
of the computer's public key under it.
"""

import hashlib
import hmac
import json
import os
import re
import secrets
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from keel.network.marker import write_private

DIR = "var/lib/keel/access/invites"
DIR_MODE = 0o700
ID_RE = re.compile(r"^[0-9a-f]{16}$")
EXPIRES_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
PREFIX = "keel-access:"
ROOT_UID = 0


@dataclass(frozen=True)
class Invite:
    """One waiting enrolment; no repr shows a key"""

    invite_id: str
    name: str
    address: str
    expires: datetime
    port: int
    certificate: str
    tls_key: str = field(repr=False)
    hmac_key: bytes = field(repr=False)
    consumed: bool = False

    def expired(self, now: datetime) -> bool:
        return now >= self.expires


def new_id() -> str:
    return secrets.token_hex(8)


def new_secret() -> str:
    """32 random bytes, base64url: only letters, digits, - and _"""
    return secrets.token_urlsafe(32)


def derive(secret: str) -> bytes:
    return hashlib.sha256(f"{PREFIX}{secret}".encode()).hexdigest().encode()


def proof(key: bytes, public_key: str) -> str:
    return hmac.new(key, public_key.encode(), hashlib.sha256).hexdigest()


def directory(root: str) -> str:
    return os.path.join(root, DIR)


def save(root: str, found: Invite) -> None:
    path = directory(root)
    os.makedirs(path, mode=DIR_MODE, exist_ok=True)
    os.chmod(path, DIR_MODE)
    data = {"invite_id": found.invite_id, "name": found.name,
            "address": found.address,
            "expires": found.expires.strftime(EXPIRES_FORMAT),
            "port": found.port, "certificate": found.certificate,
            "tls_key": found.tls_key, "hmac_key": found.hmac_key.decode(),
            "consumed": found.consumed}
    write_private(path, f"{found.invite_id}.json", json.dumps(data))


def read(root: str, invite_id: str) -> Invite | None:
    if not ID_RE.match(invite_id):
        return None
    path = os.path.join(directory(root), f"{invite_id}.json")
    try:
        if os.stat(path).st_uid != ROOT_UID:
            return None
        with open(path) as fob:
            data = json.load(fob)
        return Invite(
            invite_id=str(data["invite_id"]), name=str(data["name"]),
            address=str(data["address"]),
            expires=datetime.strptime(data["expires"], EXPIRES_FORMAT)
            .replace(tzinfo=timezone.utc),
            port=int(data["port"]), certificate=str(data["certificate"]),
            tls_key=str(data["tls_key"]),
            hmac_key=str(data["hmac_key"]).encode(),
            consumed=bool(data.get("consumed")))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def find(root: str, invite_id: str, now: datetime) -> Invite | None:
    """The enrolment, while it waits; an expired or damaged one goes"""
    found = read(root, invite_id)
    if found is None or found.expired(now):
        if ID_RE.match(invite_id):
            remove(root, invite_id)
        return None
    return found


def pending(root: str, now: datetime) -> list[Invite]:
    try:
        names = sorted(os.listdir(directory(root)))
    except OSError:
        return []
    found = [find(root, name[:-len(".json")], now) for name in names
             if name.endswith(".json")]
    return [one for one in found if one is not None]


def consume(root: str, invite_id: str) -> None:
    found = read(root, invite_id)
    if found is not None:
        save(root, replace(found, consumed=True))


def remove(root: str, invite_id: str) -> None:
    with suppress(OSError):
        os.remove(os.path.join(directory(root), f"{invite_id}.json"))
