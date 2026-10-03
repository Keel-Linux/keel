# Copyright (c) 2026 KeelLinux maintainers
"""The pending invites, under /var/lib/keel/mesh/invites (decision 0048)

One file per invite, `<id>.json`, mode 0600 in directories of mode 0700:
the reserved address, the expiry, the HTTPS port, the invite's TLS key
and certificate, and the HMAC key the join request is checked with. That
key is derived from the token's secret (keel.mesh.token.hmac_key); the
secret itself is never stored, so the file cannot be turned back into
the token. State, not configuration: never in the spec, never emitted,
never backed up.

Files are written as /var/lib/keel/network's are, through a temporary
file and a rename (keel.network.marker.write_private), and every change
holds the mesh's lock, so two invites never reserve the same address
and an invite is consumed once. A consumed invite is marked so and kept:
its address stays reserved until the invite expires, by which time the
join has put the new node in the spec as a peer, whose allowed_ips the
allocator avoids anyway. An expired or damaged invite's file is
removed.
"""

import fcntl
import ipaddress
import json
import os
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone

from keel.mesh import DIR, DIR_MODE, FILE_MODE, LOCK
from keel.network.marker import path, write_private

INVITES = f"{DIR}/invites"
ID_RE = re.compile(r"^[0-9a-f]{16}$")
FILE_RE = re.compile(r"^([0-9a-f]{16})\.json$")
# what a write that never reached its rename leaves (write_private)
STALE_RE = re.compile(r"^[0-9a-f]{16}\.json\.new$")
EXPIRES_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class InviteError(Exception):
    """An invite that cannot be reserved or consumed, and why"""


@dataclass(frozen=True)
class Pending:
    """One pending invite as its file holds it; no repr shows a key"""

    invite_id: str
    address: str
    expires: datetime
    https_port: int
    certificate: str
    hmac_key: bytes = field(repr=False)
    tls_key: str = field(repr=False)
    consumed: bool = False

    def expired(self, now: datetime) -> bool:
        return now >= self.expires


@contextmanager
def locked(root: str) -> Iterator[None]:
    """The mesh's one lock, as keel.network.marker.locked holds its own"""
    ensure(root)
    fd = os.open(path(root, LOCK), os.O_RDWR | os.O_CREAT, FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def ensure(root: str) -> None:
    """The directories, root's alone even when something widened them"""
    for relative in (DIR, INVITES):
        directory = path(root, relative)
        os.makedirs(directory, mode=DIR_MODE, exist_ok=True)
        os.chmod(directory, DIR_MODE)


def reserve(root: str, now: datetime,
            make: Callable[[tuple[Pending, ...]], Pending]) -> Pending:
    """Write the invite `make` returns, given the others still pending

    Under the lock, after the expired ones are removed, so the address
    `make` picks is free of every other invite's. An id already pending
    is refused; whatever `make` raises propagates and nothing is written.
    """
    with locked(root):
        purge(root, now)
        made = make(tuple(listed(root)))
        if read(root, made.invite_id) is not None:
            raise InviteError(f"invite {made.invite_id} is already pending")
        write_private(root, relative(made.invite_id), dumps(made))
    return made


def find(root: str, invite_id: str, now: datetime) -> Pending | None:
    """The pending invite of that id; None when unknown or expired"""
    found = read(root, invite_id)
    return None if found is None or found.expired(now) else found


def pending(root: str, now: datetime) -> tuple[Pending, ...]:
    """The invites still pending, read without the lock"""
    return tuple(found for found in listed(root) if not found.expired(now))


def consume(root: str, invite_id: str, now: datetime,
            verify: Callable[[Pending], bool] | None = None) -> Pending:
    """Spend the invite, once: check it, mark it consumed, return it

    `verify` is the request's check (its HMAC, in the listener), run
    under the same lock, so a second request finds the invite used. A
    request it refuses leaves the invite pending. The consumed invite
    keeps its address reserved until it expires. Raises InviteError.
    """
    with locked(root):
        found = read(root, invite_id)
        if found is None:
            raise InviteError(f"no pending invite {invite_id}: it was used,"
                              " or never made here")
        if found.expired(now):
            remove(root, invite_id)
            raise InviteError(f"invite {invite_id} expired at"
                              f" {found.expires:%Y-%m-%d %H:%M:%S} UTC")
        if found.consumed:
            raise InviteError(f"invite {invite_id} was already used")
        if verify is not None and not verify(found):
            raise InviteError(f"invite {invite_id}: request refused")
        spent = replace(found, consumed=True)
        write_private(root, relative(invite_id), dumps(spent))
    return spent


def expire(root: str, now: datetime) -> tuple[str, ...]:
    """Remove the expired invites and the damaged files; their ids"""
    with locked(root):
        return purge(root, now)


def purge(root: str, now: datetime) -> tuple[str, ...]:
    """Under the lock: no write is under way, so a .new file is stale"""
    for name in os.listdir(path(root, INVITES)):
        if STALE_RE.match(name):
            with suppress(FileNotFoundError):
                os.remove(path(root, f"{INVITES}/{name}"))
    removed = []
    for invite_id in ids(root):
        found = read(root, invite_id)
        if found is None or found.expired(now):
            remove(root, invite_id)
            removed.append(invite_id)
    return tuple(removed)


def listed(root: str) -> list[Pending]:
    return [found for found in map(lambda one: read(root, one), ids(root))
            if found is not None]


def ids(root: str) -> list[str]:
    try:
        names = os.listdir(path(root, INVITES))
    except FileNotFoundError:
        return []
    return sorted(found.group(1) for found in map(FILE_RE.match, names)
                  if found)


def relative(invite_id: str) -> str:
    return f"{INVITES}/{invite_id}.json"


def read(root: str, invite_id: str) -> Pending | None:
    """The invite's file; None when absent, damaged, or not an id"""
    if not ID_RE.match(invite_id):
        return None
    try:
        with open(path(root, relative(invite_id))) as fob:
            data = json.load(fob)
        return Pending(
            invite_id=invite_id,
            address=str(ipaddress.IPv6Interface(str(data["address"]))),
            expires=datetime.strptime(
                data["expires"], EXPIRES_FORMAT).replace(
                    tzinfo=timezone.utc),
            https_port=int(data["https_port"]),
            certificate=str(data["certificate"]),
            hmac_key=bytes.fromhex(data["hmac_key"]),
            tls_key=str(data["tls_key"]),
            consumed=consumed(data.get("consumed", False)),
        )
    except (OSError, ValueError, KeyError, TypeError):
        return None


def consumed(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("consumed is true or false")
    return value


def dumps(pending: Pending) -> str:
    return json.dumps({
        "address": pending.address,
        "expires": pending.expires.astimezone(timezone.utc).strftime(
            EXPIRES_FORMAT),
        "https_port": pending.https_port,
        "certificate": pending.certificate,
        "hmac_key": pending.hmac_key.hex(),
        "tls_key": pending.tls_key,
        "consumed": pending.consumed,
    }, indent=2) + "\n"


def remove(root: str, invite_id: str) -> None:
    with suppress(FileNotFoundError):
        os.remove(path(root, relative(invite_id)))
