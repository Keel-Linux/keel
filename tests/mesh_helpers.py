# Copyright (c) 2026 KeelLinux maintainers
"""What the mesh tests share: a pending invite, a node that records

`FakeNode` stands in for keel.mesh.node.Node at the listener's and the
commands' seam: it records the peers it is asked to admit and the
origins it is asked to confirm, and answers as told. `reserved` writes
a pending invite with a real certificate from openssl (a dependency of
keel), so the TLS tests serve and pin a real one.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from keel.mesh import certificate, invites, protocol
from keel.mesh.node import Change
from keel.mesh.token import hmac_key, invite_id
from keel.network import marker

SECRET = bytes(range(32))
KEY = hmac_key(SECRET)
INVITE = invite_id(SECRET)
JOINER = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="
INVITER = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
OTHER = "9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE="
NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
ASSIGNED = "fd00:6b65:1::3/64"
OWN = "fd00:6b65:1::1/64"
MADE = marker.Pending(iface="wg0", path="etc/wireguard/wg0.conf",
                      window=120, addresses=("fd00:6b65:1::1",),
                      kind=marker.OVERLAY).up("b1", 50.0)

_TLS: list[tuple[str, str]] = []


def tls() -> tuple[str, str]:
    """One key and certificate for the whole run: openssl takes a while"""
    if not _TLS:
        _TLS.append(certificate.make())
    return _TLS[0]


def reserved(root: str, port: int = 51820, expires: datetime | None = None,
             secret: bytes = SECRET) -> invites.Pending:
    key, cert = tls()
    made = invites.Pending(
        invite_id=invite_id(secret), address=ASSIGNED,
        expires=expires or NOW + timedelta(hours=1), https_port=port,
        certificate=cert, hmac_key=hmac_key(secret), tls_key=key)
    return invites.reserve(root, NOW, lambda others: made)


@dataclass
class FakeNode:
    is_waiting: bool = False
    code: int = 0
    made: marker.Pending | None = MADE
    confirmed: bool = True
    known: tuple[protocol.Peer, ...] = ()
    admitted: list[dict] = field(default_factory=list)
    origins: list = field(default_factory=list)
    overlay_value: dict = field(default_factory=dict)
    # what `wg show IFACE latest-handshakes` gives for the new node's key
    handshake_at: int | None = int(NOW.timestamp())
    asked: list[str] = field(default_factory=list)

    def handshake(self, key: str) -> int | None:
        self.asked.append(key)
        return self.handshake_at

    def overlay(self) -> dict:
        return self.overlay_value

    def waiting(self) -> bool:
        return self.is_waiting

    def admit(self, peer: dict, window: int | None = None) -> Change:
        self.admitted.append(peer)
        return Change(self.code, self.made)

    def peers(self, but: str) -> tuple[protocol.Peer, ...]:
        return self.known

    def confirm(self, origin, made):
        self.origins.append((origin, made))
        return self.confirmed, [f"confirmed from {origin.detail}"]


class Clock:
    def __init__(self, now: datetime = NOW):
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def join_body(**changed) -> bytes:
    data = {"invite_id": INVITE, "public_key": JOINER,
            "endpoint": "[2001:db8:2::20]:51820", "address": ASSIGNED,
            "nonce": protocol.new_nonce(), "time": protocol.seconds(NOW)}
    data.update(changed)
    return json.dumps(data).encode()


def confirm_body(**changed) -> bytes:
    data = {"invite_id": INVITE, "public_key": JOINER,
            "nonce": protocol.new_nonce(), "time": protocol.seconds(NOW)}
    data.update(changed)
    return json.dumps(data).encode()


def signature(path: str, body: bytes, key: bytes = KEY) -> str:
    return protocol.sign(key, protocol.METHOD, path, body)
