# Copyright (c) 2026 KeelLinux maintainers
"""What members say to each other about a VIP (decision 0049)

On the members' channel (keel.mesh.memberlink), `POST /v1/vip` carries
one message, signed as an etcd message is (keel.mesh.etcdmsg), with its
own label, `keel vip 1\\n`, so a signature made for one is never taken
for the other: "signed by a member's key, verified by the receiver"
(0048's amendment, which names 0049's announcement).

    claim     {"vip", "epoch", "address"} -> {"applied", "epoch"}: the
              sender holds the VIP at that epoch, at its overlay
              address; what the new holder announces, and what etcd
              stores. A claim is also evidence: it is kept verbatim and
              shown to other nodes, which check its signature, so it
              carries no freshness (an old claim is refused by its
              epoch, never by its age)
    release   {"vip", "epoch"} -> {"released"}: to the holder, from the
              other node of the pair, which will claim at `epoch`; the
              holder drops the address first and answers after
    epoch     {"vip"} -> {"claim"}: the newest claim the receiver took,
              or null; changes nothing
    pair      {"pair"} -> {"pair"}: the pair record, signed by the
              sender, to the other member, which signs it too when its
              own spec declares that VIP (keel.mesh.vippair)

A claim carries the pair record it rests on: only the two nodes the
record names, signed by both, may hold the VIP (0049, third round,
point 3; keel.mesh.vippair).
"""

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import datetime

from keel.mesh import signing, vippair
from keel.mesh.etcdmsg import canonical
from keel.mesh.protocol import MESH_ID_RE, SKEW, ProtocolError, loaded
from keel.mesh.vip import Claim, address
from keel.network.wireguard import is_key

PATH = "/v1/vip"
CLAIM, RELEASE, EPOCH, PAIR = "claim", "release", "epoch", "pair"
KINDS = (CLAIM, RELEASE, EPOCH, PAIR)
LABEL = b"keel vip 1\n"
# a claim with its pair record is about 1200 bytes; an answer carries one
MAX_MESSAGE = 8192
MAX_EPOCH = 2 ** 62


@dataclass(frozen=True)
class Message:
    kind: str
    mesh_id: str
    sender: str
    time: int
    body: dict
    raw: bytes
    data: bytes
    signature: str

    def verified(self, sign_key: str) -> bool:
        return signing.verified(sign_key, LABEL + self.raw, self.signature)

    def fresh(self, now: datetime) -> bool:
        return abs(self.time - now.timestamp()) <= SKEW.total_seconds()

    def vip(self) -> str:
        try:
            return address(self.body.get("vip"))
        except ValueError:
            raise ProtocolError("no VIP in the message") from None

    def epoch(self) -> int:
        found = self.body.get("epoch")
        if type(found) is not int or not 0 < found < MAX_EPOCH:
            raise ProtocolError("no epoch in the message")
        return found


def signed(root: str, kind: str, mesh_id: str, sender: str, now: datetime,
           body: dict) -> bytes:
    """A message signed with this node's key; raises SigningError"""
    message = {"kind": kind, "mesh_id": mesh_id, "sender": sender,
               "time": int(now.timestamp()), "body": body}
    signature = signing.sign(root, LABEL + canonical(message))
    return json.dumps({"message": message, "signature": signature},
                      sort_keys=True).encode()


def loads(data: bytes) -> Message:
    if len(data) > MAX_MESSAGE:
        raise ProtocolError("longer than any VIP message")
    found = loaded(data)
    message = found.get("message")
    signature = found.get("signature")
    if not isinstance(message, dict) or not isinstance(signature, str):
        raise ProtocolError("not a signed VIP message")
    kind, mesh_id = message.get("kind"), message.get("mesh_id")
    sender, time, body = (message.get("sender"), message.get("time"),
                          message.get("body"))
    if kind not in KINDS or not isinstance(mesh_id, str) or \
            not MESH_ID_RE.match(mesh_id) or not isinstance(sender, str) or \
            not is_key(sender) or type(time) is not int or \
            not isinstance(body, dict):
        raise ProtocolError("not a signed VIP message")
    try:
        base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError):
        raise ProtocolError("not a signed VIP message") from None
    return Message(kind, mesh_id, sender, time, body, canonical(message),
                   data, signature)


def claim_of(data: bytes) -> Claim:
    """The claim a signed `claim` message makes; ProtocolError for any
    other message. Its signature is the caller's to check."""
    message = loads(data)
    if message.kind != CLAIM:
        raise ProtocolError("not a claim")
    try:
        at = address(message.body.get("address"))
    except ValueError:
        raise ProtocolError("no overlay address in the claim") from None
    found = message.body.get("pair")
    pair = None if found is None else vippair.loads(found)
    return Claim(message.vip(), message.epoch(), message.sender, at, data,
                 pair)


def claim(root: str, mesh_id: str, sender: str, now: datetime, vip: str,
          epoch: int, at: str, pair=None) -> Claim:
    """This node's claim, signed, with the pair record it rests on;
    raises SigningError"""
    body = {"vip": vip, "epoch": epoch, "address": at}
    if pair is not None:
        body["pair"] = pair.dumps()
    return claim_of(signed(root, CLAIM, mesh_id, sender, now, body))


def answer_claim(data: bytes) -> Claim | None:
    """The claim an `epoch` answer carries, or None; ProtocolError"""
    found = loaded(data).get("claim")
    if found is None:
        return None
    if not isinstance(found, str):
        raise ProtocolError("not an epoch's answer")
    try:
        return claim_of(base64.b64decode(found, validate=True))
    except (binascii.Error, ValueError):
        raise ProtocolError("not an epoch's answer") from None


def epoch_answer(held_claim: Claim | None) -> bytes:
    return json.dumps({"claim": None if held_claim is None else
                       base64.b64encode(held_claim.raw).decode()}).encode()
