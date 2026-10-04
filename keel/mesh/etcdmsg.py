# Copyright (c) 2026 KeelLinux maintainers
"""What members say to each other about etcd (decision 0048)

In the join (keel.mesh.protocol), the request carries `etcd_csr`, the
request for the new node's intermediate CA, only when the node can run
etcd (third round, point 3), and the answer carries `etcd_grant` (the
intermediate, its chain and the root, third round, point 1),
`etcd_cluster` (the cluster to start, `new` at the third member or
`existing` with the new node a learner) and `etcd_ready` (the members
the inviter knows to be ready, the new node among them). The invite's
HMAC covers all of it.

On the members' channel (keel.mesh.memberlink), `POST /v1/etcd` carries
one signed message: what WireGuard says of the sender (who speaks) is
not enough for a message that acts, so the sender signs it with its
Ed25519 key and the receiver checks it against the key its trust store
holds for that member (0048's amendment: "signed by a member's key,
verified by the receiver").

    probe     -> Probe: ready for etcd, its root, formed, its address;
                 changes nothing
    enroll    -> {"csr": ...}: the request for its intermediate, its key
                 made once
    cluster   {"grant": ... or null, "cluster": ..., "ready": {...}}
              -> {"taken": true}: its intermediate if it had none, the
                 cluster to start
"""

import base64
import binascii
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime

from keel.mesh import signing
from keel.mesh.etcdpki import blocks
from keel.mesh.etcdstate import STATES, Cluster, Grant, Member
from keel.mesh.protocol import MESH_ID_RE, SKEW, ProtocolError, loaded
from keel.network.wireguard import is_key

PATH = "/v1/etcd"
PROBE, ENROLL, CLUSTER = "probe", "enroll", "cluster"
KINDS = (PROBE, ENROLL, CLUSTER)
LABEL = b"keel mesh etcd 1\n"
MAX_PEM = 4096
MAX_CHAIN = 8
# etcd's own advice is at most seven voters; a cluster sent is no more
MAX_MEMBERS = 9
MAX_READY = 256


def pem(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) > MAX_PEM or \
            len(blocks(value)) != 1 or blocks(value)[0] != value or \
            f"BEGIN {label}-----" not in value:
        raise ProtocolError(f"not one PEM {label.lower()}")
    return value


def csr(value: object) -> str | None:
    return None if value is None else pem(value, "CERTIFICATE REQUEST")


def grant(value: object) -> Grant | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get("chain"),
                                                     list) or \
            len(value["chain"]) > MAX_CHAIN:
        raise ProtocolError("not an etcd grant")
    return Grant(pem(value.get("certificate"), "CERTIFICATE"),
                 tuple(pem(one, "CERTIFICATE") for one in value["chain"]),
                 pem(value.get("root"), "CERTIFICATE"))


def grant_data(found: Grant | None) -> dict | None:
    if found is None:
        return None
    return {"certificate": found.certificate, "chain": list(found.chain),
            "root": found.root}


def cluster(value: object) -> Cluster | None:
    if value is None:
        return None
    if not isinstance(value, dict) or value.get("state") not in STATES or \
            not isinstance(value.get("members"), list) or \
            len(value["members"]) > MAX_MEMBERS or \
            not isinstance(value.get("token"), str) or \
            not MESH_ID_RE.match(value["token"]):
        raise ProtocolError("not an etcd cluster")
    members = []
    for one in value["members"]:
        if not isinstance(one, dict):
            raise ProtocolError("not an etcd cluster")
        key = one.get("public_key")
        if key is not None and (not isinstance(key, str) or not is_key(key)):
            raise ProtocolError("not an etcd cluster")
        members.append(Member(key, address(one.get("address"))))
    return Cluster(value["state"], tuple(members), value["token"])


def address(value: object) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError(value)
        return str(ipaddress.IPv6Address(value))
    except ValueError:
        raise ProtocolError(f"{value!r} is not an overlay address") from None


def cluster_data(found: Cluster | None) -> dict | None:
    return None if found is None else found.dumps()


def ready(value: object) -> dict[str, str]:
    """Members ready for etcd, WireGuard key to overlay address"""
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_READY:
        raise ProtocolError("not a map of members")
    found = {}
    for key in value:
        if not isinstance(key, str) or not is_key(key):
            raise ProtocolError("not a map of members")
        found[key] = address(value[key])
    return found


@dataclass(frozen=True)
class Message:
    kind: str
    mesh_id: str
    sender: str
    time: int
    body: dict
    raw: bytes
    signature: str

    def verified(self, sign_key: str) -> bool:
        return signing.verified(sign_key, LABEL + self.raw, self.signature)

    def fresh(self, now: datetime) -> bool:
        return abs(self.time - now.timestamp()) <= SKEW.total_seconds()


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def signed(root: str, kind: str, mesh_id: str, sender: str, now: datetime,
           body: dict) -> bytes:
    """A message signed with this node's key; raises SigningError"""
    message = {"kind": kind, "mesh_id": mesh_id, "sender": sender,
               "time": int(now.timestamp()), "body": body}
    signature = signing.sign(root, LABEL + canonical(message))
    return json.dumps({"message": message, "signature": signature}).encode()


def loads(data: bytes) -> Message:
    found = loaded(data)
    message = found.get("message")
    signature = found.get("signature")
    if not isinstance(message, dict) or not isinstance(signature, str):
        raise ProtocolError("not a signed etcd message")
    kind, mesh_id = message.get("kind"), message.get("mesh_id")
    sender, time, body = (message.get("sender"), message.get("time"),
                          message.get("body"))
    if kind not in KINDS or not isinstance(mesh_id, str) or \
            not MESH_ID_RE.match(mesh_id) or not isinstance(sender, str) or \
            not is_key(sender) or type(time) is not int or \
            not isinstance(body, dict):
        raise ProtocolError("not a signed etcd message")
    try:
        base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError):
        raise ProtocolError("not a signed etcd message") from None
    return Message(kind, mesh_id, sender, time, body, canonical(message),
                   signature)


@dataclass(frozen=True)
class Probe:
    """What a member says of itself: ready for etcd (cloud advanced,
    the overlay in its appliance), the fingerprint of the root it holds,
    whether it is in a cluster, its overlay address"""

    ready: bool
    root: str | None
    formed: bool
    address: str


def probe_dumps(is_ready: bool, root: str | None, formed: bool,
                address: str) -> bytes:
    return json.dumps({"ready": is_ready, "root": root, "formed": formed,
                       "address": address}).encode()


def probe_answer(data: bytes) -> Probe:
    found = loaded(data)
    root = found.get("root")
    if type(found.get("ready")) is not bool or \
            type(found.get("formed")) is not bool or \
            not (root is None or (isinstance(root, str) and len(root) == 64
                                  and all(c in "0123456789abcdef"
                                          for c in root))):
        raise ProtocolError("not a probe's answer")
    return Probe(found["ready"], root, found["formed"],
                 address(found.get("address")))


def enroll_answer(data: bytes) -> str:
    return pem(loaded(data).get("csr"), "CERTIFICATE REQUEST")
