# Copyright (c) 2026 KeelLinux maintainers
"""What members say to each other about etcd (decision 0048)

In the join (keel.mesh.protocol), the request carries `etcd_csr`, the
request for the new node's certificate, only when the node can run etcd
(third round, point 3), and the answer carries `etcd_grant` (the
certificate the root signed, and the root; keel#83),
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

    probe     -> Probe: ready for etcd, its root, formed, its address,
                 whether it holds the root's key, its PKI (2 since
                 keel#83) and whether it still holds an intermediate;
                 changes nothing
    enroll    -> {"csr": ..., "proof": ...}: the request for its
                 certificate, its key made once, and its signature over
                 it with its signing key (keel.mesh.etcdproof)
    cluster   {"grant": ... or null, "cluster": ..., "ready": {...}}
              -> {"taken": true}: its certificate if it had none, the
                 cluster to start, with its formation record signed by
                 the root (keel.mesh.etcdca)
    issue     {"csr": ..., "proof": ..., "address": ..., "public_key":
              ..., "admission": ... or null} -> {"grant": ...}: to the
              root's holder, a certificate signed by the root, for a
              member's own renewal (no admission) or a node an inviter
              admits (its admission evidence); signed only when the
              request is shown to be that member's (keel.mesh.etcdproof)
    revoke    {"address": ..., "public_key": ...} -> {"crl": ...}: to
              the root's holder, a removed node's certificates revoked,
              its etcd member and user removed, the new CRL
    reissue   {"grant": ...} -> {"taken": true}: from the root's holder,
              this member's certificate signed by the root, in place of
              its intermediate's (keel mesh etcd reissue)
    crl       {"crl": ...} -> {"taken": bool}: the root's CRL, taken
              when the root signed it and it is newer
    pair      {"pair": ...} -> {"roles": [...]}: to the root's holder,
              from a member of a VIP's pair: the record, so the pair's
              two members get read-write on its keys (keel.mesh.etcdauth)
"""

import base64
import binascii
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime

from keel.mesh import etcdproof, signing
from keel.mesh.etcdpki import blocks
from keel.mesh.etcdstate import STATES, Cluster, Grant, Member
from keel.mesh.protocol import MESH_ID_RE, SKEW, ProtocolError, loaded
from keel.network.wireguard import is_key

PATH = "/v1/etcd"
PROBE, ENROLL, CLUSTER = "probe", "enroll", "cluster"
ISSUE, REVOKE = "issue", "revoke"
REISSUE, CRL_KIND, PAIR = "reissue", "crl", "pair"
KINDS = (PROBE, ENROLL, CLUSTER, ISSUE, REVOKE, REISSUE, CRL_KIND, PAIR)
# the PKI a member runs: 1, an intermediate per member; 2, every
# certificate signed by the root (keel#83). A probe without it is 1
PKI = 2
MAX_RECORD = 16384
LABEL = b"keel mesh etcd 1\n"
MAX_PEM = 4096
# a grant carries no chain: the root signs every certificate itself
MAX_CHAIN = 0
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
    found = value.get("crl")
    at = value.get("holder")
    return Grant(pem(value.get("certificate"), "CERTIFICATE"),
                 tuple(pem(one, "CERTIFICATE") for one in value["chain"]),
                 pem(value.get("root"), "CERTIFICATE"),
                 None if found is None else crl(found),
                 None if at is None else address(at))


def crl(value: object) -> str:
    """One PEM CRL, of any size a roster can carry"""
    if not isinstance(value, str) or len(value) > MAX_RECORD * 8 or \
            len(blocks(value)) != 1 or blocks(value)[0] != value or \
            "BEGIN X509 CRL-----" not in value:
        raise ProtocolError("not one PEM CRL")
    return value


def grant_data(found: Grant | None) -> dict | None:
    if found is None:
        return None
    return {"certificate": found.certificate, "chain": list(found.chain),
            "root": found.root, "crl": found.crl, "holder": found.holder}


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
    record, signature = value.get("record"), value.get("signature")
    for one in (record, signature):
        if one is not None and (not isinstance(one, str)
                                or len(one) > MAX_RECORD):
            raise ProtocolError("not an etcd cluster")
    return Cluster(value["state"], tuple(members), value["token"], record,
                   signature)


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
    whether it is in a cluster, its overlay address, whether it holds
    the root CA's key, the PKI its keel runs, and whether it still holds
    an intermediate (the layout before keel#83)"""

    ready: bool
    root: str | None
    formed: bool
    address: str
    holder: bool = False
    pki: int = 1
    legacy: bool = False


def probe_dumps(is_ready: bool, root: str | None, formed: bool,
                address: str, holder: bool = False,
                legacy: bool = False) -> bytes:
    return json.dumps({"ready": is_ready, "root": root, "formed": formed,
                       "address": address, "holder": holder, "pki": PKI,
                       "legacy": legacy}).encode()


def probe_answer(data: bytes) -> Probe:
    found = loaded(data)
    root = found.get("root")
    if type(found.get("ready")) is not bool or \
            type(found.get("formed")) is not bool or \
            not (root is None or (isinstance(root, str) and len(root) == 64
                                  and all(c in "0123456789abcdef"
                                          for c in root))):
        raise ProtocolError("not a probe's answer")
    pki = found.get("pki")
    return Probe(found["ready"], root, found["formed"],
                 address(found.get("address")), found.get("holder") is True,
                 pki if type(pki) is int else 1,
                 found.get("legacy") is True)


def enroll_answer(data: bytes) -> etcdproof.Request:
    found = loaded(data)
    return etcdproof.Request(pem(found.get("csr"), "CERTIFICATE REQUEST"),
                             etcdproof.proof(found.get("proof")))
