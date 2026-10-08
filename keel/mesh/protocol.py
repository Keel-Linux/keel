# Copyright (c) 2026 KeelLinux maintainers
"""The join protocol's messages and their HMAC (decision 0048)

Two requests go to the inviter's HTTPS port, each a JSON body POSTed
with an HMAC-SHA256 of the method, the path and the body in the header
X-Keel-Mesh-Signature, keyed with the invite's HMAC key
(keel.mesh.token.hmac_key): the token's secret never crosses the wire.

    POST /v1/join      JoinRequest -> JoinAnswer, over the uplink
    POST /v1/confirm   ConfirmRequest -> ConfirmAnswer, over the overlay

An answer of 200 is signed the same way under the method ANSWER and the
request's path, and carries the request's nonce, so the new node knows
it came from the node that made the token as well as from the pinned
certificate. A refusal is a JSON {"error": reason}, unsigned: it gives
nothing to act on. Everything here is pure.
"""

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from dataclasses import asdict, dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timedelta

from keel.mesh.token import ETCD_STATES
from keel.network.wireguard import is_key, split_endpoint

JOIN = "/v1/join"
CONFIRM = "/v1/confirm"
METHOD = "POST"
ANSWER = "ANSWER"
SIGNATURE = "X-Keel-Mesh-Signature"
CONTENT_TYPE = "application/json"
# a join request is about 350 bytes: what the listener reads at most
MAX_BODY = 16384
# an answer grows with the peers and their evidence, about 600 bytes each
MAX_ANSWER = 262144
# how far a request's time may be from the inviter's clock
SKEW = timedelta(minutes=5)
NONCE_BYTES = 16
LABEL = b"keel mesh 1\n"
ID_RE = re.compile(r"^[0-9a-f]{16}$")
MESH_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# an Ed25519 signature, 64 bytes in base64
ED25519_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")
ADMISSION_LABEL = b"keel mesh admission 1\n"
REMOVAL_LABEL = b"keel mesh removal 1\n"
NONCE_RE = re.compile(rf"^[0-9a-f]{{{NONCE_BYTES * 2}}}$")
SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")


class ProtocolError(ValueError):
    """A message that is not one of the protocol's, and why"""


@dataclass(frozen=True)
class Admission:
    """Evidence that a member admitted a node (keel.mesh.trust)

    Signed with the admitting member's signing key (`by`) over the mesh
    identity, the invite id (which keel.mesh.trust requires: no member
    vouches for a node it did not admit), the node's WireGuard key and
    signing key, its overlay address and endpoint, and the time.
    """

    mesh_id: str
    invite_id: str
    public_key: str
    sign_key: str
    address: str
    endpoint: str | None
    time: int
    by: str
    signature: str

    def message(self) -> bytes:
        return ADMISSION_LABEL + "\n".join((
            self.mesh_id, self.invite_id, self.public_key, self.sign_key,
            self.address, self.endpoint or "", str(self.time),
            self.by)).encode()


@dataclass(frozen=True)
class Removal:
    """A tombstone: a member removed this node's key, signed with its
    signing key (`by`), so no sync adds it again"""

    mesh_id: str
    public_key: str
    time: int
    by: str
    signature: str

    def message(self) -> bytes:
        return REMOVAL_LABEL + "\n".join((
            self.mesh_id, self.public_key, str(self.time),
            self.by)).encode()


@dataclass(frozen=True)
class Peer:
    """A member as the answer names it: key, endpoint or None, address,
    and the evidence of its admission, None when there is none"""

    public_key: str
    endpoint: str | None
    address: str
    admission: Admission | None = None


@dataclass(frozen=True)
class JoinRequest:
    """The new node: its key, its endpoint or None, the address the
    invite reserved, with its prefix length"""

    invite_id: str
    public_key: str
    endpoint: str | None
    address: str
    nonce: str
    time: int
    # the new node's signing key, which its admission names
    sign_key: str
    # the request for its etcd certificate, sent only by a node that can
    # run etcd (keel.mesh.etcdmsg, 0048 third round), and the proof it is
    # this node's: its signature over it with `sign_key`
    # (keel.mesh.etcdproof)
    etcd_csr: str | None = None
    etcd_proof: str | None = None


@dataclass(frozen=True)
class JoinAnswer:
    """The inviter: its key and overlay address, the peers it knows
    besides the new node, the etcd state, and the seconds its change
    waits for the confirmation"""

    invite_id: str
    nonce: str
    public_key: str
    address: str
    peers: tuple[Peer, ...]
    etcd: str
    window: int
    # the inviter's signing key, and the new node's admission it signed
    sign_key: str
    admission: Admission
    # for etcd (keel.mesh.etcdmsg): the new node's intermediate CA, the
    # cluster it starts, the members ready, key to overlay address
    etcd_grant: object = None
    etcd_cluster: object = None
    etcd_ready: dict = dataclass_field(default_factory=dict)


@dataclass(frozen=True)
class ConfirmRequest:
    invite_id: str
    public_key: str
    nonce: str
    time: int


@dataclass(frozen=True)
class ConfirmAnswer:
    """Whether the inviter kept its change, and what it said"""

    invite_id: str
    nonce: str
    confirmed: bool
    detail: str
    # the inviter's signing key: what the fallback's node learns it by
    sign_key: str


def sign(key: bytes, method: str, path: str, body: bytes) -> str:
    message = LABEL + method.encode() + b"\n" + path.encode() + b"\n" + body
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def signed(key: bytes, method: str, path: str, body: bytes,
           signature: str | None) -> bool:
    """Whether `signature` is the HMAC of the message, in constant time"""
    if signature is None or not SIGNATURE_RE.match(signature):
        return False
    return hmac.compare_digest(sign(key, method, path, body), signature)


def new_nonce() -> str:
    return secrets.token_hex(NONCE_BYTES)


def seconds(now: datetime) -> int:
    return int(now.timestamp())


def fresh(time: int, now: datetime) -> bool:
    return abs(time - now.timestamp()) <= SKEW.total_seconds()


def dumps(message) -> bytes:
    return json.dumps(asdict(message), sort_keys=True).encode()


def loaded(body: bytes) -> dict:
    try:
        data = json.loads(body.decode())
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ProtocolError("the body is not JSON") from None
    if not isinstance(data, dict):
        raise ProtocolError("the body is not a JSON object")
    return data


def field(data: dict, name: str, kind: type):
    value = data.get(name)
    if type(value) is not kind:
        raise ProtocolError(f"{name} is missing or not a {kind.__name__}")
    return value


def matching(data: dict, name: str, pattern: re.Pattern) -> str:
    value = field(data, name, str)
    if not pattern.match(value):
        raise ProtocolError(f"{name} is malformed")
    return value


def key(data: dict, name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not is_key(value):
        raise ProtocolError(f"{name} is not a WireGuard key")
    return value


def endpoint(value: object) -> str | None:
    """None, or an address and port another node can reach"""
    if value is None:
        return None
    try:
        host, number = split_endpoint(str(value))
        address = ipaddress.ip_address(host)
    except ValueError as e:
        raise ProtocolError(f"endpoint {value!r}: {e}") from None
    if (address.is_unspecified or address.is_loopback
            or address.is_multicast or address.is_link_local):
        raise ProtocolError(f"endpoint {address} cannot be reached from"
                            " another node")
    shown = f"[{address}]" if address.version == 6 else str(address)
    return f"{shown}:{number}"


def overlay(data: dict, name: str, prefixed: bool) -> str:
    """An overlay address: with its prefix length when `prefixed`"""
    value = field(data, name, str)
    try:
        found = ipaddress.IPv6Interface(value)
    except ValueError:
        raise ProtocolError(f"{name} is not an IPv6 address") from None
    if prefixed != ("/" in value):
        raise ProtocolError(f"{name} is not an IPv6 address"
                            f"{' with its prefix length' if prefixed else ''}")
    return str(found) if prefixed else str(found.ip)


def number(data: dict, name: str) -> int:
    value = field(data, name, int)
    if value < 0:
        raise ProtocolError(f"{name} is negative")
    return value


def join_request(body: bytes) -> JoinRequest:
    # etcdmsg reads ProtocolError and the shapes from here
    from keel.mesh import etcdmsg, etcdproof
    data = loaded(body)
    return JoinRequest(
        invite_id=matching(data, "invite_id", ID_RE),
        public_key=key(data, "public_key"),
        endpoint=endpoint(data.get("endpoint")),
        address=overlay(data, "address", True),
        nonce=matching(data, "nonce", NONCE_RE),
        time=number(data, "time"), sign_key=key(data, "sign_key"),
        etcd_csr=etcdmsg.csr(data.get("etcd_csr")),
        etcd_proof=None if data.get("etcd_proof") is None
        else etcdproof.proof(data.get("etcd_proof")))


def join_answer(body: bytes) -> JoinAnswer:
    data = loaded(body)
    etcd = field(data, "etcd", str)
    if etcd not in ETCD_STATES:
        raise ProtocolError(f"etcd state {etcd!r} is not one this keel"
                            " knows")
    peers = field(data, "peers", list)
    return JoinAnswer(
        invite_id=matching(data, "invite_id", ID_RE),
        nonce=matching(data, "nonce", NONCE_RE),
        public_key=key(data, "public_key"),
        address=overlay(data, "address", True),
        peers=tuple(peer(one) for one in peers),
        etcd=etcd, window=number(data, "window"),
        sign_key=key(data, "sign_key"),
        admission=admission(data.get("admission")),
        **etcd_fields(data))


def etcd_fields(data: dict) -> dict:
    """The answer's etcd fields; none when they cannot be read: etcd
    never fails a join (keel.mesh.etcd), keel mesh etcd form brings the
    node in later"""
    from keel.mesh import etcdmsg
    try:
        return {"etcd_grant": etcdmsg.grant(data.get("etcd_grant")),
                "etcd_cluster": etcdmsg.cluster(data.get("etcd_cluster")),
                "etcd_ready": etcdmsg.ready(data.get("etcd_ready"))}
    except ProtocolError:
        return {}


def peer(data: object) -> Peer:
    if not isinstance(data, dict):
        raise ProtocolError("a peer is not a JSON object")
    found = data.get("admission")
    return Peer(public_key=key(data, "public_key"),
                endpoint=endpoint(data.get("endpoint")),
                address=overlay(data, "address", False),
                admission=None if found is None else admission(found))


def admission(data: object) -> Admission:
    if not isinstance(data, dict):
        raise ProtocolError("an admission is not a JSON object")
    invite = field(data, "invite_id", str)
    if invite and not ID_RE.match(invite):
        raise ProtocolError("invite_id is malformed")
    return Admission(
        mesh_id=matching(data, "mesh_id", MESH_ID_RE), invite_id=invite,
        public_key=key(data, "public_key"), sign_key=key(data, "sign_key"),
        address=overlay(data, "address", False),
        endpoint=endpoint(data.get("endpoint")), time=number(data, "time"),
        by=key(data, "by"), signature=matching(data, "signature",
                                               ED25519_RE))


def removal(data: object) -> Removal:
    if not isinstance(data, dict):
        raise ProtocolError("a removal is not a JSON object")
    return Removal(
        mesh_id=matching(data, "mesh_id", MESH_ID_RE),
        public_key=key(data, "public_key"), time=number(data, "time"),
        by=key(data, "by"), signature=matching(data, "signature",
                                               ED25519_RE))


def confirm_request(body: bytes) -> ConfirmRequest:
    data = loaded(body)
    return ConfirmRequest(
        invite_id=matching(data, "invite_id", ID_RE),
        public_key=key(data, "public_key"),
        nonce=matching(data, "nonce", NONCE_RE),
        time=number(data, "time"))


def confirm_answer(body: bytes) -> ConfirmAnswer:
    data = loaded(body)
    return ConfirmAnswer(
        invite_id=matching(data, "invite_id", ID_RE),
        nonce=matching(data, "nonce", NONCE_RE),
        confirmed=field(data, "confirmed", bool),
        detail=field(data, "detail", str), sign_key=key(data, "sign_key"))
