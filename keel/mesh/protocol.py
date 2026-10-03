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
from datetime import datetime, timedelta

from keel.mesh.token import ETCD_STATES
from keel.network.wireguard import is_key, split_endpoint

JOIN = "/v1/join"
CONFIRM = "/v1/confirm"
METHOD = "POST"
ANSWER = "ANSWER"
SIGNATURE = "X-Keel-Mesh-Signature"
CONTENT_TYPE = "application/json"
# a join request is about 300 bytes, an answer grows with the peers
MAX_BODY = 16384
# how far a request's time may be from the inviter's clock
SKEW = timedelta(minutes=5)
NONCE_BYTES = 16
LABEL = b"keel mesh 1\n"
ID_RE = re.compile(r"^[0-9a-f]{16}$")
NONCE_RE = re.compile(rf"^[0-9a-f]{{{NONCE_BYTES * 2}}}$")
SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")


class ProtocolError(ValueError):
    """A message that is not one of the protocol's, and why"""


@dataclass(frozen=True)
class Peer:
    """A member as the answer names it: key, endpoint or None, address"""

    public_key: str
    endpoint: str | None
    address: str


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
    data = loaded(body)
    return JoinRequest(
        invite_id=matching(data, "invite_id", ID_RE),
        public_key=key(data, "public_key"),
        endpoint=endpoint(data.get("endpoint")),
        address=overlay(data, "address", True),
        nonce=matching(data, "nonce", NONCE_RE),
        time=number(data, "time"))


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
        etcd=etcd, window=number(data, "window"))


def peer(data: object) -> Peer:
    if not isinstance(data, dict):
        raise ProtocolError("a peer is not a JSON object")
    return Peer(public_key=key(data, "public_key"),
                endpoint=endpoint(data.get("endpoint")),
                address=overlay(data, "address", False))


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
        detail=field(data, "detail", str))
