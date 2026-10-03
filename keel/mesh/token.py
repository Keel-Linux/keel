# Copyright (c) 2026 KeelLinux maintainers
"""The keel1: token: what a new node needs from the inviter, in one line

`keel1:` followed by the base64url encoding, without padding, of the
fields below in a fixed order, big endian, and a checksum: the first four
bytes of the SHA-256 of the prefix and the fields, so a truncated or
mistyped paste is recognised before anything is sent. A later layout is
`keel2:`, and this keel names a prefix it does not read rather than
guessing at it.

    flags            1   bit 0: an IPv6 endpoint, bit 1: an IPv4 one
    public key      32   the inviter's WireGuard key
    IPv6 endpoint   16   when bit 0
    IPv4 endpoint    4   when bit 1
    WireGuard port   2   UDP, at the endpoint
    HTTPS port       2   TCP, at the same address, for the join request
    fingerprint     32   SHA-256 of the invite's certificate, to pin it
    inviter address 16   its overlay address, the new node's allowed_ips
    prefix length    1   of the overlay prefix
    assigned        16   the new node's overlay address, in that prefix
    mesh identity   16   names the mesh; etcd's cluster token
    etcd state       1   0 none, 1 forms at this join, 2 running
    etcd port        2   when running: the inviter's member port
    invite id        8   derived from the secret, never the secret
    secret          32   the one use secret: the HMAC key's source
    expiry           4   seconds since the epoch, UTC
    checksum         4

The secret is the only value here that is not public. It is in no repr
of a Token and no message of a TokenError; neither is the token's text,
which holds it.
"""

import base64
import binascii
import hashlib
import hmac
import ipaddress
import re
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from keel.network.wireguard import KEY_BYTES, key_bytes

VERSION = 1
PREFIX = f"keel{VERSION}:"
SECRET_BYTES = 32
FINGERPRINT_BYTES = 32
MESH_ID_BYTES = 16
INVITE_ID_BYTES = 8
CHECKSUM_BYTES = 4
LIFETIME = timedelta(hours=1)
# a token is about 256 characters: anything past this is not one, and is
# refused before it is decoded
MAX_TEXT = 1024
IPV6_ENDPOINT = 0x01
IPV4_ENDPOINT = 0x02
FLAGS = IPV6_ENDPOINT | IPV4_ENDPOINT
ETCD_STATES = ("none", "forms", "running")
UNIQUE_LOCAL = ipaddress.IPv6Network("fc00::/7")
# a prefix inside fc00::/7 that leaves room for two nodes
PREFIX_LENGTHS = range(UNIQUE_LOCAL.prefixlen, 127)
VERSIONED_RE = re.compile(r"^keel(\d+):")
BODY_RE = re.compile(r"^[A-Za-z0-9_-]*$")
# labels of the values derived from the secret, so none is another's
ID_LABEL = b"keel mesh invite id"
HMAC_LABEL = b"keel mesh request key"
HEAD = struct.Struct(f">B{KEY_BYTES}s")
MIDDLE = struct.Struct(
    f">HH{FINGERPRINT_BYTES}s16sB16s{MESH_ID_BYTES}sB")
TAIL = struct.Struct(f">{INVITE_ID_BYTES}s{SECRET_BYTES}sI")
PORT = struct.Struct(">H")


class TokenError(ValueError):
    """A token that cannot be used, and why; never the token's text"""


@dataclass(frozen=True)
class Token:
    """What `keel mesh invite` puts in the line and `join` reads back

    `endpoints` are the inviter's uplink addresses, IPv6 first, one per
    family; `address` the inviter's overlay address with the prefix
    length, `assigned` the new node's on the same prefix. `etcd_port`
    is set when `etcd` is "running". `expires` is aware, in UTC.
    """

    public_key: str
    endpoints: tuple[str, ...]
    port: int
    https_port: int
    fingerprint: bytes
    address: str
    assigned: str
    mesh_id: bytes
    invite_id: str
    expires: datetime
    secret: bytes = field(repr=False)
    etcd: str = "none"
    etcd_port: int | None = None

    def prefix(self) -> ipaddress.IPv6Network:
        return ipaddress.IPv6Interface(self.address).network

    def endpoint(self) -> str:
        """Where the new node sends its handshake: IPv6 when there is one"""
        host = ipaddress.ip_address(self.endpoints[0])
        shown = f"[{host}]" if host.version == 6 else str(host)
        return f"{shown}:{self.port}"


def invite_id(secret: bytes) -> str:
    """The invite's name, derived from the secret and not revealing it"""
    return derive(secret, ID_LABEL)[:INVITE_ID_BYTES].hex()


def hmac_key(secret: bytes) -> bytes:
    """The key both sides sign the join request and answer with

    The inviter stores this, never the secret; the new node derives it
    from the secret in the token.
    """
    return derive(secret, HMAC_LABEL)


def derive(secret: bytes, label: bytes) -> bytes:
    return hmac.new(secret, label, hashlib.sha256).digest()


def checksum(payload: bytes) -> bytes:
    return hashlib.sha256(PREFIX.encode() + payload).digest()[
        :CHECKSUM_BYTES]


def encode(token: Token) -> str:
    """The token's text; raises TokenError for a token parse would refuse"""
    check(token)
    hosts = [ipaddress.ip_address(one) for one in token.endpoints]
    flags = sum(IPV6_ENDPOINT if one.version == 6 else IPV4_ENDPOINT
                for one in hosts)
    address = ipaddress.IPv6Interface(token.address)
    payload = HEAD.pack(flags, key_bytes(token.public_key))
    payload += b"".join(one.packed for one in hosts)
    payload += MIDDLE.pack(
        token.port, token.https_port, token.fingerprint, address.ip.packed,
        address.network.prefixlen,
        ipaddress.IPv6Interface(token.assigned).ip.packed, token.mesh_id,
        ETCD_STATES.index(token.etcd))
    if token.etcd_port is not None:
        payload += PORT.pack(token.etcd_port)
    payload += TAIL.pack(bytes.fromhex(token.invite_id), token.secret,
                         int(token.expires.timestamp()))
    whole = payload + checksum(payload)
    return PREFIX + base64.urlsafe_b64encode(whole).decode().rstrip("=")


def parse(text: str, now: datetime) -> Token:
    """The token in `text`, checked whole; raises TokenError with the reason

    In order: the prefix, the alphabet, the checksum, the layout, the
    values, and last the expiry against `now`, so an expired token is
    only ever called expired when it is otherwise sound.
    """
    if len(text) > MAX_TEXT:
        raise TokenError(f"not a keel mesh token: more than {MAX_TEXT}"
                         " characters, and a token is about 256")
    payload = unwrap(text.strip())
    token = unpack(payload)
    check(token)
    if now >= token.expires:
        raise TokenError(
            f"this token expired at {shown(token.expires)}; ask the"
            " inviting node for a new one (keel mesh invite)")
    return token


def unwrap(text: str) -> bytes:
    """The fields of the token, its checksum checked and removed"""
    if not text.startswith(PREFIX):
        found = VERSIONED_RE.match(text)
        if found and int(found.group(1)) > VERSION:
            raise TokenError(
                f"a {found.group(0)} token is of a later format than this"
                f" keel reads ({PREFIX}): join with a keel as new as the"
                " inviting node's")
        raise TokenError(f"not a keel mesh token: a token starts with"
                         f" {PREFIX} (paste the token alone, not the whole"
                         " line)")
    body = text[len(PREFIX):]
    if not BODY_RE.match(body):
        raise TokenError("the token holds a character base64url does not"
                         " use: it was changed in the copy")
    try:
        whole = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError):
        whole = b""
    payload, found = whole[:-CHECKSUM_BYTES], whole[-CHECKSUM_BYTES:]
    if len(whole) <= CHECKSUM_BYTES or not hmac.compare_digest(
            found, checksum(payload)):
        raise TokenError("the token is mistyped or truncated: its checksum"
                         " does not match; copy the whole line again")
    return payload


def unpack(payload: bytes) -> Token:
    """The fields, in the order of the module's table"""
    try:
        return fields(payload)
    except (struct.error, IndexError, ValueError) as e:
        raise TokenError(f"the token is malformed: {e}") from None


def fields(payload: bytes) -> Token:
    flags, public = HEAD.unpack_from(payload)
    if flags & ~FLAGS:
        raise ValueError(f"unknown flags {flags:#04x}")
    offset = HEAD.size
    endpoints = []
    for bit, size in ((IPV6_ENDPOINT, 16), (IPV4_ENDPOINT, 4)):
        if flags & bit:
            endpoints.append(str(ipaddress.ip_address(
                payload[offset:offset + size])))
            offset += size
    (port, https_port, fingerprint, inviter, length, assigned, mesh_id,
     etcd) = MIDDLE.unpack_from(payload, offset)
    offset += MIDDLE.size
    if etcd >= len(ETCD_STATES):
        raise ValueError(f"etcd state {etcd} is not one this keel knows")
    etcd_port = None
    if ETCD_STATES[etcd] == "running":
        (etcd_port,) = PORT.unpack_from(payload, offset)
        offset += PORT.size
    identifier, secret, expiry = TAIL.unpack_from(payload, offset)
    if offset + TAIL.size != len(payload):
        raise ValueError(f"{len(payload)} bytes where its flags say"
                         f" {offset + TAIL.size}")
    return Token(
        public_key=base64.b64encode(public).decode(),
        endpoints=tuple(endpoints), port=port, https_port=https_port,
        fingerprint=fingerprint,
        address=f"{ipaddress.IPv6Address(inviter)}/{length}",
        assigned=f"{ipaddress.IPv6Address(assigned)}/{length}",
        mesh_id=mesh_id, invite_id=identifier.hex(),
        expires=datetime.fromtimestamp(expiry, timezone.utc),
        secret=secret, etcd=ETCD_STATES[etcd], etcd_port=etcd_port)


def check(token: Token) -> None:
    """Raise TokenError naming every value a join could not use"""
    found = list(problems(token))
    if found:
        raise TokenError(f"the token is malformed: {'; '.join(found)}")


def problems(token: Token):
    if key_bytes(token.public_key) is None:
        yield "the inviter's public key is not a WireGuard key"
    yield from endpoint_problems(token.endpoints)
    for name, value in (("WireGuard port", token.port),
                        ("HTTPS port", token.https_port)):
        if not 1 <= value <= 65535:
            yield f"{name} {value} is not a port number"
    for name, value, size in (
            ("fingerprint", token.fingerprint, FINGERPRINT_BYTES),
            ("mesh identity", token.mesh_id, MESH_ID_BYTES),
            ("secret", token.secret, SECRET_BYTES)):
        if len(value) != size:
            yield f"the {name} is not {size} bytes"
    yield from overlay_problems(token.address, token.assigned)
    yield from etcd_problems(token.etcd, token.etcd_port)
    if token.invite_id != invite_id(token.secret):
        yield "its invite id is not the one its secret gives"
    if token.expires.utcoffset() != timedelta(0):
        yield "the expiry is not in UTC"


def endpoint_problems(endpoints: tuple[str, ...]):
    if not endpoints:
        yield "no endpoint to reach the inviter at"
        return
    try:
        hosts = [ipaddress.ip_address(one) for one in endpoints]
    except ValueError as e:
        yield f"endpoint: {e}"
        return
    versions = [one.version for one in hosts]
    if sorted(set(versions), reverse=True) != versions:
        yield "one endpoint per family, IPv6 first"
    for host in hosts:
        if (host.is_unspecified or host.is_loopback or host.is_multicast
                or host.is_link_local):
            yield f"endpoint {host} cannot be reached from another node"


def overlay_problems(address: str, assigned: str):
    try:
        inviter = ipaddress.IPv6Interface(address)
        joiner = ipaddress.IPv6Interface(assigned)
    except ValueError as e:
        yield f"overlay address: {e}"
        return
    prefix = inviter.network
    if not prefix.subnet_of(UNIQUE_LOCAL) or \
            prefix.prefixlen not in PREFIX_LENGTHS:
        yield (f"the overlay prefix {prefix} is not a unique local prefix"
               " (inside fc00::/7, with room for two nodes)")
    elif joiner.network != prefix or joiner.ip == prefix.network_address:
        yield (f"the assigned address {joiner} is not an address of the"
               f" prefix {prefix}")
    elif inviter.ip == prefix.network_address:
        yield (f"the inviter's address {inviter.ip} is the prefix's own,"
               " which is no node's")
    elif joiner.ip == inviter.ip:
        yield f"the assigned address {joiner.ip} is the inviter's own"


def etcd_problems(state: str, port: int | None):
    if state not in ETCD_STATES:
        yield f"etcd state {state!r} is not one of {', '.join(ETCD_STATES)}"
    elif (state == "running") != (port is not None):
        yield "an etcd port goes with a running etcd, and only with it"
    elif port is not None and not 1 <= port <= 65535:
        yield f"etcd port {port} is not a port number"


def shown(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
