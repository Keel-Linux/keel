# Copyright (c) 2026 KeelLinux maintainers
"""The keel1a: line the fallback prints, for the inviter (decision 0048)

When the inviter's HTTPS port cannot be reached, `keel mesh join` applies
its own side and prints `keel mesh accept keel1a:<answer>` to run back on
the inviter. The answer carries what the join request would have:

    flags          1   bit 0: an IPv6 endpoint follows, bit 1: an IPv4 one
    public key    32   the new node's WireGuard key
    endpoint    16|4   when a flag is set, and its UDP port (2)
    address       16   the address the invite reserved
    prefix length  1
    invite id      8
    time           4   seconds since the epoch, UTC
    HMAC          32   HMAC-SHA256 of the label, the prefix and the above,
                       keyed with the invite's HMAC key
    checksum       4   the first four bytes of the SHA-256 of the prefix
                       and the above

base64url without padding, as the token is. The checksum tells a
mistyped paste from a line for another invite, whose HMAC fails; so it
is accepted only by the inviter that made the token, once, before the
invite expires. The secret is in it no more than in the request.
"""

import base64
import binascii
import hashlib
import hmac
import ipaddress
import struct
from dataclasses import dataclass

from keel.mesh.protocol import ProtocolError, endpoint
from keel.mesh.token import BODY_RE, CHECKSUM_BYTES, UNIQUE_LOCAL
from keel.network.wireguard import KEY_BYTES, key_bytes

PREFIX = "keel1a:"
MAX_TEXT = 512
IPV6_ENDPOINT = 0x01
IPV4_ENDPOINT = 0x02
LABEL = b"keel mesh accept\n"
MAC_BYTES = 32
HEAD = struct.Struct(f">B{KEY_BYTES}s")
PORT = struct.Struct(">H")
BODY = struct.Struct(f">16sB8sI{MAC_BYTES}s")


class AcceptError(ValueError):
    """A line accept cannot use, and why"""


@dataclass(frozen=True)
class Accept:
    """`endpoint` is None for a new node that cannot be reached; `address`
    has its prefix length"""

    public_key: str
    endpoint: str | None
    address: str
    invite_id: str
    time: int


@dataclass(frozen=True)
class Sealed:
    """A parsed line: its fields, what the HMAC covers, and the HMAC"""

    accept: Accept
    covered: bytes
    mac: bytes

    def authentic(self, key: bytes) -> bool:
        return hmac.compare_digest(mac(key, self.covered), self.mac)


def mac(key: bytes, covered: bytes) -> bytes:
    return hmac.new(key, LABEL + PREFIX.encode() + covered,
                    hashlib.sha256).digest()


def checksum(payload: bytes) -> bytes:
    return hashlib.sha256(PREFIX.encode() + payload).digest()[
        :CHECKSUM_BYTES]


def wrap(payload: bytes) -> str:
    whole = payload + checksum(payload)
    return PREFIX + base64.urlsafe_b64encode(whole).decode().rstrip("=")


def encode(accept: Accept, key: bytes) -> str:
    """The line; raises AcceptError for one parse would refuse"""
    check(accept)
    flags, tail = 0, b""
    if accept.endpoint is not None:
        host, _, port = accept.endpoint.rpartition(":")
        address = ipaddress.ip_address(host.strip("[]"))
        flags = IPV6_ENDPOINT if address.version == 6 else IPV4_ENDPOINT
        tail = address.packed + PORT.pack(int(port))
    own = ipaddress.IPv6Interface(accept.address)
    covered = HEAD.pack(flags, key_bytes(accept.public_key)) + tail
    covered += BODY.pack(own.ip.packed, own.network.prefixlen,
                         bytes.fromhex(accept.invite_id), accept.time,
                         b"")[:-MAC_BYTES]
    return wrap(covered + mac(key, covered))


def parse(text: str) -> Sealed:
    """The line in `text`, checked; raises AcceptError with the reason"""
    if len(text) > MAX_TEXT:
        raise AcceptError(f"not a keel mesh accept line: more than"
                          f" {MAX_TEXT} characters")
    text = text.strip()
    if not text.startswith(PREFIX):
        raise AcceptError(f"not the answer of a keel mesh join: it starts"
                          f" with {PREFIX} (paste it alone)")
    body = text[len(PREFIX):]
    if not BODY_RE.match(body):
        raise AcceptError("the line holds a character base64url does not"
                          " use: it was changed in the copy")
    try:
        whole = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError):
        whole = b""
    payload, found = whole[:-CHECKSUM_BYTES], whole[-CHECKSUM_BYTES:]
    if len(whole) <= CHECKSUM_BYTES or not hmac.compare_digest(
            found, checksum(payload)):
        raise AcceptError("the line is mistyped or truncated: its checksum"
                          " does not match; copy it again")
    try:
        sealed = unpack(payload)
    except (struct.error, ValueError) as e:
        raise AcceptError(f"the line is malformed: {e}") from None
    check(sealed.accept)
    return sealed


def unpack(payload: bytes) -> Sealed:
    flags, public = HEAD.unpack_from(payload)
    if flags not in (0, IPV6_ENDPOINT, IPV4_ENDPOINT):
        raise ValueError(f"flags {flags:#04x}: one endpoint at most")
    offset, shown = HEAD.size, None
    if flags:
        size = 16 if flags == IPV6_ENDPOINT else 4
        host = ipaddress.ip_address(payload[offset:offset + size])
        (port,) = PORT.unpack_from(payload, offset + size)
        offset += size + PORT.size
        shown = f"[{host}]:{port}" if host.version == 6 else f"{host}:{port}"
    address, length, invite, time, sealed = BODY.unpack_from(payload, offset)
    if offset + BODY.size != len(payload):
        raise ValueError(f"{len(payload)} bytes where its flags say"
                         f" {offset + BODY.size}")
    return Sealed(
        accept=Accept(public_key=base64.b64encode(public).decode(),
                      endpoint=shown,
                      address=f"{ipaddress.IPv6Address(address)}/{length}",
                      invite_id=invite.hex(), time=time),
        covered=payload[:-MAC_BYTES], mac=sealed)


def check(accept: Accept) -> None:
    if key_bytes(accept.public_key) is None:
        raise AcceptError("the new node's key is not a WireGuard key")
    try:
        endpoint(accept.endpoint)
    except ProtocolError as e:
        raise AcceptError(str(e)) from None
    own = ipaddress.IPv6Interface(accept.address)
    if not own.network.subnet_of(UNIQUE_LOCAL):
        raise AcceptError(f"{own} is not an overlay address (fc00::/7)")
