# Copyright (c) 2026 KeelLinux maintainers
"""The pair record: which two nodes may hold a VIP (0049, third round)

"Only the nodes of the pair may claim the VIP: the nodes whose spec
declares the same `appliance.vip`, and that are trusted members." A
node's word about its own spec is not enough for the others, so the
pair is bound by a record: the mesh, the VIP and the two members'
WireGuard keys, signed by both members (`keel vip pair`, run once the
operator declared `appliance.vip` on both nodes), or by a trust root of
0048's amendment in place of a member's signature. A member signs only
for the VIP its own spec declares, and only a record that names itself.

Every claim carries the record it rests on, and every node checks it:
each signature by the signing key its trust store holds for that member
(its own, for itself) or for a trust root, the claim's holder one of
the members and the claim's VIP the record's. The first record a node
takes for a VIP is kept (`/var/lib/keel/vip/<vip>.pair`); another
record for the same VIP, naming other members, is refused.

    {"record": {"mesh_id", "vip", "members": [key, key]},
     "signatures": {signer's WireGuard key: Ed25519 signature}}

over `keel vip pair 1\\n` and the record's canonical JSON.
"""

import base64
import binascii
import ipaddress
import json
import os
from dataclasses import dataclass

from keel.mesh import signing
from keel.mesh.etcdmsg import canonical
from keel.mesh.protocol import MESH_ID_RE, ProtocolError
from keel.mesh.vip import DIR, address, before_range, misplaced
from keel.network.marker import path, write_private
from keel.network.wireguard import is_key, key_bytes, same_key

LABEL = b"keel vip pair 1\n"
SUFFIX = ".pair"
MEMBERS = 2
MAX_SIGNATURES = 4
# before the VIP range (0.23.3), a VIP was inside the /112 of its
# members' addresses
REGION_BITS = 112


@dataclass(frozen=True)
class Pair:
    mesh_id: str
    vip: str
    members: tuple[str, ...]
    signatures: tuple[tuple[str, str], ...] = ()

    def record(self) -> dict:
        return {"mesh_id": self.mesh_id, "vip": self.vip,
                "members": list(self.members)}

    def message(self) -> bytes:
        return LABEL + canonical(self.record())

    def has(self, key: str | None) -> bool:
        return bool(key) and any(same_key(one, key) for one in self.members)

    def same_members(self, other: "Pair") -> bool:
        return self.vip == other.vip and self.mesh_id == other.mesh_id and \
            all(other.has(one) for one in self.members)

    def dumps(self) -> dict:
        return {"record": self.record(),
                "signatures": dict(self.signatures)}

    def signed_by(self, key: str, signature: str) -> "Pair":
        kept = tuple(one for one in self.signatures
                     if not same_key(one[0], key))
        return Pair(self.mesh_id, self.vip, self.members,
                    tuple(sorted(kept + ((key, signature),))))


def made(mesh_id: str, vip: str, keys: tuple[str, str]) -> Pair:
    """The record of a pair, its members in the order of their key
    bytes, so both members sign the same bytes"""
    members = tuple(sorted(keys, key=lambda one: key_bytes(one) or b""))
    return Pair(mesh_id, address(vip), members)


def loads(value: object) -> Pair:
    """A record as a claim or a message carries it; ProtocolError"""
    if not isinstance(value, dict):
        raise ProtocolError("not a pair record")
    record, signatures = value.get("record"), value.get("signatures")
    if not isinstance(record, dict) or not isinstance(signatures, dict) or \
            len(signatures) > MAX_SIGNATURES:
        raise ProtocolError("not a pair record")
    members = record.get("members")
    mesh_id = record.get("mesh_id")
    if not isinstance(members, list) or len(members) != MEMBERS or \
            not all(isinstance(one, str) and is_key(one) for one in members) \
            or same_key(members[0], members[1]) or \
            not isinstance(mesh_id, str) or not MESH_ID_RE.match(mesh_id):
        raise ProtocolError("not a pair record")
    try:
        vip = address(record.get("vip"))
    except ValueError:
        raise ProtocolError("no VIP in the pair record") from None
    found = made(mesh_id, vip, (members[0], members[1]))
    if list(found.members) != members:
        raise ProtocolError("the pair record's members are not in order")
    for key, signature in signatures.items():
        if not isinstance(key, str) or not is_key(key) or \
                not isinstance(signature, str):
            raise ProtocolError("not a pair record")
        try:
            base64.b64decode(signature, validate=True)
        except (binascii.Error, ValueError):
            raise ProtocolError("not a pair record") from None
    return Pair(found.mesh_id, found.vip, found.members,
                tuple(sorted(signatures.items())))


def sign(root: str, pair: Pair, own_key: str) -> Pair:
    """`pair` with this node's signature; raises SigningError"""
    return pair.signed_by(own_key, signing.sign(root, pair.message()))


def problem(pair: Pair, signer_of, root_keys: set[str]) -> str | None:
    """Why the record is not taken, or None: every member signed it with
    the key `signer_of(member)` gives, or a trust root (a key of
    `root_keys`, its signing key by `signer_of`) signed it"""
    def good(key: str) -> bool:
        sign_key = signer_of(key)
        signature = next((sig for one, sig in pair.signatures
                          if same_key(one, key)), None)
        return bool(sign_key) and signature is not None and \
            signing.verified(sign_key, pair.message(), signature)
    if any(good(one) for one in root_keys):
        return None
    missing = [one for one in pair.members if not good(one)]
    if missing:
        return (f"the pair record of {pair.vip} is not signed by"
                f" {', '.join(missing)} with a key this node trusts")
    return None


def placed(pair: Pair, addresses: dict[str, str],
           prefix: ipaddress.IPv6Network, legacy: bool = False) -> str | None:
    """Why the VIP cannot be this pair's, or None: outside the overlay's
    VIP range (keel.mesh.vip: `<prefix>::ffff:n`, no region's, so the
    members may be in two regions and either carries it), or a member's
    own address. `legacy`: the pair was made before the range (0.23.3),
    and its VIP may stay outside it, in the overlay prefix"""
    vip = ipaddress.IPv6Address(pair.vip)
    for key, at in addresses.items():
        if pair.has(key) and vip == ipaddress.IPv6Address(at):
            return f"{pair.vip} is {key}'s own overlay address"
    for at in addresses.values():
        if vip == ipaddress.IPv6Address(at):
            return f"{pair.vip} is a member's own overlay address"
    why = misplaced(pair.vip, prefix)
    if why and legacy and before_range(pair.vip, prefix):
        return None
    return why


def signed_before_range(pair: Pair, addresses: dict[str, str]) -> bool:
    """Whether the VIP is inside the /112 of a member's address: where
    every record signed before the VIP range (0.23.3) had its VIP"""
    vip = ipaddress.IPv6Address(pair.vip)
    return any(pair.has(key) and vip in ipaddress.IPv6Network(
        f"{at}/{REGION_BITS}", strict=False)
        for key, at in addresses.items())


def file_of(vip: str) -> str:
    return f"{DIR}/{vip}{SUFFIX}"


def read(root: str, vip: str) -> Pair | None:
    """The record kept for `vip`; None without one, ValueError when it
    cannot be read"""
    try:
        with open(path(root, file_of(vip))) as fob:
            return loads(json.load(fob))
    except FileNotFoundError:
        return None
    except (ValueError, ProtocolError):
        raise ValueError(f"/{file_of(vip)} is damaged: run keel vip pair"
                         " again on the pair") from None


def kept_vips(root: str) -> tuple[str, ...]:
    """The VIPs this node keeps a readable pair record for, sorted"""
    try:
        names = os.listdir(path(root, DIR))
    except FileNotFoundError:
        return ()
    found = []
    for name in sorted(names):
        if not name.endswith(SUFFIX):
            continue
        try:
            kept = read(root, address(name[:-len(SUFFIX)]))
        except ValueError:
            continue
        if kept is not None:
            found.append(kept.vip)
    return tuple(found)


def write(root: str, pair: Pair) -> None:
    from keel.mesh import vip as vipstate
    vipstate.ensure(root)
    write_private(root, file_of(pair.vip),
                  json.dumps(pair.dumps(), sort_keys=True) + "\n")
