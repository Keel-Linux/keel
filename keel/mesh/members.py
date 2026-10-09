# Copyright (c) 2026 KeelLinux maintainers
"""What the members of a mesh tell each other (decision 0048)

"Until etcd exists, members learn about each other through the
inviter": a member's roster is its mesh identity, its own WireGuard and
signing keys and overlay address, every peer its spec declares (key,
endpoint, address) with the evidence of its admission it keeps, and the
tombstones of the keys removed (keel.mesh.trust). It goes over the
overlay alone, between two members' overlay addresses (keel.mesh.sync):

    GET  /v1/members    -> Roster, what `keel mesh sync` pulls
    POST /v1/announce   Roster, what the inviter pushes once a join is
                        confirmed: its roster, the new node in it

WireGuard binds a peer's overlay address to that peer's key, so a
connection that arrives on the overlay interface from an address of a
peer's allowed_ips came from that peer, and the answer to one sent to a
peer's address can only come from it: the overlay authenticates who
speaks. What it says of other members is taken only with evidence a
trusted member signed (keel.mesh.trust.accepted).

`with_members` is the change the members taken make to a spec: those
it does not know become peers, each routed its address as a /128, and
nothing it knows is ever replaced. Everything here is pure.
"""

import ipaddress
import json
from dataclasses import asdict, dataclass

from keel.manifest.firewall import MEMBERS_PORT
from keel.mesh import protocol
from keel.mesh.protocol import Peer, ProtocolError, Removal
from keel.mesh.token import MESH_ID_BYTES
from keel.network.wireguard import allowed, same_key

# TCP, on the overlay address alone: never the invite's port, which
# faces the network on every address. keel's firewall accepts it on the
# overlay's interface (keel.manifest.firewall, which keeps the number)
PORT = MEMBERS_PORT
LIST = "/v1/members"
ANNOUNCE = "/v1/announce"
MAX_MEMBERS = 256
# every tombstone the node keeps (keel.mesh.trust.MAX_REMOVED)
MAX_REMOVED = 1024
# a member with its evidence is about 600 bytes, a tombstone 300
MAX_BODY = 524288


@dataclass(frozen=True)
class Roster:
    """A member's identity (None before it has one), WireGuard key,
    signing key, overlay address, the peers its spec declares with
    their evidence, and the tombstones it keeps"""

    identity: bytes | None
    public_key: str
    sign_key: str
    address: str
    members: tuple[Peer, ...]
    removed: tuple[Removal, ...] = ()
    # the root's CRL for etcd, the newest this member holds
    # (keel.mesh.etcdca), or None
    crl: str | None = None
    # the mesh's root certificate this member holds, and the notice of
    # where the root's key is, signed by it (keel.mesh.rootholder,
    # keel#105); None when it holds none
    root: str | None = None
    holder: dict | None = None


def dumps(roster: Roster) -> bytes:
    return json.dumps({
        "identity": roster.identity.hex() if roster.identity else None,
        "public_key": roster.public_key, "sign_key": roster.sign_key,
        "address": roster.address,
        "members": [asdict(one) for one in roster.members],
        "removed": [asdict(one) for one in roster.removed],
        "crl": roster.crl, "root": roster.root,
        "holder": roster.holder}, sort_keys=True).encode()


def loads(body: bytes) -> Roster:
    data = protocol.loaded(body)
    found = protocol.field(data, "members", list)
    gone = protocol.field(data, "removed", list)
    if len(found) > MAX_MEMBERS or len(gone) > MAX_REMOVED:
        raise ProtocolError(f"more than {MAX_MEMBERS} members or"
                            f" {MAX_REMOVED} tombstones")
    return Roster(identity=mesh_identity(data.get("identity")),
                  public_key=protocol.key(data, "public_key"),
                  sign_key=protocol.key(data, "sign_key"),
                  address=protocol.overlay(data, "address", False),
                  members=tuple(protocol.peer(one) for one in found),
                  removed=tuple(protocol.removal(one) for one in gone),
                  crl=crl(data.get("crl")),
                  root=root_certificate(data.get("root")),
                  holder=holder_notice(data.get("holder")))


def root_certificate(value: object) -> str | None:
    """A roster's root certificate; one that cannot be read is left out"""
    from keel.mesh import rootholder
    return rootholder.certificate(value)


def holder_notice(value: object) -> dict | None:
    """A roster's notice of the root's holder; one that cannot be read
    is left out"""
    from keel.mesh import rootholder
    return rootholder.notice(value)


def crl(value: object) -> str | None:
    """A roster's CRL; one that cannot be read is left out, never a
    roster refused for it"""
    from keel.mesh import etcdmsg
    try:
        return None if value is None else etcdmsg.crl(value)
    except ProtocolError:
        return None


def mesh_identity(value: object) -> bytes | None:
    if value is None:
        return None
    try:
        found = bytes.fromhex(value) if isinstance(value, str) else b""
    except ValueError:
        found = b""
    if len(found) != MESH_ID_BYTES:
        raise ProtocolError("identity is not a mesh identity")
    return found


def with_members(doc: dict, found: tuple[Peer, ...],
                 own_key: str) -> tuple[dict, tuple[Peer, ...]]:
    """`doc` with the members of `found` it can take as peers, as a new
    document, and those members; `doc` itself when there are none

    A member is left out when its key is this node's or a peer's
    already, or its address is off this node's overlay prefix, this
    node's own, or inside a peer's allowed_ips: a roster never replaces
    or shadows what the spec declares.
    """
    network = doc.get("network") or {}
    overlay = dict((network.get("overlay") or {}).get("wireguard") or {})
    if not overlay.get("address"):
        return doc, ()
    own = ipaddress.IPv6Interface(str(overlay["address"]))
    peers = list(overlay.get("peers") or [])
    keys = [own_key] + [str(one.get("public_key")) for one in peers]
    taken = [ipaddress.ip_network(f"{own.ip}/128")] + [
        ipaddress.ip_network(net) for one in peers for net in allowed(one)]
    added = []
    for member in found:
        address = ipaddress.IPv6Address(member.address)
        if any(same_key(member.public_key, key) for key in keys) or \
                address not in own.network or \
                any(address in net for net in taken):
            continue
        entry = {"public_key": member.public_key}
        if member.endpoint:
            entry["endpoint"] = member.endpoint
        entry["allowed_ips"] = [f"{address}/128"]
        peers.append(entry)
        keys.append(member.public_key)
        taken.append(ipaddress.ip_network(f"{address}/128"))
        added.append(member)
    if not added:
        return doc, ()
    return {**doc, "network": {**network, "overlay": {
        **(network.get("overlay") or {}),
        "wireguard": {**overlay, "peers": peers}}}}, tuple(added)
