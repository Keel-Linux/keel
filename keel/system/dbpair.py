# Copyright (c) 2026 KeelLinux maintainers
"""A paired database node, as the planner sees it (0020, 0031, 0049)

A node that declares `appliance.vip` is one of a pair. Its primary is
the VIP's holder (0049, third round, point 2): `database.server.role` in
the spec is the role chosen at installation, which decides who seeds
from whom before any claim exists, and is runtime state from the first
claim on (0020, "One role"). Everything that depends on the role follows
the VIP: read_only, the root lock, replication's direction. With the
pair record (keel vip pair) nothing is typed twice: the other member's
address is who may replicate and, when it holds the VIP, where to
replicate from; the credential is the pair's (keel.system.dbsecret).

Pure but for the files it reads: the VIP's state and the pair record
under /var/lib/keel/vip, and this node's WireGuard key.
"""

import ipaddress
from dataclasses import dataclass

from keel.inspect.tree import Tree
from keel.mesh import vip as vipstate
from keel.mesh import vippair
from keel.network import wgkeys, wireguard
from keel.network.wireguard import allowed, same_key

PRIMARY, REPLICA = vipstate.PRIMARY, vipstate.REPLICA
ROLE_FILE = "var/lib/keel/role"
# what keel-database-follow and the Webmin banner of tracker#57 read
ROLE_TEXT = "role={role}\nreplicates=database\nvip={vip}\n"


@dataclass(frozen=True)
class PairState:
    """What this node knows of its pair"""

    vip: str
    own_key: str | None
    # the other member of the pair record, and its overlay address from
    # this node's spec; None before keel vip pair, or when the spec has
    # no peer of that key
    peer_key: str | None = None
    peer_address: str | None = None
    # the VIP's role here, from the newest claim this node took; None
    # before any claim (the installation's declared role then stands)
    role: str | None = None
    holder_address: str | None = None
    fenced: bool = False
    released: bool = False
    problem: str = ""

    @property
    def claimed(self) -> bool:
        return self.role is not None


def observe_pair(root: str, doc: dict) -> PairState | None:
    """The pair this node is in, or None on a node that declares no VIP"""
    vip = vipstate.declared(doc)
    if vip is None:
        return None
    tree = Tree(root)
    overlay = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    own_key = wgkeys.public(tree.path(
        wireguard.key_path(overlay).lstrip("/")))[0] if overlay else None
    problem = ""
    try:
        record = vippair.read(root, vip)
    except ValueError as e:
        record, problem = None, str(e)
    peer_key = None
    if record is not None:
        peer_key = next((one for one in record.members
                         if not (own_key and same_key(one, own_key))), None)
    try:
        held = vipstate.read(root, vip)
    except ValueError as e:
        held, problem = None, problem or str(e)
    peer_at = peer_address(doc, peer_key)
    role = holder_at = None
    if held is not None and held.claim is not None:
        role = vipstate.role(doc, held, own_key)
        # a node that released, or was fenced, while its own claim is
        # still the newest it knows: the other member is the primary
        holder_at = peer_at if own_key and same_key(
            held.claim.holder, own_key) else held.claim.address
    return PairState(
        vip=vip, own_key=own_key, peer_key=peer_key,
        peer_address=peer_at, role=role,
        holder_address=holder_at,
        fenced=bool(held and held.fenced),
        released=bool(held and held.released), problem=problem)


def peer_address(doc: dict, key: str | None) -> str | None:
    """The /128 the spec routes to the peer `key`, as an address"""
    if key is None:
        return None
    overlay = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    for peer in overlay.get("peers") or []:
        if not same_key(str(peer.get("public_key")), key):
            continue
        for net in allowed(peer):
            try:
                found = ipaddress.ip_network(net)
            except ValueError:
                continue
            if found.version == 6 and found.prefixlen == 128:
                return str(found.network_address)
    return None


def role_of(pair: PairState, declared: str) -> str:
    """The role this node acts in: the VIP's once claimed, else the
    installation's (0020)"""
    return pair.role or declared


def primary_host(pair: PairState, server: dict) -> str | None:
    """Where a replica replicates from: the holder's own overlay address
    (never the VIP, 0029), the declared endpoint, or the other member"""
    if pair.role == REPLICA and pair.holder_address:
        return pair.holder_address
    declared = ((server.get("replication") or {}).get("primary") or {})
    if declared.get("host"):
        return str(declared["host"])
    return pair.peer_address


def allowed_hosts(pair: PairState, server: dict) -> list[str] | None:
    """Who may replicate from this node: what the spec declares, else
    the other member's address; None when neither is known"""
    declared = (server.get("replication") or {}).get("allowed_from")
    if declared is not None:
        return [str(one) for one in declared]
    return [pair.peer_address] if pair.peer_address else None


def role_text(role: str, vip: str) -> str:
    return ROLE_TEXT.format(role=role, vip=vip)


def bind_addresses(listen: list | None, overlay: list[str],
                   vip: str) -> list[str]:
    """What a paired server binds: the declared addresses, else its own
    overlay addresses and the loopbacks, and the VIP (with
    net.ipv6.ip_nonlocal_bind, so the replica binds an address it does
    not carry, and the primary answers on it the moment it does)"""
    found = [str(one) for one in (listen or [])] or \
        list(overlay) + ["::1", "127.0.0.1"]
    if vip not in found:
        found.append(vip)
    return found
