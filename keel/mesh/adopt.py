# Copyright (c) 2026 KeelLinux maintainers
"""The mesh's identity and trust roots, set by the operator (0048)

Only a join (keel.mesh.joining) or an explicit act of the operator sets
a node's mesh identity; no roster does (keel.mesh.sync). The acts are:

- `keel mesh create --adopt` (`adopt_mesh`), on one node of a mesh built
  by hand before `keel mesh` existed: its own identity, else the one
  its peers hold, else a new one;
- `keel mesh sync --adopt ADDRESS` (`adopt_from`), on each other node,
  and to repair a split: the identity of the member at ADDRESS in place
  of this node's.

Each also makes the peers the spec lists this node's trust roots
(keel.mesh.trust): a mesh built by hand has no admission evidence, and
the operator's act is what vouches for the nodes it lists. And `keel
mesh invite` never makes a second identity for a mesh
(`invite_identity`).
"""

from collections.abc import Callable

from keel import exits
from keel.mesh import identity, invites, signing, trust
from keel.mesh.node import NodeError
from keel.mesh.signing import SigningError
from keel.mesh.sync import Syncer, asked, pull, short


class Refused(ValueError):
    """An invite that would split the mesh's identity, and why"""


def rooted(syncer: Syncer) -> trust.Store:
    """This node's signing key made, and the peers of its spec its trust
    roots; raises SigningError, ValueError (a damaged store)"""
    signing.ensure(syncer.root)
    store = trust.load(syncer.root)
    trust.make_roots(store, (one.public_key
                             for one in syncer.node.peers("")))
    trust.save(syncer.root, store)
    return store


def adopt_from(syncer: Syncer, host: str) -> int:
    """`keel mesh sync --adopt ADDRESS`: the identity of the member at
    `host` in place of this node's, the spec's peers made trust roots,
    then a sync"""
    public, problem = syncer.node.public_key()
    if public is None:
        syncer.err(problem)
        return exits.MESH_REFUSED
    peer = next((one for one in syncer.node.peers(public)
                 if one.address == host), None)
    if peer is None:
        syncer.err(f"{host}: not a peer of this node; the identity is taken"
                   " from a member this node knows")
        return exits.MESH_REFUSED
    waiting = invites.pending(syncer.root, syncer.clock())
    if waiting:
        syncer.err(f"{len(waiting)} pending invite(s) carry this node's"
                   " identity in their tokens: wait until they are used or"
                   " expire, then adopt")
        return exits.MESH_REFUSED
    found = asked(syncer, (peer,))
    if not found:
        return exits.MESH_REFUSED
    if found[0].identity is None:
        syncer.err(f"member {host} holds no mesh identity: keel mesh create"
                   " --adopt there first")
        return exits.MESH_REFUSED
    try:
        rooted(syncer)
    except (SigningError, ValueError) as e:
        syncer.err(str(e))
        return exits.MESH_REFUSED
    before = identity.replace(syncer.root, found[0].identity)
    syncer.err(f"this node now holds the mesh identity"
               f" {short(found[0].identity)} of {host}"
               f" (was {short(before) if before else 'none'}), and trusts"
               " the peers its spec lists as roots")
    return pull(syncer)


def peer_identities(syncer: Syncer) -> tuple[dict[bytes, str], int, list]:
    """(each identity this node's peers hold, with the address of one of
    them; how many peers it has; the rosters that answered)"""
    public, problem = syncer.node.public_key()
    if public is None:
        raise ValueError(problem)
    known = syncer.node.peers(public)
    found = asked(syncer, known)
    named: dict[bytes, str] = {}
    for one in found:
        if one.identity is not None:
            named.setdefault(one.identity, one.address)
    return named, len(known), found


def adopt_mesh(syncer: Syncer, out: Callable[[str], None]) -> int:
    """`keel mesh create --adopt`: one identity for a mesh built by hand

    On the node chosen: its own identity, else the one its peers hold,
    else a new one; refused when its peers hold another than its own,
    or disagree. The spec's peers become its trust roots, and those
    that answered with the identity are bound to their signing keys.
    """
    try:
        overlay = syncer.node.overlay()
        if not overlay.get("address"):
            raise ValueError("this node has no overlay: keel mesh create"
                             " makes a new mesh, without --adopt")
        own = identity.read(syncer.root)
        holders, _, rosters = peer_identities(syncer)
    except (ValueError, NodeError) as e:
        syncer.err(str(e))
        return exits.MESH_REFUSED
    named = set(holders)
    if own is not None and named - {own}:
        syncer.err(f"this node holds {short(own)} and its peers"
                   f" {', '.join(short(one) for one in sorted(named))}: on"
                   " this node, keel mesh sync --adopt with the address of"
                   " a member of the identity to keep")
        return exits.MESH_REFUSED
    if own is None and len(named) > 1:
        syncer.err("the peers name different mesh identities: keep one"
                   " with keel mesh sync --adopt on the others")
        return exits.MESH_REFUSED
    try:
        store = rooted(syncer)
    except (SigningError, ValueError) as e:
        syncer.err(str(e))
        return exits.MESH_REFUSED
    if own is None:
        own = named.pop() if named else identity.ensure(syncer.root)
        identity.adopt(syncer.root, own)
    # fetched by this node from each root's own address (`asked`)
    for one in rosters:
        if one.identity == own:
            trust.bind_root(store, one.public_key, one.sign_key)
    trust.save(syncer.root, store)
    out(f"the mesh's identity is {own.hex()}, held by this node, which"
        f" trusts the {len(syncer.node.peers(''))} peer(s) its spec lists"
        " as roots")
    out("on each other node: keel mesh sync --adopt with this node's"
        " overlay address")
    return exits.OK


def invite_identity(syncer: Syncer) -> bytes:
    """The identity an invite carries, never a second one for a mesh

    A node with no peer makes one, as before. One with peers checks what
    they hold: another than its own refuses, with the repair; with none
    of its own it refuses too, since only a join or the operator's
    --adopt sets it. Peers that do not answer are warned about, and
    decide nothing. Raises Refused, or ValueError for an identity file
    damaged or a key that cannot be read.
    """
    own = identity.read(syncer.root)
    holders, count, rosters = peer_identities(syncer)
    named = set(holders)
    if count == 0:
        return identity.ensure(syncer.root)
    if own is None:
        raise Refused(
            f"this node has {count} peer(s) and no mesh identity: an invite"
            " here would make a second identity for the mesh. Run keel"
            " mesh create --adopt on one node of the mesh, and keel mesh"
            " sync --adopt with that node's address on the others, this"
            " one included")
    if named - {own}:
        other = sorted(named - {own})[0]
        raise Refused(
            f"this node's peers are in mesh {short(other)} and this node"
            f" in {short(own)}: an invite here would add a node to neither."
            f" keel mesh sync --adopt {holders[other]} takes their"
            " identity, then invite again")
    if len(rosters) < count:
        syncer.err(f"Warning: {count - len(rosters)} of this node's {count}"
                   " peer(s) did not say which mesh they are in")
    return own
