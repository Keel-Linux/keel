# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh remove: a node out of the mesh, before etcd (0048)

"Before etcd, the command removes the peer on the member it ran on and
sends the same announcement as a join, so the others drop it too." On
the member it runs on: a tombstone, signed with this node's key
(keel.mesh.trust), and the peer out of this node's spec (0013), applied
under 0018's window and confirmed as keel mesh sync confirms a change
(keel.mesh.sync): by a handshake from a peer it keeps, or, with no peer
left, by the route check alone. Then this node's roster, the tombstone
in it, goes to each of its other peers. Each takes the tombstone only
when the key that signed it may remove that node: the member that
admitted it, an operator root, or the node itself (trust.may_remove);
it
then drops the peer through one window of its own, and no sync adds the
key again. A member offline then learns it at its next sync.

With etcd, the node's etcd member goes too, but only when this node may
remove it from the whole mesh, by the same rule (0048, third round,
point 4: trust.may_remove_everywhere); otherwise the removal is local
only, and its admitter or a trust root removes it from etcd
(keel.mesh.etcd.leave). A root is not always a root both ways (the
inviter of a node is its root, not the other way), so the removal of
one of this node's roots is refused, and nothing changes, unless every
other peer that holds that root as one holds this node as one too, as
their rosters say (`root_problem`, keel#99).
"""

import ipaddress
from collections.abc import Callable

from keel import exits
from keel.mesh import etcd, etcdcare, identity, signing, sync, trust
from keel.mesh.node import NodeError, without_peer
from keel.mesh.signing import SigningError
from keel.mesh.sync import Syncer
from keel.network.wireguard import same_key


def named(syncer: Syncer, which: str) -> tuple[str, str] | None:
    """(key, overlay address) of the peer `which` names: its key, or an
    address its allowed_ips hold"""
    try:
        address = ipaddress.ip_address(which)
    except ValueError:
        address = None
    for one in syncer.node.peers(""):
        if same_key(one.public_key, which) or (
                address is not None
                and ipaddress.ip_address(one.address) == address):
            return one.public_key, one.address
    return None


def root_problem(syncer: Syncer, store: trust.Store, key: str) -> str | None:
    """Why this node may not remove `key`, one of its operator roots,
    mesh-wide: a member that holds `key` as a root and not this node
    would not take the tombstone (trust.everywhere_problem). The
    rosters of this node's other peers say it; a node this node
    admitted needs none"""
    known = store.find(key)
    if known is None or trust.admitted_by(store.members[known],
                                          signing.public(syncer.root)):
        return None
    public, problem = syncer.node.public_key()
    if public is None:
        return problem
    others = tuple(one for one in syncer.node.peers(public)
                   if not same_key(one.public_key, key))
    rosters = sync.asked(syncer, others)
    return trust.everywhere_problem(store, signing.public(syncer.root),
                                    public, key, rosters, len(others))


def remove(syncer: Syncer, which: str, out: Callable[[str], None]) -> int:
    try:
        found = named(syncer, which)
        own = identity.read(syncer.root)
        if found is None:
            raise ValueError(f"{which}: no peer of this node has that key"
                             " or overlay address")
        if own is None:
            raise ValueError("this node holds no mesh identity to sign the"
                             " removal in")
        if syncer.node.waiting():
            raise ValueError("a network change waits for its confirmation"
                             " on this node: confirm or revert it, then"
                             " remove")
        signing.ensure(syncer.root)
        store = trust.load(syncer.root)
        if not trust.room_for(store, signing.public(syncer.root)):
            raise ValueError(f"this node keeps {len(store.removed)}"
                             " tombstones, as many as it may")
        doc = syncer.node.document()
        # asked before the tombstone, which forgets the node's evidence
        everywhere = trust.may_remove_everywhere(
            store, signing.public(syncer.root), found[0])
        problem = everywhere and root_problem(syncer, store, found[0])
        if problem:
            raise ValueError(problem)
        trust.record_removal(store, trust.removal(syncer.root, own,
                                                  found[0], syncer.clock()))
        trust.save(syncer.root, store)
    except (ValueError, NodeError, SigningError) as e:
        syncer.err(str(e))
        return exits.MESH_REFUSED
    code = sync.changed_and_confirmed(syncer, doc,
                                      without_peer(doc, found[0]), (),
                                      (found[0],))
    if code != exits.OK:
        syncer.err("the tombstone is kept: keel mesh sync drops the peer"
                   " again once the change can be confirmed")
        return code
    etcdcare.leave(etcd.Etcd(syncer.node, syncer.clock, syncer.err),
                   found[1], everywhere, found[0])
    # the roster announced carries the CRL that revokes the node
    sync.announce(syncer, found[0], "the removal")
    out(f"removed {found[0]} at {found[1]}: the other members drop it on"
        " its tombstone, and no keel mesh sync adds it again")
    return exits.OK
