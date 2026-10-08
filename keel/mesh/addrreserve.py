# Copyright (c) 2026 KeelLinux maintainers
"""A new node's address reserved in etcd by its invite (0048, 0051)

`keel mesh invite` draws a random address of the inviter's region
(keel.mesh.allocate). Two members of one region that invite at the same
time do not know each other's pending invites, so their draws can meet.
With etcd formed, the invite therefore also reserves the address there:
one key per address, written only when it does not exist yet (a
compare-and-swap on its version), attached to a lease that ends a day
(AFTER_JOIN) after the invite and the window of its join end:

    /keel/<mesh id>/etcd/addresses/<address>
    {"mesh_id", "address", "invite", "by"}

A draw another invite holds is drawn again (`TRIES` at most). The join
is admitted only while the key still names its invite (`problem`): a
reservation that expired, or that another invite holds, refuses the
join, and etcd not answering refuses it too. The key is under the
mesh's own prefix, which every member may write (keel.mesh.etcdauth).
Once the join is confirmed the new node is a peer, which keel mesh
sync announces to every member and every inviter's allocator avoids;
the lease lets the key go a day later.

Before etcd, or on a node whose etcd is not formed, nothing is
reserved: the random draw alone keeps two inviters apart.
"""

import ipaddress
import json
from collections.abc import Callable
from contextlib import suppress

from keel.mesh import etcdstate, identity
from keel.mesh.etcdauth import own_prefix
from keel.mesh.etcdclient import Client, EtcdError, absent
from keel.mesh.etcdmsg import canonical

ADDRESSES = "addresses/"
# draws in a row that other invites hold in etcd before the invite is
# refused
TRIES = 8
# how long the key outlives the invite and its join's window: the new
# node is then a peer, and keel mesh sync has told every member of it
AFTER_JOIN = 24 * 60 * 60


def key_of(mesh_id: str, address: str) -> str:
    found = ipaddress.IPv6Interface(address).ip
    return f"{own_prefix(mesh_id)}{ADDRESSES}{found}"


def record(mesh_id: str, address: str, invite_id: str, by: str) -> dict:
    return {"mesh_id": mesh_id,
            "address": str(ipaddress.IPv6Interface(address).ip),
            "invite": invite_id, "by": by}


def reserve(client: Client, mesh_id: str, address: str, invite_id: str,
            by: str, ttl: int) -> bool:
    """`address` reserved for the invite for `ttl` seconds; False when
    another invite holds it. Raises EtcdError"""
    key = key_of(mesh_id, address)
    lease = client.grant(max(int(ttl), 1))
    if client.swap([absent(key)], [(key, canonical(record(
            mesh_id, address, invite_id, by)), lease)]):
        return True
    with suppress(EtcdError):
        client.revoke(lease)
    return False


def problem(client: Client, mesh_id: str, address: str,
            invite_id: str) -> str | None:
    """Why the join at `address` is not admitted by the reservation of
    invite `invite_id`, or None"""
    key = key_of(mesh_id, address)
    try:
        found = next((one for one in client.prefix(key) if one.key == key),
                     None)
    except EtcdError as e:
        return (f"etcd did not answer ({e}): with etcd, a join is admitted"
                " only while its address is reserved there")
    if found is None:
        return (f"the reservation of {address} in etcd is gone (it"
                " expired or was removed): ask the inviter for a new"
                " invite")
    try:
        held = json.loads(found.value.decode())
        holder = held["invite"]
    except (ValueError, KeyError, TypeError, AttributeError):
        holder = None
    if holder != invite_id:
        return (f"{address} is reserved in etcd by another invite"
                f" ({holder or 'an unreadable reservation'}): ask the"
                " inviter for a new invite")
    return None


def formed(root: str, ready: Callable[[], bool]) -> bool:
    """Whether this node is a member of a formed etcd cluster; `ready`
    says whether its spec runs etcd (keel.mesh.etcd.ready)"""
    try:
        return etcdstate.cluster(root) is not None and ready()
    except (etcdstate.StateError, ValueError):
        return False


def mesh_of(root: str) -> str:
    """This node's mesh identity in hex; ValueError without one"""
    found = identity.read(root)
    if found is None:
        raise ValueError("this node holds no mesh identity")
    return found.hex()
