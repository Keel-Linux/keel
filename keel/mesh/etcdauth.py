# Copyright (c) 2026 KeelLinux maintainers
"""etcd's users and roles: who may write which of the mesh's keys

keel#83: the root signs every certificate etcd is shown, and names it
after its member (keel.mesh.etcdpki), so etcd's users, which are the
CNs of client certificates over gRPC, are the members themselves, and
etcd's access control means what it says. The root's holder manages
the users and the roles, with its admin certificate (CN `root`, etcd's
root user); no other member can, since etcd lets only the root role
change them.

| User | Roles |
| --- | --- |
| `root` | `root`: the holder's admin certificate alone |
| each member, `keel-<address>` | `keel-member`, and `keel-vip-<vip>` for each VIP whose pair it is in |

| Role | Permissions |
| --- | --- |
| `keel-member` | read every key under `/keel/<mesh>/`; read-write under `/keel/<mesh>/etcd/`, the mesh's own keys (the lock of etcd's rolling restart) |
| `keel-vip-<vip>` | read-write under `/keel/<mesh>/vip/<vip>/`: the VIP's counter and holder keys, its pair's two members alone |

So a member outside a VIP's pair can read its keys and cannot write or
delete them, or revoke a lease attached to them (etcd lets a lease be
revoked only by a user that may write every key on it). It can still
keep a lease alive by its ID, which etcd 3.5 checks no permission for:
the VIP's controllers decide by their own lease and by the counter's
transaction, never by a key's value (keel.mesh.vipetcd), as before
keel#83, so that is a delay at most, never a second holder.

Membership changes (member add, promote, remove) take the root role in
etcd once auth is on, so they run on the holder, as admissions already
do. The pairs are known to the holder from the pair records it is sent
(`pair`, by `keel vip pair` and `keel mesh etcd tend` on the pair's
members) and from the claims under the VIP's keys, each checked as any
node checks a pair record (keel.mesh.vipnode.record_problem); a VIP
whose role is not granted yet cannot be claimed by its pair until it
is, which is a new pair waiting for the root, as a new member does.

The holder converges etcd to what it wants (`converge`): it adds what
is missing and takes away only what keel made (roles and permissions
named keel-), never a user or a role an operator added. Auth itself is
enabled by `keel mesh etcd reissue` once every member holds a
certificate the root signed (keel.mesh.etcdreissue). Whether it is on
is etcd's to say (`enabled` asks `auth status`, kept for a few
seconds), never a file's: a run that stopped between enabling it and
anything else finds the truth when it runs again.
"""

import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass

from keel.mesh import etcdstate
from keel.mesh.etcdclient import Client, EtcdError, range_end
from keel.mesh.etcdstate import ROOT_USER, StateError, name, read, write

ROOT_ROLE = "root"
MEMBER_ROLE = "keel-member"
OWN = "keel-"
# how long etcd's answer about its auth is kept
STATUS_FOR = 5.0
_STATUS: dict[str, tuple[float, bool]] = {}
PAIRS = f"{etcdstate.DIR}/pairs.json"
PAIR_SUFFIX = ".pair"


def mesh_prefix(mesh_id: str) -> str:
    return f"/keel/{mesh_id}/"


def own_prefix(mesh_id: str) -> str:
    """The mesh's own keys, which every member may write"""
    return f"/keel/{mesh_id}/etcd/"


def vip_prefix(mesh_id: str, vip: str) -> str:
    """keel.mesh.vipetcd's keys of `vip`, and nothing else's: the slash
    keeps fd00::1's role off fd00::10's keys"""
    return f"/keel/{mesh_id}/vip/{vip}/"


def vip_role(vip: str) -> str:
    return f"{OWN}vip-{vip}"


@dataclass(frozen=True)
class Wanted:
    """The roles (their permissions: kind and key prefix) and the users
    (their roles) etcd should have"""

    roles: dict[str, frozenset[tuple[str, str]]]
    users: dict[str, frozenset[str]]


def wanted(mesh_id: str, members: tuple[str, ...],
           pairs: dict[str, tuple[str, ...]]) -> Wanted:
    """For the members at `members` and the pairs, VIP to its members'
    addresses"""
    roles = {MEMBER_ROLE: frozenset({("read", mesh_prefix(mesh_id)),
                                     ("readwrite", own_prefix(mesh_id))})}
    users: dict[str, set[str]] = {ROOT_USER: {ROOT_ROLE}}
    for one in members:
        users[name(one)] = {MEMBER_ROLE}
    for vip, both in sorted(pairs.items()):
        role = vip_role(vip)
        roles[role] = frozenset({("readwrite", vip_prefix(mesh_id, vip))})
        for one in both:
            users.setdefault(name(one), {MEMBER_ROLE}).add(role)
    return Wanted(roles, {k: frozenset(v) for k, v in users.items()})


def converge(client: Client, want: Wanted) -> list[str]:
    """etcd's roles and users made what `want` says, as etcd's root
    user; what was changed. Raises EtcdError"""
    done = []
    roles = set(client.roles())
    for role in sorted({ROOT_ROLE, *want.roles} - roles):
        client.role_add(role)
        done.append(f"role {role} added")
    for role, perms in sorted(want.roles.items()):
        have = client.permissions(role)
        wished = {(kind, key, range_end(key)) for kind, key in perms}
        for kind, key, end in sorted(wished - have):
            client.permit(role, kind, key)
            done.append(f"role {role}: {kind} on {key}")
        for kind, key, end in sorted(have - wished):
            client.unpermit(role, key)
            done.append(f"role {role}: no longer {kind} on {key}")
    for role in sorted(one for one in roles - set(want.roles)
                       if one.startswith(OWN)):
        client.role_delete(role)
        done.append(f"role {role} deleted")
    users = set(client.users())
    for user, wished in sorted(want.users.items()):
        if user not in users:
            client.user_add(user)
            done.append(f"user {user} added")
            have = set()
        else:
            have = set(client.user_roles(user))
        for role in sorted(wished - have):
            client.grant_role(user, role)
            done.append(f"user {user}: role {role}")
        for role in sorted(one for one in have - wished
                           if one.startswith(OWN)):
            client.revoke_role(user, role)
            done.append(f"user {user}: no longer role {role}")
    return done


def enabled(etcd, client: Client | None = None,
            now: Callable[[], float] = time.monotonic) -> bool:
    """Whether etcd's auth is on, as etcd says (`auth status`), kept
    STATUS_FOR seconds; raises EtcdError when etcd does not answer"""
    kept = _STATUS.get(etcd.root)
    if kept is not None and now() - kept[0] < STATUS_FOR:
        return kept[1]
    found = (client or etcd.admin()).auth_enabled()
    _STATUS[etcd.root] = (now(), found)
    return found


def forget(root: str) -> None:
    """etcd's auth changed: asked again next time"""
    _STATUS.pop(root, None)


def pairs(root: str) -> dict[str, list[str]]:
    """On the holder: the pairs it gave a role, VIP to its two keys"""
    try:
        found = json.loads(read(root, PAIRS) or "{}")
    except ValueError:
        return {}
    if not isinstance(found, dict):
        return {}
    return {str(k): [str(one) for one in v] for k, v in found.items()
            if isinstance(v, list) and len(v) == 2}


def keep_pair(root: str, vip: str, members: tuple[str, ...]) -> None:
    with etcdstate.locked(root):
        found = pairs(root)
        found[vip] = list(members)
        write(root, PAIRS, json.dumps(found, sort_keys=True) + "\n")


def checked_pair(etcd, raw: object, sender: str | None = None):
    """The pair record `raw`, when this node takes it as any node does
    and `sender`, when given, is one of its members; raises StateError.
    The first record kept for a VIP binds it, as on every node"""
    from keel.mesh import vipnode, vippair
    from keel.mesh.protocol import ProtocolError
    from keel.mesh.vipnode import VipError
    from keel.network.wireguard import same_key
    here = vipnode.Here(etcd.node, etcd.clock, etcd.err)
    try:
        pair = vippair.loads(raw)
        if sender is not None and not any(same_key(one, sender)
                                          for one in pair.members):
            raise StateError("only a member of the pair sends its record")
        problem = vipnode.record_problem(here, pair)
        if problem:
            raise StateError(problem)
        if vippair.read(etcd.root, pair.vip) is None:
            vippair.write(etcd.root, pair)
    except (ProtocolError, VipError, ValueError) as e:
        raise StateError(f"the pair record is not taken: {e}") from None
    return pair


def addresses(etcd) -> dict[str, str]:
    """Every member this node knows, by WireGuard key"""
    from keel.mesh import etcd as etcd_
    found = {one.public_key: one.address for one in etcd.node.peers("")}
    own = etcd_.own_key(etcd)
    if own:
        found[own] = etcd_.own_address(etcd.node)
    return found


def from_claims(etcd, client: Client, mesh_id: str) -> int:
    """The pairs the claims under the VIPs' keys rest on, checked and
    kept; how many. Raises EtcdError"""
    from keel.mesh import vipmsg
    from keel.mesh.protocol import ProtocolError
    found = 0
    for value in client.prefix(f"/keel/{mesh_id}/vip/"):
        if not value.key.endswith("/epoch"):
            continue
        try:
            claim = vipmsg.claim_of(value.value)
            pair = checked_pair(etcd, claim.pair.dumps())
        except (ProtocolError, StateError, AttributeError) as e:
            etcd.err(f"etcd: the claim at {value.key} gives no pair: {e}")
            continue
        keep_pair(etcd.root, pair.vip, pair.members)
        found += 1
    return found


def reconcile(etcd, client: Client | None = None) -> list[str]:
    """On the root's holder: etcd's users and roles converged for the
    cluster's members and the pairs it knows; what changed. Raises
    StateError or EtcdError"""
    from keel.mesh import identity
    if not etcdstate.holds_root(etcd.root):
        raise StateError("only the root's holder manages etcd's users")
    admin = client or etcd.admin()
    mesh_id = identity.read(etcd.root).hex()
    members = tuple(sorted({one.address for one in admin.members()
                            if one.address}))
    known = addresses(etcd)
    placed = {}
    for vip, keys in pairs(etcd.root).items():
        at = tuple(known[one] for one in keys if one in known)
        if len(at) == len(keys):
            placed[vip] = at
        else:
            etcd.err(f"etcd: the pair of {vip} names a node this holder"
                     " does not know; its role waits")
    return converge(admin, wanted(mesh_id, members, placed))


def pair_roles(etcd, raw: object, sender: str) -> list[str]:
    """On the root's holder: a pair's record from one of its members,
    kept, and the roles converged; the pair's role. Raises StateError or
    EtcdError"""
    pair = checked_pair(etcd, raw, sender)
    keep_pair(etcd.root, pair.vip, pair.members)
    for line in reconcile(etcd):
        etcd.err(f"etcd: {line}")
    return [vip_role(pair.vip)]


def kept_pairs(root: str) -> list[dict]:
    """The pair records this node keeps, as messages carry them"""
    from keel.mesh import vip as vipstate
    from keel.mesh import vippair
    try:
        names = os.listdir(etcdstate.path(root, vipstate.DIR))
    except FileNotFoundError:
        return []
    found = []
    for one in sorted(names):
        if not one.endswith(PAIR_SUFFIX):
            continue
        try:
            pair = vippair.read(root, one[:-len(PAIR_SUFFIX)])
        except ValueError:
            continue
        if pair is not None:
            found.append(pair)
    return found


def announce(etcd) -> list[str]:
    """This node's pairs sent to the root's holder, which gives each
    pair its role: what `keel vip pair` and `keel mesh etcd tend` do on a
    pair's member; what was said"""
    from keel.mesh import etcd as etcd_
    from keel.mesh import etcdmsg
    from keel.mesh.memberlink import LinkError
    from keel.mesh.protocol import ProtocolError
    from keel.mesh.signing import SigningError
    own = etcd_.own_key(etcd)
    said = []
    for pair in kept_pairs(etcd.root):
        if not own or not pair.has(own):
            continue
        try:
            if etcdstate.holds_root(etcd.root):
                pair_roles(etcd, pair.dumps(), own)
            else:
                at = etcdstate.holder(etcd.root)
                if at is None:
                    raise StateError("this node does not know the root's"
                                     " holder")
                etcdmsg.loaded(etcd_.said(etcd, etcdmsg.PAIR, at,
                                          {"pair": pair.dumps()}))
            said.append(f"etcd: {pair.vip}: its pair's role is granted")
        except (StateError, EtcdError, LinkError, SigningError,
                ProtocolError, ValueError) as e:
            said.append(f"etcd: {pair.vip}: its pair's role waits for the"
                        f" root's holder ({e})")
    return said
