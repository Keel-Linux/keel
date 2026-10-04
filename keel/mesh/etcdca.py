# Copyright (c) 2026 KeelLinux maintainers
"""What only the root CA's holder does: form the cluster, revoke

The root CA's key stays on the first node (0048, third round, point 1),
and that node alone forms the cluster, once: so two inviters admitting
two nodes at once can never start two clusters ({A,B,C} and {A,B,D}).

- **The formation record.** The holder picks the members and signs, with
  the root's key, a record of the cluster token, the members (overlay
  address and WireGuard key) and the root's fingerprint (`record`). A
  member takes a cluster only with a record the root signed, for its own
  root and its own mesh, that names it (`problem`), and a member that is
  in a cluster takes no other record. The holder reserves its formation
  under its lock before it sends anything (`reserve`), so a second
  formation, by a concurrent join or a second `keel mesh etcd form`, is
  refused; a join that reverts gives the reservation back (`release`).
- **Revocation.** The holder keeps the serials it revoked and signs the
  CRL with the root (`revoke`), which every member writes to etcd's
  `--peer-crl-file` and `--client-crl-file`: etcd checks each
  certificate a peer or a client presents, its chain included, so
  revoking a removed member's intermediate revokes its leaves and every
  intermediate it issued. The holder signs the intermediates itself
  whenever it can (keel.mesh.etcdstate.grant_for) and records them by
  address, so a removal names them. The CRL travels in grants, in the
  members' rosters and in the answer to a revocation, and is taken only
  when the root signed it and it is newer (etcdstate.take_crl); the
  holder signs it again every ten days (`refresh`), its life being 30.
"""

import json
import os
from datetime import datetime, timedelta

from keel.mesh import etcdpki, etcdstate
from keel.mesh.etcdpki import PkiError
from keel.mesh.etcdstate import Cluster, Member, StateError, path, read, write

FORMATION = f"{etcdstate.DIR}/formation.json"
REVOKED = f"{etcdstate.DIR}/revoked.json"
LABEL = "keel mesh etcd formation 1"
REFRESH = timedelta(days=etcdpki.CRL_DAYS // 3)


def text(token: str, root: str, members: tuple[Member, ...]) -> str:
    return json.dumps({"label": LABEL, "token": token, "root": root,
                       "members": sorted([one.address, one.public_key]
                                         for one in members)},
                      sort_keys=True, separators=(",", ":"))


def record(root: str, members: tuple[Member, ...], token: str) -> Cluster:
    """A `new` cluster of `members`, its record signed with the root;
    raises StateError off the root's holder"""
    if not etcdstate.holds_root(root):
        raise StateError("only the node that holds the mesh's root CA forms"
                         " the cluster")
    ordered = tuple(sorted(members, key=lambda one: one.address))
    body = text(token, etcdstate.root_fingerprint(root), ordered)
    try:
        signature = etcdpki.sign(path(root, etcdstate.ROOT_KEY),
                                 body.encode())
    except PkiError as e:
        raise StateError(str(e)) from None
    return Cluster("new", ordered, token, body, signature)


def problem(root: str, cluster: Cluster) -> str | None:
    """Why `cluster` is not one this member may take, None when it may:
    its record signed by the root this member holds, for that root and
    the cluster's token, and for a `new` cluster, naming its members"""
    trusted = read(root, etcdstate.ROOT_CERT)
    if not trusted:
        return "this node holds no root to check the cluster's record"
    if not cluster.record or not cluster.signature or \
            not etcdpki.verified_by(trusted, cluster.record.encode(),
                                    cluster.signature):
        return "the cluster carries no record signed by the mesh's root"
    try:
        data = json.loads(cluster.record)
        named = {str(one[0]) for one in data["members"]}
        fine = (data["label"] == LABEL and data["token"] == cluster.token
                and data["root"] == etcdpki.fingerprint(trusted))
    except (ValueError, KeyError, TypeError, IndexError, PkiError):
        return "the cluster's record cannot be read"
    if not fine:
        return "the cluster's record is for another root or token"
    if cluster.state == "new" and named != set(cluster.addresses()):
        return "the cluster is not the one its record names"
    return None


def reserve(root: str, cluster: Cluster) -> bool:
    """The holder's one formation reserved, under the lock; False when
    one was reserved or a cluster exists"""
    with etcdstate.locked(root):
        if os.path.exists(path(root, FORMATION)) or \
                os.path.exists(path(root, etcdstate.CLUSTER)):
            return False
        write(root, FORMATION, json.dumps(cluster.dumps(),
                                          sort_keys=True) + "\n")
    return True


def release(root: str) -> None:
    """A formation whose join reverted given back, before any cluster"""
    with etcdstate.locked(root):
        if not os.path.exists(path(root, etcdstate.CLUSTER)):
            try:
                os.remove(path(root, FORMATION))
            except FileNotFoundError:
                pass


def revoked(root: str) -> dict[str, list[str]]:
    try:
        data = json.loads(read(root, REVOKED) or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def revoke(root: str, address: str | None, serials: dict[str, str],
           now: datetime) -> str:
    """On the root's holder: the intermediates it signed for the member
    at `address`, and `serials` (serial to its expiry, as openssl writes
    it), revoked; the new CRL. Raises StateError"""
    if not etcdstate.holds_root(root):
        raise StateError("only the root CA's holder revokes")
    with etcdstate.locked(root):
        found = revoked(root)
        try:
            issued = json.loads(read(root, etcdstate.ISSUED) or "{}")
        except ValueError:
            issued = {}
        named = dict(serials)
        if address is not None:
            named.update({one[0]: one[1] for one in issued.get(address, [])})
        for serial, expiry in named.items():
            found.setdefault(serial.upper(), [expiry, etcdpki.stamp(now)])
        write(root, REVOKED, json.dumps(found, sort_keys=True) + "\n")
        return signed(root, found)


def signed(root: str, found: dict[str, list[str]]) -> str:
    held = read(root, etcdstate.CRL)
    try:
        number = etcdpki.crl_number(held) + 1 if held else 1
        made = etcdpki.crl(path(root, etcdstate.ROOT_KEY),
                           read(root, etcdstate.ROOT_CERT),
                           {k: (v[0], v[1]) for k, v in found.items()},
                           number)
    except PkiError as e:
        raise StateError(str(e)) from None
    write(root, etcdstate.CRL, made)
    return made


def refresh(root: str, now: datetime) -> bool:
    """On the root's holder: the CRL signed again once a third of its
    life went by; whether it was"""
    if not etcdstate.holds_root(root):
        return False
    try:
        age = now.timestamp() - os.path.getmtime(path(root, etcdstate.CRL))
    except OSError:
        age = REFRESH.total_seconds()
    if age < REFRESH.total_seconds():
        return False
    with etcdstate.locked(root):
        signed(root, revoked(root))
    return True


def ca_due(root: str, now: datetime) -> bool:
    """Whether this member's intermediate has a third of its life left"""
    found = read(root, etcdstate.CA_CERT)
    if not found:
        return False
    left = etcdpki.not_after(found) - now
    return left < timedelta(days=etcdpki.CA_DAYS // 3)


def renew_own(root: str, address: str) -> None:
    """On the root's holder: its own intermediate signed again"""
    etcdstate.take_grant(root, etcdstate.grant_for(
        root, etcdstate.ca_request(root), address))


