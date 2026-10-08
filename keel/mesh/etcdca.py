# Copyright (c) 2026 KeelLinux maintainers
"""What only the root CA's holder does: form the cluster, revoke

The root CA's key stays on the first node (0048, third round, point 1),
and that node alone forms the cluster, once: so two inviters admitting
two nodes at once can never start two clusters ({A,B,C} and {A,B,D}).

- **Records.** The holder picks the members and signs, with the root's
  key, a record of the cluster token and etcd's cluster ID, the members
  (overlay address and WireGuard key), the root's fingerprint, the
  cluster's state (`new` at formation, `existing` once a learner is
  added), an epoch that only grows, a nonce and an expiry an hour on
  (`record`). A member takes a cluster only with a record the root
  signed, for its root, its mesh and that state, naming exactly the
  cluster's members, unexpired, and newer than every record it took
  (`problem`, `taken`); a member in a cluster takes no other. Only the
  holder adds a learner (an inviter relays the request), so every
  `existing` record is the holder's too. The holder reserves its
  formation under its lock before it sends anything (`reserve`), so a
  second formation, by a concurrent join or a second `keel mesh etcd
  form`, is refused; a join that reverts gives the reservation back
  (`release`).
- **Revocation.** The holder keeps the serials it revoked and signs the
  CRL with the root (`revoke`), which every member writes to etcd's
  `--peer-crl-file` and `--client-crl-file`: etcd checks each
  certificate a peer or a client presents, its chain included. The
  holder signs every member's certificate and records it with its
  member's address and key (keel.mesh.etcdstate.grant_for), so a
  removal revokes that member's certificates and no other's (`revoke`,
  which takes no serial from the asker); the intermediates of the
  layout before keel#83, recorded the same way, are revoked by
  `revoke_legacy` once every member holds a certificate the root
  signed (keel.mesh.etcdreissue), and with them every leaf they
  issued. The CRL travels in grants, in the members' rosters and in the
  answer to a revocation, and is taken only when the root signed it and
  it is newer (etcdstate.take_crl); the holder signs it again every ten
  days (`refresh`), its life being 30. Only the root signs a CRL, on
  its holder; members sign nothing (keel#83). With 0051's several
  roots, etcd still reads one CRL file and does not check its signer:
  the merged CRL is then signed by a root's holder, and a member takes
  it only when its entries are the union it computed from each root's
  own CRL, which it verifies as today (the note keel#83 adds to 0051).
"""

import json
import os
import secrets
from datetime import datetime, timedelta

from keel.mesh import etcdpki, etcdstate
from keel.mesh.etcdpki import PkiError
from keel.mesh.etcdstate import Cluster, Member, StateError, path, read, write

FORMATION = f"{etcdstate.DIR}/formation.json"
EPOCH = f"{etcdstate.DIR}/epoch"
SEEN = f"{etcdstate.DIR}/seen"
# how long a record may be taken after the holder signed it: a join's
# answer, or a form's message, arrives within it
RECORD_LIFE = timedelta(hours=1)
REVOKED = f"{etcdstate.DIR}/revoked.json"
LABEL = "keel mesh etcd formation 1"
REFRESH = timedelta(days=etcdpki.CRL_DAYS // 3)


def text(token: str, root: str, members: tuple[Member, ...], state: str,
         epoch: int, nonce: str, expires: int, cluster_id: str) -> str:
    return json.dumps({"label": LABEL, "token": token, "root": root,
                       "state": state, "epoch": epoch, "nonce": nonce,
                       "expires": expires, "cluster_id": cluster_id,
                       "members": sorted([one.address, one.public_key or ""]
                                         for one in members)},
                      sort_keys=True, separators=(",", ":"))


def next_epoch(root: str) -> int:
    """The holder's next record epoch: it only grows"""
    try:
        found = int((read(root, EPOCH) or "0").strip())
    except ValueError:
        found = 0
    write(root, EPOCH, f"{found + 1}\n")
    return found + 1


def record(root: str, members: tuple[Member, ...], token: str,
           now: datetime, state: str = "new",
           cluster_id: str = "") -> Cluster:
    """A cluster of `members` (`new` at formation, `existing` with a
    learner added), its record signed with the root: the cluster token
    and etcd's cluster ID, the root's fingerprint, the members, an epoch
    that only grows, a nonce and an expiry. Raises StateError off the
    root's holder"""
    if not etcdstate.holds_root(root):
        raise StateError("only the node that holds the mesh's root CA forms"
                         " the cluster")
    ordered = tuple(sorted(members, key=lambda one: one.address))
    with etcdstate.locked(root):
        epoch = next_epoch(root)
    body = text(token, etcdstate.root_fingerprint(root), ordered, state,
                epoch, secrets.token_hex(16),
                int((now + RECORD_LIFE).timestamp()), cluster_id)
    try:
        signature = etcdpki.sign(path(root, etcdstate.ROOT_KEY),
                                 body.encode())
    except PkiError as e:
        raise StateError(str(e)) from None
    return Cluster(state, ordered, token, body, signature)


def epoch(cluster: Cluster | None) -> int:
    """The epoch of a cluster's record, 0 without one"""
    try:
        return int(json.loads(cluster.record)["epoch"])
    except (AttributeError, TypeError, ValueError, KeyError):
        return 0


def problem(root: str, cluster: Cluster, now: datetime) -> str | None:
    """Why `cluster` is not one this member may take, None when it may:
    its record signed by the root this member holds, for that root, the
    cluster's token and state, naming exactly its members, not expired,
    and newer than the highest epoch this member has seen"""
    anchor = read(root, etcdstate.ROOT_CERT)
    if not anchor:
        return "this node holds no root to check the cluster's record"
    if not cluster.record or not cluster.signature or \
            not etcdpki.verified_by(anchor, cluster.record.encode(),
                                    cluster.signature):
        return "the cluster carries no record signed by the mesh's root"
    try:
        data = json.loads(cluster.record)
        named = {str(one[0]) for one in data["members"]}
        fine = (data["label"] == LABEL and data["token"] == cluster.token
                and data["state"] == cluster.state
                and data["root"] == etcdpki.fingerprint(anchor))
        expires, seen = int(data["expires"]), int(data["epoch"])
    except (ValueError, KeyError, TypeError, IndexError, PkiError):
        return "the cluster's record cannot be read"
    if not fine:
        return "the cluster's record is for another root or token"
    if named != set(cluster.addresses()):
        return "the cluster is not the one its record names"
    if now.timestamp() > expires:
        return "the cluster's record expired"
    if seen <= highest(root):
        return "the cluster's record is no newer than one this node took"
    return None


def expired(cluster: Cluster, now: datetime) -> bool:
    """Whether the record of `cluster` can no longer be taken"""
    try:
        return now.timestamp() > int(json.loads(cluster.record)["expires"])
    except (TypeError, ValueError, KeyError):
        return True


def highest(root: str) -> int:
    """The highest record epoch this member has taken"""
    try:
        return int((read(root, SEEN) or "0").strip())
    except ValueError:
        return 0


def taken(root: str, cluster: Cluster) -> None:
    """The record of `cluster`, taken: its epoch is the floor now"""
    write(root, SEEN, f"{max(epoch(cluster), highest(root))}\n")


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


def revoke(root: str, address: str, public_key: str,
           now: datetime) -> str:
    """On the root's holder: the certificates it signed for the member
    at `address` whose key is `public_key`, revoked, and nothing else;
    the new CRL. Raises StateError when it signed none for them"""
    if not etcdstate.holds_root(root):
        raise StateError("only the root CA's holder revokes")
    with etcdstate.locked(root):
        try:
            issued = json.loads(read(root, etcdstate.ISSUED) or "{}")
        except ValueError:
            issued = {}
        entries = [one for one in issued.get(address, [])
                   if isinstance(one, list) and len(one) >= 3
                   and one[2] == public_key]
        if not entries:
            raise StateError(f"no certificate of {address} with that key"
                             " was signed here")
        found = revoked(root)
        for one in entries:
            found.setdefault(str(one[0]).upper(),
                             [one[1], etcdpki.stamp(now)])
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


def impostors(root: str, sign_key_of) -> list[tuple[str, str]]:
    """On the root's holder: the (address, WireGuard key) of certificates
    it issued under a signing key the trust store now disowns for that
    node (`sign_key_of(key)` gives the key it holds): an inviter that
    vouched for a signing key of its own in place of the node's. They
    are revoked (keel.mesh.etcdproof)"""
    found = []
    gone = revoked(root)
    for address, entries in etcdstate.issued(root).items():
        for one in entries:
            if len(one) < 5 or not one[2] or not one[4] or \
                    str(one[0]).upper() in gone:
                continue
            known = sign_key_of(one[2])
            if known is not None and known != one[4] and \
                    (address, one[2]) not in found:
                found.append((address, one[2]))
    return found


def legacy_serials(root: str) -> dict[str, str]:
    """On the root's holder: the intermediates of the layout before
    keel#83, serial to expiry: those it recorded (an entry without a
    kind), and its own"""
    found = {}
    for entries in etcdstate.issued(root).values():
        for one in entries:
            if len(one) == 3 or one[3] == etcdstate.INTERMEDIATE:
                found[str(one[0]).upper()] = str(one[1])
    own = read(root, etcdstate.CA_CERT)
    if own:
        try:
            found[etcdpki.serial(own)] = etcdpki.stamp(
                etcdpki.not_after(own))
        except PkiError:
            pass
    return found


def revoke_legacy(root: str, serials: dict[str, str],
                  now: datetime) -> str:
    """On the root's holder: the intermediates `serials` names revoked,
    and the leaves under them with them; the new CRL"""
    if not etcdstate.holds_root(root):
        raise StateError("only the root CA's holder revokes")
    with etcdstate.locked(root):
        found = revoked(root)
        for serial, expiry in serials.items():
            found.setdefault(serial.upper(), [expiry, etcdpki.stamp(now)])
        write(root, REVOKED, json.dumps(found, sort_keys=True) + "\n")
        return signed(root, found)
