# Copyright (c) 2026 KeelLinux maintainers
"""etcd once it runs: tend, leave, revocation and status (0025, 0048)

- `keel-mesh-etcd.timer` runs `keel mesh etcd tend` (`tend`): learners in
  sync promoted, learners that never started within an hour removed,
  the member's intermediate renewed by the root's holder with a third
  of its year left, its leaves with a third of their 30 days left, and
  on the holder, the CRL signed again every ten days;
- `keel mesh remove` removes a member under the amendment's rule
  (`leave`), and has the root's holder revoke its certificates
  (`revoked`); every member takes the new CRL from the rosters
  (`crl_taken`, keel.mesh.sync);
- `keel mesh status` shows the members, the leader and their health
  (`status`).
"""

from datetime import datetime

from keel import exits
from keel.mesh import etcdca, etcdmsg, etcdstate
from keel.mesh.etcd import (
    NO_TOLERANCE,
    QUORUM_AT,
    STALE_LEARNER,
    Etcd,
    issued,
    known_ready,
    own_address,
    ready,
    said,
    start,
)
from keel.mesh.etcdclient import Client, EtcdError
from keel.mesh.etcdstate import StateError
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.mesh.signing import SigningError


def tend(etcd: Etcd) -> int:
    """`keel mesh etcd tend`: learners in sync promoted, learners that
    never started within an hour removed, the leaves renewed"""
    try:
        if etcdstate.cluster(etcd.root) is None:
            return exits.OK
        client = etcd.local()
        listed = client.members()
    except (StateError, EtcdError) as e:
        etcd.err(f"etcd: {e}")
        return exits.APPLY_FAILED
    now = etcd.clock()
    learners = [one for one in listed if one.learner]
    seen = etcdstate.learners(etcd.root, [one.id for one in learners
                                          if not one.started], now)
    for one in learners:
        try:
            if one.started:
                client.promote(one.id)
                etcd.err(f"etcd: learner {one.name} promoted to a voter")
            elif now - seen[one.id] >= STALE_LEARNER:
                client.remove(one.id)
                etcd.err(f"etcd: learner {one.id} at {one.address} never"
                         " started within an hour: removed")
        except EtcdError as e:
            etcd.err(f"etcd: learner {one.name or one.id}: {e}")
    try:
        renewed = renew(etcd, now)
    except StateError as e:
        etcd.err(f"etcd: {e}")
        return exits.APPLY_FAILED
    if renewed:
        return exits.OK if start(etcd) else exits.APPLY_FAILED
    return exits.OK


def renew(etcd: Etcd, now: datetime) -> bool:
    """This member's intermediate with a third of its life left, signed
    again by the root's holder (re-anchored under the root); its leaves,
    with a third left; on the holder, the CRL once a third of its life
    went by. Whether anything changed, which apply then writes for etcd.
    Raises StateError"""
    address = own_address(etcd.node)
    changed = False
    if etcdca.ca_due(etcd.root, now):
        if etcdstate.holds_root(etcd.root):
            etcdca.renew_own(etcd.root, address)
        else:
            etcdstate.take_grant(etcd.root, issued(
                etcd, etcdstate.ca_request(etcd.root), address, False))
        etcd.err("etcd: this member's intermediate CA renewed")
        changed = True
    if etcdstate.leaves(etcd.root, address, now) or changed:
        etcd.err("etcd: this member's certificates renewed")
        changed = True
    if etcdca.refresh(etcd.root, now):
        etcd.err("etcd: the CRL signed again with the root")
        changed = True
    return changed


def leave(etcd: Etcd, address: str, may: bool, key: str = "") -> None:
    """After `keel mesh remove`: the node's etcd member removed, only
    when this node may remove it mesh-wide (third round, point 4)"""
    try:
        if etcdstate.cluster(etcd.root) is None:
            return
    except StateError as e:
        etcd.err(f"etcd: {e}")
        return
    if not may:
        etcd.err(f"etcd: the member at {address} stays: this node neither"
                 " admitted it nor is it a trust root's, so the removal is"
                 " local only; its admitter or a root removes it from etcd")
        return
    try:
        client = etcd.local()
        found = [one for one in client.members() if one.address == address]
        for one in found:
            client.remove(one.id)
        left = [one for one in client.members() if not one.learner]
    except EtcdError as e:
        etcd.err(f"etcd: the member at {address} was not removed ({e})")
        return
    gone = {key for key, at in etcdstate.ready(etcd.root).items()
            if at == address}
    for key in gone:
        etcdstate.drop_ready(etcd.root, key)
    if found:
        etcd.err(f"etcd: the member at {address} removed; {len(left)}"
                 " voter(s) left")
    if len(left) == 2:
        etcd.err(f"etcd: {NO_TOLERANCE}")
    revoked(etcd, address, key)


def revoked(etcd: Etcd, address: str, key: str) -> None:
    """The removed node's certificates revoked by the root's holder (its
    intermediates, and so its leaves and every intermediate it issued),
    the new CRL kept and written for etcd; said when it cannot be"""
    from keel.mesh.memberlink import LinkError
    holder = etcdstate.holder(etcd.root)
    try:
        if etcdstate.holds_root(etcd.root):
            found = etcdca.revoke(etcd.root, address, {}, etcd.clock())
        elif holder is None:
            raise StateError("this node does not know the root's holder")
        else:
            found = etcdmsg.crl(etcdmsg.loaded(said(
                etcd, etcdmsg.REVOKE, holder, {
                    "address": address, "public_key": key,
                    "serials": {}})).get("crl"))
            etcdstate.take_crl(etcd.root, found)
    except (StateError, LinkError, SigningError, ValueError,
            ProtocolError) as e:
        etcd.err(f"etcd: the certificates of {address} were not revoked"
                 f" ({e}); they expire within a year, its leaves within 30"
                 " days")
        return
    etcd.err(f"etcd: the certificates of {address} revoked; the CRL goes"
             " to every member with the rosters")
    start(etcd)


def crl_taken(etcd: Etcd, found: str) -> None:
    """A CRL from a member's roster: kept when the root signed it and it
    is newer, then written for etcd by apply"""
    try:
        if etcdstate.take_crl(etcd.root, found) and \
                etcdstate.cluster(etcd.root) is not None:
            etcd.err("etcd: a newer CRL from the root, written for etcd")
            start(etcd)
    except StateError as e:
        etcd.err(f"etcd: {e}")


def status(etcd: Etcd, live: bool = True) -> list[str]:
    """What `keel mesh status` says of etcd; never a secret, and etcd is
    asked on the live system only"""
    try:
        doc = etcd.node.document()
        formed = etcdstate.cluster(etcd.root)
    except (NodeError, StateError) as e:
        return [f"etcd: {e}"]
    if not ready(doc):
        mode = (doc.get("installation") or {}).get("mode", "not declared")
        return [f"etcd: not on this node (installation.mode {mode}; etcd"
                " runs on cloud advanced members only)"]
    if formed is None:
        found = known_ready(etcd)
        return [f"etcd: not formed; {len(found)} of {QUORUM_AT} ready"
                " member(s) known; it forms at the third join, or with keel"
                " mesh etcd form"]
    if not live:
        return [f"etcd: this node is in a cluster of {len(formed.members)}"
                " (not the live system: etcd is not asked)"]
    try:
        client = etcd.local()
        listed = client.members()
    except EtcdError as e:
        return [f"etcd: this node is in a cluster of"
                f" {len(formed.members)}, but its member does not answer:"
                f" {e}"]
    return members_lines(client, listed)


def members_lines(client: Client, listed: list) -> list[str]:
    voters = [one for one in listed if not one.learner]
    lines = [f"etcd: {len(voters)} voter(s), {len(listed) - len(voters)}"
             " learner(s)"]
    leaders = set()
    for one in listed:
        url = one.client_urls[0] if one.client_urls else None
        healthy, why = client.health(url) if url else (False, "not started")
        if url and healthy:
            try:
                leaders.add(client.status(url).leader)
            except EtcdError:
                pass
        role = "learner" if one.learner else "voter"
        lines.append(f"  {one.name or '(not started)'}  {one.address}"
                     f"  {role}  {'healthy' if healthy else why}")
    leader = next((one for one in listed if one.id in leaders), None)
    lines.append(f"leader: {leader.name if leader else 'none known'}"
                 f"{'' if len(leaders) <= 1 else ' (members disagree)'}")
    if len(voters) == 2:
        lines.append(f"etcd: {NO_TOLERANCE}")
    return lines
