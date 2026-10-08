# Copyright (c) 2026 KeelLinux maintainers
"""etcd once it runs: tend, leave, revocation and status (0025, 0048)

- `keel-mesh-etcd.timer` runs `keel mesh etcd tend` (`tend`): on the
  root's holder, learners in sync promoted, learners that never started
  within an hour removed (etcd lets only its root user change the
  membership once auth is on), its admin certificate renewed, the CRL
  signed again every ten days, and etcd's users and roles converged
  once auth is on (keel.mesh.etcdauth); on every member, its
  certificate renewed by the root with a third of its 30 days left (a
  renewal waits, alerted, while the root's holder cannot be reached),
  and its VIP pairs sent to the holder for their role;
- `keel mesh remove` removes a member under the amendment's rule
  (`leave`), and has the root's holder revoke its certificates
  (`revoked`); every member takes the new CRL from the rosters
  (`crl_taken`, keel.mesh.sync);
- `keel mesh status` shows the members, the leader and their health
  (`status`).
"""

import json
import os
from datetime import datetime, timedelta

from keel import exits
from keel.mesh import etcdca, etcdmsg, etcdproof, etcdstate, protocol
from keel.mesh.etcdproof import Request
from keel.mesh.etcd import (
    NO_TOLERANCE,
    QUORUM_AT,
    STALE_LEARNER,
    Etcd,
    issued,
    known_ready,
    own_address,
    own_key,
    ready,
    said,
    start,
)
from keel.mesh.etcdclient import Client, EtcdError
from keel.mesh.etcdstate import Member, StateError
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.mesh.signing import SigningError

# when a certificate that was not renewed is alerted again
WARN_BEFORE = timedelta(days=7)


def tend(etcd: Etcd) -> int:
    """`keel mesh etcd tend`: the requests that wait for the root's
    holder asked again; learners in sync promoted, learners that never
    started within an hour removed; the certificates renewed, a failure
    alerted and kept for status and diff"""
    code = waiting(etcd)
    try:
        if etcdstate.cluster(etcd.root) is None:
            return code
        client = etcd.local()
        listed = client.members()
    except (StateError, EtcdError) as e:
        etcd.err(f"etcd: {e}")
        return exits.APPLY_FAILED
    now = etcd.clock()
    learners = [one for one in listed if one.learner] \
        if etcdstate.holds_root(etcd.root) else []
    seen = etcdstate.learners(etcd.root, [one.id for one in learners
                                          if not one.started], now)
    for one in learners:
        try:
            if one.started:
                etcd.admin().promote(one.id)
                etcd.err(f"etcd: learner {one.name} promoted to a voter")
            elif now - seen[one.id] >= STALE_LEARNER:
                etcd.admin().remove(one.id)
                etcd.err(f"etcd: learner {one.id} at {one.address} never"
                         " started within an hour: removed")
        except EtcdError as e:
            etcd.err(f"etcd: learner {one.name or one.id}: {e}")
    try:
        renewed = renew(etcd, now)
    except (StateError, SigningError) as e:
        failed(etcd, str(e))
        return exits.APPLY_FAILED
    etcdstate.write(etcd.root, etcdstate.RENEWAL, "{}\n")
    code = max(code, roles(etcd))
    left = etcdstate.expires(etcd.root)
    if left is not None and left - now < WARN_BEFORE:
        alert(etcd, "etcd certificate expires soon",
              f"this member's etcd certificate expires at"
              f" {left:%Y-%m-%d %H:%M} UTC, in less than"
              f" {WARN_BEFORE.days} days, and"
              " was not renewed: run keel mesh etcd tend and read why")
    if renewed:
        return exits.OK if start(etcd) else exits.APPLY_FAILED
    return code


def roles(etcd: Etcd) -> int:
    """etcd's users and roles: converged on the root's holder once auth
    is on; this node's VIP pairs sent to the holder"""
    from keel.mesh import etcdauth
    from keel.mesh.etcdclient import EtcdError
    code = exits.OK
    if etcdstate.holds_root(etcd.root):
        try:
            if etcdauth.enabled(etcd):
                for line in etcdauth.reconcile(etcd):
                    etcd.err(f"etcd: {line}")
        except (StateError, EtcdError) as e:
            etcd.err(f"etcd: users and roles not converged: {e}")
            code = exits.APPLY_FAILED
        for address, key in etcdca.impostors(
                etcd.root, lambda one: etcdproof.trusted_sign_key(
                    etcd.root, one)):
            etcd.err(f"etcd: the certificate of {address} was issued under"
                     " a signing key the trust store does not hold for it:"
                     " revoked")
            revoked(etcd, address, key)
    for line in etcdauth.announce(etcd):
        etcd.err(line)
    return code


def waiting(etcd: Etcd) -> int:
    """The requests this inviter queued while the root's holder could
    not be reached: asked again, and each node given its certificate
    (and its cluster) over the members' channel once the holder
    signs"""
    from keel.mesh import etcdform
    code = exits.OK
    for one in etcdstate.pending(etcd.root):
        address, key = str(one.get("address")), str(one.get("public_key"))
        try:
            evidence = one.get("admission")
            found = issued(etcd, Request(str(one.get("csr")),
                                         str(one.get("proof"))),
                           address, key, None if evidence is None
                           else protocol.admission(evidence))
        except (StateError, ProtocolError) as e:
            etcd.err(f"etcd: {address} still waits: {e}")
            code = exits.APPLY_FAILED
            continue
        problem = etcdform.send_cluster(etcd, Member(key, address),
                                        found.cluster, found.grant)
        if problem:
            etcd.err(f"etcd: {address} did not take its certificate"
                     f" ({problem})")
            code = exits.APPLY_FAILED
            continue
        etcdstate.unqueue(etcd.root, address)
        etcd.err(f"etcd: {address} has its certificate from the root's"
                 " holder")
    return code


def failed(etcd: Etcd, problem: str) -> None:
    """A renewal that failed: kept for status and diff, and alerted"""
    etcdstate.write(etcd.root, etcdstate.RENEWAL, json.dumps(
        {"problem": problem, "at": int(etcd.clock().timestamp())}) + "\n")
    etcd.err(f"etcd: renewal failed: {problem}")
    alert(etcd, "etcd certificate renewal failed",
          f"keel mesh etcd tend could not renew this member's etcd"
          f" certificates: {problem}. They expire at"
          f" {etcdstate.expires(etcd.root) or 'an unknown time'}; once"
          " they do, this member leaves the cluster.")


def alert(etcd: Etcd, title: str, text: str) -> None:
    """Through the monitor's channels (decision 0021), as Monit's alerts
    go: every channel keel's monitor settings declare; said when there
    are none"""
    from keel.monitor import channelfile
    from keel.monitor import notify as notifier
    from keel.spec import SpecError
    where = os.path.join(etcd.root, channelfile.PATH.lstrip("/"))
    try:
        settings = channelfile.load(where)
    except SpecError as e:
        etcd.err(f"etcd: {title}; no alert sent ({e})")
        return
    host = str(settings.get("host") or notifier.hostname())
    for one in notifier.send(settings, notifier.Message(
            f"[{host}] {title}", text, {"check": "etcd-certificates"}),
            "critical"):
        etcd.err(f"etcd: alert {one.line()}")


def renewal_problem(root: str) -> str | None:
    """The last renewal's failure, if it failed"""
    try:
        found = json.loads(etcdstate.read(root, etcdstate.RENEWAL) or "{}")
    except ValueError:
        return None
    return found.get("problem") if isinstance(found, dict) else None


def renew(etcd: Etcd, now: datetime) -> bool:
    """This member's certificate with a third of its life left signed
    again by the root: here on its holder, else asked of the holder
    (keel#83); on the holder, its admin certificate and the CRL once a
    third of their life went by. Whether anything changed, which apply
    then writes for etcd. Raises StateError: a renewal waits while the
    root's holder cannot be reached"""
    address = own_address(etcd.node)
    changed = False
    if etcdstate.stale(etcd.root, address, now):
        csr = etcdstate.member_request(etcd.root)
        grant = etcdstate.grant_for(etcd.root, csr, address, own_key(etcd)) \
            if etcdstate.holds_root(etcd.root) else issued(
                etcd, Request(csr, etcdproof.sign(etcd.root, csr)), address,
                own_key(etcd) or "").grant
        etcdstate.keep_own_intermediate(etcd.root, address, own_key(etcd))
        etcdstate.take_grant(etcd.root, grant, address)
        etcd.err("etcd: this member's certificate renewed by the root")
        changed = True
    if etcdstate.holds_root(etcd.root):
        if etcdstate.admin(etcd.root, now):
            etcd.err("etcd: the root's admin certificate renewed")
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
        # the root's user on the holder; elsewhere this member, which
        # etcd lets remove a member only while auth is off: then the
        # holder removes it when it revokes the node's certificates
        client = etcd.admin() if etcdstate.holds_root(etcd.root) \
            else etcd.local()
        found = [one for one in client.members() if one.address == address]
        for one in found:
            client.remove(one.id)
        left = [one for one in client.members() if not one.learner]
    except EtcdError as e:
        etcd.err(f"etcd: the member at {address} was not removed here"
                 f" ({e}); the root's holder removes it")
        found, left = [], None
    gone = {one for one, at in etcdstate.ready(etcd.root).items()
            if at == address}
    for one in gone:
        etcdstate.drop_ready(etcd.root, one)
    if found:
        etcd.err(f"etcd: the member at {address} removed; {len(left)}"
                 " voter(s) left")
    if left is not None and len(left) == 2:
        etcd.err(f"etcd: {NO_TOLERANCE}")
    revoked(etcd, address, key)


def revoked(etcd: Etcd, address: str, key: str) -> None:
    """The removed node's certificates revoked by the root's holder,
    what it signed for that address and key, and its etcd member and
    user removed there; the new CRL kept and written for etcd; said
    when it cannot be"""
    from keel.mesh.memberlink import LinkError
    holder = etcdstate.holder(etcd.root)
    try:
        if etcdstate.holds_root(etcd.root):
            etcdca.revoke(etcd.root, address, key, etcd.clock())
            from keel.mesh import etcdserve
            etcdserve.removed_from_etcd(etcd, address)
        elif holder is None:
            raise StateError("this node does not know the root's holder")
        else:
            found = etcdmsg.crl(etcdmsg.loaded(said(
                etcd, etcdmsg.REVOKE, holder, {
                    "address": address, "public_key": key})).get("crl"))
            etcdstate.take_crl(etcd.root, found)
    except (StateError, LinkError, SigningError, ValueError,
            ProtocolError) as e:
        etcd.err(f"etcd: the certificates of {address} were not revoked"
                 f" ({e}); they expire within 30 days")
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
    notes = certificates(etcd)
    if formed is None:
        found = known_ready(etcd)
        return [f"etcd: not formed; {len(found)} of {QUORUM_AT} ready"
                " member(s) known; it forms at the third join, or with keel"
                " mesh etcd form"] + notes
    if not live:
        return [f"etcd: this node is in a cluster of {len(formed.members)}"
                " (not the live system: etcd is not asked)"] + notes
    try:
        client = etcd.local()
        listed = client.members()
    except EtcdError as e:
        return [f"etcd: this node is in a cluster of"
                f" {len(formed.members)}, but its member does not answer:"
                f" {e}"] + notes
    return members_lines(client, listed) + notes


def certificates(etcd: Etcd) -> list[str]:
    """What status says of this member's certificates and its queue"""
    lines = []
    waits = etcdstate.pending(etcd.root)
    if waits:
        lines.append(f"etcd: {len(waits)} node(s) wait for the root CA's"
                     " holder to sign their certificate ("
                     + ", ".join(str(one.get("address")) for one in waits)
                     + "); keel-mesh-etcd.timer asks again")
    ends = etcdstate.expires(etcd.root)
    if ends is not None:
        soon = ends - etcd.clock() < WARN_BEFORE
        lines.append(f"etcd: this member's certificate expires"
                     f" {ends:%Y-%m-%d %H:%M} UTC"
                     f"{' (WARNING: within 7 days)' if soon else ''}")
    problem = renewal_problem(etcd.root)
    if problem:
        lines.append(f"etcd: the last renewal failed: {problem}")
    return lines


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
