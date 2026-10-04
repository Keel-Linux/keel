# Copyright (c) 2026 KeelLinux maintainers
"""etcd, the mesh's registry, over the overlay (decisions 0025, 0048)

etcd runs on the members whose `installation.mode` is `cloud_advanced`
and whose appliance carries the `etcd` overlay (0048, third round,
point 3: `ready`), and forms at the third of them. This module is the
flows of a join, seen from etcd:

- `keel mesh create` on a ready node makes the mesh's root CA and this
  node's intermediate (`created`, keel.mesh.etcdstate);
- a ready joining node sends the request for its intermediate in the
  join request (`join_csr`);
- the inviter, before it answers (`admit`), signs it with its own
  intermediate, and either adds the new node as a learner of a running
  cluster (`member add --learner`, 0048 "From the fourth node on, the
  inviter runs member add ... before it answers") or, at the third
  ready member, writes the three member cluster to start (`new`);
- once the join is confirmed, the new node keeps its grant, issues its
  leaves and enables etcd (`joined`), and the inviter does the same and
  sends the cluster to the members that start it with them, over the
  members' channel (`admitted`, keel.mesh.etcdform.send_cluster); a
  learner is promoted once etcd says it is in sync (`promote`);
- `keel-mesh-etcd.timer` promotes what is still a learner, removes a
  learner that never started within an hour, and renews the leaves
  (`tend`); `keel mesh remove` removes a member under the amendment's
  rule (`leave`); `keel mesh status` shows the members, the leader and
  their health (`status`).

Each node writes only its own spec (0013): enabling etcd is
`overlays.etcd: enabled` in this node's spec, and `apply`, which renders
etcd's configuration from the state (keel.system.etcd). Nothing here
fails a join: etcd that cannot be set up is said, and `keel mesh etcd
form` brings the node in later.
"""

import ipaddress
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from keel import exits
from keel.mesh import etcdclient, etcdstate, identity
from keel.mesh.etcdclient import Client, EtcdError
from keel.mesh.etcdstate import Cluster, Grant, Member, StateError
from keel.mesh.node import Node, NodeError

MODE = "cloud_advanced"
OVERLAY = "etcd"
ENABLED = "enabled"
QUORUM_AT = 3
# how long the inviter's helper tries to promote a learner it added,
# and how often; keel-mesh-etcd.timer takes over after
PROMOTE_FOR = 120
PROMOTE_EVERY = 5.0
# a learner that never started within this is a join that never came
STALE_LEARNER = timedelta(hours=1)
NO_TOLERANCE = ("2 voters have no fault tolerance: a majority of 2 is 2, so"
                " losing either stops both")


def over_the_overlay(host: str, iface: str, body: bytes) -> bytes:
    """The members' channel (keel.mesh.memberlink, which imports the
    listener, which imports the admitter, which imports this)"""
    from keel.mesh import memberlink
    return memberlink.etcd_exchange(host, iface, body)


@dataclass
class Etcd:
    """This node as an etcd member; etcd and the members' channel as
    fields, so each flow is tested without either"""

    node: Node
    clock: Callable[[], datetime]
    err: Callable[[str], None]
    client: Callable[[], Client] | None = None
    exchange: Callable[[str, str, bytes], bytes] = over_the_overlay
    sleep: Callable[[float], None] = time.sleep

    @property
    def root(self) -> str:
        return self.node.root

    def local(self) -> Client:
        """This member's etcd on ::1; raises EtcdError"""
        return self.client() if self.client else etcdclient.local(self.root)


def ready(doc: dict) -> bool:
    """Whether this node can run etcd: cloud advanced, the overlay in its
    appliance"""
    installation = doc.get("installation") or {}
    return installation.get("mode") == MODE and \
        OVERLAY in (doc.get("overlays") or {})


def own_address(node: Node) -> str:
    return str(ipaddress.IPv6Interface(str(node.overlay()["address"])).ip)


def own_key(etcd: Etcd) -> str | None:
    return etcd.node.public_key()[0]


def known_ready(etcd: Etcd) -> dict[str, str]:
    """The members ready for etcd this node knows, itself included when
    it holds its credentials"""
    found = etcdstate.ready(etcd.root)
    key = own_key(etcd)
    if key and etcdstate.credentials(etcd.root):
        found[key] = own_address(etcd.node)
    return found


def token_state(etcd: Etcd) -> str:
    """What the token says: `running` once this node is in a cluster,
    `forms` when it and exactly one other ready member wait for a third,
    `none` otherwise"""
    try:
        if etcdstate.cluster(etcd.root) is not None:
            return "running"
        doc = etcd.node.document()
    except (StateError, NodeError):
        return "none"
    if ready(doc) and etcdstate.credentials(etcd.root) and \
            len(known_ready(etcd)) == QUORUM_AT - 1:
        return "forms"
    return "none"


def created(etcd: Etcd) -> None:
    """After `keel mesh create`: the root CA and this node's
    intermediate, on a ready node"""
    try:
        if not ready(etcd.node.document()):
            return
        mesh_id = identity.read(etcd.root)
        etcdstate.make_root(etcd.root, mesh_id.hex())
    except (StateError, NodeError, ValueError, AttributeError) as e:
        etcd.err(f"etcd: the mesh's CA was not made ({e}); keel mesh etcd"
                 " form makes it")
        return
    etcd.err("etcd: this node holds the mesh's root CA; etcd forms when"
             " the third cloud advanced member joins")


def join_csr(etcd: Etcd) -> str | None:
    """The request for this node's intermediate, when it can run etcd:
    what tells the inviter it can (third round, point 3)"""
    try:
        if not ready(etcd.node.document()):
            return None
        return etcdstate.ca_request(etcd.root)
    except (StateError, NodeError) as e:
        etcd.err(f"etcd: no request for this node's CA ({e}); keel mesh"
                 " etcd form brings it in later")
        return None


@dataclass(frozen=True)
class Admission:
    """What the inviter decided for the new node: its grant, the cluster
    it starts (or None), the members ready, those to send the cluster
    to, and the learner added for it"""

    grant: Grant | None = None
    cluster: Cluster | None = None
    ready: dict[str, str] = field(default_factory=dict)
    notify: tuple[Member, ...] = ()
    learner: str | None = None

    @property
    def state(self) -> str:
        return "none" if self.cluster is None else (
            "forms" if self.cluster.state == "new" else "running")


def admit(etcd: Etcd, csr: str | None, key: str, address: str) -> Admission:
    """The inviter's decision, before it answers; never raises"""
    if csr is None:
        return Admission()
    try:
        doc = etcd.node.document()
        if not ready(doc) or not etcdstate.credentials(etcd.root):
            return Admission(ready=known_ready(etcd))
        grant = etcdstate.grant_for(etcd.root, csr, etcdstate.name(address))
        members = {**known_ready(etcd), key: address}
        formed = etcdstate.cluster(etcd.root)
        mesh = identity.read(etcd.root).hex()
    except (StateError, NodeError, ValueError, AttributeError) as e:
        etcd.err(f"etcd: the new node gets no etcd CA ({e})")
        return Admission()
    if formed is not None:
        return learner(etcd, grant, members, formed, key, address)
    if len(members) < QUORUM_AT:
        return Admission(grant, None, members)
    own = own_key(etcd)
    cluster = Cluster("new", tuple(
        Member(one, members[one]) for one in sorted(members)), mesh)
    return Admission(grant, cluster, members, tuple(
        one for one in cluster.members if one.public_key not in (own, key)))


def learner(etcd: Etcd, grant: Grant, members: dict[str, str],
            formed: Cluster, key: str, address: str) -> Admission:
    """The new node added as a learner of the running cluster"""
    try:
        client = etcd.local()
        added = client.add_learner(etcdstate.peer_url(address))
        listed = client.members()
    except EtcdError as e:
        etcd.err(f"etcd: the new node was not added as a learner ({e});"
                 " keel mesh etcd form adds it later")
        return Admission(grant, None, members)
    etcd.err(f"etcd: {address} added as a learner ({added.id})")
    keys = {v: k for k, v in members.items()}
    cluster = Cluster("existing", tuple(
        Member(keys.get(one.address), one.address) for one in listed
        if one.address), formed.token)
    return Admission(grant, cluster, members, (), added.id)


def admitted(etcd: Etcd, admission: Admission, key: str,
             send: Callable[[Member, Cluster], str | None]) -> None:
    """The inviter, once the join is confirmed: the new node is ready;
    at the third member this node starts etcd and sends the cluster to
    the others (`send`, which says why one was not reached); a learner
    is promoted once in sync"""
    if admission.grant is None:
        return
    etcdstate.add_ready(etcd.root, admission.ready)
    cluster = admission.cluster
    if cluster is None:
        return
    if cluster.state == "new":
        etcdstate.save_cluster(etcd.root, cluster)
        start(etcd)
        for member in admission.notify:
            problem = send(member, cluster)
            etcd.err(f"etcd: the cluster sent to {member.address}" if
                     problem is None else
                     f"etcd: {member.address} did not take the cluster"
                     f" ({problem}); keel mesh etcd form sends it again")
        return
    etcdstate.save_cluster(etcd.root, cluster)
    promote(etcd, admission.learner, PROMOTE_FOR)


def joined(etcd: Etcd, grant: Grant | None, cluster: Cluster | None,
           members: dict[str, str]) -> str:
    """The new node, once its join is confirmed: its grant kept, the
    members ready noted, and etcd started when there is a cluster; the
    line `join` prints about etcd"""
    if grant is None:
        return ("etcd: not on this node (it needs cloud advanced, and an"
                " inviter that can run etcd)")
    try:
        etcdstate.take_grant(etcd.root, grant)
        etcdstate.add_ready(etcd.root, members)
        if cluster is None:
            return (f"etcd: this node is ready; {len(members)} of"
                    f" {QUORUM_AT} ready members known, etcd forms at the"
                    " third")
        etcdstate.save_cluster(etcd.root, cluster)
    except StateError as e:
        return f"etcd: not set up ({e}); keel mesh etcd form brings it in"
    started = start(etcd)
    what = ("forms with" if cluster.state == "new"
            else "joins as a learner with")
    return (f"etcd: this node {what} {len(cluster.members) - 1} other"
            f" member(s){'' if started else ', but did not start'}")


def start(etcd: Etcd) -> bool:
    """This node's leaves issued and `overlays.etcd: enabled` in its own
    spec, applied: apply renders etcd's configuration and starts it"""
    try:
        etcdstate.leaves(etcd.root, own_address(etcd.node), etcd.clock())
        doc = etcd.node.document()
        overlays = dict(doc.get("overlays") or {})
        overlays[OVERLAY] = ENABLED
        change = etcd.node.change({**doc, "overlays": overlays})
    except (StateError, NodeError) as e:
        etcd.err(f"etcd: not started: {e}")
        return False
    if change.code != 0:
        change.shown(etcd.err)
        etcd.err(f"etcd: apply exited {change.code}; etcd may not run")
        return False
    return True


def promote(etcd: Etcd, member_id: str | None, seconds: float) -> bool:
    """The learner promoted once etcd says it is in sync, tried for
    `seconds`; keel-mesh-etcd.timer goes on after"""
    if member_id is None:
        return False
    deadline = etcd.clock().timestamp() + seconds
    while True:
        try:
            etcd.local().promote(member_id)
            etcd.err(f"etcd: learner {member_id} promoted to a voter")
            return True
        except EtcdError as e:
            if etcd.clock().timestamp() + PROMOTE_EVERY > deadline:
                etcd.err(f"etcd: learner {member_id} not promoted yet ({e});"
                         " keel-mesh-etcd.timer tries again")
                return False
        etcd.sleep(PROMOTE_EVERY)


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
        renewed = etcdstate.leaves(etcd.root, own_address(etcd.node), now)
    except StateError as e:
        etcd.err(f"etcd: {e}")
        return exits.APPLY_FAILED
    if renewed:
        etcd.err("etcd: this member's certificates renewed")
        return exits.OK if start(etcd) else exits.APPLY_FAILED
    return exits.OK


def leave(etcd: Etcd, address: str, may: bool) -> None:
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
