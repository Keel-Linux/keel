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
- only the node that holds the root CA forms the cluster, once
  (keel.mesh.etcdca): another inviter of a third member admits it to the
  mesh, gives it its CA, and says to run `keel mesh etcd form` on the
  root's holder;
- tend, leave and status are keel.mesh.etcdcare's.

Each node writes only its own spec (0013): enabling etcd is
`overlays.etcd: enabled` in this node's spec, and `apply`, which renders
etcd's configuration from the state (keel.system.etcd). Nothing here
fails a join: etcd that cannot be set up is said, and `keel mesh etcd
form` brings the node in later.
"""

import ipaddress
import os
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from keel.mesh import etcdca, etcdclient, etcdmsg, etcdstate, identity
from keel.mesh.etcdclient import Client, EtcdError
from keel.mesh.etcdstate import Cluster, Grant, Member, StateError
from keel.mesh.node import Node, NodeError
from keel.mesh.protocol import ProtocolError
from keel.mesh.signing import SigningError

MODE = "cloud_advanced"
OVERLAY = "etcd"
ENABLED = "enabled"
QUORUM_AT = 3
# the most members a cluster starts with, or a join's answer names:
# etcd's own advice is at most seven voters (keel.mesh.etcdmsg's cap)
MAX_FORMED = 7
# how long the inviter's helper tries to promote a learner it added,
# and how often; keel-mesh-etcd.timer takes over after
PROMOTE_FOR = 120
PROMOTE_EVERY = 5.0
# a learner that never started within this is a join that never came
STALE_LEARNER = timedelta(hours=1)
MEMBER_DIR = "var/lib/etcd/default/member"
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


def said(etcd: Etcd, kind: str, address: str, body: dict) -> bytes:
    """The answer of the member at `address` to one message signed with
    this node's key (keel.mesh.etcdmsg); raises LinkError, SigningError
    or ValueError"""
    from keel.network import wireguard
    mesh = identity.read(etcd.root).hex()
    message = etcdmsg.signed(etcd.root, kind, mesh, own_key(etcd),
                             etcd.clock(), body)
    return etcd.exchange(address, wireguard.interface(etcd.node.overlay()),
                         message)


def issued(etcd: Etcd, csr: str, address: str,
           fallback: bool = True) -> Grant:
    """An intermediate for `csr`: from the root's holder when this node
    is it or can reach it, which keeps the chain one deep; else, with
    `fallback`, signed with this node's own intermediate, and
    re-anchored under the root at its first renewal. Raises StateError"""
    from keel.mesh.memberlink import LinkError
    holder = etcdstate.holder(etcd.root)
    if etcdstate.holds_root(etcd.root) or holder is None:
        return etcdstate.grant_for(etcd.root, csr, address)
    try:
        found = etcdmsg.grant(etcdmsg.loaded(said(
            etcd, etcdmsg.ISSUE, holder, {"csr": csr, "address": address}
        )).get("grant"))
        if found is None:
            raise ValueError("its answer holds no grant")
        return found
    except (LinkError, SigningError, ValueError, ProtocolError) as e:
        if not fallback:
            raise StateError(f"the root's holder at {holder} did not sign"
                             f" ({e}); the next tend asks again") from None
        etcd.err(f"etcd: the root's holder at {holder} did not sign ({e});"
                 " this node signs, and the chain is re-anchored at the"
                 " first renewal")
    return etcdstate.grant_for(etcd.root, csr, address)


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


def vetted(etcd: Etcd, members: dict[str, str]) -> dict[str, str]:
    """The members of `members` this node knows at those addresses: a
    peer of its spec, or itself; what another member says is ready is
    never taken for a node this node does not have as a peer"""
    known = {one.public_key: one.address for one in etcd.node.peers("")}
    key = own_key(etcd)
    if key:
        known[key] = own_address(etcd.node)
    return {k: v for k, v in members.items() if known.get(k) == v}


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
        etcdstate.make_root(etcd.root, mesh_id.hex(),
                            own_address(etcd.node))
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
    # what the new node prints about etcd, when there is more to say
    said: str | None = None

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
        grant = issued(etcd, csr, address)
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
    if len(members) > MAX_FORMED:
        etcd.err(f"etcd: {len(members)} ready members, more than a cluster"
                 f" starts with ({MAX_FORMED}); keel mesh etcd form forms"
                 " it")
        return Admission(grant, None, {})
    if not etcdstate.holds_root(etcd.root):
        at = etcdstate.holder(etcd.root) or "the node that holds it"
        line = (f"etcd: {len(members)} cloud advanced members are ready;"
                f" run keel mesh etcd form on the root CA's holder ({at}),"
                " which alone forms the cluster")
        etcd.err(line)
        return Admission(grant, None, members, said=line)
    own = own_key(etcd)
    try:
        cluster = etcdca.record(etcd.root, tuple(
            Member(one, members[one]) for one in sorted(members)), mesh)
    except StateError as e:
        etcd.err(f"etcd: no cluster formed ({e})")
        return Admission(grant, None, members)
    if not etcdca.reserve(etcd.root, cluster):
        line = ("etcd: a formation is under way already; keel mesh etcd"
                " form on this node brings the new node in once it is done")
        etcd.err(line)
        return Admission(grant, None, members, said=line)
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
        if one.address), formed.token, formed.record, formed.signature)
    return Admission(grant, cluster, members, (), added.id)


def abandoned(etcd: Etcd, admission: Admission) -> None:
    """A join that was not confirmed: the formation it reserved, given
    back"""
    if admission.cluster is not None and admission.cluster.state == "new":
        etcdca.release(etcd.root)


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
        etcdstate.add_ready(etcd.root, vetted(etcd, members))
        if cluster is None and len(members) >= QUORUM_AT:
            return (f"etcd: {len(members)} cloud advanced members are"
                    " ready; keel mesh etcd form on the root CA's holder"
                    f" ({grant.holder or 'the first node'}) forms the"
                    " cluster")
        if cluster is None:
            return (f"etcd: this node is ready; {len(members)} of"
                    f" {QUORUM_AT} ready members known, etcd forms at the"
                    " third")
        problem = etcdca.problem(etcd.root, cluster)
        if problem:
            return f"etcd: not started: {problem}"
        etcdstate.save_cluster(etcd.root, cluster)
    except StateError as e:
        return f"etcd: not set up ({e}); keel mesh etcd form brings it in"
    started = start(etcd)
    what = ("forms with" if cluster.state == "new"
            else "joins as a learner with")
    return (f"etcd: this node {what} {len(cluster.members) - 1} other"
            f" member(s){'' if started else ', but did not start'}")


def stray(etcd: Etcd) -> None:
    """A data directory this node holds before keel ever started etcd
    here, left by etcd-server's own start at its installation (a lone
    member of no cluster): etcd stopped and the directory removed, said.
    Never once keel started etcd for this mesh's cluster"""
    found = etcdstate.path(etcd.root, MEMBER_DIR)
    if not os.path.isdir(found) or \
            os.path.exists(etcdstate.path(etcd.root, etcdstate.STARTED)):
        return
    etcd.node.run(("systemctl", "stop", "etcd.service"))
    shutil.rmtree(found)
    etcd.err(f"etcd: removed /{MEMBER_DIR}, a lone member etcd-server's own"
             " start left at its installation; this node was never a"
             " member of this mesh's cluster")


def start(etcd: Etcd) -> bool:
    """This node's leaves issued and `overlays.etcd: enabled` in its own
    spec, applied: apply renders etcd's configuration and starts it"""
    try:
        stray(etcd)
        etcdstate.leaves(etcd.root, own_address(etcd.node), etcd.clock())
        doc = etcd.node.document()
        overlays = dict(doc.get("overlays") or {})
        overlays[OVERLAY] = ENABLED
        change = etcd.node.change({**doc, "overlays": overlays})
    except (StateError, NodeError, OSError) as e:
        etcd.err(f"etcd: not started: {e}")
        return False
    if change.code != 0:
        change.shown(etcd.err)
        etcd.err(f"etcd: apply exited {change.code}; etcd may not run")
        return False
    etcdstate.write(etcd.root, etcdstate.STARTED, "started\n")
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
