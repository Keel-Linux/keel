# Copyright (c) 2026 KeelLinux maintainers
"""The answer to `POST /v1/etcd` on the members' channel (0048)

What a member says to this node about etcd (keel.mesh.etcdmsg), on the
root side of the members' channel (keel.mesh.memberd), which has
already refused any source that is not a peer and names the peer by its
WireGuard key. A message is taken only when it names that same key as
its sender, is fresh, is for this node's mesh, and is signed by the
signing key this node's trust store holds for that member
(keel.mesh.trust): what WireGuard says is who speaks, and a message
that acts needs the member's own signature too (0048's amendment).

- `probe` changes nothing: ready for etcd, the root held, in a cluster,
  the overlay address;
- `enroll` makes this node's intermediate key once and answers its
  request;
- `cluster` keeps the intermediate a grant brings, only from this
  node's inviter or a trust root (never in place of one this node
  holds, never under another root), notes the members ready that are
  this node's peers at those addresses, and with a cluster of this mesh
  that names this node, and no other cluster held, keeps it and starts
  etcd (keel.mesh.etcd.start), as a join's new node does; never while a
  network change waits.
"""

import ipaddress
import json

from keel.mesh import (
    etcd,
    etcdca,
    etcdmsg,
    etcdpki,
    etcdstate,
    identity,
    trust,
)
from keel.mesh.etcd import Etcd
from keel.mesh.etcdpki import PkiError
from keel.mesh.etcdstate import Cluster, StateError
from keel.mesh.memberlink import Answer, refused
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.network.wireguard import same_key


class Refusal(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def trusted(root: str, key: str) -> trust.Member | None:
    """The member `key` as this node's trust store holds it"""
    try:
        store = trust.load(root)
    except ValueError:
        return None
    found = store.find(key)
    return None if found is None else store.members[found]


def sign_key(root: str, key: str) -> str | None:
    """The signing key this node trusts for the member `key`"""
    found = trusted(root, key)
    return None if found is None else found.sign_key


def same(held: Cluster, cluster: Cluster) -> bool:
    """The same cluster: the same formation record, for the same token"""
    return (held.token, held.record, held.signature) == (
        cluster.token, cluster.record, cluster.signature)


def checked(member: Etcd, body: bytes, key: str) -> etcdmsg.Message:
    """The message, if `key` sent it and signed it; raises Refusal"""
    try:
        message = etcdmsg.loads(body)
    except ProtocolError as e:
        raise Refusal(400, f"malformed etcd message: {e}") from None
    if not same_key(message.sender, key):
        raise Refusal(403, "the message is not the sender's")
    if not message.fresh(member.clock()):
        raise Refusal(403, "the message is stale")
    try:
        own = identity.read(member.root)
    except ValueError:
        own = None
    if own is None or message.mesh_id != own.hex():
        raise Refusal(403, "the message is for another mesh")
    signer = sign_key(member.root, key)
    if signer is None or not message.verified(signer):
        raise Refusal(403, "the message is not signed by a key this node"
                      " trusts for its sender (keel mesh sync on this node"
                      " learns its trust roots' keys)")
    return message


def answer(member: Etcd, body: bytes, key: str) -> Answer:
    """The answer to one etcd message from the peer `key`; never raises"""
    try:
        message = checked(member, body, key)
        doc = member.node.document()
        if message.kind == etcdmsg.PROBE:
            return Answer(200, etcdmsg.probe_dumps(
                etcd.ready(doc), etcdstate.root_fingerprint(member.root),
                etcdstate.cluster(member.root) is not None,
                etcd.own_address(member.node),
                etcdstate.holds_root(member.root)))
        if message.kind in (etcdmsg.ISSUE, etcdmsg.REVOKE):
            return holder(member, message)
        if not etcd.ready(doc):
            raise Refusal(409, "this node does not run etcd (cloud advanced"
                          " members only)")
        if message.kind == etcdmsg.ENROLL:
            return Answer(200, json.dumps(
                {"csr": etcdstate.ca_request(member.root)}).encode())
        return taken(member, message)
    except Refusal as e:
        member.err(f"etcd: refused a message from {key}: {e.reason}")
        return refused(e.status, e.reason)
    except (StateError, NodeError, PkiError, OSError) as e:
        member.err(f"etcd: cannot answer {key}: {e}")
        return refused(503, f"this node cannot answer now: {e}")


def taken(member: Etcd, message: etcdmsg.Message) -> Answer:
    """A `cluster` message: the grant, the members ready, the cluster"""
    try:
        grant = etcdmsg.grant(message.body.get("grant"))
        cluster = etcdmsg.cluster(message.body.get("cluster"))
        members = etcdmsg.ready(message.body.get("ready"))
    except ProtocolError as e:
        raise Refusal(400, f"malformed cluster: {e}") from None
    own = etcd.own_address(member.node)
    if cluster is not None and (own not in cluster.addresses()
                                or cluster.token != message.mesh_id):
        raise Refusal(409, "the cluster does not name this node, or is"
                      " another mesh's")
    held = etcdstate.cluster(member.root)
    if cluster is not None and held is not None and not same(held, cluster):
        raise Refusal(409, "this node is in a cluster already: a cluster"
                      " is never replaced by a message")
    if cluster is not None and member.node.waiting():
        raise Refusal(409, "a network change waits for its confirmation"
                      " on this node; send it again once it is kept")
    if grant is not None and not etcdstate.credentials(member.root):
        sender = trusted(member.root, message.sender)
        if sender is None or not sender.root:
            raise Refusal(403, "an etcd CA is taken only from this node's"
                          " inviter or a trust root")
        etcdstate.take_grant(member.root, grant)
    elif grant is not None and etcdstate.root_fingerprint(member.root) != \
            etcdpki.fingerprint(grant.root):
        raise Refusal(409, "this node holds another root")
    if not etcdstate.credentials(member.root):
        raise Refusal(409, "this node holds no etcd CA, and the message"
                      " brings none")
    problem = None if cluster is None else etcdca.problem(member.root,
                                                          cluster)
    if problem:
        raise Refusal(403, problem)
    etcdstate.add_ready(member.root, etcd.vetted(member, members))
    if cluster is None:
        return Answer(200, b'{"taken": true, "started": false}')
    etcdstate.save_cluster(member.root, cluster)
    started = etcd.start(member)
    member.err(f"etcd: a cluster of {len(cluster.members)} from"
               f" {message.sender}; {'started' if started else 'not started'}")
    return Answer(200, json.dumps({"taken": True,
                                   "started": started}).encode())


def holder(member: Etcd, message: etcdmsg.Message) -> Answer:
    """On the root's holder: an intermediate signed by the root
    (`issue`), or a removed node's certificates revoked (`revoke`)"""
    if not etcdstate.holds_root(member.root):
        raise Refusal(409, "this node does not hold the mesh's root CA")
    body = message.body
    try:
        address = etcdmsg.address(body.get("address"))
    except ProtocolError as e:
        raise Refusal(400, str(e)) from None
    own = etcd.own_address(member.node)
    if ipaddress.IPv6Address(address) not in ipaddress.IPv6Network(
            etcdstate.prefix_of(own)):
        raise Refusal(403, f"{address} is not in this mesh's prefix")
    if message.kind == etcdmsg.ISSUE:
        try:
            csr = etcdmsg.csr(body.get("csr"))
        except ProtocolError as e:
            raise Refusal(400, str(e)) from None
        if csr is None:
            raise Refusal(400, "no request to sign")
        grant = etcdstate.grant_for(member.root, csr, address)
        member.err(f"etcd: an intermediate for {address} signed with the"
                   f" root, asked by {message.sender}")
        return Answer(200, json.dumps(
            {"grant": etcdmsg.grant_data(grant)}).encode())
    removed = body.get("public_key")
    serials = body.get("serials") or {}
    if not isinstance(removed, str) or not isinstance(serials, dict) or \
            not all(isinstance(k, str) and isinstance(v, str)
                    for k, v in serials.items()):
        raise Refusal(400, "malformed revocation")
    if not may_revoke(member.root, message.sender, removed):
        raise Refusal(403, "the sender may not remove that node: neither"
                      " its admitter, nor a trust root, nor the node")
    found = etcdca.revoke(member.root, address, serials, member.clock())
    member.err(f"etcd: the certificates of {address} revoked, asked by"
               f" {message.sender}")
    if etcdstate.cluster(member.root) is not None:
        etcd.start(member)
    return Answer(200, json.dumps({"crl": found}).encode())


def may_revoke(root: str, sender: str, removed: str) -> bool:
    """The amendment's rule, as this node knows it: the node itself, a
    trust root, or the member whose key signed the node's admission"""
    if same_key(sender, removed):
        return True
    member = trusted(root, sender)
    if member is None:
        return False
    if member.root:
        return True
    admitted = trusted(root, removed)
    return admitted is not None and admitted.admission is not None and \
        admitted.admission.by == member.sign_key
