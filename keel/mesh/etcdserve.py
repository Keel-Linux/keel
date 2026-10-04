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
- `cluster` keeps the intermediate a grant brings (never in place of
  one this node holds, never under another root), notes the members
  ready, and with a cluster of this mesh that names this node, keeps it
  and starts etcd (keel.mesh.etcd.start), as a join's new node does.
"""

import json

from keel.mesh import etcd, etcdmsg, etcdpki, etcdstate, identity, trust
from keel.mesh.etcd import Etcd
from keel.mesh.etcdstate import StateError
from keel.mesh.memberlink import Answer, refused
from keel.mesh.node import NodeError
from keel.mesh.protocol import ProtocolError
from keel.network.wireguard import same_key


class Refusal(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def sign_key(root: str, key: str) -> str | None:
    """The signing key this node trusts for the member `key`"""
    try:
        store = trust.load(root)
    except ValueError:
        return None
    found = store.find(key)
    return None if found is None else store.members[found].sign_key


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
                etcd.own_address(member.node)))
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
    except (StateError, NodeError) as e:
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
    if cluster is not None and held is not None and \
            held.token != cluster.token:
        raise Refusal(409, "this node is in another cluster")
    if grant is not None and not etcdstate.credentials(member.root):
        etcdstate.take_grant(member.root, grant)
    elif grant is not None and etcdstate.root_fingerprint(member.root) != \
            etcdpki.fingerprint(grant.root):
        raise Refusal(409, "this node holds another root")
    if not etcdstate.credentials(member.root):
        raise Refusal(409, "this node holds no etcd CA, and the message"
                      " brings none")
    etcdstate.add_ready(member.root, members)
    if cluster is None:
        return Answer(200, b'{"taken": true, "started": false}')
    etcdstate.save_cluster(member.root, cluster)
    started = etcd.start(member)
    member.err(f"etcd: a cluster of {len(cluster.members)} from"
               f" {message.sender}; {'started' if started else 'not started'}")
    return Answer(200, json.dumps({"taken": True,
                                   "started": started}).encode())
