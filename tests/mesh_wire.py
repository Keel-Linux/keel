# Copyright (c) 2026 KeelLinux maintainers
"""Two nodes in one process: a real Node each, a wire between them

`node()` is keel.mesh.node.Node on a scratch root with apply replaced
by `Armed`, which arms the overlay change a live apply would (the marker
of decision 0018, dated as up) and records the document; the real
keel.network.confirm decides each confirmation, with probes that say
every route leaves through eth0. `Wire` stands for channel.post: it
hands the joiner's request to the inviter's Listener.handle with the
addresses a connection would carry, over the uplink for a join and
over the overlay for the mesh session, and checks the answer's HMAC as
the client does.
"""

import json
import os
from datetime import timedelta

from mesh_helpers import ASSIGNED, INVITER, JOINER, MADE, NOW, OWN, SECRET
from test_network_window import Recorder

from keel.mesh import certificate, protocol
from keel.mesh.channel import Forged, Refused, Reply, Unreachable
from keel.mesh.node import Node
from keel.mesh.token import Token, invite_id
from keel.network import marker, wireguard
from keel.network.confirm import Probes

INVITER_UPLINK = "2001:db8:1::10"
JOINER_UPLINK = "2001:db8:2::20"
INVITER_OVERLAY = "fd00:6b65:1::1"
JOINER_OVERLAY = "fd00:6b65:1::3"
INVITER_SPEC = f"""\
version: 1
network:
  overlay:
    wireguard:
      address: {OWN}
      listen_port: 51821
"""


class Armed:
    """apply, as far as keel mesh sees it: the overlay change armed"""

    def __init__(self, code: int = 0, arms: bool = True):
        self.code = code
        self.arms = arms
        self.documents = []

    def __call__(self, doc: dict, root: str, window: int) -> int:
        self.documents.append((doc, window))
        if self.arms:
            overlay = doc["network"]["overlay"]["wireguard"]
            iface = wireguard.interface(overlay)
            marker.save(root, "", marker.Target(
                wireguard.conf_path(iface), marker.OVERLAY, True))
            marker.write(root, marker.Pending(
                iface=iface, path=wireguard.conf_path(iface), window=window,
                addresses=tuple(one.split("/")[0] for one in
                                wireguard.addresses(overlay)),
                kind=marker.OVERLAY, absent=True).up("b1", 50.0))
        return self.code


def probes(route: str = "eth0") -> Probes:
    """Every route, the default one's gateway's included, through `route`"""
    return Probes(boot_id=lambda: "b1", addresses=lambda iface: [],
                  route_via=lambda peer: None, holder=lambda address: None,
                  route_dev=lambda address: route,
                  gateways=lambda: ["2001:db8:1::1"])


def node(root: str, text: str | None = None, apply=None,
         route: str = "eth0", clients=()) -> Node:
    path = os.path.join(root, "instance.yaml")
    if text is not None:
        with open(path, "w") as fob:
            fob.write(text)
    found = Node(root, path, clients=clients, apply=apply or Armed(),
                 probes=lambda: probes(route), run=Recorder(),
                 output=handshakes)
    return found


def handshakes(argv: tuple[str, ...]) -> str | None:
    """`wg show wg0 latest-handshakes`: the new node's key, just now"""
    if argv[-1] == "latest-handshakes":
        return f"{JOINER}\t{int(NOW.timestamp())}\n"
    return None


def token(invite, **changed) -> Token:
    values = dict(
        public_key=INVITER, endpoints=(INVITER_UPLINK,), port=51821,
        https_port=51820,
        fingerprint=certificate.fingerprint(invite.certificate),
        address=OWN, assigned=ASSIGNED, mesh_id=bytes(range(16)),
        invite_id=invite_id(SECRET), expires=NOW + timedelta(hours=1),
        secret=SECRET)
    values.update(changed)
    return Token(**values)


class Wire:
    """channel.post, through a Listener in this process"""

    def __init__(self, listener, pinned: bytes):
        self.listener = listener
        self.pinned = pinned
        self.unreachable: set[str] = set()
        self.calls: list[tuple[str, str]] = []

    def __call__(self, host, port, path, body, key, pinned, **timeouts):
        self.calls.append((host, path))
        if path in self.unreachable:
            raise Unreachable(f"[{host}]:{port}: Connection timed out")
        if pinned != self.pinned:
            raise Forged("another certificate")
        if path == protocol.JOIN:
            local, peer = INVITER_UPLINK, JOINER_UPLINK
        else:
            local, peer = host, JOINER_OVERLAY
        found = self.listener.handle(
            protocol.METHOD, path,
            protocol.sign(key, protocol.METHOD, path, body), body, local,
            peer)
        if found.status != 200:
            raise Refused(json.loads(found.body)["error"])
        if not protocol.signed(key, protocol.ANSWER, path, found.body,
                               found.signature):
            raise Forged("not signed")
        return Reply(found.body, peer, local)


__all__ = ["MADE", "Wire", "node", "token"]
