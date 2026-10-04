# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh create: the first node makes the mesh (decision 0048)

A random unique local /64 with this node at ::1 (as `keel network
wireguard suggest-address` gives it), WireGuard's default port, and
the mesh's identity. The overlay is converged by apply under 0018's
window like any first overlay; apply makes the key pair on the machine
(keel-core#8). No peer can confirm an overlay that has none, so create
confirms it itself, once apply.md's route check finds every gateway,
and the operator's SSH client, still leaving through the uplink: an
overlay with no peer routes its own private prefix only (0048, second
round, point 1).
"""

import secrets
from collections.abc import Callable

from keel import exits
from keel.mesh import identity
from keel.mesh.node import Node, NodeError, with_overlay
from keel.network import session, wireguard
from keel.network.wireguard import GLOBAL_ID_BYTES
from keel.system.ovstate import overlay_of


def create(node: Node, out: Callable[[str], None],
           err: Callable[[str], None]) -> int:
    try:
        doc = node.document()
    except NodeError as e:
        err(str(e))
        return exits.MESH_REFUSED
    current = overlay_of(doc) or {}
    if current.get("address"):
        err(f"this node is already in a mesh, at {current['address']}:"
            " keel mesh invite brings a new node into it")
        return exits.MESH_REFUSED
    address = wireguard.suggest_address(
        secrets.token_bytes(GLOBAL_ID_BYTES))
    after = with_overlay(doc, {"address": address})
    try:
        identity.ensure(node.root)
        change = node.change(after)
    except (NodeError, ValueError) as e:
        err(str(e))
        return exits.MESH_REFUSED
    if change.made is None:
        change.shown(err)
        err(f"the overlay did not come up under the window (apply exited"
            f" {change.code}); the spec declares it, and the next apply"
            " --system brings it up")
        return exits.APPLY_FAILED
    # apply's lines are held: they say the change reverts unless
    # confirmed, and create confirms it itself; shown when it cannot
    err("confirming the new overlay…")
    kept, lines = node.confirm(
        session.Origin(session.SELF, "keel mesh create"), change.made)
    if not kept:
        change.shown(err)
    for line in lines:
        err(line)
    if not kept:
        return exits.NETWORK_NOT_CONFIRMED
    overlay = overlay_of(after)
    out(f"created the mesh: this node is {address} on"
        f" {wireguard.interface(overlay)}, WireGuard on UDP"
        f" {wireguard.port(overlay)}")
    out("keel mesh invite prints the line that joins the next node")
    return exits.OK
