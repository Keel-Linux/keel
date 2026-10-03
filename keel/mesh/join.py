# Copyright (c) 2026 KeelLinux maintainers
"""The change a token makes to the new node's spec (decision 0048)

A join writes the same fields an operator would write by hand: this
node's `network.overlay.wireguard.address`, the one the invite reserved,
and the inviter as a peer, known by its public key, reached at its
endpoint, routed its overlay address as a /128. Nothing records that a
join wrote them. Everything here is pure; keel.mesh.commands reads the
spec and prints.
"""

import ipaddress

from keel.mesh.token import Token
from keel.network.wireguard import same_key


class JoinError(Exception):
    """This node cannot take the token, and why"""


def change(overlay: dict | None, token: Token) -> dict:
    """The fields of network.overlay.wireguard the join sets

    A node with no overlay takes the assigned address. One that has an
    overlay must already be on the token's prefix at that address: a
    node is in one mesh, and the address was reserved for it alone.
    """
    assigned = ipaddress.IPv6Interface(token.assigned)
    current = (overlay or {}).get("address")
    if current:
        own = ipaddress.IPv6Interface(str(current))
        if own.network != assigned.network:
            raise JoinError(
                f"this node is in another mesh: its overlay address is"
                f" {own}, and the token is for {assigned.network}")
        if own != assigned:
            raise JoinError(
                f"this node is already {own} in this mesh, and the invite"
                f" reserved {assigned}: a node joins a mesh once")
    inviter = ipaddress.IPv6Interface(token.address).ip
    return {
        "address": str(assigned),
        "peers": [{
            "public_key": token.public_key,
            "endpoint": token.endpoint(),
            "allowed_ips": [f"{inviter}/128"],
        }],
    }


def merged(doc: dict, made: dict) -> dict:
    """`doc` with the change made, as a new document

    The inviter replaces a peer of the same key, compared as a key;
    every other peer and field stays as it is.
    """
    network = dict(doc.get("network") or {})
    overlay = dict(network.get("overlay") or {})
    wireguard = dict(overlay.get("wireguard") or {})
    added = made["peers"][0]
    kept = [peer for peer in wireguard.get("peers") or []
            if not same_key(str(peer.get("public_key")),
                            added["public_key"])]
    wireguard.update(address=made["address"], peers=kept + [added])
    return {**doc, "network": {**network, "overlay": {
        **overlay, "wireguard": wireguard}}}
