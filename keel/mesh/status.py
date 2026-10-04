# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh status: the peers, their handshakes, the pending invites

Read from the spec, from the mesh's identity, from `wg show` (its
public-key, endpoints and latest-handshakes views, never `dump` or
`private-key`, which hold the private key) and from the invite files,
of which only the id, the reserved address, the port and the expiry are
shown. Nothing secret is printed.
"""

import ipaddress
from collections.abc import Callable
from datetime import datetime

from keel.mesh import identity, invites
from keel.mesh.token import shown
from keel.network import wireguard
from keel.network.wireguard import allowed, same_key

Reader = Callable[[tuple[str, ...]], str | None]


def table(text: str | None) -> dict[str, str]:
    """`wg show IFACE endpoints|latest-handshakes`: key to value"""
    found = {}
    for line in (text or "").splitlines():
        fields = line.split("\t")
        if len(fields) == 2:
            found[fields[0]] = fields[1]
    return found


def handshake(value: str | None, now: datetime) -> str:
    if value is None:
        return "no handshake known"
    if not value.isdigit() or value == "0":
        return "no handshake yet"
    ago = int(now.timestamp()) - int(value)
    return f"handshake {max(ago, 0)} s ago"


def mesh_identity(root: str) -> str:
    """Which mesh this node is in: its identity, as every member holds
    it (keel.mesh.identity)"""
    try:
        found = identity.read(root)
    except ValueError as e:
        return f"mesh identity: {e}"
    if found is None:
        return ("mesh identity: none yet (a mesh built by hand gets one with"
                " keel mesh create --adopt on one node, keel mesh sync on"
                " the others)")
    return f"mesh identity: {found.hex()}"


def lines(overlay: dict | None, root: str, now: datetime,
          output: Reader | None) -> list[str]:
    """What status prints; `output` None off the live system"""
    if not overlay or not overlay.get("address"):
        return ["this node is in no mesh: keel mesh create makes one, keel"
                " mesh join joins one"]
    iface = wireguard.interface(overlay)
    found = [f"this node: {overlay['address']} on {iface}, WireGuard on"
             f" UDP {wireguard.port(overlay)}", mesh_identity(root)]
    if output is None:
        found.append("not the live system: no handshake read")
        endpoints = handshakes = {}
    else:
        public = (output(("wg", "show", iface, "public-key")) or "").strip()
        found.append("public key: "
                     f"{public or 'unknown (is the interface up?)'}")
        endpoints = table(output(("wg", "show", iface, "endpoints")))
        handshakes = table(output(("wg", "show", iface,
                                   "latest-handshakes")))
    peers = overlay.get("peers") or []
    found.append(f"peers: {len(peers)}")
    for peer in peers:
        key = str(peer.get("public_key"))
        live_key = next((one for one in endpoints | handshakes
                         if same_key(one, key)), None)
        endpoint = endpoints.get(live_key) or peer.get("endpoint")
        if endpoint in (None, "(none)"):
            endpoint = "no endpoint"
        state = (handshake(handshakes.get(live_key), now)
                 if output is not None else "")
        found.append(f"  {key}  {', '.join(allowed(peer))}  {endpoint}"
                     f"{'  ' + state if state else ''}")
    waiting = invites.pending(root, now)
    found.append(f"pending invites: {len(waiting)}")
    for one in waiting:
        used = "used, waiting for its confirmation" if one.consumed \
            else "pending"
        address = ipaddress.IPv6Interface(one.address)
        found.append(f"  {one.invite_id}  {address}  TCP {one.https_port}"
                     f"  until {shown(one.expires)}  {used}")
    return found
