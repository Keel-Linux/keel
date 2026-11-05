# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh status: the peers, their handshakes, the pending invites

A peer with no handshake is drift, said on a line of its own (keel#117):
keel mesh keeps a peer it added live before the other member has this
node too.

Read from the spec, from the mesh's identity, from `wg show` (its
public-key, endpoints and latest-handshakes views, never `dump` or
`private-key`, which hold the private key) and from the invite files,
of which only the id, the reserved address, the port and the expiry are
shown. Nothing secret is printed.
"""

import ipaddress
from collections.abc import Callable
from datetime import datetime, timezone

from keel.diff.handshakes import NOT_HELD, STALE, UNREACHABLE
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


def drift_of(value: str | None, now: datetime, iface: str) -> str | None:
    """Why a peer is drift: not held, no handshake, or one older than
    STALE (keel#140); None for a recent one"""
    if value is None:
        return f"is not held by {iface}: {NOT_HELD}"
    if not value.isdigit() or value == "0":
        return f"has no handshake since {iface} came up: {UNREACHABLE}"
    ago = int(now.timestamp()) - int(value)
    if ago > STALE:
        return f"has its last handshake {ago} s ago: {UNREACHABLE}"
    return None


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
    drift = []
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
        why = drift_of(handshakes.get(live_key) if live_key else None,
                       now, iface) if output is not None else None
        if why:
            drift.append(f"drift: peer {key} {why}")
    found += drift
    waiting = invites.pending(root, now)
    found.append(f"pending invites: {len(waiting)}")
    for one in waiting:
        used = "used, waiting for its confirmation" if one.consumed \
            else "pending"
        address = ipaddress.IPv6Interface(one.address)
        found.append(f"  {one.invite_id}  {address}  TCP {one.https_port}"
                     f"  until {shown(one.expires)}  {used}")
    return found


ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def report(overlay: dict | None, root: str, now: datetime,
           output: Reader | None) -> dict:
    """What `status --json` gives of the mesh (docs/mesh.md, "The
    contract for confconsole"); `output` None off the live system, and
    every field that needs it is then None"""
    if not overlay or not overlay.get("address"):
        return {"in_mesh": False, "address": None, "interface": None,
                "port": None, "identity": identity_hex(root),
                "public_key": None, "members": [], "invites": []}
    iface = wireguard.interface(overlay)
    endpoints = handshakes = {}
    public = None
    if output is not None:
        public = (output(("wg", "show", iface, "public-key")) or "").strip() \
            or None
        endpoints = table(output(("wg", "show", iface, "endpoints")))
        handshakes = table(output(("wg", "show", iface,
                                   "latest-handshakes")))
    members = []
    for peer in overlay.get("peers") or []:
        key = str(peer.get("public_key"))
        live_key = next((one for one in endpoints | handshakes
                         if same_key(one, key)), None)
        endpoint = endpoints.get(live_key) or peer.get("endpoint")
        seen = handshakes.get(live_key) if live_key else None
        members.append({
            "public_key": key,
            "address": host_of(allowed(peer)),
            "allowed_ips": list(allowed(peer)),
            "endpoint": None if endpoint in (None, "(none)") else
            str(endpoint),
            "handshake_age": age(seen, now),
            "reachable": None if output is None else
            drift_of(seen, now, iface) is None,
        })
    return {
        "in_mesh": True, "address": str(overlay["address"]),
        "interface": iface, "port": wireguard.port(overlay),
        "identity": identity_hex(root), "public_key": public,
        "members": members,
        "invites": [{
            "invite_id": one.invite_id, "assigned": one.address,
            "https_port": one.https_port,
            "expires": one.expires.astimezone(timezone.utc).strftime(
                ISO_FORMAT),
            "used": one.consumed, "vip": one.vip}
            for one in invites.pending(root, now)],
    }


def identity_hex(root: str) -> str | None:
    try:
        found = identity.read(root)
    except ValueError:
        return None
    return found.hex() if found else None


def host_of(nets: list[str]) -> str | None:
    """A peer's overlay address: the first IPv6 /128 it is given"""
    for net in nets:
        try:
            found = ipaddress.ip_network(net)
        except ValueError:
            continue
        if found.version == 6 and found.prefixlen == 128:
            return str(found.network_address)
    return None


def age(value: str | None, now: datetime) -> int | None:
    """Seconds since a handshake `wg show` gives, None with none"""
    if value is None or not value.isdecimal() or value == "0":
        return None
    return max(int(now.timestamp()) - int(value), 0)
