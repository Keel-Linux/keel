# Copyright (c) 2026 KeelLinux maintainers
"""Drift of the overlay's peers: a peer with no WireGuard handshake

keel mesh keeps a peer it added live with no handshake (keel#117): the
addition cannot cut this node off, and the handshake comes once the
other member has this node as a peer too. Until then the peer is
drift: `network.overlay.wireguard.peers.<key>.handshake`, with the age
of the last handshake when there is one. A peer the interface does not
hold is drift too. Read from `wg show <interface> latest-handshakes` on
the live system only (never `dump`, which holds the private key);
nothing is compared under another root.
"""

from collections.abc import Callable
from datetime import datetime, timezone

from keel.diff.report import DRIFT, SAME, UNKNOWN, FieldDiff
from keel.network import wireguard
from keel.network.wireguard import same_key
from keel.system.ovstate import overlay_of

WANTED = "a handshake"
LATER = ("it comes once that member has this node as a peer too (keel"
         " mesh sync on that member)")

NOT_HELD = ("keel mesh sync on this node applies it again, or keel spec"
            " apply --system")

Reader = Callable[[tuple[str, ...]], str | None]


def latest(text: str) -> dict[str, str]:
    """`wg show IFACE latest-handshakes`: key to seconds since the epoch"""
    found = {}
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) == 2:
            found[fields[0]] = fields[1]
    return found


def handshake_fields(declared: dict, live: bool, output: Reader | None = None,
                     now: datetime | None = None) -> list[FieldDiff]:
    """One field for each peer the spec declares, on the live system"""
    overlay = overlay_of(declared) or {}
    peers = overlay.get("peers") or []
    if not live or not overlay.get("address") or not peers:
        return []
    if output is None:
        from keel.network import live as live_link
        output = live_link.output
    iface = wireguard.interface(overlay)
    text = output(("wg", "show", iface, "latest-handshakes"))
    if text is None:
        return [FieldDiff("network.overlay.wireguard.handshakes", UNKNOWN,
                          WANTED, None, f"wg show {iface} latest-handshakes"
                          " gave no answer: is the interface up?")]
    seen = latest(text)
    now = now or datetime.now(timezone.utc)
    fields = []
    for peer in peers:
        key = str(peer.get("public_key"))
        name = f"network.overlay.wireguard.peers.{key}.handshake"
        at = next((value for one, value in seen.items()
                   if same_key(one, key)), None)
        if at is None:
            fields.append(FieldDiff(name, DRIFT, WANTED, None,
                                    note=f"{iface} does not hold this peer:"
                                    f" {NOT_HELD}"))
        elif not at.isdigit() or at == "0":
            fields.append(FieldDiff(
                name, DRIFT, WANTED, "none",
                note=f"no handshake since {iface} came up: {LATER}"))
        else:
            ago = max(int(now.timestamp()) - int(at), 0)
            fields.append(FieldDiff(name, SAME, f"{WANTED} ({ago} s ago)",
                                    f"{WANTED} ({ago} s ago)"))
    return fields
