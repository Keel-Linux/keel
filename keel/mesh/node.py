# Copyright (c) 2026 KeelLinux maintainers
"""This machine as keel mesh changes it: its spec, apply, confirm

The one seam between the mesh commands and the rest of keel. A join
writes the same `network.overlay.wireguard` fields an operator writes
by hand, into this node's own spec (0013), and converges them with the
same `apply --system` under the same window (0018), with the uplink
left alone (`--skip-uplink`, as confconsole's overlay screen asks) and
no certificate requested. The spec is validated whole before it is
written, and written as keel writes its state, through a temporary
file and a rename (keel.network.marker.write_private), so a crash
leaves the old spec or the new one. It is written as YAML from the
document keel read, so comments in it are not kept.

The change apply made is read back from its marker: that is the change
keel mesh may confirm, and no other (keel.network.confirm).
"""

import contextlib
import ipaddress
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field

import yaml

from keel import spec
from keel.commands import apply_system, manifest_facts
from keel.mesh.protocol import Peer
from keel.network import confirm as netconfirm
from keel.network import live, marker, session, wireguard
from keel.network.marker import write_private
from keel.network.wireguard import allowed, same_key
from keel.system import DEFAULT_WINDOW
from keel.system.ovstate import overlay_of


class NodeError(Exception):
    """The spec cannot take the change, and why"""


@dataclass(frozen=True)
class Change:
    """apply's exit code, and the overlay change waiting, if it made one"""

    code: int
    made: marker.Pending | None


def live_apply(doc: dict, root: str, window: int) -> int:
    """apply --system-only --skip-uplink, its lines on standard error

    Standard output stays the command's own: the line to paste, or the
    summary confconsole shows.
    """
    with contextlib.redirect_stdout(sys.stderr):
        return apply_system(doc, root, False, "keel mesh",
                            defer_certificate=True, network_window=window,
                            skip_uplink=True)


@dataclass
class Node:
    root: str
    path: str
    window: int = DEFAULT_WINDOW
    clients: tuple[str, ...] = ()
    apply: Callable[[dict, str, int], int] = live_apply
    probes: Callable[[], netconfirm.Probes] = field(default=live.probes)
    run: Callable[[tuple[str, ...]], str | None] = field(default=live.run)
    output: Callable[[tuple[str, ...]], str | None] = field(
        default=live.output)

    def document(self) -> dict:
        """The spec as keel reads it; an absent one is an empty spec"""
        if not os.path.exists(self.path):
            return {"version": 1}
        try:
            return spec.canonical(spec.load(self.path))
        except spec.SpecError as e:
            raise NodeError(str(e)) from None

    def overlay(self) -> dict:
        return overlay_of(self.document()) or {}

    def problems(self, doc: dict) -> list[str]:
        return spec.validate(doc, check_secret_files=False,
                             facts=manifest_facts(doc, self.root))

    def write(self, doc: dict) -> None:
        """Validate the whole spec, then replace the file with it"""
        problems = self.problems(doc)
        if problems:
            raise NodeError("; ".join(f"{self.path}: {one}"
                                      for one in problems))
        text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False,
                              allow_unicode=True)
        directory, name = os.path.split(os.path.abspath(self.path))
        try:
            write_private(directory, name, text)
        except OSError as e:
            raise NodeError(f"{self.path} cannot be written:"
                            f" {e.strerror or e}") from None

    def change(self, doc: dict, window: int | None = None) -> Change:
        """Write `doc` and apply it; the change waiting, if any"""
        self.write(doc)
        code = self.apply(doc, self.root, window or self.window)
        made = marker.read(self.root) if marker.exists(self.root) else None
        if made is not None and (made.kind != marker.OVERLAY
                                 or made.changed_at is None):
            made = None
        return Change(code, made)

    def waiting(self) -> bool:
        return marker.exists(self.root)

    def admit(self, peer: dict, window: int | None = None) -> Change:
        """This node's spec with `peer` added, written and applied; a
        peer of the same key is refused (NodeError), never replaced"""
        return self.change(with_peer(self.document(), peer), window)

    def peers(self, but: str) -> tuple[Peer, ...]:
        """The peers the spec declares, but the one of key `but`"""
        found = []
        for peer in self.overlay().get("peers") or []:
            key = str(peer.get("public_key"))
            if same_key(key, but):
                continue
            hosts = [one for one in allowed(peer) if one.endswith("/128")]
            if hosts:
                found.append(Peer(key, peer.get("endpoint"),
                                  hosts[0].split("/")[0]))
        return tuple(found)

    def handshake(self, key: str) -> int | None:
        """When `key` last completed a WireGuard handshake with this node,
        in seconds since the epoch, as `wg show IFACE latest-handshakes`
        says; None for no handshake, or no answer"""
        iface = wireguard.interface(self.overlay())
        text = self.output(("wg", "show", iface, "latest-handshakes")) or ""
        for line in text.splitlines():
            fields = line.split("\t")
            if len(fields) == 2 and same_key(fields[0], key) and \
                    fields[1].isdigit() and fields[1] != "0":
                return int(fields[1])
        return None

    def confirm(self, origin: session.Origin,
                made: marker.Pending | None) -> tuple[bool, list[str]]:
        return netconfirm.confirm(self.root, origin, self.probes(), self.run,
                                  expected=made, clients=self.clients)


def static_addresses(doc: dict):
    """The static addresses network.interfaces declares, in its order"""
    interfaces = (doc.get("network") or {}).get("interfaces") or {}
    for iface in interfaces.values():
        for family in ("ipv6", "ipv4"):
            block = (iface or {}).get(family) or {}
            if block.get("method") == "static" and block.get("address"):
                yield ipaddress.ip_interface(str(block["address"])).ip


def global_addresses(text: str) -> list[tuple[str, str]]:
    """`ip -o address show scope global` output: (interface, address)"""
    found = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) > 3 and fields[2] in ("inet", "inet6"):
            found.append((fields[1].split("@")[0],
                          fields[3].split("/")[0]))
    return found


def with_peer(doc: dict, peer: dict) -> dict:
    """`doc` with the peer added to its overlay, as a new document

    A peer of the same key is never replaced: raises NodeError.
    """
    network = dict(doc.get("network") or {})
    overlay = dict(network.get("overlay") or {})
    wireguard = dict(overlay.get("wireguard") or {})
    kept = list(wireguard.get("peers") or [])
    if any(same_key(str(one.get("public_key")), peer["public_key"])
           for one in kept):
        raise NodeError(f"{peer['public_key']} is already a peer of this"
                        " node; a join never replaces one")
    wireguard["peers"] = kept + [peer]
    return {**doc, "network": {**network, "overlay": {
        **overlay, "wireguard": wireguard}}}


def with_overlay(doc: dict, fields: dict) -> dict:
    """`doc` with fields of its overlay set, as a new document"""
    network = dict(doc.get("network") or {})
    overlay = dict(network.get("overlay") or {})
    wireguard = {**(overlay.get("wireguard") or {}), **fields}
    return {**doc, "network": {**network, "overlay": {
        **overlay, "wireguard": wireguard}}}
