# Copyright (c) 2026 KeelLinux maintainers
"""The VIP an invite proposes for the pair, and the one a join received
(decision 0076, point 3)

In a cloud mode `keel mesh invite` carries the pair's VIP in the token,
so the operator never types it: this node's own `appliance.vip` when it
declares one, else the VIP of a pending invite of this node (the two
invites of cloud advanced carry one VIP), else the lowest free address
of the overlay's VIP range (keel.mesh.vip.vip_range). Not free: a VIP
this node keeps a state file or a pair record for, and one reserved in
etcd. A witness (`overlays.vip: disabled`) proposes none.

`keel mesh join` keeps the VIP of a join that confirmed in
/var/lib/keel/mesh/proposed-vip.json, for `keel mesh status --json` and
the screen that writes `appliance.vip`. Nothing here writes a spec.
"""

import ipaddress
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from keel.mesh import vip as vipstate
from keel.mesh import vippair
from keel.network.marker import path, write_private

CLOUD_MODES = ("cloud_simple", "cloud_advanced")
RECORD = "var/lib/keel/mesh/proposed-vip.json"
RESERVED = "/keel/{mesh}/vips/"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class Proposal:
    """The VIP to carry, or None and why none"""

    vip: str | None
    why: str = ""


def proposed(root: str, doc: dict, pending: Iterable,
             reserved: Callable[[], Iterable[str]] = lambda: ()) -> Proposal:
    """The VIP an invite of this node carries; `pending` are this node's
    pending invites (keel.mesh.invites.Pending), `reserved` the VIPs
    etcd holds (it may raise, see etcd_reserved)"""
    mode = (doc.get("installation") or {}).get("mode")
    if mode not in CLOUD_MODES:
        return Proposal(None, f"installation.mode is {mode or 'not declared'},"
                        " not a cloud mode")
    if (doc.get("overlays") or {}).get("vip") == "disabled":
        return Proposal(None, "overlays.vip is disabled here (a witness"
                        " holds no VIP)")
    try:
        own = vipstate.declared(doc)
    except ValueError:
        own = None
    if own is not None:
        return Proposal(own)
    for one in pending:
        if one.vip:
            return Proposal(one.vip)
    overlay = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    prefix = ipaddress.IPv6Interface(str(overlay["address"])).network
    vips = vipstate.vip_range(prefix)
    if vips is None:
        return Proposal(None, f"the overlay {prefix} is too narrow for a VIP"
                        " range (narrower than a /96)")
    taken = known(root) | set(reserved())
    for host in range(1, vips.num_addresses):
        found = str(vips.network_address + host)
        if found not in taken:
            return Proposal(found)
    return Proposal(None, f"every address of the VIP range {vips} is taken")


def known(root: str) -> set[str]:
    """The VIPs this node keeps a state file or a pair record for"""
    return set(vipstate.known(root)) | set(vippair.recorded_vips(root))


def etcd_reserved(client, mesh_id: str) -> list[str]:
    """The VIPs reserved in etcd (`/keel/<mesh>/vips/<vip>/pair`, the
    reservation of keel vip pair); raises EtcdError"""
    prefix = RESERVED.format(mesh=mesh_id)
    found = []
    for value in client.prefix(prefix):
        name = value.key[len(prefix):].split("/")[0]
        try:
            found.append(vipstate.address(name))
        except ValueError:
            continue
    return found


def keep(root: str, vip: str, invite_id: str, inviter: str,
         now: datetime) -> None:
    """The VIP a confirmed join received, for status and the screens"""
    write_private(root, RECORD, json.dumps({
        "vip": vip, "invite_id": invite_id,
        "inviter": str(ipaddress.IPv6Interface(inviter).ip),
        "joined": now.astimezone(timezone.utc).strftime(TIME_FORMAT),
    }, sort_keys=True) + "\n")


def received(root: str) -> str | None:
    """The VIP the last confirmed join received, or None; a damaged
    record is none"""
    try:
        with open(path(root, RECORD)) as fob:
            return vipstate.address(json.load(fob)["vip"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
