# Copyright (c) 2026 KeelLinux maintainers
"""The JSON that confconsole's screens read (decision 0076)

`keel mesh invite --json` and `keel mesh status --json` print one line
of JSON each, as docs/mesh.md, "The contract for confconsole", writes
them down field by field. A field is added, never renamed or removed,
while `format` is 1.
"""

import ipaddress
from collections.abc import Callable
from datetime import datetime, timezone

from keel.mesh import etcd, etcdcare, invites, status, vippropose
from keel.mesh.node import Node
from keel.network import live
from keel.system.ovstate import overlay_of

FORMAT = 1
ISO_FORMAT = status.ISO_FORMAT


def iso(when: datetime) -> str:
    return when.astimezone(timezone.utc).strftime(ISO_FORMAT)


def invite(made: invites.Pending, token_text: str) -> dict:
    """The invite: the line, the token in it, the VIP it carries"""
    return {
        "format": FORMAT,
        "line": f"keel mesh join - <<< {token_text}",
        "token": token_text,
        "vip": made.vip,
        "expires": iso(made.expires),
        "invite_id": made.invite_id,
        "assigned": made.address,
        "https_port": made.https_port,
    }


def mesh_status(root: str, spec: str, doc: dict, overlay: dict | None,
                live_system: bool, now: datetime,
                err: Callable[[str], None]) -> dict:
    """The mesh, etcd, the VIP, and whether it is ready"""
    mode = (doc.get("installation") or {}).get("mode")
    found = {"format": FORMAT, "live": live_system, "mode": mode}
    found.update(status.report(overlay, root, now,
                               live.output if live_system else None))
    if found["in_mesh"]:
        found["etcd"] = etcdcare.report(
            etcd.Etcd(Node(root, spec), lambda: now, err), live_system)
    else:
        found["etcd"] = etcdcare.report_off()
    found["vip"] = vip(root, doc, found["invites"])
    found["ready"] = ready(found, mode) if live_system else None
    return found


def vip(root: str, doc: dict, pending: list[dict]) -> dict:
    """The VIP declared, the one proposed, and this node's role in it"""
    from keel.mesh import vip as vipstate
    from keel.system import dbpair
    try:
        declared = vipstate.declared(doc)
    except ValueError:
        declared = None
    proposed = vippropose.received(root) or next(
        (one["vip"] for one in pending if one["vip"]), None)
    role = holder = None
    if declared is not None:
        pair = dbpair.observe_pair(root, doc)
        role = pair.role or vipstate.REPLICA
        holder = pair.holder_address if pair.role else None
        if pair.role == vipstate.PRIMARY:
            holder = str(ipaddress.IPv6Interface(
                str(overlay_of(doc)["address"])).ip)
    return {"declared": declared, "proposed": proposed, "role": role,
            "holder": holder}


def ready(found: dict, mode: str | None) -> bool:
    """In the mesh, with members, every one reachable; in cloud advanced,
    etcd formed with 3 voters or more, every one healthy"""
    members = found["members"]
    if not found["in_mesh"] or not members or \
            not all(one["reachable"] for one in members):
        return False
    if mode != "cloud_advanced":
        return True
    found_etcd = found["etcd"]
    return found_etcd["state"] == "formed" and \
        (found_etcd["voters"] or 0) >= etcd.QUORUM_AT and \
        found_etcd["healthy_voters"] == found_etcd["voters"]
