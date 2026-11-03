# Copyright (c) 2026 KeelLinux maintainers
"""The specs of a pair that cannot work (keel#267)

keel.spec.validate holds the spec by itself, and this file holds it against
the pair record on the node. The primary of a paired node comes from the
record (decision 0049), so a spec that is correct on a node with a record
cannot work on a node with no record.

With a record the pair exists and keel acts from the holder's claim, so
nothing here refuses it: an upgrade must not break a running node (keel#266).

keel spec validate, keel spec apply with the system phase and keel diff call
this. The conf phase and the mesh commands do not: a first boot and keel mesh
join read the spec before the record can exist.
"""

import ipaddress
from typing import Any

REPLICA = "replica"
STANDALONE = "standalone"
PRIMARY_FIELD = "database.server.replication.primary"
ROLE_FIELD = "database.server.role"
# what appliance.vip needs from the chain; the manifests decide the rest
VIP_NEEDS = ("vip", "wireguard")


def pair_problems(doc: dict, recorded: tuple[str, ...]) -> list[str]:
    """Every reason this pair spec cannot work on a node that holds the
    pair records of `recorded`, empty when it can"""
    server = _mapping(_mapping(doc.get("database")).get("server"))
    vip = _mapping(doc.get("appliance")).get("vip")
    if vip and _same_in(vip, recorded):
        return []
    errors = _source(server, vip, _own_addresses(doc))
    if not vip:
        return errors
    if str(server.get("role")) == STANDALONE:
        errors.append(
            f"{ROLE_FIELD}: standalone, but appliance.vip {vip} says this node"
            " is one of a pair. Write primary or replica, or remove"
            " appliance.vip")
    overlays = _mapping(doc.get("overlays"))
    errors += [
        f"overlays.{name}: disabled, but appliance.vip {vip} needs it. Enable"
        f" overlays.{name}, or remove appliance.vip"
        for name in VIP_NEEDS if overlays.get(name) == "disabled"
    ]
    return errors


def _source(server: dict, vip: Any, own: list[str]) -> list[str]:
    """Where a replica replicates from"""
    if str(server.get("role")) != REPLICA:
        return []
    primary = _mapping(server.get("replication")).get("primary")
    host = primary.get("host") if isinstance(primary, dict) else None
    if not host:
        if not vip:
            return []  # keel.spec.validate_database refuses this one
        return [
            f"{PRIMARY_FIELD}: required on this replica: appliance.vip {vip}"
            " names a pair, and this node has no pair record, so keel does"
            " not know where to replicate from. Declare"
            f" {PRIMARY_FIELD}.host with the overlay address of the primary,"
            " or run keel vip pair first"
        ]
    if vip and _same(host, vip):
        return [
            f"{PRIMARY_FIELD}.host: {host} is the VIP. A replica replicates"
            " from the overlay address of the primary and never from the VIP"
            " (decision 0029)"
        ]
    if _same_in(host, tuple(own)):
        return [
            f"{PRIMARY_FIELD}.host: {host} is this node's own overlay address."
            " Write the overlay address of the primary"
        ]
    return []


def _own_addresses(doc: dict) -> list[str]:
    overlay = _mapping(_mapping(doc.get("network")).get("overlay"))
    wireguard = _mapping(overlay.get("wireguard"))
    return [str(wireguard[key]).split("/")[0]
            for key in ("address", "ipv4_address") if wireguard.get(key)]


def _mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _same_in(one: Any, others: tuple[str, ...]) -> bool:
    return any(_same(one, other) for other in others)


def _same(one: Any, other: Any) -> bool:
    try:
        return (ipaddress.ip_address(str(one))
                == ipaddress.ip_address(str(other)))
    except ValueError:
        return str(one) == str(other)
