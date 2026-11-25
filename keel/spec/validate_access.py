# Copyright (c) 2026 KeelLinux maintainers
"""Validation of network.access: the administrators' WireGuard (0098)

The access network is a WireGuard interface of its own, never the
mesh's: its name, its UDP port and its prefix differ from the overlay's.
Its address is a unique local /64 (answer 3), with the node at an
address of its choice (keel access invite writes `::1`); the prefix may
not overlap the uplink, the overlay's prefix or a mesh peer's
allowed_ips or endpoint, since wg-quick routes it into the interface.

A peer is the computer of one administrator: a name, its public key,
one /128 in the access prefix, and the day of its enrolment. A key that
is also a mesh peer's is refused: an access peer is never a mesh member
(the maintainer's rule of 2026-11-25), so it can never become an
operator root through `--adopt`. A peer has no endpoint, no keepalive
and no other prefix: the computer starts each handshake.

The access network needs keel's firewall: with `firewall.state: off`
nothing would hold an access peer to its ports, so the two are refused
together (keel.spec.validate).
"""

import ipaddress
from typing import Any

from keel.network import access as acc
from keel.network import wireguard
from keel.spec.fields import list_error, mapping_error, port_error
from keel.spec.validate_overlay import (
    UNIQUE_LOCAL,
    Reserved,
    as_prefix,
    endpoint_prefixes,
    interface_errors,
    overlaps,
    own_key_errors,
    private_key_errors,
    uplink_prefixes,
)

KEY = "network.access"
ACCESS_KEYS = ("interface", "address", "listen_port", "private_key",
               "token_minutes", "peers")
PEER_KEYS = ("name", "public_key", "address", "enrolled")


def validate_access(access: Any, network: dict,
                    check_secret_files: bool = True) -> list[str]:
    error = mapping_error(KEY, access)
    if error or access is None:
        return [error] if error else []
    errors = [f"{KEY}.{name}: unknown key" for name in access
              if name not in ACCESS_KEYS]
    overlay = ((network.get("overlay") or {}).get("wireguard")
               if isinstance(network.get("overlay"), dict) else None)
    overlay = overlay if isinstance(overlay, dict) else {}
    interfaces = network.get("interfaces")
    uplinks = tuple(str(name) for name in interfaces) if isinstance(
        interfaces, dict) else ()
    errors += interface_errors(KEY, access.get("interface"), uplinks)
    errors += apart_from_overlay(access, overlay)
    if "listen_port" in access:
        error = port_error(f"{KEY}.listen_port", access["listen_port"])
        errors += [error] if error else []
    errors += token_errors(access.get("token_minutes"))
    if "private_key" in access:
        errors += private_key_errors(f"{KEY}.private_key",
                                     access["private_key"],
                                     check_secret_files)
    reserved = uplink_prefixes(interfaces) + mesh_prefixes(overlay)
    prefix, found = address_errors(access.get("address"), reserved)
    errors += found
    errors += peers_errors(access.get("peers"), prefix, access, overlay)
    if check_secret_files and isinstance(access.get("peers"), list) and \
            isinstance(access.get("private_key", {}), dict):
        errors += own_key_errors(f"{KEY}.peers", {
            "interface": acc.interface(access),
            "private_key": {"file": acc.key_path(access)},
            "peers": access["peers"]})
    return errors


def apart_from_overlay(access: dict, overlay: dict) -> list[str]:
    """Not the mesh's interface, not its UDP port; a port that is no
    number has its own error"""
    if not overlay or not all(isinstance(one.get("listen_port", 0), int)
                              for one in (access, overlay)):
        return []
    errors = []
    if acc.interface(access) == wireguard.interface(overlay):
        errors.append(f"{KEY}.interface: {acc.interface(access)} is the"
                      " mesh's interface; the access network is an"
                      " interface of its own (decision 0098, answer 1)")
    if acc.port(access) == wireguard.port(overlay):
        errors.append(f"{KEY}.listen_port: {acc.port(access)} is the mesh's"
                      " UDP port; the access network listens on its own")
    return errors


def token_errors(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, bool) or not isinstance(value, int) or not (
            acc.MIN_TOKEN_MINUTES <= value <= acc.MAX_TOKEN_MINUTES):
        return [f"{KEY}.token_minutes: a whole number of minutes from"
                f" {acc.MIN_TOKEN_MINUTES} to {acc.MAX_TOKEN_MINUTES}"
                f" (default {acc.DEFAULT_TOKEN_MINUTES})"]
    return []


def mesh_prefixes(overlay: dict) -> Reserved:
    """The overlay's prefix, its peers' allowed_ips and endpoints"""
    found: Reserved = []
    prefix = as_prefix(overlay.get("address"))
    if prefix is not None:
        found.append((f"the mesh prefix {prefix}"
                      " (network.overlay.wireguard.address)", prefix))
    peers = overlay.get("peers")
    for index, peer in enumerate(peers if isinstance(peers, list) else []):
        allowed = peer.get("allowed_ips") if isinstance(peer, dict) else None
        for one in allowed if isinstance(allowed, list) else []:
            net = as_prefix(one)
            if net is not None:
                found.append((f"network.overlay.wireguard.peers[{index}]"
                              f".allowed_ips {one}", net))
    return found + endpoint_prefixes("network.overlay.wireguard.peers",
                                     peers)


def address_errors(value: Any, reserved: Reserved) -> (
    tuple[ipaddress.IPv6Interface | None, list[str]]
):
    key = f"{KEY}.address"
    if value is None:
        return None, [f"{key}: required, this node's address on the access"
                      f" network: a unique local /{acc.PREFIX_LENGTH}"
                      " (keel access invite makes one at the first"
                      " enrolment)"]
    text = str(value)
    try:
        found = ipaddress.IPv6Interface(text)
    except ValueError:
        return None, [f"{key}: {text} is not an IPv6 address with its"
                      f" prefix length (/{acc.PREFIX_LENGTH})"]
    if "/" not in text or found.network.prefixlen != acc.PREFIX_LENGTH:
        return None, [f"{key}: {text}: the access network is one /"
                      f"{acc.PREFIX_LENGTH} (decision 0098, answer 3)"]
    if not found.network.subnet_of(UNIQUE_LOCAL[0]):
        return None, [f"{key}: {text} must be a unique local address"
                      " (fc00::/7, RFC 4193): wg-quick routes its prefix"
                      " into the access interface"]
    if found.ip == found.network.network_address:
        return None, [f"{key}: {text} is the prefix itself, not an address"]
    return found, [f"{key}: {found.network} overlaps {label}"
                   for label in overlaps(found.network, reserved)]


def peers_errors(peers: Any, prefix: ipaddress.IPv6Interface | None,
                 access: dict, overlay: dict) -> list[str]:
    key = f"{KEY}.peers"
    error = list_error(key, peers)
    if error:
        return [error]
    mesh_keys = [str(peer.get("public_key")) for peer in
                 overlay.get("peers") or [] if isinstance(peer, dict)]
    errors: list[str] = []
    seen: dict[str, dict] = {"name": {}, "public_key": {}, "address": {}}
    for index, peer in enumerate(peers or []):
        where = f"{key}[{index}]"
        if not isinstance(peer, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        errors += peer_errors(where, peer, prefix, mesh_keys)
        errors += twice(where, peer, seen)
    return errors


def peer_errors(where: str, peer: dict,
                prefix: ipaddress.IPv6Interface | None,
                mesh_keys: list[str]) -> list[str]:
    errors = [f"{where}.{name}: unknown key; an access peer has a name, a"
              " public key, one address and the day of its enrolment"
              for name in peer if name not in PEER_KEYS]
    name = peer.get("name")
    if not isinstance(name, str) or not acc.NAME_RE.match(name):
        errors.append(f"{where}.name: required, 1 to 32 of a-z 0-9 and -,"
                      " beginning with a letter or a digit")
    key = peer.get("public_key")
    if not isinstance(key, str) or not wireguard.is_key(key):
        errors.append(f"{where}.public_key: required, the key as wg pubkey"
                      " prints it (44 characters of base64)")
    elif any(wireguard.same_key(key, one) for one in mesh_keys):
        errors.append(f"{where}.public_key: this key is a mesh peer's"
                      " (network.overlay.wireguard.peers); an access peer"
                      " is never a mesh member")
    errors += peer_address_errors(where, peer.get("address"), prefix)
    enrolled = peer.get("enrolled")
    if enrolled is not None and not (isinstance(enrolled, str)
                                     and acc.DATE_RE.match(enrolled)):
        errors.append(f"{where}.enrolled: the day of the enrolment,"
                      " YYYY-MM-DD")
    return errors


def peer_address_errors(where: str, value: Any,
                        prefix: ipaddress.IPv6Interface | None) -> list[str]:
    key = f"{where}.address"
    if value is None:
        return [f"{key}: required, one /128 in the access prefix"]
    try:
        found = ipaddress.IPv6Interface(str(value))
    except ValueError:
        return [f"{key}: {value} is not an IPv6 address"]
    if found.network.prefixlen != 128:
        return [f"{key}: {value}: a computer gets one /128 and no other"
                " prefix"]
    if prefix is None:
        return []
    if found.ip not in prefix.network:
        return [f"{key}: {found.ip} is not in the access prefix"
                f" {prefix.network}"]
    if found.ip in (prefix.ip, prefix.network.network_address):
        return [f"{key}: {found.ip} is the node's own address or the"
                " prefix itself"]
    return []


def twice(where: str, peer: dict, seen: dict[str, dict]) -> list[str]:
    """A name, a key or an address given to two peers"""
    errors = []
    for field in ("name", "public_key", "address"):
        value = peer.get(field)
        if value is None:
            continue
        text = str(value)
        if field == "public_key":
            text = str(wireguard.key_bytes(text) or text)
        elif field == "address":
            prefix = as_prefix(value)
            text = str(prefix) if prefix is not None else text
        if text in seen[field]:
            errors.append(f"{where}.{field}: {value} is given to"
                          f" {seen[field][text]} too")
        else:
            seen[field][text] = where
    return errors
