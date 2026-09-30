# Copyright (c) 2026 KeelLinux maintainers
"""Validation of network.overlay: the WireGuard interface (decision 0020)

IPv6 first: the overlay address is IPv6 and required, an IPv4 address
beside it is optional. The private key is a file reference and is never
inlined; unlike every other secret of the spec, its absence is not an
error, because apply makes it on the machine at the first converge.

wg-quick adds a route for the overlay's own prefixes and for each peer's
allowed_ips, so a prefix that covers the uplink would send the uplink's
replies into the overlay (keel#49). The overlay's addresses are
therefore private ones (fc00::/7; RFC 1918 or 100.64.0.0/10), and
neither they nor any allowed_ips may overlap what network.interfaces
declares (an address's prefix, a gateway) or a peer's endpoint address;
a route to every address (/0) is refused outright. An endpoint given by
name, or an uplink left to DHCP or SLAAC, cannot be checked here:
`keel network confirm` checks the gateways' routes on the machine.
"""

import ipaddress
import os
from typing import Any

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
# a prefix and what declares it, `network.interfaces.eth0.ipv6.gateway X`
Reserved = list[tuple[str, Network]]
UNIQUE_LOCAL = (ipaddress.ip_network("fc00::/7"),)
PRIVATE_IPV4 = tuple(ipaddress.ip_network(one) for one in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))
PRIVATE = {
    6: (UNIQUE_LOCAL, "a unique local address (fc00::/7, RFC 4193)"),
    4: (PRIVATE_IPV4, "a private address, RFC 1918 or the shared"
        " 100.64.0.0/10 (RFC 6598)"),
}

from keel.network import wireguard
from keel.spec.fields import (
    domain_error,
    is_unicast,
    list_error,
    mapping_error,
    port_error,
)
from keel.spec.secretstore import secret_file_error

OVERLAY_KEYS = ("wireguard",)
WIREGUARD_KEYS = ("interface", "address", "ipv4_address", "listen_port",
                  "private_key", "peers")
PEER_KEYS = ("public_key", "endpoint", "allowed_ips", "persistent_keepalive")
MAX_KEEPALIVE = 65535
KEY = "network.overlay"


def validate_overlay(overlay: Any, interfaces: Any = None,
                     check_secret_files: bool = True) -> list[str]:
    """`interfaces` is what network.interfaces declares, the uplink"""
    error = mapping_error(KEY, overlay)
    if error or not overlay:
        return [error] if error else []
    errors = [f"{KEY}.{name}: unknown key" for name in overlay
              if name not in OVERLAY_KEYS]
    return errors + validate_wireguard(overlay.get("wireguard"), interfaces,
                                       check_secret_files)


def validate_wireguard(wg: Any, interfaces: Any,
                       check_secret_files: bool) -> list[str]:
    key = f"{KEY}.wireguard"
    error = mapping_error(key, wg)
    if error or wg is None:
        return [error] if error else []
    uplinks = tuple(str(name) for name in interfaces) if isinstance(
        interfaces, dict) else ()
    reserved = uplink_prefixes(interfaces) + endpoint_prefixes(
        f"{key}.peers", wg.get("peers"))
    errors = [f"{key}.{name}: unknown key" for name in wg
              if name not in WIREGUARD_KEYS]
    errors += interface_errors(key, wg.get("interface"), uplinks)
    if "address" not in wg:
        errors.append(f"{key}.address: required, this node's IPv6 address"
                      " on the overlay with its prefix length")
    else:
        errors += address_errors(f"{key}.address", wg["address"], 6,
                                 reserved)
    if "ipv4_address" in wg:
        errors += address_errors(f"{key}.ipv4_address", wg["ipv4_address"],
                                 4, reserved)
    if "listen_port" in wg:
        error = port_error(f"{key}.listen_port", wg["listen_port"])
        errors += [error] if error else []
    if "private_key" in wg:
        errors += private_key_errors(f"{key}.private_key", wg["private_key"],
                                     check_secret_files)
    return errors + peers_errors(f"{key}.peers", wg.get("peers"), reserved)


def as_prefix(value: Any) -> Network | None:
    """An address's prefix, a bare address as one host; None if neither"""
    if value is None:
        return None
    try:
        return ipaddress.ip_interface(str(value)).network
    except ValueError:
        return None


def uplink_prefixes(interfaces: Any) -> Reserved:
    """The prefixes and gateways network.interfaces declares

    One its own validation refuses is left out: its error says why.
    """
    if not isinstance(interfaces, dict):
        return []
    found: Reserved = []
    for name, iface in interfaces.items():
        if not isinstance(iface, dict):
            continue
        for family in ("ipv6", "ipv4"):
            found += family_prefixes(f"network.interfaces.{name}.{family}",
                                     iface.get(family))
    return found


def family_prefixes(key: str, family: Any) -> Reserved:
    if not isinstance(family, dict):
        return []
    found: Reserved = []
    for field in ("address", "gateway"):
        prefix = as_prefix(family.get(field))
        if prefix is not None:
            found.append((f"{key}.{field} {family[field]}", prefix))
    return found


def endpoint_prefixes(key: str, peers: Any) -> Reserved:
    """Each peer's endpoint given as an address; a name cannot be known"""
    found: Reserved = []
    for index, peer in enumerate(peers if isinstance(peers, list) else []):
        if not isinstance(peer, dict) or not peer.get("endpoint"):
            continue
        try:
            host, _ = wireguard.split_endpoint(str(peer["endpoint"]))
            prefix = ipaddress.ip_network(host)
        except ValueError:
            continue
        found.append((f"{key}[{index}].endpoint {host}", prefix))
    return found


def overlaps(prefix: Network, reserved: Reserved) -> list[str]:
    """What of `reserved` the prefix covers or shares addresses with"""
    return [label for label, other in reserved
            if other.version == prefix.version and prefix.overlaps(other)]


def interface_errors(key: str, name: Any, uplinks: tuple[str, ...]) -> (
    list[str]
):
    if name is None:
        return []
    text = str(name)
    if not isinstance(name, str) or not wireguard.INTERFACE_RE.match(text):
        return [f"{key}.interface: {text!r} is not an interface name"
                " wg-quick accepts (at most 15 of A-Z a-z 0-9 _ = + . -)"]
    if text in uplinks:
        return [f"{key}.interface: {text} is declared under"
                " network.interfaces too; the overlay is an interface of"
                " its own"]
    return []


def address_errors(key: str, value: Any, version: int,
                   reserved: Reserved) -> list[str]:
    """An overlay address, private and apart from the uplink

    wg-quick routes the address's whole prefix into the overlay, so the
    prefix, not only the address, must stay inside the private range and
    clear of the uplink.
    """
    text = str(value)
    if "/" not in text:
        return [f"{key}: prefix length is required ({text})"]
    try:
        address = ipaddress.ip_interface(text)
    except ValueError as e:
        return [f"{key}: {e}"]
    if address.version != version:
        return [f"{key}: not an IPv{version} address ({text})"]
    if not is_unicast(address.ip):
        return [f"{key}: must be a unicast address, not link local,"
                f" loopback or multicast ({text})"]
    ranges, private = PRIVATE[version]
    if not any(address.network.subnet_of(one) for one in ranges):
        return [f"{key}: must be {private}, its whole prefix, since"
                f" wg-quick routes the prefix into the overlay ({text})"]
    return [f"{key}: {address.network} overlaps {label}, which would then"
            " be routed into the overlay"
            for label in overlaps(address.network, reserved)]


def private_key_errors(key: str, value: Any, check_files: bool) -> (
    list[str]
):
    """A file reference only: the key is made by apply, never generated
    into the conf and never written in the spec"""
    if not isinstance(value, dict):
        return [f"{key}: must be a mapping with file: PATH"]
    errors = [f"{key}.{name}: the private key is a file, made by apply"
              " when absent; no other backend" for name in value
              if name != "file"]
    path = value.get("file")
    if not isinstance(path, str) or not wireguard.KEY_PATH_RE.match(path):
        return errors + [f"{key}.file: must be an absolute path of letters,"
                         " digits and . _ - / only (wg-quick hands it to a"
                         " shell)"]
    if check_files and os.path.exists(path):
        problem = secret_file_error(path)
        errors += [f"{key}: {problem}"] if problem else []
    return errors


def peers_errors(key: str, peers: Any, reserved: Reserved) -> list[str]:
    error = list_error(key, peers)
    if error:
        return [error]
    errors: list[str] = []
    for index, peer in enumerate(peers or []):
        errors += peer_errors(f"{key}[{index}]", peer, reserved)
    keys = [str(peer.get("public_key")) for peer in peers or []
            if isinstance(peer, dict) and peer.get("public_key")]
    errors += [f"{key}: public key {one} is declared twice"
               for one in sorted(set(keys)) if keys.count(one) > 1]
    return errors + shared_ips(key, peers or [])


def peer_errors(key: str, peer: Any, reserved: Reserved) -> list[str]:
    error = mapping_error(key, peer)
    if error or peer is None:
        return [error or f"{key}: must be a mapping"]
    errors = [f"{key}.{name}: unknown key" for name in peer
              if name not in PEER_KEYS]
    public = peer.get("public_key")
    if public is None:
        errors.append(f"{key}.public_key: required")
    elif not wireguard.is_key(str(public)):
        errors.append(f"{key}.public_key: not a WireGuard key (44"
                      " characters of base64, as wg pubkey prints it)")
    if peer.get("endpoint") is not None:
        errors += endpoint_errors(f"{key}.endpoint", peer["endpoint"])
    errors += allowed_errors(f"{key}.allowed_ips", peer.get("allowed_ips"),
                             reserved)
    if "persistent_keepalive" in peer:
        errors += keepalive_errors(f"{key}.persistent_keepalive",
                                   peer["persistent_keepalive"])
    return errors


def endpoint_errors(key: str, value: Any) -> list[str]:
    text = str(value)
    try:
        host, _ = wireguard.split_endpoint(text)
    except ValueError as e:
        return [f"{key}: {text}: {e}"]
    if text.startswith("["):
        return []  # split_endpoint parsed the IPv6 literal
    if host.replace(".", "").isdigit():
        try:
            ipaddress.IPv4Address(host)
        except ValueError as e:
            return [f"{key}: {e}"]
        return []
    error = domain_error(key, host)
    return [error] if error else []


def allowed_errors(key: str, value: Any, reserved: Reserved) -> list[str]:
    error = list_error(key, value)
    if error:
        return [error]
    if not value:
        return [f"{key}: at least one prefix, the peer's overlay address"
                " as /128 for a node"]
    errors = []
    for one in value:
        try:
            prefix = ipaddress.ip_network(str(one))
        except ValueError as e:
            errors.append(f"{key}: {one}: {e}")
            continue
        errors += captured(key, prefix, reserved)
    return errors


def captured(key: str, prefix: Network, reserved: Reserved) -> list[str]:
    """A route wg-quick would add that takes traffic from the uplink"""
    if prefix.prefixlen == 0:
        return [f"{key}: {prefix} routes every address to this peer, the"
                " uplink's replies included; list the peer's overlay"
                " addresses instead"]
    return [f"{key}: {prefix} covers {label}, which would then be routed"
            " into the overlay" for label in overlaps(prefix, reserved)]


def keepalive_errors(key: str, value: Any) -> list[str]:
    if isinstance(value, bool) or not isinstance(value, int) \
            or not 1 <= value <= MAX_KEEPALIVE:
        return [f"{key}: seconds between 1 and {MAX_KEEPALIVE}; leave it"
                " out for none"]
    return []


def shared_ips(key: str, peers: list) -> list[str]:
    """A prefix routed to two peers: wg gives it to the last one silently"""
    seen: dict[str, int] = {}
    errors = []
    for index, peer in enumerate(peers):
        if not isinstance(peer, dict) or not isinstance(
                peer.get("allowed_ips"), list):
            continue
        for one in peer["allowed_ips"]:
            try:
                network = str(ipaddress.ip_network(str(one)))
            except ValueError:
                continue
            if network in seen:
                errors.append(f"{key}[{index}].allowed_ips: {network} is"
                              f" already routed to peers[{seen[network]}]")
            else:
                seen[network] = index
    return errors
