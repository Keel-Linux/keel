# Copyright (c) 2026 KeelLinux maintainers
"""Validation of the network section

IPv6 is the primary family: an interface may declare IPv6 only, and IPv4
is optional everywhere.
"""

import ipaddress
from typing import Any

from keel.spec.constants import IPV4_METHODS, IPV6_METHODS, MANAGED_BY
from keel.spec.fields import is_unicast, mapping_error


def validate_network(network: Any) -> list[str]:
    error = mapping_error("network", network)
    if error or not network:
        return [error] if error else []

    errors = []
    for key in network:
        if key not in ("managed_by", "interfaces", "nameservers"):
            errors.append(f"network.{key}: unknown key")

    managed_by = network.get("managed_by")
    if managed_by is not None and str(managed_by) not in MANAGED_BY:
        errors.append(f"network.managed_by: must be one of {MANAGED_BY}")

    for server in network.get("nameservers") or []:
        try:
            ipaddress.ip_address(str(server))
        except ValueError:
            errors.append(f"network.nameservers: {server} is not an address")

    interfaces = network.get("interfaces")
    error = mapping_error("network.interfaces", interfaces)
    if error:
        return errors + [error]
    for name, iface in (interfaces or {}).items():
        errors.extend(
            _validate_interface(
                f"network.interfaces.{name}", iface, str(managed_by or "")
            )
        )
    return errors


def _validate_interface(key: str, iface: Any, managed_by: str) -> list[str]:
    error = mapping_error(key, iface)
    if error or not iface:
        return [error] if error else []

    errors = []
    for family in iface:
        if family not in ("ipv4", "ipv6"):
            errors.append(f"{key}.{family}: unknown key")
    errors.extend(_validate_family(f"{key}.ipv4", iface.get("ipv4"), 4))
    errors.extend(_validate_family(f"{key}.ipv6", iface.get("ipv6"), 6))

    ipv6 = iface.get("ipv6") or {}
    if managed_by == "file" and ipv6.get("method") == "static":
        errors.append(
            f"{key}.ipv6: static addresses cannot be written to"
            " /etc/network/interfaces by this version; use"
            " network.managed_by: host and set the address on the host"
        )
    return errors


def _validate_family(key: str, family: Any, version: int) -> list[str]:
    error = mapping_error(key, family)
    if error or not family:
        return [error] if error else []

    methods = IPV4_METHODS if version == 4 else IPV6_METHODS
    errors = []
    for name in family:
        if name not in ("method", "address", "gateway"):
            errors.append(f"{key}.{name}: unknown key")

    method = family.get("method")
    if method is None or str(method) not in methods:
        errors.append(f"{key}.method: must be one of {methods}")
    if str(method) == "static" and "address" not in family:
        errors.append(f"{key}.address: required when method is static")

    if "address" in family:
        errors.extend(_address_errors(key, str(family["address"]), version))
    if "gateway" in family:
        errors.extend(_gateway_errors(key, str(family["gateway"]), version))
    return errors


def _address_errors(key: str, address: str, version: int) -> list[str]:
    if "/" not in address:
        return [f"{key}.address: prefix length is required ({address})"]
    try:
        value = ipaddress.ip_interface(address)
    except ValueError as e:
        return [f"{key}.address: {e}"]
    if value.version != version:
        return [f"{key}.address: not an IPv{version} address ({address})"]
    if version == 6 and not is_unicast(value.ip):
        return [
            f"{key}.address: must be a unicast address, not link local,"
            f" loopback or multicast ({address})"
        ]
    return []


def _gateway_errors(key: str, gateway: str, version: int) -> list[str]:
    try:
        value = ipaddress.ip_address(gateway)
    except ValueError as e:
        return [f"{key}.gateway: {e}"]
    if value.version != version:
        return [f"{key}.gateway: not an IPv{version} address ({gateway})"]
    return []
