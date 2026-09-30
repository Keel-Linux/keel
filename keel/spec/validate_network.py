# Copyright (c) 2026 KeelLinux maintainers
"""Validation of the network section

IPv6 is the primary family: an interface may declare IPv6 only, and IPv4
is optional everywhere.
"""

import ipaddress
from typing import Any

from keel.spec.constants import IPV4_METHODS, IPV6_METHODS, MANAGED_BY
from keel.spec.fields import is_unicast, list_error, mapping_error
from keel.spec.validate_overlay import validate_overlay

FAMILY_KEYS = ("method", "address", "gateway")


def validate_network(network: Any, check_secret_files: bool = True) -> (
    list[str]
):
    error = mapping_error("network", network)
    if error or not network:
        return [error] if error else []

    errors = []
    for key in network:
        if key not in ("managed_by", "interfaces", "nameservers", "overlay"):
            errors.append(f"network.{key}: unknown key")
    uplinks = network.get("interfaces")
    errors.extend(validate_overlay(
        network.get("overlay"),
        tuple(str(name) for name in uplinks)
        if isinstance(uplinks, dict) else (),
        check_secret_files,
    ))

    managed_by = network.get("managed_by")
    if managed_by is not None and str(managed_by) not in MANAGED_BY:
        errors.append(f"network.managed_by: must be one of {MANAGED_BY}")

    nameservers = network.get("nameservers")
    error = list_error("network.nameservers", nameservers)
    if error:
        errors.append(error)
        nameservers = []
    for server in nameservers or []:
        try:
            ipaddress.ip_address(str(server))
        except ValueError:
            errors.append(f"network.nameservers: {server} is not an address")

    interfaces = network.get("interfaces")
    error = mapping_error("network.interfaces", interfaces)
    if error:
        return errors + [error]
    for name, iface in (interfaces or {}).items():
        errors.extend(_validate_interface(f"network.interfaces.{name}", iface))
    return errors


def _validate_interface(key: str, iface: Any) -> list[str]:
    error = mapping_error(key, iface)
    if error or not iface:
        return [error] if error else []

    errors = []
    for family in iface:
        if family not in ("ipv4", "ipv6"):
            errors.append(f"{key}.{family}: unknown key")
    errors.extend(_validate_family(f"{key}.ipv4", iface.get("ipv4"), 4))
    errors.extend(_validate_family(f"{key}.ipv6", iface.get("ipv6"), 6))
    return errors


def _validate_family(key: str, family: Any, version: int) -> list[str]:
    error = mapping_error(key, family)
    if error or not family:
        return [error] if error else []

    methods = IPV4_METHODS if version == 4 else IPV6_METHODS
    known = FAMILY_KEYS + (("slaac",) if version == 6 else ())
    errors = []
    for name in family:
        if name not in known:
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
    if version == 6 and "slaac" in family:
        errors.extend(_slaac_errors(key, family["slaac"], str(method)))
    return errors


def _slaac_errors(key: str, slaac: Any, method: str) -> list[str]:
    """SLAAC beside a static address; the other methods decide it already"""
    if not isinstance(slaac, bool):
        return [f"{key}.slaac: must be true or false"]
    if method != "static":
        return [f"{key}.slaac: only valid when method is static"]
    return []


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
