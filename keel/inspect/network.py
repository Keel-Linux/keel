# Copyright (c) 2026 KeelLinux maintainers
"""The network section, IPv6 first, from ifupdown files and resolv.conf"""

import ipaddress

from keel.inspect.interfaces import Stanza, parse_interfaces
from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File

FAMILIES = {"inet6": "ipv6", "inet": "ipv4"}
METHODS = {
    "ipv6": ("static", "dhcp", "auto", "manual"),
    "ipv4": ("static", "dhcp", "manual"),
}
LOOPBACK = "lo"


def probe_network(
    interfaces: list[File], resolv: File, in_container: bool
) -> tuple[dict | None, list[Finding]]:
    """Build the network section

    `interfaces` is /etc/network/interfaces followed by the files it
    sources from interfaces.d. `in_container` is the LXC marker: a
    container's addresses belong to the host; anywhere else the stanzas,
    static IPv6 included, are what the 01ipconfig hook writes from the
    spec, so the file owns them.
    """
    findings: list[Finding] = []
    declared, nameservers = _interfaces(interfaces, findings)
    nameservers += _resolvers(resolv, findings)

    network: dict = {}
    if declared:
        network["managed_by"] = "host" if in_container else "file"
        findings.append(inferred(
            "network.managed_by", network["managed_by"],
            _managed_reason(in_container),
        ))
        network["interfaces"] = declared
    if nameservers:
        ordered = sorted(
            dict.fromkeys(nameservers),
            key=lambda server: ipaddress.ip_address(server).version != 6,
        )
        network["nameservers"] = ordered
        findings.append(inferred(
            "network.nameservers", ", ".join(ordered), resolv.path
        ))
    return (network or None), findings


def _managed_reason(in_container: bool) -> str:
    if in_container:
        return "LXC marker present, the host owns the interfaces"
    return "no LXC marker, the interfaces file owns the addresses"


def _interfaces(
    files: list[File], findings: list[Finding]
) -> tuple[dict, list[str]]:
    readable = [file for file in files if file.readable]
    if not readable:
        main = files[0]
        findings.append(
            missing("network.interfaces", f"{main.path} {main.problem}")
        )
        return {}, []

    declared: dict = {}
    nameservers: list[str] = []
    for file in readable:
        stanzas, problems = parse_interfaces(file.text or "")
        for header in problems:
            findings.append(missing(
                "network.interfaces",
                f"{file.path}: malformed line {header!r}",
            ))
        for stanza in stanzas:
            if stanza.iface == LOOPBACK or stanza.family not in FAMILIES:
                continue
            family = FAMILIES[stanza.family]
            field = f"network.interfaces.{stanza.iface}.{family}"
            section, finding = _family(field, family, stanza, file.path)
            findings.append(finding)
            if section is not None:
                declared.setdefault(stanza.iface, {})[family] = section
            nameservers += stanza.values("dns-nameservers")
    if not declared:
        findings.append(missing(
            "network.interfaces",
            f"{readable[0].path} has no interface stanza besides lo",
        ))
    return declared, nameservers


def _family(
    field: str, family: str, stanza: Stanza, path: str
) -> tuple[dict | None, Finding]:
    if stanza.method not in METHODS[family]:
        return None, missing(
            field, f"method {stanza.method} in {path} has no spec equivalent"
        )
    section: dict = {"method": stanza.method}
    summary = stanza.method
    if stanza.method == "static":
        address, problem = _address(stanza, family)
        if problem:
            return None, missing(field, f"{problem} in {path}")
        section["address"] = address
        summary += f" {address}"
    gateway = stanza.option("gateway")
    if gateway:
        section["gateway"] = gateway
        summary += f" gateway {gateway}"
    return section, inferred(field, summary, path)


def _address(stanza: Stanza, family: str) -> tuple[str | None, str | None]:
    address = stanza.option("address")
    if not address:
        return None, "static stanza without an address"
    netmask = stanza.option("netmask")
    if "/" not in address and netmask:
        address = f"{address}/{netmask}"
    if "/" not in address:
        return None, f"address {address} has no prefix length or netmask"
    try:
        value = ipaddress.ip_interface(address)
    except ValueError:
        return None, f"address {address} is not valid"
    if value.version != (6 if family == "ipv6" else 4):
        return None, f"address {address} is not an {family} address"
    return str(value), None


def _resolvers(resolv: File, findings: list[Finding]) -> list[str]:
    if not resolv.readable:
        findings.append(
            missing("network.nameservers", f"{resolv.path} {resolv.problem}")
        )
        return []
    found = []
    for line in resolv.lines():
        fields = line.split()
        if fields[0] != "nameserver" or len(fields) < 2:
            continue
        try:
            server = ipaddress.ip_address(fields[1])
        except ValueError:
            continue
        if server.is_loopback:
            findings.append(missing(
                "network.nameservers",
                f"{resolv.path} points at a local resolver ({server}), the"
                " upstream servers are not visible",
            ))
            continue
        found.append(str(server))
    return found
