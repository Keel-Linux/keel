# Copyright (c) 2026 KeelLinux maintainers
"""The network section, IPv6 first, from ifupdown files and resolv.conf"""

import ipaddress

from keel.inspect.interfaces import Stanza, parse_interfaces
from keel.inspect.ipv6 import Runtime, resolve_method
from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File

FAMILIES = {"inet6": "ipv6", "inet": "ipv4"}
METHODS = {
    "ipv6": ("static", "dhcp", "auto", "manual"),
    "ipv4": ("static", "dhcp", "manual"),
}
LOOPBACK = "lo"
# The one ifupdown method that does not settle the spec method by itself.
AMBIGUOUS_IPV6 = "dhcp"


def probe_network(
    interfaces: list[File], resolv: File, in_container: bool,
    runtime: Runtime,
) -> tuple[dict | None, list[Finding]]:
    """Build the network section

    `interfaces` is /etc/network/interfaces followed by the files it
    sources from interfaces.d. `in_container` is the LXC marker: a
    container's addresses belong to the host; anywhere else the stanzas,
    static IPv6 included, are what the 01ipconfig hook writes from the
    spec, so the file owns them. `runtime` is the live IPv6 evidence
    (keel.inspect.ipv6), needed because one ifupdown method stands for
    two spec methods.
    """
    findings: list[Finding] = []
    declared, nameservers = _interfaces(interfaces, findings, runtime)
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
    files: list[File], findings: list[Finding], runtime: Runtime
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
            section, finding = _family(
                field, family, stanza, file.path, runtime
            )
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
    field: str, family: str, stanza: Stanza, path: str, runtime: Runtime
) -> tuple[dict | None, Finding]:
    if stanza.method not in METHODS[family]:
        return None, missing(
            field, f"method {stanza.method} in {path} has no spec equivalent"
        )
    method, source = _method(family, stanza, path, runtime)
    if method is None:
        return None, missing(field, source)
    section: dict = {"method": method}
    summary = method
    if method == "static":
        address, problem = _address(stanza, family)
        if problem:
            return None, missing(field, f"{problem} in {path}")
        section["address"] = address
        summary += f" {address}"
    gateway = stanza.option("gateway")
    if gateway:
        section["gateway"] = gateway
        summary += f" gateway {gateway}"
    if family == "ipv6" and method == "static":
        section["slaac"] = slaac_enabled(stanza)
        summary += "" if section["slaac"] else " without SLAAC"
    return section, inferred(field, summary, source)


def slaac_enabled(stanza: Stanza) -> bool:
    """False when the stanza turns autoconf off before it comes up

    The option lib/ipconfig.sh writes for IP6_SLAAC=no (keel#45),
    `pre-up sysctl -q -w net.ipv6.conf.IFACE.autoconf=0`, read by its
    words, so other spacing, other flags or a full path to sysctl still
    count. Without it a static inet6 stanza keeps SLAAC, as ifupdown-ng
    leaves it.
    """
    setting = f"net.ipv6.conf.{stanza.iface}.autoconf=0"
    return not any(
        len(fields) > 2 and fields[0] == "pre-up"
        and fields[1].rsplit("/", 1)[-1] == "sysctl"
        and setting in fields[2:]
        for fields in stanza.options
    )


def _method(
    family: str, stanza: Stanza, path: str, runtime: Runtime
) -> tuple[str | None, str]:
    """The spec method a stanza means, and the source that settles it

    Every ifupdown method is its own spec method except `inet6 dhcp`,
    which the hook writes for `auto` and for `dhcp` alike; that one is
    settled by what the machine did with it, or by nothing at all.
    """
    if family != "ipv6" or stanza.method != AMBIGUOUS_IPV6:
        return stanza.method, path
    return resolve_method(stanza.iface, runtime)


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
