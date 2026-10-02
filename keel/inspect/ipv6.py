# Copyright (c) 2026 KeelLinux maintainers
"""Tell SLAAC from DHCPv6, which the interfaces file cannot say

ifupdown has one method for both: `iface eth0 inet6 dhcp` is what the
01ipconfig hook writes for `method: auto` and for `method: dhcp` alike,
so the file alone cannot say which of the two a spec declared. The
running machine can, and these are the two traces it leaves:

- a SLAAC address is formed from a router advertisement, and the kernel
  marks it `mngtmpaddr` in `ip -6 addr`, because it manages the
  temporary addresses of a prefix it learned that way;
- a DHCPv6 address comes from a lease, and the client writes the lease
  down: dhcpcd in /var/lib/dhcpcd/<iface>.lease6, dhclient in
  /var/lib/dhcp/dhclient6*.leases.

A lease is positive evidence of a DHCPv6 exchange and wins. A router
advertisement address with no lease is `auto`. Neither is not inferred,
never a guess: guessing is what made a SLAAC container report `dhcp`
against a spec that declared `auto`.
"""

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass

from keel.inspect.tree import File

AUTO = "auto"
# The ifupdown method that is ambiguous, and the spec method it may mean.
DHCP = "dhcp"
SLAAC_FLAG = "mngtmpaddr"
GLOBAL_SCOPE = "global"
LEASE_SOURCES = "/var/lib/dhcpcd/*.lease6 or /var/lib/dhcp/dhclient6*.leases"
GENERIC_LEASE = "dhclient6"
GENERIC_LEASE_PARTS = 2
IFACE_RE = re.compile(r"^\d+:\s+([^:@\s]+)(?:@\S+)?:")


@dataclass(frozen=True)
class Address:
    """One `inet6` line of `ip -6 addr`: the address, its scope, its flags"""

    iface: str
    address: str
    scope: str
    flags: tuple[str, ...]

    @property
    def from_router_advertisement(self) -> bool:
        return self.scope == GLOBAL_SCOPE and SLAAC_FLAG in self.flags


@dataclass(frozen=True)
class Runtime:
    """The evidence only a running machine has, gathered by the collector

    `output` is `ip -6 addr show`, or why it could not be run (an offline
    root, no `ip` command); `leases` is every DHCPv6 lease file found
    under the root, which an offline root does carry. `links` are the
    interfaces the live machine has (/sys/class/net), or None where that
    is not known, an offline root.
    """

    output: File
    leases: tuple[File, ...] = ()
    links: frozenset[str] | None = None

    @property
    def addresses(self) -> tuple[Address, ...]:
        return parse_addresses(self.output)


def parse_addresses(output: File) -> tuple[Address, ...]:
    """Every inet6 address in `ip -6 addr` output, with the interface it is on

    A line before the first interface header belongs to no interface and
    is skipped, as is an `inet6` line with no address after it.
    """
    found: list[Address] = []
    iface: str | None = None
    for line in output.lines():
        header = IFACE_RE.match(line)
        if header:
            iface = header.group(1)
            continue
        fields = line.split()
        if iface is None or len(fields) < 2 or fields[0] != "inet6":
            continue
        found.append(_address(iface, fields))
    return tuple(found)


def _address(iface: str, fields: list[str]) -> Address:
    """`inet6 ADDR/LEN scope SCOPE FLAG...`; anything else has no scope"""
    if "scope" not in fields:
        return Address(iface, fields[1], "", ())
    index = fields.index("scope") + 1
    scope = fields[index] if index < len(fields) else ""
    return Address(iface, fields[1], scope, tuple(fields[index + 1:]))


def lease_of(iface: str, leases: Sequence[File]) -> File | None:
    """The DHCPv6 lease file that covers `iface`, when one holds anything

    dhcpcd and dhclient both name the interface in the file name
    (`eth0.lease6`, `dhclient6.eth0.leases`); a plain `dhclient6.leases`
    names none and covers whichever interface is asked about. An empty
    lease file is no evidence at all.
    """
    for file in leases:
        parts = os.path.basename(file.path).split(".")
        generic = (
            GENERIC_LEASE in parts and len(parts) == GENERIC_LEASE_PARTS
        )
        if (file.text or "").strip() and (iface in parts or generic):
            return file
    return None


def resolve_method(iface: str, runtime: Runtime) -> tuple[str | None, str]:
    """`auto` or `dhcp` for an `inet6 dhcp` stanza, and where that came from

    Returns (None, reason) when the machine says neither, so the caller
    reports the field as not inferred instead of picking one.
    """
    lease = lease_of(iface, runtime.leases)
    slaac = [
        address for address in runtime.addresses
        if address.iface == iface and address.from_router_advertisement
    ]
    if lease is not None:
        also = (
            " (a router advertisement address is configured as well)"
            if slaac else ""
        )
        return DHCP, f"{lease.path} holds a DHCPv6 lease{also}"
    if slaac:
        return AUTO, (
            f"{runtime.output.path}: {slaac[0].address} on {iface} is"
            f" marked {SLAAC_FLAG}, formed from a router advertisement"
        )
    return None, _no_evidence(iface, runtime)


def _no_evidence(iface: str, runtime: Runtime) -> str:
    output = runtime.output
    state = output.problem or f"lists no {SLAAC_FLAG} address for {iface}"
    return (
        f"inet6 dhcp is written for method auto and for method dhcp alike;"
        f" {output.path} {state}, and no DHCPv6 lease for {iface} was found"
        f" in {LEASE_SOURCES}"
    )
