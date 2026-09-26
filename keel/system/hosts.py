# Copyright (c) 2026 KeelLinux maintainers
"""Plan the instance section: the fully qualified name in /etc/hosts

Upstream 09hostname writes /etc/hostname and replaces the old name
wherever it appears, /etc/hosts included, but it never writes a fully
qualified entry. A container that declares `instance.fqdn` therefore
boots with `127.0.1.1 forum2`, `hostname -f` answers `forum2`, and
inspect reports the field as not inferred: the spec declares a name the
machine does not carry.

apply --system writes the entry, and asks the same reader inspect uses
(keel.inspect.hostname.fqdn_in_hosts) whether the name is already there,
so what apply writes is what inspect reads back.

The address is the static IPv6 address the spec declares for an
interface, when it declares one, which is the Debian convention for a
machine with a permanent address; otherwise 127.0.1.1, because an
address a router hands out is a lease and must never be frozen into a
file. Either way the entry is for local resolution: what the appliance
is reachable at is its global address, not this line.
"""

import ipaddress

from keel.inspect.hostname import fqdn_in_hosts
from keel.inspect.tree import File
from keel.system.actions import Note, Step, WriteFile, unchanged
from keel.system.state import SystemState
from keel.system.users import readable_or_absent

HOSTS = "etc/hosts"
HOSTS_MODE = 0o644
LOOPBACK = "127.0.1.1"
FIELD = "instance.fqdn"


def plan_hosts(
    instance: dict, network: dict, state: SystemState
) -> list[Step]:
    """One step, or none when the spec declares no fully qualified name"""
    fqdn = instance.get("fqdn")
    if fqdn is None:
        return []
    fqdn = str(fqdn)
    name = str(instance.get("hostname") or fqdn.split(".")[0])
    hosts = state.hosts
    if not readable_or_absent(hosts):
        return [Step(FIELD, (Note(
            f"cannot plan: {hosts.path} {hosts.problem}"
        ),))]

    names = [fqdn] if name == fqdn else [fqdn, name]
    address = entry_address(network)
    settled = _settled(hosts, fqdn, name, address, set(names))
    if settled is not None:
        return [unchanged(FIELD, settled)]
    entry = " ".join([address, *names])
    actions = [WriteFile(
        HOSTS, with_entry(hosts, address, entry, set(names)), HOSTS_MODE,
        None, f"write /{HOSTS} with {entry!r}",
    )]
    actions += [Note(
        f"kept: {shadow!r} names {name} beside another name and answers"
        f" before the entry, so hostname -f keeps answering {name};"
        f" edit that line by hand"
    ) for shadow in _shadowing(hosts, address, set(names))]
    return [Step(FIELD, tuple(actions))]


def entry_address(network: dict) -> str:
    """The declared static IPv6 address of any interface, else 127.0.1.1

    IPv6 first: a static IPv4 address alone does not put the name on an
    address, because the family the appliance is reached on is IPv6.
    """
    for iface in (network.get("interfaces") or {}).values():
        ipv6 = (iface or {}).get("ipv6") or {}
        address = ipv6.get("address")
        if str(ipv6.get("method")) == "static" and address:
            return str(ipaddress.ip_interface(str(address)).ip)
    return LOOPBACK


def _settled(
    hosts: File, fqdn: str, name: str, address: str, names: set[str]
) -> str | None:
    """Why there is nothing to write, or None when there is

    Either the reader inspect uses already finds the declared name, at
    whatever address the operator chose for it, or the entry this planner
    would write is there already, which is the only way a name with no
    dot in it can be settled.
    """
    found = fqdn_in_hosts(name, hosts)
    if found is not None and found.lower() == fqdn.lower():
        return f"/{HOSTS} maps {name} to {found}"
    for line in hosts.lines():
        fields = line.split()
        if fields[0] == address and names <= set(fields[1:]):
            return f"/{HOSTS} already has {address} {fqdn}"
    return None


def with_entry(
    hosts: File, address: str, entry: str, names: set[str]
) -> str:
    """The file with `entry` in place of the lines it supersedes

    The line 09hostname left behind (`127.0.1.1 forum2`) is replaced where
    it stood, so the entry keeps its position in the file and nothing
    resolves the short name ahead of the fully qualified one, whether or
    not the entry goes at that same address. Every other line, comments
    and blanks included, is kept as it was.
    """
    kept: list[str] = []
    written = False
    for line in (hosts.text or "").splitlines():
        if not _superseded(line, address, names):
            kept.append(line)
            continue
        if not written:
            kept.append(entry)
            written = True
    if not written:
        kept.append(entry)
    return "".join(f"{line}\n" for line in kept)


def _superseded(line: str, address: str, names: set[str]) -> bool:
    """Whether the entry being written stands in for this line

    Two kinds of line are replaced. One at the address being written that
    names the host: that is the entry itself, wherever the operator put it.
    And one that names the host and nothing else without giving it a fully
    qualified name, at any address: that is the `127.0.1.1 blog` line
    09hostname leaves behind. The second has to go, because a name is
    resolved from the first line that carries it, so the short entry would
    answer first and `hostname -f` would keep answering the short name
    although the fully qualified entry is in the file.

    A line that names the host beside another name (`127.0.0.1 localhost
    blog`) is not this phase's to rewrite, and is kept; the plan says so.
    """
    fields = line.split()
    if line.strip().startswith("#") or len(fields) < 2:
        return False
    listed = set(fields[1:])
    if not (names & listed):
        return False
    if fields[0] == address:
        return True
    return listed <= names and not any("." in one for one in listed)


def _shadowing(hosts: File, address: str, names: set[str]) -> list[str]:
    """The kept lines that name the host and would answer before the entry"""
    return [
        line.strip() for line in (hosts.text or "").splitlines()
        if not _superseded(line, address, names)
        and _names_the_host_alone(line, names)
    ]


def _names_the_host_alone(line: str, names: set[str]) -> bool:
    fields = line.split()
    if line.strip().startswith("#") or len(fields) < 2:
        return False
    listed = set(fields[1:])
    return bool(names & listed) and not any("." in one for one in listed)
