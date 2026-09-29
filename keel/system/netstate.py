# Copyright (c) 2026 KeelLinux maintainers
"""What the network plan looks at, read once from the root

The observed section is what `keel inspect` builds from the same files,
so the plan decides from the comparison `keel diff` makes: a file that
says the same thing in other words is not rewritten, and the interface
is not bounced for a spelling. The new file is rendered here, by
inithooks' library (keel.network.render), because running it is a read.
"""

import ipaddress
import os
from dataclasses import dataclass

from keel.diff.compare import not_inferred
from keel.inspect import constants as paths
from keel.inspect.collect import leases, run_command
from keel.inspect.ipv6 import Runtime
from keel.inspect.network import probe_network
from keel.inspect.interfaces import Stanza, parse_interfaces
from keel.inspect.tree import Tree
from keel.network import marker
from keel.network.render import LIBRARY, Rendered, render
from keel.spec.render import network_env


@dataclass(frozen=True)
class NetworkState:
    observed: dict | None
    unknowns: dict[str, str]
    in_container: bool
    owner: str
    pending: bool
    rendered: Rendered | None
    current: str | None = None


def observe_network(root: str, doc: dict) -> NetworkState | None:
    """None when the spec declares no interface: nothing to plan"""
    network = doc.get("network") or {}
    interfaces = network.get("interfaces") or {}
    if not isinstance(interfaces, dict) or not interfaces:
        return None
    tree = Tree(root)
    in_container = tree.exists(paths.LXC_MARKER)
    observed, findings = probe_network(
        [tree.read(paths.INTERFACES)] + tree.read_dir(paths.INTERFACES_D),
        tree.read(paths.RESOLV_CONF),
        in_container,
        Runtime(run_command(tree, paths.IP_ADDR_COMMAND), leases(tree)),
    )
    unknowns = not_inferred(tuple(findings))
    # the declared owner, else what this root says, not the machine keel
    # runs on: keel.spec.runtime.managed_by looks at the live marker
    owner = str(network.get("managed_by")
                or ("host" if in_container else "file"))
    rendered = None
    current = tree.read(paths.INTERFACES).text
    if len(interfaces) == 1 and owner == "file":
        iface = str(next(iter(interfaces)))
        env, problem = rendering_env(network, iface, current or "")
        rendered = Rendered(problem=problem) if problem else render(
            tree.path(LIBRARY), iface, hostname(tree, doc), env)
    return NetworkState(observed, unknowns, in_container, owner,
                        os.path.exists(tree.path(marker.PENDING)), rendered,
                        current)


def rendering_env(network: dict, iface: str, current: str) -> (
    tuple[dict[str, str], str | None]
):
    """The IP_* and IP6_* variables, with what the spec leaves out kept

    A spec that declares IPv6 only means IPv4 stays as the machine has it
    (decision 0018), but the library renders an absent family as DHCP, as
    01ipconfig does at first boot. So a family the spec does not declare
    is taken from the file's own stanza, word for word: its method, and a
    static stanza's address, mask, gateway and nameservers. A file with
    no stanza of that family gets `manual`, which configures nothing, and
    a stanza the library cannot write again is a reason not to converge.
    """
    declared = (network.get("interfaces") or {}).get(iface) or {}
    env = network_env({**network, "managed_by": "file",
                       "interfaces": {iface: declared}})
    stanzas, _ = parse_interfaces(current)
    for family, word in (("ipv4", "inet"), ("ipv6", "inet6")):
        found = [one for one in stanzas
                 if one.iface == iface and one.family == word]
        kept, problem = (({}, None) if family in declared
                         else kept_family(family, found))
        if problem:
            return env, problem
        env.update(kept)
        if not network.get("nameservers") and found:
            dns_prefix = "IP_DNS" if family == "ipv4" else "IP6_DNS"
            servers = found[0].values("dns-nameservers")[:2]
            for index, server in enumerate(servers, start=1):
                env.setdefault(f"{dns_prefix}{index}", server)
    return env, None


def kept_family(family: str, found: list[Stanza]) -> (
    tuple[dict[str, str], str | None]
):
    config = "IP_CONFIG" if family == "ipv4" else "IP6_CONFIG"
    if not found:
        return {config: "manual"}, None
    stanza = found[0]
    if stanza.method in ("dhcp", "manual"):
        return {config: stanza.method}, None
    address = stanza.option("address")
    if stanza.method != "static" or address is None:
        return {}, (f"the file's {stanza.family} stanza ({stanza.method})"
                    f" is not one lib/ipconfig.sh can write again, and the"
                    f" spec does not declare {family}; declare it")
    if family == "ipv6":
        prefix = stanza.option("netmask")
        if "/" not in address and prefix:
            address = f"{address}/{prefix}"
        return {config: "static", "IP6_ADDRESS": address,
                "IP6_GW": stanza.option("gateway") or ""}, None
    try:
        value = ipaddress.ip_interface(
            address if "/" in address
            else f"{address}/{stanza.option('netmask')}")
    except ValueError:
        return {}, (f"the file's inet stanza has no usable address and"
                    f" netmask ({address}), and the spec does not declare"
                    " ipv4; declare it")
    return {config: "static", "IP_ADDRESS": str(value.ip),
            "IP_NETMASK": str(value.netmask),
            "IP_GW": stanza.option("gateway") or ""}, None


def hostname(tree: Tree, doc: dict) -> str:
    """The declared name, which the hostname step sets first, or the file's"""
    declared = (doc.get("instance") or {}).get("hostname")
    if declared:
        return str(declared).rstrip(".")
    lines = tree.read(paths.HOSTNAME).lines()
    return lines[0].split()[0] if lines else "localhost"
