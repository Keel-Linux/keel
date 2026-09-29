# Copyright (c) 2026 KeelLinux maintainers
"""What the network plan looks at, read once from the root

The observed section is what `keel inspect` builds from the same files,
so the plan decides from the comparison `keel diff` makes: a file that
says the same thing in other words is not rewritten, and the interface
is not bounced for a spelling. The new file is rendered here, by
inithooks' library (keel.network.render), because running it is a read.
"""

import os
from dataclasses import dataclass

from keel.diff.compare import not_inferred
from keel.inspect import constants as paths
from keel.inspect.collect import leases, run_command
from keel.inspect.ipv6 import Runtime
from keel.inspect.network import probe_network
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
    if len(interfaces) == 1 and owner == "file":
        iface = str(next(iter(interfaces)))
        rendered = render(
            tree.path(LIBRARY), iface, hostname(tree, doc),
            network_env(completed(network, observed or {}, iface)),
        )
    return NetworkState(observed, unknowns, in_container, owner,
                        os.path.exists(tree.path(marker.PENDING)), rendered,
                        tree.read(paths.INTERFACES).text)


def completed(network: dict, observed: dict, iface: str) -> dict:
    """The declared section, with what it leaves out taken from the machine

    A spec that declares IPv6 only means IPv4 stays as the machine has it
    (decision 0018), but the library renders an absent family as DHCP, as
    01ipconfig does at first boot. So a family the spec does not declare,
    and the nameservers when it declares none, are filled in from what
    inspect read, and the file keeps them.
    """
    declared = dict((network.get("interfaces") or {}).get(iface) or {})
    found = ((observed.get("interfaces") or {}).get(iface)) or {}
    for family in ("ipv4", "ipv6"):
        kept = found.get(family) or {}
        if family not in declared and kept.get("method"):
            declared[family] = kept
    nameservers = network.get("nameservers") or observed.get("nameservers")
    return {"managed_by": "file", "interfaces": {iface: declared},
            "nameservers": nameservers or []}


def hostname(tree: Tree, doc: dict) -> str:
    """The declared name, which the hostname step sets first, or the file's"""
    declared = (doc.get("instance") or {}).get("hostname")
    if declared:
        return str(declared).rstrip(".")
    lines = tree.read(paths.HOSTNAME).lines()
    return lines[0].split()[0] if lines else "localhost"
