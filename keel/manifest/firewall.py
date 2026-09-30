# Copyright (c) 2026 KeelLinux maintainers
"""The firewall, derived from the manifests' exposure classes; pure

docs/manifest-v1.md, "What is derived, and how": every `listen` with
`expose: public` of a process whose overlay is enabled (and every one of
the appliance's own processes) is opened on every interface, every
`expose: mesh` one on the WireGuard interface only, and the overlay's
own UDP port on the uplink. `loopback` opens nothing. This replaces
`WEBMIN_FW_TCP_INCOMING` of the recipes (0041, 6).

nftables, one table of keel's own, `inet keel`, one input chain whose
policy is drop. What a machine needs to stay reachable is always let in,
whatever the manifests say: the loopback, established and related
traffic (so the session that ran apply lives through the change), ICMPv6,
which neighbour discovery and path MTU need, IPv4 echo, and the DHCPv6
and DHCPv4 client replies, without which a lease would lapse. The file
replaces the table in one transaction (`table`, `delete table`, the
table), so a file nft refuses changes nothing. Nothing else is touched:
not iptables, not the tables of CrowdSec's bouncer, not a table of the
operator's.

The table carries a digest of the rest of the file in its comment, so
apply and diff can tell whether the table the kernel holds is the one
the file says, without comparing nft's own listing line by line.
"""

import hashlib
import re
from dataclasses import dataclass

from keel.manifest.resolve import Resolved
from keel.network import wireguard as wg

# where apply writes the ruleset; keel-firewall.service loads it at boot
PATH = "etc/keel/firewall/keel-manifest.nft"
TABLE = ("inet", "keel")
HEADER = (
    "#!/usr/sbin/nft -f\n"
    "# written by keel spec apply --system from the appliance manifests\n"
    "# (handbook decision 0041): the public and mesh ports of every\n"
    "# process whose overlay is enabled; a change made here is overwritten"
)
COMMENT = "keel-manifest"
COMMENT_RE = re.compile(r'comment "keel-manifest ([0-9a-f]+)"')
DIGEST_LENGTH = 16
ALWAYS = (
    'iif "lo" accept',
    "ct state established,related accept",
    "ct state invalid drop",
    "meta l4proto ipv6-icmp accept",
    "icmp type echo-request accept",
    "ip6 saddr fe80::/10 udp dport 546 accept",
    "udp dport 68 accept",
)
ENABLED = "enabled"

Port = tuple[int, str]


@dataclass(frozen=True)
class Ruleset:
    text: str
    public: tuple[Port, ...]
    mesh: tuple[Port, ...]
    notes: tuple[str, ...]
    digest: str


def render(resolved: Resolved, states: dict,
           wireguard: dict | None) -> Ruleset:
    """`states` are the spec's overlays, `wireguard` its
    network.overlay.wireguard, None when it declares none"""
    public: set[Port] = set()
    mesh: dict[str, set[Port]] = {}
    for owned in resolved.processes:
        if owned.overlay is not None and states.get(owned.overlay) != ENABLED:
            continue
        for listen in owned.item.get("listen") or []:
            port = (listen["port"], listen["protocol"])
            if listen["expose"] == "public":
                public.add(port)
            elif listen["expose"] == "mesh":
                mesh.setdefault(owned.item["name"], set()).add(port)
    notes = []
    iface = None
    if wireguard is not None:
        iface = wireguard.get("interface") or wg.DEFAULT_INTERFACE
        public.add((wireguard.get("listen_port") or wg.DEFAULT_PORT, "udp"))
    elif mesh:
        for name, ports in mesh.items():
            notes.append(f"{', '.join(_named(sorted(ports)))} of {name} not"
                         " opened: they are mesh ports, and the spec declares"
                         " no network.overlay.wireguard")
        mesh = {}
    opened_mesh = sorted({port for ports in mesh.values() for port in ports})
    rules = list(ALWAYS) + _rules("", sorted(public))
    if iface:
        rules += _rules(f'iifname "{iface}" ', opened_mesh)
    body = "".join(f"\t\t{rule}\n" for rule in rules)
    digest = hashlib.sha256(body.encode()).hexdigest()[:DIGEST_LENGTH]
    family, name = TABLE
    text = (
        f"{HEADER}\n"
        f"table {family} {name}\n"
        f"delete table {family} {name}\n"
        f"table {family} {name} {{\n"
        f'\tcomment "{COMMENT} {digest}"\n'
        "\tchain input {\n"
        "\t\ttype filter hook input priority filter; policy drop;\n"
        f"{body}"
        "\t}\n"
        "}\n"
    )
    return Ruleset(text, tuple(sorted(public)), tuple(opened_mesh),
                   tuple(notes), digest)


def _named(ports: list[Port]) -> list[str]:
    return [f"{port}/{protocol}" for port, protocol in ports]


def _rules(prefix: str, ports: list[Port]) -> list[str]:
    """One rule per protocol, a set when there are several ports"""
    rules = []
    for protocol in ("tcp", "udp"):
        numbers = [str(port) for port, proto in ports if proto == protocol]
        if not numbers:
            continue
        match = (numbers[0] if len(numbers) == 1
                 else "{ " + ", ".join(numbers) + " }")
        rules.append(f"{prefix}{protocol} dport {match} accept")
    return rules


def loaded_digest(listing: str) -> str | None:
    """The digest in `nft list table inet keel`, or None"""
    found = COMMENT_RE.search(listing)
    return found.group(1) if found else None
