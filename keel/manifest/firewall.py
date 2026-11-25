# Copyright (c) 2026 KeelLinux maintainers
"""The firewall, derived from the manifests' exposure classes; pure

Decision 0097: written in every mode (simple, cloud simple, cloud
advanced and the etcd witness), in one of two states. `enforce` has the
drop policy below. `report` has the same rules, a policy accept, no
drop but the two of the access interface (decision 0098, below), and
one counter as its last rule: what reaches it is what enforce would
drop. The ports sshd listens on (`ssh`), the spec's
`firewall.allow` and, while the init fence runs, its ports for
redirected packets only (`ct status dnat`) are opened too.

docs/manifest-v1.md, "What is derived, and how": every `listen` with
`expose: public` of a process whose overlay is enabled (and every one of
the appliance's own processes) is opened on every interface, every
`expose: mesh` one on the WireGuard interface only, and the overlay's
own UDP port on the uplink. `loopback` opens nothing. With an overlay,
a named set holds the TCP ports of the pending mesh invites (decision
0048), each with a timeout, and one rule accepts them. This replaces
`WEBMIN_FW_TCP_INCOMING` of the recipes (0041, 6).

Decision 0098 adds the access network, where the spec declares
`network.access`: its UDP port on every interface, and on its interface
(`keel-access`) only the `expose: access` ports of the manifests, the
ports sshd listens on and the database relays, each to the node's access
address only; what comes to that address on another interface is
dropped. Those rules come right
after the ones that are always let in, and a drop of everything else
from that interface follows them, before the public ports: an access
peer reaches no public port, no port of firewall.allow, no mesh port,
and no mesh address or VIP through the node. A forward chain drops what
comes in on that interface, so a node with ip_forward on is no router
for an access peer either (0098, section 4, item 5). Both drops are in
report too: the interface is new, so nothing that worked before stops.
With `ssh_ipv6_only` (answer 6, B), the sshd ports open on IPv6 and on
the access interface only; the plan decides it (keel.system.firewall).

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
import ipaddress
import re
from dataclasses import dataclass

from keel.manifest.resolve import Resolved
from keel.network import wireguard as wg
from keel.spec.validate_firewall import (  # noqa: F401  (callers' names)
    ENFORCE,
    OFF,
    REPORT,
    STATES,
)

# where apply writes the ruleset; keel-firewall.service loads it at boot
PATH = "etc/keel/firewall/keel-manifest.nft"
TABLE = ("inet", "keel")
HEADER = (
    "#!/usr/sbin/nft -f\n"
    "# written by keel spec apply --system from the appliance manifests\n"
    "# (handbook decision 0041): the public and mesh ports of every\n"
    "# process whose overlay is enabled; a change made here is overwritten"
)
POLICY = {ENFORCE: "drop", REPORT: "accept"}
POLICY_RE = re.compile(r"hook input priority filter; policy (drop|accept);")
REPORT_COUNTER = "keel-report: enforce would drop these"
INVALID = "ct state invalid drop"
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
# the TCP ports of the pending mesh invites (decision 0048): keel mesh
# invite adds its port with a timeout, so it closes by itself
INVITES_SET = "mesh_invites"
MEMBERS_PORT = 51821
INVITES_SET_TEXT = (
    f"\tset {INVITES_SET} {{\n\t\ttype inet_service\n"
    "\t\tflags timeout\n\t}\n")
# What a host serves the guests on its bridges (lxcbr0, docker0, a
# Proxmox vmbr): lxc-net's and libvirt's dnsmasq answer DNS, DHCPv4 and
# DHCPv6 there, and a drop policy would make every guest lose its lease.
# Router advertisements are ICMPv6, which ALWAYS lets in.
BRIDGE_SERVICES = ((53, "tcp"), (53, "udp"), (67, "udp"), (547, "udp"))

Port = tuple[int, str]
ACCESS = "access"
SSH_LINE = "# ssh: IPv6 and the access interface only (decision 0098)"


@dataclass(frozen=True)
class Access:
    """network.access as the ruleset needs it: the interface, its UDP
    port, the node's address on it, and the TCP ports of its database
    relays"""

    iface: str
    port: int
    address: str
    relays: tuple[int, ...] = ()


@dataclass(frozen=True)
class Allow:
    """One item of the spec's firewall.allow: open everywhere, or only
    from `sources`, IPv4 and IPv6 prefixes"""

    port: int
    protocol: str
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class Ruleset:
    text: str
    public: tuple[Port, ...]
    mesh: tuple[Port, ...]
    notes: tuple[str, ...]
    digest: str
    state: str = ENFORCE
    ssh: tuple[int, ...] = ()
    # the init fence's ports, accepted for redirected packets only
    fence: tuple[int, ...] = ()
    # what the access interface opens (decision 0098), and its name
    access: tuple[Port, ...] = ()
    access_iface: str | None = None
    ssh_ipv6_only: bool = False


def render(resolved: Resolved, states: dict, wireguard: dict | None,
           bridges: tuple[str, ...] = (), *, state: str = ENFORCE,
           ssh: tuple[int, ...] = (), allow: tuple[Allow, ...] = (),
           fence: tuple[int, ...] = (), access: Access | None = None,
           ssh_ipv6_only: bool = False) -> Ruleset:
    """`states` are the spec's overlays, `wireguard` its
    network.overlay.wireguard, None when it declares none, and `bridges`
    the machine's bridge interfaces, whose guests get their leases and
    names from the host (BRIDGE_SERVICES). `state` is enforce or report,
    `ssh` the ports sshd listens on, `allow` the spec's firewall.allow,
    `fence` the ports of the init fence while it runs, `access` the
    spec's network.access, None when it declares none, and
    `ssh_ipv6_only` answer 6, B of decision 0098"""
    if state not in POLICY:
        raise ValueError(f"a ruleset is enforce or report, not {state}")
    declared, mesh = exposed(resolved, states)
    sshd = {(port, "tcp") for port in ssh}
    public: set[Port] = declared | sshd
    if ssh_ipv6_only:
        public -= sshd
    notes = []
    wanted = access_exposed(resolved, states)
    opened_access: set[Port] = set()
    if access is not None:
        public.add((access.port, "udp"))
        opened_access = wanted | sshd | {(port, "tcp")
                                         for port in access.relays}
    elif wanted:
        notes.append(f"{', '.join(_named(sorted(wanted)))} not opened: they"
                     " are access ports, and the spec declares no"
                     " network.access (keel access invite makes it,"
                     " decision 0098)")
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
    always = [rule for rule in ALWAYS
              if state == ENFORCE or rule != INVALID]
    rules = always + _access_rules(access, sorted(opened_access))
    if ssh_ipv6_only and ssh:
        rules += _rules("meta nfproto ipv6 ", sorted(sshd))
    rules += _rules("", sorted(public))
    rules += _allowed(allow)
    if fence:
        rules += _rules("ct status dnat ", [(port, "tcp")
                                            for port in sorted(fence)])
    sets = ""
    if iface:
        rules += _rules(f'iifname "{iface}" ', opened_mesh)
        # keel mesh sync and the announcement of a new node, between
        # members, on the overlay alone (keel.mesh.members)
        rules.append(f'iifname "{iface}" tcp dport {MEMBERS_PORT} accept')
        rules.append(f"tcp dport @{INVITES_SET} accept")
        sets = INVITES_SET_TEXT
    if access is not None:
        sets += _forward(access.iface)
    if bridges:
        rules += _rules(_iifname(sorted(set(bridges))) + " ",
                        list(BRIDGE_SERVICES))
    if state == REPORT:
        rules.append(f'counter comment "{REPORT_COUNTER}"')
    body = "".join(f"\t\t{rule}\n" for rule in rules)
    policy = POLICY[state]
    digest = hashlib.sha256((sets + policy + body).encode()).hexdigest()[
        :DIGEST_LENGTH]
    family, name = TABLE
    text = (
        f"{HEADER}\n"
        f"# state: {state}\n"
        + (f"{SSH_LINE}\n" if ssh_ipv6_only else "") +
        f"table {family} {name}\n"
        f"delete table {family} {name}\n"
        f"table {family} {name} {{\n"
        f'\tcomment "{COMMENT} {digest}"\n'
        f"{sets}"
        "\tchain input {\n"
        "\t\ttype filter hook input priority filter; policy"
        f" {policy};\n"
        f"{body}"
        "\t}\n"
        "}\n"
    )
    return Ruleset(text, tuple(sorted(public)), tuple(opened_mesh),
                   tuple(notes), digest, state, tuple(sorted(set(ssh))),
                   tuple(sorted(set(fence))), tuple(sorted(opened_access)),
                   access.iface if access else None, ssh_ipv6_only)


def _access_rules(access: Access | None, ports: list[Port]) -> list[str]:
    """The access interface's ports on the node's access address only,
    then a drop of the rest from it, and a drop of what comes to the
    access address on another interface: a peer that widens its own
    AllowedIPs reaches no port on the mesh address or a VIP, and the
    relays on the access address answer nobody outside the tunnel"""
    if access is None:
        return []
    iface = f'iifname "{access.iface}"'
    daddr = f"ip6 daddr {access.address}"
    return _rules(f"{iface} {daddr} ", ports) + [
        f"{iface} drop", f'iifname != "{access.iface}" {daddr} drop']


def _forward(iface: str) -> str:
    """A node is no router for an access peer (0098, 4.5); policy accept,
    so nothing else that is forwarded changes"""
    return ("\tchain forward {\n"
            "\t\ttype filter hook forward priority filter; policy accept;\n"
            f'\t\tiifname "{iface}" drop\n'
            "\t}\n")


def access_exposed(resolved: Resolved, states: dict) -> set[Port]:
    """The `expose: access` ports of every process whose overlay is
    enabled (decision 0098)"""
    found: set[Port] = set()
    for owned in resolved.processes:
        if owned.overlay is not None and states.get(owned.overlay) != ENABLED:
            continue
        for listen in owned.item.get("listen") or []:
            if listen["expose"] == ACCESS:
                found.add((listen["port"], listen["protocol"]))
    return found


def file_ssh_ipv6_only(text: str | None) -> bool:
    """Whether a file keel wrote narrows SSH to IPv6 (answer 6, B)"""
    return bool(text) and text.startswith(HEADER) and \
        f"\n{SSH_LINE}\n" in text


def exposed(resolved: Resolved, states: dict
            ) -> tuple[set[Port], dict[str, set[Port]]]:
    """The public ports, and the mesh ports by process, of every process
    whose overlay is enabled"""
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
    return public, mesh


def _allowed(allow: tuple[Allow, ...]) -> list[str]:
    """The administrator's ports: everywhere, or one rule per family"""
    rules = []
    for item in allow:
        match = f"{item.protocol} dport {item.port} accept"
        if not item.sources:
            rules.append(match)
            continue
        networks = [ipaddress.ip_network(source, strict=False)
                    for source in item.sources]
        for family, version in (("ip", 4), ("ip6", 6)):
            found = sorted({str(net) for net in networks
                            if net.version == version})
            if found:
                rules.append(f"{family} saddr {_one_or_set(found)} {match}")
    return rules


def _one_or_set(items: list[str]) -> str:
    return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"


def keel_owns(text: str | None) -> bool:
    """Whether a file at keel's path is keel's to write again: empty,
    cut inside keel's header, or carrying keel's header (a power loss
    before the data reached the disk, or a cut copy). Only a non-empty
    file with no mark of keel's is foreign"""
    if text is None:
        return True
    return (not text.strip() or text.startswith(HEADER)
            or HEADER.startswith(text))


def file_state(text: str | None) -> str | None:
    """enforce or report, by the policy of a file keel wrote; None for no
    file or another's. A file of keel 0.23.97 and before has no state
    line, and its drop policy reads as enforce."""
    if not text or not text.startswith(HEADER):
        return None
    found = POLICY_RE.search(text)
    if found is None:
        return None
    return ENFORCE if found.group(1) == "drop" else REPORT


def _iifname(names: list[str]) -> str:
    if len(names) == 1:
        return f'iifname "{names[0]}"'
    return "iifname { " + ", ".join(f'"{name}"' for name in names) + " }"


def _named(ports: list[Port]) -> list[str]:
    return [f"{port}/{protocol}" for port, protocol in ports]


def _rules(prefix: str, ports: list[Port]) -> list[str]:
    """One rule per protocol, a set when there are several ports"""
    rules = []
    for protocol in ("tcp", "udp"):
        numbers = [str(port) for port, proto in ports if proto == protocol]
        if not numbers:
            continue
        match = _one_or_set(numbers)
        rules.append(f"{prefix}{protocol} dport {match} accept")
    return rules


CHAIN_HEAD = "\tchain input {\n"
TYPE_RE = re.compile(r"\t\ttype filter hook input priority filter;"
                     r" policy (drop|accept);\n")
TAIL = "\t}\n}\n"


def digest_of(text: str) -> str | None:
    """The digest of the rules a file of keel's really holds, computed
    as render() computes it, to compare with the one in its comment; a
    file of keel 0.23.97 (no state line) has the digest of its sets and
    rules alone. None for a file of another shape."""
    found = COMMENT_RE.search(text or "")
    if found is None or CHAIN_HEAD not in text:
        return None
    sets = text[text.index("\n", found.end()) + 1:text.index(CHAIN_HEAD)]
    head = TYPE_RE.search(text, text.index(CHAIN_HEAD))
    if head is None or not text.endswith(TAIL):
        return None
    body = text[head.end():-len(TAIL)]
    policy = head.group(1) if "\n# state: " in text else ""
    return hashlib.sha256((sets + policy + body).encode()).hexdigest()[
        :DIGEST_LENGTH]


def loaded_digest(listing: str) -> str | None:
    """The digest in `nft list table inet keel`, or None"""
    found = COMMENT_RE.search(listing)
    return found.group(1) if found else None
