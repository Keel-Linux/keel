# Copyright (c) 2026 KeelLinux maintainers
"""What the firewall plan looks at, read once from the root (0041)

keel's ruleset file as it was last written, the digest in the comment of
the `inet keel` table the kernel holds (asked of nft on the live system
only), the ports sshd listens on, which the ruleset must open, the
machine's bridge interfaces, whose guests the host serves DHCP and DNS,
and whether a network change waits for its confirmation (decision 0018).

The SSH ports are never guessed. On the live system `sshd -T`, sshd's
own reading of its configuration, is the source, and an active
`ssh.socket` adds the ports it listens on for socket activation. Where
`sshd -T` cannot answer, and under --root, the files are read the way
sshd reads them (`Port 22`, `Port=22`, `ListenAddress [::1]:22 rdomain
x`); a file that sets no port is sshd's documented default, 22, but a
file that cannot be read, or an Include of anything but the drop-in
directory, leaves the ports unknown, and the plan refuses.
"""

import re
import subprocess
from dataclasses import dataclass

from keel.inspect.tree import File, Tree
from keel.manifest.firewall import PATH, TABLE, loaded_digest
from keel.network import marker

SSHD_CONFIG = "etc/ssh/sshd_config"
SSHD_DROP_INS = "etc/ssh/sshd_config.d/*.conf"
DROP_IN_INCLUDE = "/etc/ssh/sshd_config.d/*.conf"
SSH_DEFAULT = 22
BRIDGES = "sys/class/net/*/bridge"
ROUTE4 = "proc/net/route"
ROUTE6 = "proc/net/ipv6_route"
ZERO4 = "00000000"
ZERO6 = "0" * 32
SSHD_T = ("sshd", "-T")
SOCKET = ("systemctl", "show", "ssh.socket", "-p", "ActiveState", "-p",
          "Listen")
# keyword and value are separated by whitespace or `=` (sshd_config(5))
PORT_RE = re.compile(r"^\s*port[\s=]+(\d+)\s*$", re.IGNORECASE)
LISTEN_RE = re.compile(
    r"^\s*listenaddress[\s=]+(?:\[[^]]*\]|[^\s:\[\]]+):(\d+)"
    r"(?:\s+rdomain\s+\S+)?\s*$", re.IGNORECASE)
INCLUDE_RE = re.compile(r"^\s*include[\s=]+(.+?)\s*$", re.IGNORECASE)
STREAM_RE = re.compile(r"(\S+) \(Stream\)")


@dataclass(frozen=True)
class FirewallState:
    file: File
    # the digest of the table the kernel holds; None when there is none,
    # or when nothing was asked (--root)
    loaded: str | None
    # empty when they cannot be determined; ssh_source then says why
    ssh_ports: tuple[int, ...]
    ssh_source: str
    pending: bool
    bridges: tuple[str, ...] = ()


def ports_in(lines: list[str]) -> set[int]:
    found = set()
    for line in lines:
        match = PORT_RE.match(line) or LISTEN_RE.match(line)
        if match:
            found.add(int(match.group(1)))
    return found


def ports_from_files(tree: Tree) -> tuple[tuple[int, ...], str]:
    main = tree.read(SSHD_CONFIG)
    if not main.readable:
        return (), f"{main.path} {main.problem}"
    for line in main.lines():
        include = INCLUDE_RE.match(line)
        if include and include.group(1) != DROP_IN_INCLUDE:
            return (), (f"{main.path} says Include {include.group(1)},"
                        " which keel does not follow")
    lines = main.lines()
    for name in tree.glob(SSHD_DROP_INS):
        lines += tree.read(name).lines()
    ports = ports_in(lines)
    if not ports:
        return (SSH_DEFAULT,), (f"{main.path} sets no Port: sshd's default"
                                f" {SSH_DEFAULT}")
    return tuple(sorted(ports)), main.path


def ssh_ports(tree: Tree, live: bool,
              run=None) -> tuple[tuple[int, ...], str]:
    """The ports sshd listens on and where they were read; () and why
    when they cannot be determined"""
    if not live:
        return ports_from_files(tree)
    run = run or subprocess.run
    ports: set[int] = set()
    sources = []
    daemon = ask(run, SSHD_T)
    if daemon is not None and ports_in(daemon.splitlines()):
        ports |= ports_in(daemon.splitlines())
        sources.append("sshd -T")
    else:
        found, source = ports_from_files(tree)
        if not found:
            return (), f"sshd -T did not answer, and {source}"
        ports |= set(found)
        sources.append(source)
    socket = ask(run, SOCKET) or ""
    if "ActiveState=active" in socket.splitlines():
        listened = {int(address.rsplit(":", 1)[-1])
                    for address in STREAM_RE.findall(socket)
                    if address.rsplit(":", 1)[-1].isdigit()}
        if listened:
            ports |= listened
            sources.append("ssh.socket")
    return tuple(sorted(ports)), ", ".join(sources)


def ask(run, argv: tuple[str, ...]) -> str | None:
    try:
        out = run(list(argv), capture_output=True, text=True, check=False)
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None


def observe_firewall(tree: Tree, live: bool) -> FirewallState:
    ports, source = ssh_ports(tree, live)
    return FirewallState(
        file=tree.read(PATH),
        loaded=table_digest() if live else None,
        ssh_ports=ports,
        ssh_source=source,
        pending=tree.exists(marker.PENDING),
        bridges=bridges_of(tree),
    )


def bridges_of(tree: Tree) -> tuple[str, ...]:
    """The bridges whose guests the host serves DHCP and DNS

    Only a bridge that cannot carry the uplink: every port enslaved to
    it a veth or a tap, and no default route through it, which is what
    lxc-net's lxcbr0, libvirt's virbr0 and docker0 are. A Proxmox vmbr0
    or a br0 with a physical port, a VLAN or a bond enslaved, or with the
    default route, is the uplink, and opening 53, 67 and 547 there would
    open them to the internet.
    """
    defaults = default_route_devices(tree)
    found = []
    for path in tree.glob(BRIDGES):
        name = path.split("/")[-2]
        ports = [port.split("/")[-1]
                 for port in tree.glob(f"sys/class/net/{name}/brif/*")]
        if name not in defaults and all(guest_port(tree, port)
                                        for port in ports):
            found.append(name)
    return tuple(sorted(found))


def guest_port(tree: Tree, port: str) -> bool:
    """A tap (tun_flags), or a veth: no device behind it and no DEVTYPE
    (a VLAN, a bond, WireGuard and the others each say theirs)"""
    base = f"sys/class/net/{port}"
    if tree.exists(f"{base}/device"):
        return False
    if tree.exists(f"{base}/tun_flags"):
        return True
    uevent = tree.read(f"{base}/uevent")
    return uevent.readable and not any(
        line.startswith("DEVTYPE=") for line in uevent.lines())


def default_route_devices(tree: Tree) -> set[str]:
    """The interfaces a default route goes through, IPv4 and IPv6"""
    devices = set()
    for line in tree.read(ROUTE4).lines()[1:]:
        fields = line.split()
        if len(fields) > 7 and fields[1] == ZERO4 and fields[7] == ZERO4:
            devices.add(fields[0])
    for line in tree.read(ROUTE6).lines():
        fields = line.split()
        if len(fields) == 10 and fields[0] == ZERO6 and fields[1] == "00":
            devices.add(fields[9])
    return devices


def table_digest() -> str | None:
    try:
        out = subprocess.run(["nft", "list", "table", *TABLE],
                             capture_output=True, text=True, check=False)
    except OSError:
        return None
    return loaded_digest(out.stdout) if out.returncode == 0 else None
