# Copyright (c) 2026 KeelLinux maintainers
"""The sockets a node listens on, and the unit of each (decision 0097)

Rule B (the maintainer's answer of 2026-11-23) looks at the process, not
at the port: at an apply a person runs, a node in report goes to enforce
only when each socket on an address that is not a loopback belongs to a
unit of the resolved manifest. `ss -Hlnptu` lists the sockets and their
processes; the cgroup of each process names its unit.

What counts as known without a unit of the manifests:

- the ports sshd listens on, whatever holds them (an active ssh.socket
  is held by systemd itself, init.scope);
- the ports of the spec's firewall.allow, which the administrator
  declared;
- the overlay's own UDP port, a socket of the kernel with no process;
- the DHCP client (UDP 68, and 546 on IPv6), which the ruleset always
  lets in;
- the init fence's ports (`fence`) while its unit is enabled: the
  ruleset accepts them for redirected packets only, and the fence is the
  first boot's own page (decision 0097, section 2, item 4);
- the listener of a pending mesh invite (`keel-mesh-invite@ID.service`,
  decision 0048), whose port the set `mesh_invites` opens until it
  expires.

A socket bound to the loopback, or to the overlay's interface, is not
public. A socket ss shows with no process is unknown: the node stays in
report and the socket is named, never guessed.
"""

import ipaddress
import re
import subprocess
from dataclasses import dataclass, replace

from keel.inspect.tree import Tree

SS = ("ss", "-H", "-l", "-n", "-p", "-t", "-u")
LOOPBACK_DEVICE = "lo"
ANY = "*"
DHCP_CLIENT = frozenset({(68, "udp"), (546, "udp")})
NO_PROCESS = "no process ss could read"
LOCAL_RE = re.compile(
    r"^(?:\[(?P<v6>[^\]]+)\]|(?P<addr>[^\s\[\]%]+?))"
    r"(?:%(?P<dev>[^\s:]+))?:(?P<port>\d+|\*)$")
USER_RE = re.compile(r'\("(?P<name>[^"]*)",pid=(?P<pid>\d+)')
UNIT_SUFFIXES = (".service", ".scope", ".socket")
INVITE_UNIT = "keel-mesh-invite@"

Port = tuple[int, str]


@dataclass(frozen=True)
class Listener:
    protocol: str
    address: str
    device: str | None
    port: int
    pids: tuple[int, ...]
    names: tuple[str, ...] = ()
    units: tuple[str, ...] = ()

    def with_units(self, units: tuple[str, ...]) -> "Listener":
        return replace(self, units=units)

    def describe(self) -> str:
        address = f"[{self.address}]" if ":" in self.address \
            else self.address
        if self.device:
            address += f"%{self.device}"
        owner = ", ".join(sorted(set(self.units))) or NO_PROCESS
        names = (f" ({', '.join(sorted(set(self.names)))})"
                 if self.names else "")
        return f"{self.protocol} {address}:{self.port} of {owner}{names}"


EXPOSED = ("enforce opens this port on {iface} only, and a client outside"
           " the mesh would be cut")


@dataclass(frozen=True)
class Classified:
    # sockets that keep the node in report: of no unit of the manifests,
    # or on a mesh port on an address outside the overlay
    undeclared: tuple[Listener, ...]
    # sockets of a declared unit on a port the ruleset does not open:
    # enforce closes them, which is information
    closed: tuple[Listener, ...]
    reasons: tuple[tuple[Listener, str], ...] = ()

    @property
    def clean(self) -> bool:
        return not self.undeclared

    def why(self, item: Listener) -> str:
        return dict(self.reasons).get(item, "")

    def named(self) -> list[str]:
        """Each socket that keeps report, with why where it is not the
        plain lack of a unit"""
        return [item.describe() + (f": {self.why(item)}"
                                   if self.why(item) else "")
                for item in self.undeclared]


def parse_ss(text: str) -> tuple[Listener, ...]:
    """Each line of `ss -Hlnptu`; a line it cannot read is an error"""
    found = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ("tcp", "udp"):
            raise ValueError(f"cannot read the ss line {line.strip()!r}")
        local = LOCAL_RE.match(fields[4])
        if local is None:
            raise ValueError(f"cannot read the ss line {line.strip()!r}")
        if local.group("port") == ANY:
            continue
        users = USER_RE.findall(" ".join(fields[6:]))
        found.append(Listener(
            fields[0], local.group("v6") or local.group("addr"),
            local.group("dev"), int(local.group("port")),
            tuple(int(pid) for _, pid in users),
            tuple(name for name, _ in users)))
    return tuple(found)


def unit_of(cgroup: str) -> str | None:
    """The unit a process runs in, from /proc/PID/cgroup"""
    for line in cgroup.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3 or parts[1] not in ("", "name=systemd"):
            continue
        last = parts[2].rstrip("/").rsplit("/", 1)[-1]
        if last.endswith(UNIT_SUFFIXES):
            return last
    return None


def loopback(listener: Listener) -> bool:
    if listener.device == LOOPBACK_DEVICE:
        return True
    if listener.address == ANY:
        return False
    try:
        address = ipaddress.ip_address(listener.address)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return address.is_loopback or bool(mapped and mapped.is_loopback)


def declared_units(resolved, states: dict) -> frozenset[str]:
    """The units of the processes whose overlay is enabled"""
    return frozenset(owned.item["unit"] for owned in resolved.processes
                     if owned.overlay is None
                     or states.get(owned.overlay) == "enabled")


def belongs(unit: str, units: frozenset[str]) -> bool:
    """`postgresql.service` holds `postgresql@17-main.service`: a
    declared NAME.service covers each instance NAME@X.service"""
    if unit in units:
        return True
    if "@" in unit:
        return unit.split("@", 1)[0] + ".service" in units
    return False


def classify(listeners: tuple[Listener, ...], units: frozenset[str], *,
             ssh: tuple[int, ...], allow: frozenset[Port],
             opened: frozenset[Port],
             overlay: tuple[str, int] | None,
             fence: tuple[int, ...] = (),
             mesh: frozenset[Port] = frozenset(),
             overlay_addresses: frozenset[str] = frozenset()) -> Classified:
    """`opened` the ports the ruleset opens; `overlay` the WireGuard
    interface and UDP port, None without an overlay; `fence` the init
    fence's ports while its unit is enabled; `mesh` the manifests' mesh
    ports and `overlay_addresses` this node's overlay addresses and VIP:
    a mesh port on another address serves someone the ruleset cuts
    (decision 0097, section 7), so it keeps report too"""
    undeclared, closed, reasons = [], [], []
    iface = overlay[0] if overlay else wireguard_default()
    for item in listeners:
        if loopback(item) or (overlay and item.device == overlay[0]):
            continue
        port = (item.port, item.protocol)
        if known(item, ssh, allow, overlay) or fenced(item, fence):
            continue
        if port in mesh and not on_overlay(item, overlay_addresses):
            undeclared.append(item)
            reasons.append((item, EXPOSED.format(iface=iface)))
        elif not any(belongs(unit, units) for unit in item.units):
            undeclared.append(item)
        elif port not in opened:
            closed.append(item)
    return Classified(tuple(undeclared), tuple(closed), tuple(reasons))


FENCE_UNIT = "turnkey-init-fence.service"
SSH_UNITS = ("ssh.service", "ssh.socket")
SSHD_NAMES = ("sshd",)


def fenced(item: Listener, fence: tuple[int, ...]) -> bool:
    """A socket of the init fence's own unit on one of its ports"""
    return (item.protocol == "tcp" and item.port in fence
            and bool(item.units)
            and all(unit == FENCE_UNIT for unit in item.units))


def sshd_ports(listeners: tuple[Listener, ...] | None) -> tuple[int, ...]:
    """The TCP ports a running sshd listens on now, on an address that is
    not a loopback: its units (ssh.service, ssh.socket, sshd@...), or a
    process named sshd. What `sshd -T` cannot see: SSHD_OPTS="-p N" of
    /etc/default/ssh, or a Port edited and sshd not restarted"""
    found = set()
    for item in listeners or ():
        if item.protocol != "tcp" or loopback(item):
            continue
        if any(unit in SSH_UNITS or unit.startswith("sshd@")
               for unit in item.units) or any(
                name in SSHD_NAMES for name in item.names):
            found.add(item.port)
    return tuple(sorted(found))


def wireguard_default() -> str:
    from keel.network import wireguard
    return wireguard.DEFAULT_INTERFACE


def on_overlay(item: Listener, addresses: frozenset[str]) -> bool:
    """Bound to an overlay address or the VIP, which only wg0 reaches
    under enforce"""
    try:
        address = ipaddress.ip_address(item.address)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    return str(address) in addresses or (
        mapped is not None and str(mapped) in addresses)


def known(item: Listener, ssh: tuple[int, ...], allow: frozenset[Port],
          overlay: tuple[str, int] | None) -> bool:
    port = (item.port, item.protocol)
    if item.protocol == "tcp" and item.port in ssh:
        return True
    if port in allow or port in DHCP_CLIENT:
        return True
    if item.units and all(unit.startswith(INVITE_UNIT)
                          for unit in item.units):
        return True
    return bool(overlay and not item.pids
                and port == (overlay[1], "udp"))


def unopened(listeners: tuple[Listener, ...], opened: frozenset[Port],
             overlay_device: str | None,
             mesh: frozenset[Port] = frozenset(),
             overlay_addresses: frozenset[str] = frozenset()
             ) -> tuple[Listener, ...]:
    """Sockets on an address that is not a loopback whose port the
    ruleset does not open, or a mesh port on an address outside the
    overlay: what enforce would close (keel diff)"""
    def closes(item: Listener) -> bool:
        port = (item.port, item.protocol)
        if port in DHCP_CLIENT:
            return False
        if port in mesh and not on_overlay(item, overlay_addresses):
            return True
        return port not in opened
    return tuple(item for item in listeners
                 if not loopback(item)
                 and not (overlay_device and item.device == overlay_device)
                 and closes(item))


def observe_listeners(tree: Tree, live: bool, run=None
                      ) -> tuple[tuple[Listener, ...] | None, str]:
    """The sockets and their units, and the source; None and why when
    they cannot be listed"""
    if not live:
        return None, "not the live system: no socket is seen"
    run = run or subprocess.run
    try:
        out = run(list(SS), capture_output=True, text=True, check=False)
    except OSError as e:
        return None, f"ss cannot run: {e.strerror}"
    if out.returncode != 0:
        return None, f"ss failed: {(out.stderr or '').strip()}"
    try:
        found = parse_ss(out.stdout)
    except ValueError as e:
        return None, str(e)
    return tuple(item.with_units(units_of(tree, item.pids))
                 for item in found), "ss"


def units_of(tree: Tree, pids: tuple[int, ...]) -> tuple[str, ...]:
    """The unit of each process that still runs; one gone is left out"""
    units = []
    for pid in pids:
        cgroup = tree.read(f"proc/{pid}/cgroup")
        unit = unit_of(cgroup.text or "") if cgroup.readable else None
        if unit:
            units.append(unit)
    return tuple(units)
