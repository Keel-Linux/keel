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

Decision 0097 adds the sockets the node listens on with the unit of
each (keel.system.listeners, live only), and the ports of the init
fence while its unit is enabled, read from its defaults file.
"""

import re
import subprocess
from dataclasses import dataclass

from keel.inspect.tree import File, Tree
from keel.manifest.firewall import PATH, POLICY_RE, TABLE, loaded_digest
from keel.network import marker
from keel.system import fwrecord
from keel.system.listeners import Listener, observe_listeners, sshd_ports

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
# the state keel last wrote, enforce or report, beside the ruleset file
# and apart from it: an empty or cut file loses its policy line, and the
# state the node was in must survive it (the third real test of 0097)
RECORD = fwrecord.RECORD
FENCE_UNIT = ("etc/systemd/system/multi-user.target.wants/"
              "turnkey-init-fence.service")
FENCE_DEFAULTS = "etc/default/turnkey-init-fence"
FENCE_KEYS = ("HTTP_FENCE_PORT", "HTTPS_FENCE_PORT")


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
    # the sockets with their units; None when they cannot be listed,
    # and listeners_source then says why
    listeners: tuple[Listener, ...] | None = None
    listeners_source: str = ""
    # the init fence's ports while it is enabled; fence_note says why
    # an enabled fence has none
    fence: tuple[int, ...] = ()
    fence_note: str = ""
    # whether keel-firewall-watch.timer runs; None when not asked
    # (--root, or systemctl cannot answer)
    watch: bool | None = None
    # `systemctl is-enabled` of the timer: masked or disabled is the
    # administrator's, and left alone
    watch_enabled: str | None = None
    # said when a running sshd listens on a port its configuration does
    # not name (both are opened)
    ssh_note: str = ""
    # the state keel last wrote (RECORD); None when there is none, or
    # when the record is not trusted, and recorded_warning then says why
    recorded: str | None = None
    recorded_warning: str = ""
    # the sha256 of the ruleset the last apply loaded, from the record
    recorded_digest: str | None = None
    # the policy of the table the kernel holds, drop or accept; None
    # when there is none, or when nothing was asked (--root)
    loaded_policy: str | None = None
    # keel's last good copy of the ruleset (fwrecord.COPY), when trusted
    copy: str | None = None
    # whether keel-firewall.service is failed; None when not asked
    boot_failed: bool | None = None
    # whether keel-firewall-watch.service is failed; None when not asked
    watch_failed: bool | None = None


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
    listeners, listened = observe_listeners(tree, live)
    running = sshd_ports(listeners, sshd_main_pid() if live else None)
    ports, ssh_note = with_running(ports, source, running)
    fence, fence_note = fence_ports(tree)
    recorded, digest, warning = fwrecord.read_full(tree)
    listing = table_listing() if live else None
    found = POLICY_RE.search(listing or "")
    policy = found.group(1) if found else None
    return FirewallState(
        file=tree.read(PATH),
        loaded=loaded_digest(listing) if listing else None,
        ssh_ports=ports,
        ssh_source=source,
        pending=tree.exists(marker.PENDING),
        bridges=bridges_of(tree),
        listeners=listeners,
        listeners_source=listened,
        fence=fence,
        fence_note=fence_note,
        watch=watch_active() if live else None,
        watch_enabled=watch_enabled() if live else None,
        ssh_note=ssh_note,
        recorded=recorded,
        recorded_warning=warning,
        recorded_digest=digest,
        loaded_policy=policy,
        copy=fwrecord.read_copy(tree)[0],
        boot_failed=unit_failed() if live else None,
        watch_failed=unit_failed(WATCH_UNIT) if live else None,
    )


BOOT_UNIT = "keel-firewall.service"
WATCH_UNIT = "keel-firewall-watch.service"


def unit_failed(unit: str = BOOT_UNIT) -> bool | None:
    """Whether a unit of keel's firewall is failed (a boot in the
    fallback, a watch that said a problem)"""
    try:
        out = subprocess.run(["systemctl", "is-failed", "--quiet", unit],
                             capture_output=True, text=True, check=False)
    except OSError:
        return None
    return out.returncode == 0


def recorded_state(tree: Tree) -> str | None:
    """The trusted record, or None (keel.system.fwrecord)"""
    return fwrecord.read(tree)[0]


SSHD_MAIN = ("systemctl", "show", "--value", "-p", "MainPID", "ssh.service")


def sshd_main_pid() -> int | None:
    """ssh.service's MainPID, the listening daemon; None when it does
    not run or systemctl cannot answer"""
    try:
        out = subprocess.run(list(SSHD_MAIN), capture_output=True,
                             text=True, check=False)
    except OSError:
        return None
    value = out.stdout.strip()
    return int(value) if out.returncode == 0 and value.isdigit() \
        and int(value) > 0 else None


def with_running(configured: tuple[int, ...], source: str,
                 running: tuple[int, ...]) -> tuple[tuple[int, ...], str]:
    """The union of the ports sshd is configured for and the ports a
    running sshd listens on now, and what the plan says when they
    differ. Configured ports that cannot be determined stay unknown, and
    the plan refuses as before."""
    if not configured:
        return configured, ""
    extra = [port for port in running if port not in configured]
    if not extra:
        return configured, ""
    named = ", ".join(str(port) for port in extra)
    return (tuple(sorted(set(configured) | set(extra))),
            f"sshd listens now on tcp {named}, which its configuration"
            f" ({source}) does not name: both stay open")


WATCH_TIMER = "keel-firewall-watch.timer"


def watch_enabled() -> str | None:
    """`systemctl is-enabled` of the timer (enabled, disabled, masked,
    ...); None when systemctl cannot be asked"""
    try:
        out = subprocess.run(["systemctl", "is-enabled", WATCH_TIMER],
                             capture_output=True, text=True, check=False)
    except OSError:
        return None
    return out.stdout.strip() or None


def watch_active() -> bool | None:
    """Whether keel-firewall-watch.timer runs; None when systemctl
    cannot be asked"""
    try:
        out = subprocess.run(["systemctl", "is-active", "--quiet",
                              WATCH_TIMER], capture_output=True, text=True,
                             check=False)
    except OSError:
        return None
    return out.returncode == 0


def fence_enabled(tree: Tree) -> bool:
    """Whether the unit of the init fence is enabled: its link in
    multi-user.target.wants, which 97turnkey-init-fence-disable removes
    before it stops the fence"""
    return tree.exists(FENCE_UNIT)


def fence_ports(tree: Tree) -> tuple[tuple[int, ...], str]:
    """The ports turnkey-init-fence redirects to, while it is enabled"""
    if not fence_enabled(tree):
        return (), ""
    defaults = tree.read(FENCE_DEFAULTS)
    values = defaults.assignments() if defaults.readable else {}
    ports = tuple(sorted(int(values[key]) for key in FENCE_KEYS
                         if values.get(key, "").isdigit()))
    if not ports:
        return (), (f"the init fence is enabled, and {defaults.path} names"
                    " no fence port: its page will not answer under"
                    " enforce")
    return ports, ""


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


def table_listing() -> str | None:
    """`nft list table inet keel`, or None when there is none"""
    try:
        out = subprocess.run(["nft", "list", "table", *TABLE],
                             capture_output=True, text=True, check=False)
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None


def table_digest() -> str | None:
    listing = table_listing()
    return loaded_digest(listing) if listing else None
