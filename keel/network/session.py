# Copyright (c) 2026 KeelLinux maintainers
"""Where `keel network confirm` is being run from

Read from the process tree, never from the environment: `sudo` resets
SSH_CONNECTION, and a shell that survived a change in tmux still has it.
Walking up from the confirming process:

- an `sshd-session` ancestor (OpenSSH 10's per connection process in
  Debian 13) makes it an SSH session; its start time, in seconds since
  boot, is the session's age, and the socket it holds gives the local
  and the peer address;
- a parent of 0 below the machine's own init is a process attached from
  the host of a container (`pct enter`, `lxc-attach`), which is as good
  as a console;
- otherwise a console terminal on standard input, output or error;
- otherwise nothing that proves anything, and confirm refuses.
"""

import ipaddress
import os
import re
from collections.abc import Callable
from dataclasses import dataclass

SSH_PROCESS = "sshd-session"
# /dev/lxc/: in an LXC container (plain LXC and Proxmox) /dev/tty1 is a
# link to lxc/tty1, so the console the first boot runs on, and a login
# from lxc-console or pct console, hold /dev/lxc/ttyN. Only the host
# reaches those, which is as good as a console, like `pct enter` below.
CONSOLE = re.compile(
    r"^/dev/(tty[0-9]+|ttyS[0-9]+|hvc[0-9]+|console"
    r"|lxc/tty[0-9]+|lxc/console)$"
)
# /proc/PID/stat after the command name: field 3 onwards, so the parent is
# index 1 and the start time (field 22) index 19
PPID_INDEX = 1
STARTTIME_INDEX = 19
SSH = "ssh"
CONSOLE_KIND = "console"
HOST = "host"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Origin:
    kind: str
    detail: str
    started: float | None = None
    local: str | None = None
    peer: str | None = None


@dataclass(frozen=True)
class Process:
    comm: str
    ppid: int
    started: float


def process(proc: str, pid: int) -> Process | None:
    """One process from /proc, or None when it is gone or unreadable"""
    try:
        with open(os.path.join(proc, str(pid), "stat")) as fob:
            stat = fob.read()
        with open(os.path.join(proc, str(pid), "comm")) as fob:
            comm = fob.read().strip()
    except OSError:
        return None
    rest = stat[stat.rindex(")") + 2:].split()
    ticks = os.sysconf("SC_CLK_TCK")
    return Process(comm, int(rest[PPID_INDEX]),
                   int(rest[STARTTIME_INDEX]) / ticks)


def origin(proc: str, pid: int, sockets: Callable[[], str | None]) -> Origin:
    """Classify the session `pid` belongs to; `sockets` is `ss` output"""
    ssh: list[tuple[int, Process]] = []
    attached = False
    current, seen = pid, set()
    while current > 0 and current not in seen:
        seen.add(current)
        found = process(proc, current)
        if found is None:
            break
        if found.comm == SSH_PROCESS:
            ssh.append((current, found))
        if found.ppid == 0 and current != 1:
            attached = True
        current = found.ppid
    if ssh:
        return ssh_origin(ssh, sockets())
    if attached:
        return Origin(HOST, "a process attached from the container's host")
    terminal = console_terminal(proc, pid)
    if terminal:
        return Origin(CONSOLE_KIND, f"the console {terminal}")
    return Origin(UNKNOWN, "neither an SSH session nor a console: a shell"
                  " that survived the change (tmux, screen) or a service"
                  " cannot show that the new network is reachable")


def ssh_origin(chain: list[tuple[int, Process]], sockets: str | None) -> (
    Origin
):
    """The oldest sshd-session of the chain dates the connection"""
    started = min(found.started for _, found in chain)
    pids = {pid for pid, _ in chain}
    for line in (sockets or "").splitlines():
        owners = {int(p) for p in re.findall(r"pid=(\d+)", line)}
        fields = line.split()
        if owners & pids and len(fields) >= 4:
            return Origin(SSH, "an SSH session", started,
                          address(fields[2]), address(fields[3]))
    return Origin(SSH, "an SSH session whose socket was not found", started)


def address(endpoint: str) -> str:
    """`[::ffff:192.0.2.5]:22` or `[fe80::1%eth0]:22` to a plain address"""
    host = endpoint.rsplit(":", 1)[0].strip("[]").split("%")[0]
    value = ipaddress.ip_address(host)
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped:
        value = value.ipv4_mapped
    return str(value)


def console_terminal(proc: str, pid: int) -> str | None:
    for fd in (0, 1, 2):
        try:
            target = os.readlink(os.path.join(proc, str(pid), "fd", str(fd)))
        except OSError:
            continue
        if CONSOLE.match(target):
            return target
    return None
