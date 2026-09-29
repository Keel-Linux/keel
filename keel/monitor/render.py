# Copyright (c) 2026 KeelLinux maintainers
"""Render /etc/monit/conf.d/keel.conf from the monitor section; pure

What monit can express shapes the file (decision 0021):

- one service per test that has a level of its own. Two thresholds in
  one service share monit's one resource event, so a filesystem going
  from critical back to warn would report a recovery it did not make;
  warn and critical are two services, and memory, swap, CPU and load
  are one service each for the same reason;
- `exec` runs once when a test fails, so every alert asks for its
  reminder (`repeat every N cycles`) and its recovery (`else if
  succeeded then exec`) explicitly;
- `set daemon` sets the cycle every `for N cycles` counts in. monit
  reads it wherever it stands, the last one read wins, and Debian's
  monitrc includes conf.d after its own `set daemon 120`, so this file's
  cycle is the one monit uses unless a file included later sets another.

Nothing here acts: every action is `exec` of keel notify, which tells.
"""

import re

from keel.monitor.mounts import Mount
from keel.monitor.settings import (
    CYCLE_SECONDS,
    REMIND_CYCLES,
    bytes_per_second,
    cycles,
    number,
)

HEADER = (
    "# written by keel spec apply --system from the monitor section of the"
    " instance spec\n"
    "# (handbook decision 0021); a change made here is overwritten"
)
INDENT = "    "
SLUG = re.compile(r"[^A-Za-z0-9]+")
# check, the monit test, and the service name, for check system
SYSTEM = (
    ("memory", "memory usage > {warn}%", "keel_memory"),
    ("swap", "swap usage > {warn}%", "keel_swap"),
    ("cpu", "cpu usage > {warn}%", "keel_cpu"),
    ("load_per_core", "loadavg (1min) per core > {warn}", "keel_load"),
)
# the check name keel notify is given, per spec check
NOTIFY_CHECK = {"load_per_core": "load"}


def slug(path: str) -> str:
    """A service name part from a path: / is root, /var/lib is var_lib"""
    return SLUG.sub("_", path).strip("_") or "root"


def filesystem_names(mounts: list[Mount]) -> dict[str, str]:
    """A distinct name part per mount point, in mount order

    /var-lib and /var/lib slug alike; the second one gets a number, so
    two filesystems never share a service name, which monit refuses.
    """
    names: dict[str, str] = {}
    taken: set[str] = set()
    for mount in mounts:
        base = candidate = slug(mount.path)
        count = 1
        while candidate in taken:
            count += 1
            candidate = f"{base}_{count}"
        taken.add(candidate)
        names[mount.path] = candidate
    return names


def render(checks: dict, mounts: list[Mount], notify: tuple[str, ...]) -> str:
    """The whole file, from effective checks (keel.monitor.settings)

    `notify` is the argv prefix of keel notify; the level, the check and
    what it is about are added per test, never a secret.
    """
    command = Exec(notify)
    blocks = [f"{HEADER}\nset daemon {CYCLE_SECONDS}\n"]
    names = filesystem_names(mounts)
    for mount in mounts:
        blocks += filesystem_blocks(checks, mount, names[mount.path],
                                    command)
    for name, test, service in SYSTEM:
        check = checks[name]
        blocks.append(service_block(
            f"check system {service}",
            test.format(warn=number(check["warn"])),
            cycles(check["for_minutes"]),
            command.line("warn", NOTIFY_CHECK.get(name, name),
                         number(check["warn"])),
            command.line("recovery", NOTIFY_CHECK.get(name, name),
                         number(check["warn"])),
        ))
    for iface, check in checks["network"].items():
        blocks.append(network_block(iface, check, command))
    return "\n".join(blocks)


class Exec:
    """The keel notify command line of one test, as monit runs it"""

    def __init__(self, prefix: tuple[str, ...]):
        self.prefix = " ".join(prefix)

    def line(self, level: str, check: str, threshold: str = "",
             about: tuple[str, str] | None = None) -> str:
        words = [self.prefix, "--level", level, "--check", check]
        if about:
            words += list(about)
        if threshold:
            words += ["--threshold", threshold]
        return " ".join(words)


def action(fail: str, recover: str, hold: int = 1) -> list[str]:
    """then exec, its reminder and its recovery, as test continuation"""
    held = f" for {hold} cycles" if hold > 1 else ""
    return [
        f"{held} then exec \"{fail}\"",
        f"{INDENT}{INDENT}repeat every {REMIND_CYCLES} cycles",
        f"{INDENT}else if succeeded then exec \"{recover}\"",
    ]


def service_block(head: str, test: str, hold: int, fail: str,
                  recover: str) -> str:
    first, *rest = action(fail, recover, hold)
    lines = [head, f"{INDENT}if {test}{first}", *rest]
    return "".join(f"{line}\n" for line in lines)


def filesystem_blocks(checks: dict, mount: Mount, name: str,
                      command: Exec) -> list[str]:
    about = ("--path", mount.path)
    found = []
    tests: list[tuple[str, str, str, float]] = [
        ("disk", "warn", "space", checks["disk"]["warn"]),
        ("disk", "critical", "space", checks["disk"]["critical"]),
        ("inodes", "critical", "inode", checks["inodes"]["critical"]),
    ]
    for check, level, measure, threshold in tests:
        limit = number(threshold)
        found.append(service_block(
            f"check filesystem keel_{check}_{level}_{name} with path"
            f" {mount.path}",
            f"{measure} usage > {limit}%",
            1,
            command.line(level, check, limit, about),
            command.line("recovery", check, limit, about),
        ))
    return found


def network_block(iface: str, check: dict, command: Exec) -> str:
    """Link and throughput of one declared interface, in one service

    Link, upload and download are three events in monit, so one service
    holds them without one test's recovery answering for another.
    """
    about = ("--iface", iface)
    hold = cycles(check["for_minutes"])
    lines = [f"check network keel_network_{slug(iface)} with interface"
             f" {iface}"]
    if check.get("link"):
        first, *rest = action(
            command.line("critical", "link", "", about),
            command.line("recovery", "link", "", about), hold)
        lines += [f"{INDENT}if failed link{first}", *rest]
    if "max_mbit" in check:
        limit = number(check["max_mbit"])
        rate = bytes_per_second(check["max_mbit"])
        for direction in ("upload", "download"):
            first, *rest = action(
                command.line("warn", "throughput", limit, about),
                command.line("recovery", "throughput", limit, about),
                hold)
            lines += [f"{INDENT}if {direction} > {rate} B/s{first}", *rest]
    return "".join(f"{line}\n" for line in lines)
