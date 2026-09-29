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
- `for N cycles` counts in the cycle monit already runs at. keel does
  not set it: `set daemon` is global, and one in this file would reset
  the operator's cycle and start delay for every check on the machine.
  The duration the spec declared is kept in a comment above each test,
  so that `keel inspect` can give it back while the cycles agree with it.

Nothing here acts: every action is `exec` of keel notify, which tells.
"""

import re

from keel.monitor.mounts import Mount
from keel.monitor.settings import (
    bytes_per_second,
    cycles,
    number,
    reminder,
)

HEADER = (
    "# written by keel spec apply --system from the monitor section of the"
    " instance spec\n"
    "# (handbook decision 0021); a change made here is overwritten"
)
MINUTES_COMMENT = "# for_minutes:"
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


class Writer:
    """The file's blocks, at one cycle and with one notify command"""

    def __init__(self, notify: tuple[str, ...], cycle: int):
        self.prefix = " ".join(notify)
        self.cycle = cycle

    def command(self, level: str, check: str, threshold: str = "",
                about: tuple[str, ...] = ()) -> str:
        words = [self.prefix, "--level", level, "--check", check, *about]
        if threshold:
            words += ["--threshold", threshold]
        return " ".join(words)

    def test(self, test: str, fail: str, recover: str,
             for_minutes: int | None = None) -> list[str]:
        """One test with its exec, reminder and recovery, and its minutes"""
        lines = []
        held = ""
        if for_minutes is not None:
            lines.append(f"{INDENT}{MINUTES_COMMENT} {for_minutes}")
            hold = cycles(for_minutes, self.cycle)
            held = f" for {hold} cycles" if hold > 1 else ""
        return lines + [
            f"{INDENT}if {test}{held} then exec \"{fail}\"",
            f"{INDENT}{INDENT}repeat every {reminder(self.cycle)} cycles",
            f"{INDENT}else if succeeded then exec \"{recover}\"",
        ]


def block(head: str, lines: list[str]) -> str:
    return "".join(f"{line}\n" for line in [head, *lines])


def render(checks: dict, mounts: list[Mount], notify: tuple[str, ...],
           cycle: int) -> str:
    """The whole file, from effective checks (keel.monitor.settings)

    `notify` is the argv prefix of keel notify; the level, the check and
    what it is about are added per test, never a secret or a URL.
    `cycle` is monit's, in seconds, which `for N cycles` counts in.
    """
    writer = Writer(notify, cycle)
    blocks = [f"{HEADER}\n"]
    names = filesystem_names(mounts)
    for mount in mounts:
        blocks += filesystem_blocks(checks, mount, names[mount.path], writer)
    for name, test, service in SYSTEM:
        check = checks[name]
        limit = number(check["warn"])
        notify_check = NOTIFY_CHECK.get(name, name)
        blocks.append(block(f"check system {service}", writer.test(
            test.format(warn=limit),
            writer.command("warn", notify_check, limit),
            writer.command("recovery", notify_check, limit),
            check["for_minutes"],
        )))
    for iface, check in checks["network"].items():
        blocks.append(network_block(iface, check, writer))
    return "\n".join(blocks)


def filesystem_blocks(checks: dict, mount: Mount, name: str,
                      writer: Writer) -> list[str]:
    about = ("--path", mount.path)
    tests = [
        ("disk", "warn", "space", checks["disk"]["warn"]),
        ("disk", "critical", "space", checks["disk"]["critical"]),
        ("inodes", "critical", "inode", checks["inodes"]["critical"]),
    ]
    return [
        block(f"check filesystem keel_{check}_{level}_{name} with path"
              f" {mount.path}", writer.test(
                  f"{measure} usage > {number(threshold)}%",
                  writer.command(level, check, number(threshold), about),
                  writer.command("recovery", check, number(threshold),
                                 about),
              ))
        for check, level, measure, threshold in tests
    ]


def network_block(iface: str, check: dict, writer: Writer) -> str:
    """Link and throughput of one declared interface, in one service

    Link, upload and download are three events in monit, so one service
    holds them without one test's recovery answering for another, and
    keel notify is told which direction it is about, recovery included.
    """
    lines = []
    minutes = check["for_minutes"]
    if check.get("link"):
        about = ("--iface", iface)
        lines += writer.test(
            "failed link",
            writer.command("critical", "link", "", about),
            writer.command("recovery", "link", "", about), minutes)
    if "max_mbit" in check:
        limit = number(check["max_mbit"])
        rate = bytes_per_second(check["max_mbit"])
        for direction in ("upload", "download"):
            about = ("--iface", iface, "--direction", direction)
            lines += writer.test(
                f"{direction} > {rate} B/s",
                writer.command("warn", "throughput", limit, about),
                writer.command("recovery", "throughput", limit, about),
                minutes)
    return block(f"check network keel_network_{slug(iface)} with interface"
                 f" {iface}", lines)
