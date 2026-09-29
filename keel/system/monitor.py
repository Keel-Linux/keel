# Copyright (c) 2026 KeelLinux maintainers
"""Plan the monitor section: monit's file, and nothing else (decision 0021)

`enabled: true` renders /etc/monit/conf.d/keel.conf, mode 0600 because a
later step of the decision puts monit's HTTP credentials there, and on
the live system checks monit's configuration and reloads it, only when
the file changed. Off, stated or by the section being absent, removes
the file when keel wrote it and leaves any other alone.

What it never does:

- install monit. Without the package on the live system the step is
  refused, with the command that installs it;
- act on an alert. Every test runs keel notify, which tells the operator
  what to do; nothing grows a disk, restarts a service or kills a
  process.
"""

import re

from keel.inspect.monitor import KEEL_HEADER
from keel.inspect.tree import File
from keel.monitor.mounts import Mount, real_filesystems
from keel.monitor.render import render
from keel.monitor.settings import effective
from keel.system.actions import (
    Action,
    Note,
    Refuse,
    RemoveFile,
    Run,
    Step,
    WriteFile,
)
from keel.system.monstate import MonitorState

FIELD = "monitor"
MONIT_CONF = "etc/monit/conf.d/keel.conf"
MONIT_MODE = 0o600
PYTHON = "/usr/bin/python3"
# what monit's exec line carries unquoted; see keel.monitor.mounts
SAFE_ARG = re.compile(r"^/[A-Za-z0-9_.@+:,=/-]*$")
ROOT_ONLY = Mount("/", "", "")


def notify_argv(spec_path: str) -> tuple[str, ...]:
    """keel notify, as monit runs it: -B, so not even bytecode is written"""
    return (PYTHON, "-B", "-m", "keel", "notify", "--spec", spec_path)


def plan_monitor(monitor: dict | None, state: MonitorState | None,
                 live: bool, available: frozenset[str],
                 spec_path: str) -> list[Step]:
    if state is None:
        return []
    if not (monitor or {}).get("enabled"):
        return off(monitor, state, live, available)
    if not SAFE_ARG.match(spec_path):
        return [Step(FIELD, (Refuse(
            f"the spec path {spec_path} has characters monit's exec line"
            " cannot carry; apply it from a path without spaces or quotes"
        ),))]
    if live and "monit" not in available:
        return [Step(FIELD, (Refuse(
            "monit is not installed, and keel installs no package: install"
            " it (apt install monit) and run apply again"),))]
    mounts, notes = filesystems(state.mountinfo)
    checks = effective(monitor or {})
    content = render(checks, mounts, notify_argv(spec_path))
    summary = watched(mounts, checks)
    if state.current.text == content:
        return [Step(FIELD, (*notes, Note(
            f"unchanged (/{MONIT_CONF}, {summary})")))]
    return [Step(FIELD, (
        *notes,
        WriteFile(MONIT_CONF, content, MONIT_MODE, None,
                  f"write /{MONIT_CONF}: {summary}"),
        *reload(live, available),
    ))]


def off(monitor: dict | None, state: MonitorState, live: bool,
        available: frozenset[str]) -> list[Step]:
    """Absent or `enabled: false`: keel's file goes, anybody else's stays"""
    if not written_by_keel(state.current):
        return [] if monitor is None else [Step(FIELD, (
            Note("unchanged (off)"),))]
    return [Step(FIELD, (
        RemoveFile(MONIT_CONF, f"remove /{MONIT_CONF}, which keel wrote:"
                   " the monitor is off in the spec"),
        *reload(live, available),
    ))]


def written_by_keel(current: File) -> bool:
    return (current.text or "").startswith(KEEL_HEADER)


def filesystems(mountinfo: File) -> tuple[list[Mount], list[Note]]:
    """The mounts to watch, with a note for what could not be

    A tree without a mount table of its own (any --root but the live
    system, usually) is watched at / alone, and the note says so, so the
    next apply on the machine itself writes one check per filesystem.
    """
    if not mountinfo.readable:
        return [ROOT_ONLY], [Note(
            f"no mount table at {mountinfo.path} ({mountinfo.problem}):"
            " watching / only; an apply on the live system watches every"
            " filesystem")]
    mounts, unsafe = real_filesystems(mountinfo.text or "")
    notes = [Note(f"{path} not watched: monit's exec line cannot carry its"
                  " name") for path in unsafe]
    if not mounts:
        return [ROOT_ONLY], notes + [Note(
            f"{mountinfo.path} lists no filesystem that holds data:"
            " watching / only")]
    return mounts, notes


def watched(mounts: list[Mount], checks: dict) -> str:
    paths = ", ".join(mount.path for mount in mounts)
    found = f"{len(mounts)} filesystem(s) ({paths}), memory, swap, cpu, load"
    return "".join([found] + [f", {iface}" for iface in checks["network"]])


def reload(live: bool, available: frozenset[str]) -> list[Action]:
    """monit -t, then a reload of the daemon where it runs

    try-reload-or-restart does nothing to a stopped monit, so an
    operator who stopped it is not overruled. A file monit refuses fails
    the check, and the reload after it is skipped: the running daemon
    keeps the configuration it had.
    """
    if not live:
        return [Note("monit not reloaded: not the live system")]
    if "monit" not in available:
        return [Note("monit not reloaded: monit not found")]
    if "systemctl" not in available:
        return [Note("monit not reloaded: systemctl not found")]
    return [
        Run(("monit", "-t"), "check monit's configuration"),
        Run(("systemctl", "try-reload-or-restart", "monit.service"),
            "reload monit, where it runs"),
    ]
