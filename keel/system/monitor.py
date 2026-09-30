# Copyright (c) 2026 KeelLinux maintainers
"""Plan the monitor section: monit's file and notify's (decision 0021)

`enabled: true` writes two files, both mode 0600:

- /etc/monit/conf.d/keel.conf, the checks, at the cycle monit already
  runs at, which is read and never set; on the live system monit's
  configuration is then checked and monit reloaded, only when the file
  changed;
- /etc/keel/monitor.json, all keel notify reads: the channels resolved
  from the spec, token files by path. notify never reads the spec.

Off, stated or by the section being absent, removes both when keel wrote
them and leaves any other file alone; and a keel.conf keel did not write
is never overwritten either.

What it never does:

- install monit. Without the package on the live system the step is
  refused, with the command that installs it;
- act on an alert. Every test runs keel notify, which tells the operator
  what to do; nothing grows a disk, restarts a service or kills a
  process.
"""

from keel.inspect.monitor import KEEL_HEADER
from keel.inspect.tree import File
from keel.monitor import channelfile
from keel.monitor.mounts import Mount, real_filesystems
from keel.monitor.render import render
from keel.monitor.settings import effective, too_long
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
SETTINGS = channelfile.PATH.lstrip("/")
MODE = 0o600
# keel notify as monit runs it: -B, so not even bytecode is written, and
# no spec path, since notify reads only the settings apply wrote
NOTIFY = ("/usr/bin/python3", "-B", "-m", "keel", "notify")
ROOT_ONLY = Mount("/", "", "")


def plan_monitor(monitor: dict | None, doc: dict,
                 state: MonitorState | None, live: bool,
                 available: frozenset[str]) -> list[Step]:
    if state is None:
        return []
    if monitor is None:
        return not_declared(state)
    if not monitor.get("enabled"):
        return off(monitor, state, live, available)
    if state.current.readable and not written_by_keel(state.current):
        return [Step(FIELD, (Refuse(
            f"/{MONIT_CONF} is there and keel did not write it: it is not"
            " overwritten; move it away, or rename it, and apply again"),))]
    if live and "monit" not in available:
        return [Step(FIELD, (Refuse(
            "monit is not installed, and keel installs no package: install"
            " it (apt install monit) and run apply again"),))]
    checks = effective(monitor or {})
    cycle = state.cycle
    longer = too_long(checks, cycle.seconds)
    if longer:
        return [Step(FIELD, (Refuse(
            "; ".join(longer) + f" ({cycle.source}); shorten the duration,"
            " or the cycle"),))]
    mounts, notes = filesystems(state.mountinfo)
    notes += [Note(f"{problem}: that channel fails until it is fixed")
              for problem in state.secret_problems]
    content = render(checks, mounts, NOTIFY, cycle.seconds)
    settings = channelfile.render(doc)
    summary = (f"{watched(mounts, checks)}; monit's cycle is"
               f" {cycle.seconds} s ({cycle.source})")
    actions: list[Action] = list(notes)
    if state.settings.text != settings or state.settings_problem:
        reason = (f" ({state.settings_problem}, which keel notify refuses)"
                  if state.settings.text == settings else "")
        # an existing file keeps its owner through a rewrite, so on the
        # live system the owner is set too, or a chown behind apply stays
        actions.append(WriteFile(
            SETTINGS, settings, MODE, "root" if live else None,
            f"write /{SETTINGS}: the channels keel notify uses{reason}"))
    if state.current.text != content:
        actions.append(WriteFile(MONIT_CONF, content, MODE, None,
                                 f"write /{MONIT_CONF}: {summary}"))
        actions += reload(live, available)
    if all(isinstance(action, Note) for action in actions):
        actions.append(Note(f"unchanged (/{MONIT_CONF}, {summary})"))
    return [Step(FIELD, tuple(actions))]


def not_declared(state: MonitorState) -> list[Step]:
    """No `monitor` section: not managed by this spec, so nothing moves

    Every other section reads absent as "leave it", and a spec that only
    declares the network must not end the alerting another spec turned
    on: a monitor that stops in silence is what decision 0021 is against.
    Only `enabled: false` turns it off.
    """
    if not (written_by_keel(state.current)
            or channelfile.written_by_keel(state.settings.text)):
        return []
    return [Step(FIELD, (Note(
        "not declared: the monitor keel set up earlier is left as it is;"
        " `monitor.enabled: false` turns it off"),))]


def off(monitor: dict, state: MonitorState, live: bool,
        available: frozenset[str]) -> list[Step]:
    """`enabled: false`, or not true: keel's files go, anybody else's stay"""
    actions: list[Action] = []
    if channelfile.written_by_keel(state.settings.text):
        actions.append(RemoveFile(SETTINGS, f"remove /{SETTINGS}, which"
                                  " keel wrote: the monitor is off"))
    if written_by_keel(state.current):
        actions.append(RemoveFile(MONIT_CONF, f"remove /{MONIT_CONF},"
                                  " which keel wrote: the monitor is off"
                                  " in the spec"))
        actions += reload(live, available)
    if actions:
        return [Step(FIELD, tuple(actions))]
    return [Step(FIELD, (Note("unchanged (off)"),))]


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
    notes = [Note(f"{path} not watched: monit cannot take its name as a"
                  " path") for path in unsafe]
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
