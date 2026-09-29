# Copyright (c) 2026 KeelLinux maintainers
"""Plan the instance section: renaming a running machine

Upstream 09hostname sets the name once, at first boot, with a sed of the
old name over thirteen files, so on a running machine a declared name
that differs from /etc/hostname was drift nothing could correct
(keel#35). This converges it, more narrowly than the hook: the old name
is replaced only as a whole token or as the first label of a dotted name
(`blog`, `blog.example.org`), never inside another word (`weblog`,
`backup-blog`), and only in the files where the name does something:
/etc/hostname, /etc/hosts, /etc/mailname and postfix's main.cf. The SSH
public key comments and the motd the hook also edits are labels, not
configuration.

The renamed /etc/hosts is handed to the fqdn step (keel.system.hosts),
which plans on it, so the two compose into one final file instead of the
second write bringing the old name back.

The self-signed certificate keeps the name it was made for: making a new
one replaces the key and restarts every web server, which is a decision
for the operator, and the plan says how.
"""

import re
from dataclasses import replace

from keel.inspect.tree import NOT_PRESENT, File
from keel.system.actions import Action, Note, Refuse, Run, Step, WriteFile
from keel.system.state import SystemState

FIELD = "instance.hostname"
HOSTNAME = "etc/hostname"
HOSTS = "etc/hosts"
MAILNAME = "etc/mailname"
POSTFIX_MAIN = "etc/postfix/main.cf"
ETC_MODE = 0o644
# a character that can be part of a name on either side of it
NAME_CHAR = "A-Za-z0-9-"


def plan_hostname(
    instance: dict, state: SystemState
) -> tuple[list[Step], SystemState]:
    """The step, and the state the later steps plan on"""
    declared = instance.get("hostname")
    if declared is None:
        return [], state
    new = str(declared)
    old = current_name(state.hostname)
    if old is not None and old.lower() == new.lower():
        return [Step(FIELD, (Note(f"unchanged ({new})"),))], state

    files = {HOSTS: state.hosts, MAILNAME: state.mailname,
             POSTFIX_MAIN: state.postfix_main}
    blocked = [f for f in (state.hostname, *files.values())
               if f is not None and not f.readable and f.problem != NOT_PRESENT]
    if blocked:
        return [Step(FIELD, tuple(Refuse(
            f"cannot rename: {f.path} {f.problem}, and it may carry the old"
            " name") for f in blocked))], state

    actions: list[Action] = [WriteFile(
        HOSTNAME, f"{new}\n", ETC_MODE, None, f"write /{HOSTNAME} with {new}")]
    rewritten = {}
    if old is not None:
        for path, file in files.items():
            if file is None or not file.readable:
                continue
            text = renamed(file.text or "", old, new)
            if text != (file.text or ""):
                rewritten[path] = text
                actions.append(WriteFile(
                    path, text, ETC_MODE, None,
                    f"write /{path} with {old} renamed {new}"))
    actions += live_actions(new, state, POSTFIX_MAIN in rewritten
                            or MAILNAME in rewritten)
    if old is not None:
        actions.append(Note(
            f"the self-signed certificate still names {old}; on the live"
            " system turnkey-make-ssl-cert --default --force makes one for"
            f" {new} and replaces its key"))

    after = state
    if HOSTS in rewritten:
        after = replace(state, hosts=File(state.hosts.path, rewritten[HOSTS]))
    return [Step(FIELD, tuple(actions))], after


def current_name(hostname: File | None) -> str | None:
    lines = hostname.lines() if hostname is not None else []
    return lines[0].split()[0] if lines else None


def renamed(text: str, old: str, new: str) -> str:
    """`old` as a whole token or a first label becomes `new`; case ignored"""
    pattern = re.compile(
        rf"(?<![{NAME_CHAR}.]){re.escape(old)}(?![{NAME_CHAR}])",
        re.IGNORECASE,
    )
    return pattern.sub(new, text)


def live_actions(new: str, state: SystemState, mail: bool) -> list[Action]:
    """The running kernel name, and postfix when its name changed"""
    if not state.live:
        return [Note("kernel hostname and postfix left alone: not the live"
                     " system")]
    actions: list[Action] = []
    if "hostnamectl" in state.available:
        actions.append(Run(("hostnamectl", "set-hostname", new),
                           f"set the hostname to {new}"))
    elif "hostname" in state.available:
        actions.append(Run(("hostname", new), f"set the hostname to {new}"))
    else:
        actions.append(Note("kernel hostname not set: neither hostnamectl"
                            " nor hostname found"))
    if mail:
        if "systemctl" in state.available:
            actions.append(Run(
                ("systemctl", "try-reload-or-restart", "postfix.service"),
                "reload postfix if it is running"))
        else:
            actions.append(Note("postfix not reloaded: systemctl not found"))
    return actions
