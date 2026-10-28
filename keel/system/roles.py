# Copyright (c) 2026 KeelLinux maintainers
"""The role hooks an application ships (0050's amendment, point 7)

After keel flips the pair's role it runs each executable in
/usr/lib/keel/roles.d/ with the argument `primary` or `replica`, in name
order: an application's reaction to the flip. Nextcloud runs
`occ files:scan --all` there; keel itself knows no application.

They run as root, so before anything runs the directory must be root's
and not writable by group or others, and every entry a root-owned
regular file, not writable by group or others, a link staying inside
/usr/lib/keel, and executable; otherwise the entry is not run and the
reason is said. What dpkg leaves behind (.dpkg-old) is not a hook, by
run-parts(8)'s naming rule, the same checks keel.system.hooks makes for
an overlay's state hooks (0041).
"""

import os
import re
import stat
import subprocess
from dataclasses import dataclass

from keel.manifest import machine

BASE = "/usr/lib/keel"
DIR = "/usr/lib/keel/roles.d"
STATES = ("primary", "replica")
TIMEOUT = 120
# what a hook gets: nothing of the caller's environment
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
# run-parts(8)'s rule: what dpkg leaves behind (.dpkg-old) is not a hook
PLAIN = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True)
class RoleHook:
    path: str
    timeout: int


def hooks(root: str) -> tuple[tuple[RoleHook, ...], tuple[str, ...]]:
    """What would run, and why each entry may not run; [] when there is
    no directory (the appliance ships no hook)"""
    found: list[RoleHook] = []
    problems: list[str] = []
    if not os.path.lexists(os.path.join(root, DIR.lstrip("/"))):
        return (), ()
    problems.extend(_unsafe(root, DIR, directory=True))
    if problems:
        # an unsafe directory poisons everything, as an overlay's unsafe
        # state hook directory stops its step (keel.system.hooks)
        return (), tuple(problems)
    full = os.path.join(root, DIR.lstrip("/"))
    if not os.path.isdir(full):
        return (), ()
    for entry in sorted(os.listdir(full)):
        if not PLAIN.fullmatch(entry):
            continue
        path = f"{DIR}/{entry}"
        if os.path.isdir(os.path.join(full, entry)):
            continue
        why = _unsafe(root, path)
        problems.extend(why)
        if why or not _executable(root, path):
            continue
        found.append(RoleHook(path, TIMEOUT))
    return tuple(found), tuple(problems)


def run(root: str, role: str, runner, say) -> list[str]:
    """Every hook with `role`; a failing hook is said with its tail and
    named in the result, so the flip that ran it can fail and be tried
    again. A hook runs as root with a minimal environment, in /, in a
    session of its own."""
    found, problems = hooks(root)
    failed: list[str] = []
    for problem in problems:
        say(problem)
    for hook in found:
        try:
            done = runner(list((hook.path, role)), capture_output=True,
                          text=True, check=False, timeout=hook.timeout,
                          env=dict(ENV), cwd="/", start_new_session=True)
        except subprocess.TimeoutExpired:
            say(f"{hook.path} {role}: stopped after {hook.timeout} s")
            failed.append(hook.path)
            continue
        except OSError as e:
            say(f"{hook.path} {role}: cannot be run: {e.strerror or e}")
            failed.append(hook.path)
            continue
        if done.returncode != 0:
            tail = " ".join((done.stderr or done.stdout or "").split())[-200:]
            say(f"{hook.path} {role}: failed ({done.returncode})"
                + (f": {tail}" if tail else ""))
            failed.append(hook.path)
    return failed


def _under(root: str, path: str) -> str:
    return os.path.join(root, path.lstrip("/"))


def _executable(root: str, path: str) -> bool:
    full = os.path.realpath(_under(root, path))
    return os.path.isfile(full) and os.access(full, os.X_OK)


def _unsafe(root: str, path: str, directory: bool = False) -> list[str]:
    """Why PATH may not be run (or hold what is run), as root would"""
    full = _under(root, path)
    try:
        info = os.lstat(full)
        if stat.S_ISLNK(info.st_mode):
            real = os.path.realpath(full)
            base = os.path.realpath(_under(root, BASE))
            if os.path.commonpath([real, base]) != base:
                shown = "/" + os.path.relpath(real, os.path.realpath(root))
                return [f"{path} is a link to {shown}, outside {BASE}: it"
                        " is not run"]
            info = os.stat(real)
    except OSError as e:
        # a dangling link, or a file gone meanwhile: refused, never a crash
        return [f"{path} cannot be read: {e.strerror}: it is not run"]
    problems = []
    if not directory and not stat.S_ISREG(info.st_mode):
        problems.append(f"{path} is not a regular file: it is not run")
    if info.st_uid != machine.ROOT_UID:
        problems.append(f"{path} is not owned by root: it is not run")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        problems.append(f"{path} is writable by group or others: it is"
                        " not run")
    return problems
