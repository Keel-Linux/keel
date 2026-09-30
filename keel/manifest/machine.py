# Copyright (c) 2026 KeelLinux maintainers
"""What a manifest names that must exist on the machine (rules 5 and 12)

Looked up under a root, the live system or a tree a package build or a
test made, never outside it: every path reaching here has passed the
normalisation check of rule 4 first, so none climbs out with `..`.
"""

import os
import stat

from keel.manifest.constants import INIT_DIR, UNIT_DIRS, UNIT_SUFFIX

ROOT_UID = 0


def under(root: str, path: str) -> str:
    return os.path.join(root, path.lstrip("/"))


def unit_problem(root: str, unit: str) -> str | None:
    """A unit file in one of systemd's directories, or an init script

    UNIT has the shape of a systemd unit name (no "/"), checked by the
    caller. The init script systemd's sysv generator would read must be a
    regular executable file that resolves inside the root, not a symbolic
    link to something outside it.
    """
    for directory in UNIT_DIRS:
        for name in unit_files(unit):
            if os.path.exists(under(root, f"{directory}/{name}")):
                return None
    script = under(root, f"{INIT_DIR}/{unit[:-len(UNIT_SUFFIX)]}")
    if _executable_inside(root, script):
        return None
    return f"{unit} has no unit file under {root}"


def unit_files(unit: str) -> tuple[str, ...]:
    """The files that define UNIT: its own, and for an instance
    (`getty@tty1.service`) its template (`getty@.service`), which is how
    instances ship"""
    prefix, at, rest = unit.partition("@")
    instance, dot, suffix = rest.rpartition(".")
    if at and instance:
        return unit, f"{prefix}@{dot}{suffix}"
    return (unit,)


def _executable_inside(root: str, path: str) -> bool:
    real, top = os.path.realpath(path), os.path.realpath(root)
    if os.path.commonpath([real, top]) != top:
        return False
    try:
        info = os.stat(real)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111)


def hook_problems(root: str, path: str) -> list[str]:
    """Exists, executable, owned by root, not writable by group or others"""
    try:
        info = os.stat(under(root, path))
    except FileNotFoundError:
        return [f"{path} does not exist under {root}"]
    except OSError as e:
        return [f"{path} cannot be read under {root}: {e.strerror}"]
    problems = []
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        problems.append(f"{path} is not executable")
    if info.st_uid != ROOT_UID:
        problems.append(f"{path} is not owned by root")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        problems.append(f"{path} is writable by group or others")
    return problems
