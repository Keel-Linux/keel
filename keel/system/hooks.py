# Copyright (c) 2026 KeelLinux maintainers
"""An overlay's state hooks (decision 0041, keel#62)

Not every overlay is a unit. Coraza is an Nginx module: its manifest
declares `hooks.state`, /usr/lib/keel/overlays/coraza/state, which links
the module, tests and reloads Nginx and checks the WAF's probe, and rolls
back on failure. Another package may react to an overlay's state with an
executable in /usr/lib/keel/overlays/<name>/state.d/ (Keel Web routes its
default site through Anubis that way). The declared hook runs first, then
the directory's in name order, each with `enabled` or `disabled`, each
within its timeout: the manifest's `hooks.state.timeout` for the declared
hook, 120 seconds for the rest. A `state` file the manifest does not
declare is not run, and the step says so.

They run as root, so before anything runs every hook and its directory
must be root's and not writable by group or others, and a link must stay
inside /usr/lib/keel/overlays; otherwise the step is refused, naming why.

keel runs them on the live system only, when what it recorded in
/var/lib/keel/overlays/<name> after their last run differs from what it
would record now: the spec's state, and a digest of the hooks (each path
and the hash of its content). So a second apply changes nothing, and a
hook installed or upgraded later, keel-web's on a machine already
`enabled`, runs at the next apply. A hook that fails fails its step and
nothing is recorded, so the next apply runs them again.
"""

import hashlib
import os
import re
import stat
from dataclasses import dataclass

from keel.manifest import machine
from keel.manifest.constants import STATE_HOOK, STATE_TIMEOUT_DEFAULT
from keel.system.actions import Action, Note, Run, WriteFile

BASE = "/usr/lib/keel/overlays"
RECORD = "var/lib/keel/overlays/{name}"
RECORD_MODE = 0o644
STATES = ("enabled", "disabled")
# run-parts(8)'s rule: what dpkg leaves behind (.dpkg-old) is not a hook
PLAIN = re.compile(r"[A-Za-z0-9_-]+")
DIGEST = re.compile(r"sha256:([0-9a-f]{64})")


@dataclass(frozen=True)
class Hook:
    path: str
    timeout: int


@dataclass(frozen=True)
class OverlayHooks:
    """What runs, in order; the digest of it; why it may not run; what
    the step says regardless; and the state and digest recorded"""

    hooks: tuple[Hook, ...] = ()
    digest: str = ""
    problems: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    recorded: tuple[str, str] | None = None


def observe_hooks(root: str, name: str,
                  manifest: dict) -> OverlayHooks | None:
    """None when the overlay has no hook of any kind"""
    declared = ((manifest.get("hooks") or {}).get("state")
                if isinstance(manifest.get("hooks"), dict) else None)
    own = STATE_HOOK.format(name=name)
    problems: list[str] = []
    notes: list[str] = []
    hooks: list[Hook] = []
    for directory in (os.path.dirname(own), own + ".d"):
        if os.path.lexists(_under(root, directory)):
            problems.extend(_unsafe(root, directory, directory=True))
    if isinstance(declared, dict):
        if not os.path.lexists(_under(root, own)):
            problems.append(f"{own}: declared in hooks.state and not there")
        else:
            problems.extend(_unsafe(root, own))
            hooks.append(Hook(own, int(declared.get(
                "timeout", STATE_TIMEOUT_DEFAULT))))
    elif os.path.lexists(_under(root, own)):
        notes.append(f"not run: {own} is not declared in the overlay"
                     " manifest's hooks.state")
    for path in _state_d(root, own + ".d"):
        found = _unsafe(root, path)
        problems.extend(found)
        if not found and not _executable(root, path):
            continue
        hooks.append(Hook(path, STATE_TIMEOUT_DEFAULT))
    if not (hooks or problems or notes):
        return None
    return OverlayHooks(
        hooks=tuple(hooks), digest=_digest(root, hooks),
        problems=tuple(problems), notes=tuple(notes),
        recorded=read_record(root, name))


def _under(root: str, path: str) -> str:
    return os.path.join(root, path.lstrip("/"))


def _state_d(root: str, directory: str) -> list[str]:
    full = _under(root, directory)
    if not os.path.isdir(full):
        return []
    return [f"{directory}/{entry}" for entry in sorted(os.listdir(full))
            if PLAIN.fullmatch(entry)
            and not os.path.isdir(os.path.join(full, entry))]


def _executable(root: str, path: str) -> bool:
    full = os.path.realpath(_under(root, path))
    return os.path.isfile(full) and os.access(full, os.X_OK)


def _unsafe(root: str, path: str, directory: bool = False) -> list[str]:
    """Why PATH may not be run (or hold what is run), as root would"""
    full = _under(root, path)
    info = os.lstat(full)
    if stat.S_ISLNK(info.st_mode):
        real = os.path.realpath(full)
        base = os.path.realpath(_under(root, BASE))
        if os.path.commonpath([real, base]) != base:
            shown = "/" + os.path.relpath(real, os.path.realpath(root))
            return [f"{path} is a link to {shown}, outside {BASE}: it is"
                    " not run"]
        info = os.stat(real)
    problems = []
    if not directory and not stat.S_ISREG(info.st_mode):
        problems.append(f"{path} is not a regular file: it is not run")
    if info.st_uid != machine.ROOT_UID:
        problems.append(f"{path} is not owned by root: it is not run")
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        problems.append(f"{path} is writable by group or others: it is"
                        " not run")
    return problems


def _digest(root: str, hooks: list[Hook]) -> str:
    """The hooks as they would run: each path and the hash of its content"""
    total = hashlib.sha256()
    for hook in hooks:
        try:
            with open(os.path.realpath(_under(root, hook.path)), "rb") as fob:
                content = hashlib.sha256(fob.read()).hexdigest()
        except OSError:
            content = "unreadable"
        total.update(f"{hook.path}\0{content}\n".encode())
    return total.hexdigest()


def read_record(root: str, name: str) -> tuple[str, str] | None:
    """The state and the digest recorded after the hooks last passed"""
    try:
        with open(os.path.join(root, RECORD.format(name=name))) as fob:
            lines = fob.read().split()
    except OSError:
        return None
    if len(lines) != 2 or lines[0] not in STATES:
        return None
    found = DIGEST.fullmatch(lines[1])
    return (lines[0], found.group(1)) if found else None


def plan_hooks(name: str, wanted: str, found: OverlayHooks | None,
               live: bool) -> list[Action]:
    """Problems are the caller's to refuse before anything else runs"""
    if found is None:
        return []
    notes: list[Action] = [Note(note) for note in found.notes]
    if not found.hooks:
        return notes
    if not live:
        return notes + [Note(f"not run under --root: {hook.path} runs on"
                             " the live system") for hook in found.hooks]
    if found.recorded == (wanted, found.digest):
        return notes
    record = RECORD.format(name=name)
    return [*notes,
            *(Run((hook.path, wanted),
                  f"run {hook.path}: the overlay is {wanted}",
                  timeout=hook.timeout) for hook in found.hooks),
            WriteFile(record, f"{wanted}\nsha256:{found.digest}\n",
                      RECORD_MODE, None,
                      f"record {wanted} and the hooks' digest in /{record}")]
