# Copyright (c) 2026 KeelLinux maintainers
"""An overlay's state hooks (decision 0041, keel#62)

Not every overlay is a unit. Coraza is an Nginx module: its package
ships /usr/lib/keel/overlays/coraza/state, which links the module, tests
and reloads Nginx and checks the WAF's probe, and rolls back on failure.
Another package may react to an overlay's state with an executable in
/usr/lib/keel/overlays/<name>/state.d/ (Keel Web routes its default site
through Anubis that way). The overlay's own hook runs first, then the
directory's in name order, each with `enabled` or `disabled`.

keel runs them on the live system only, when the state it recorded in
/var/lib/keel/overlays/<name> after their last run differs from the
spec's, or when nothing is recorded: a hook is not a unit keel can ask,
so the record is what keeps a second apply from changing anything. A
hook that fails fails its step, and the state is not recorded, so the
next apply runs them again. The overlay's units come up before its hooks
run and go down after.
"""

import os
import re

from keel.system.actions import Action, Note, Run, WriteFile

HOOK = "usr/lib/keel/overlays/{name}/state"
RECORD = "var/lib/keel/overlays/{name}"
RECORD_MODE = 0o644
STATES = ("enabled", "disabled")
# run-parts(8)'s rule: what dpkg leaves behind (.dpkg-old) is not a hook
PLAIN = re.compile(r"[A-Za-z0-9_-]+")


def hook_paths(root: str, name: str) -> tuple[str, ...]:
    """The overlay's executable hooks, as absolute paths on the machine"""
    hook = HOOK.format(name=name)
    found = [hook] if is_executable(root, hook) else []
    directory = os.path.join(root, hook + ".d")
    names = sorted(os.listdir(directory)) if os.path.isdir(directory) else []
    found += [f"{hook}.d/{entry}" for entry in names
              if PLAIN.fullmatch(entry)
              and is_executable(root, f"{hook}.d/{entry}")]
    return tuple("/" + path for path in found)


def is_executable(root: str, relative: str) -> bool:
    path = os.path.join(root, relative)
    return os.path.isfile(path) and os.access(path, os.X_OK)


def read_record(root: str, name: str) -> str | None:
    """The state recorded after the hooks last passed; None when unknown"""
    try:
        with open(os.path.join(root, RECORD.format(name=name))) as fob:
            word = fob.read().strip()
    except OSError:
        return None
    return word if word in STATES else None


def plan_hooks(name: str, wanted: str, hooks: tuple[str, ...],
               recorded: str | None, live: bool) -> list[Action]:
    if not hooks:
        return []
    if not live:
        return [Note(f"not run under --root: {hook} runs on the live"
                     " system") for hook in hooks]
    if recorded == wanted:
        return []
    record = RECORD.format(name=name)
    return [*(Run((hook, wanted), f"run {hook}: the overlay is {wanted}")
              for hook in hooks),
            WriteFile(record, wanted + "\n", RECORD_MODE, None,
                      f"record {wanted} in /{record}")]
