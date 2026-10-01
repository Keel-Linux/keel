# Copyright (c) 2026 KeelLinux maintainers
"""hooks.state of an overlay manifest (keel#62)

An overlay that is not a unit, Coraza's Nginx module for one, declares
the hook apply runs to turn it on and off:

    hooks:
      state: {path: /usr/lib/keel/overlays/coraza/state, timeout: 120}

The path is always the overlay's own, so the state.d/ directory other
packages put their hooks in sits beside it; on a machine it exists, is
executable, is root's and is not writable by group or others, as rule 12
asks of a first boot hook. `timeout`, in seconds, is optional.
"""

from typing import Any

from keel.manifest import machine
from keel.manifest.constants import (
    STATE_HOOK,
    STATE_HOOK_KEYS,
    STATE_TIMEOUT_MAX,
)
from keel.manifest.fields import keys_errors, mapping_error, missing


def state_hook_errors(value: Any, name: str, root: str) -> list[str]:
    if value is None:
        return []
    error = mapping_error("hooks.state", value)
    if error:
        return [error]
    errors = keys_errors("hooks.state", value, STATE_HOOK_KEYS)
    errors.extend(missing("hooks.state", value, ("path",)))
    if "timeout" in value and not is_timeout(value["timeout"]):
        errors.append("hooks.state.timeout: must be a whole number of"
                      f" seconds from 1 to {STATE_TIMEOUT_MAX}")
    if "path" not in value:
        return errors
    path, wanted = value["path"], STATE_HOOK.format(name=name)
    if path != wanted:
        return errors + [f"hooks.state.path: must be {wanted}"]
    return errors + [f"hooks.state.path: {problem}"
                     for problem in machine.hook_problems(root, path)]


def is_timeout(value: Any) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool)
            and 1 <= value <= STATE_TIMEOUT_MAX)
