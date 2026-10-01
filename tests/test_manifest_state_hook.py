# Copyright (c) 2026 KeelLinux maintainers
"""hooks.state of an overlay manifest (keel#62, the erratum of 0041)

An overlay that is not a unit declares the hook apply runs to turn it on
and off: `hooks.state: {path: /usr/lib/keel/overlays/<name>/state}`, with
an optional `timeout` in seconds. validate checks the path is that one,
that it exists, is executable, is root's and is not writable by group or
others (rule 12's checks), and that the timeout is a whole number of
seconds within the limit.
"""

import os
import unittest
from unittest import mock

from manifest_helpers import ManifestCase

STATE = "/usr/lib/keel/overlays/coraza/state"


def executable(root: str, path: str, mode: int = 0o755) -> None:
    full = os.path.join(root, path.lstrip("/"))
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as fob:
        fob.write("#!/bin/sh\n")
    os.chmod(full, mode)


class StateHook(ManifestCase):
    def declare(self, value: str) -> None:
        self.edit("overlays", "coraza", "requires: [nginx]\n",
                  f"requires: [nginx]\nhooks:\n  state: {value}\n")

    def accepted(self, target: str = "coraza") -> None:
        code, _, err = self.cli("manifest", "validate", target)
        self.assertEqual(code, 0, err)

    def test_a_declared_hook_that_is_there_validates(self):
        executable(self.root, STATE)
        self.declare(f"{{path: {STATE}, timeout: 300}}")
        self.accepted()

    def test_the_timeout_may_be_left_out(self):
        executable(self.root, STATE)
        self.declare(f"{{path: {STATE}}}")
        self.accepted()

    def test_a_declared_hook_that_is_missing_is_refused(self):
        self.declare(f"{{path: {STATE}}}")
        self.refused("coraza", f"hooks.state.path: {STATE} does not exist"
                     f" under {self.root}")

    def test_the_path_is_the_overlay_s_own(self):
        executable(self.root, "/usr/lib/keel/overlays/nginx/state")
        self.declare("{path: /usr/lib/keel/overlays/nginx/state}")
        self.refused("coraza", f"hooks.state.path: must be {STATE}")

    def test_a_hook_writable_by_others_is_refused(self):
        executable(self.root, STATE, 0o757)
        self.declare(f"{{path: {STATE}}}")
        self.refused("coraza", f"hooks.state.path: {STATE} is writable by"
                     " group or others")

    def test_a_hook_not_owned_by_root_is_refused(self):
        executable(self.root, STATE)
        self.declare(f"{{path: {STATE}}}")
        with mock.patch("keel.manifest.machine.ROOT_UID", os.getuid() + 1):
            self.refused("coraza", f"hooks.state.path: {STATE} is not owned"
                         " by root")

    def test_the_timeout_is_a_whole_number_within_the_limit(self):
        executable(self.root, STATE)
        for value in ("0", "601", "true", "2.5", "soon"):
            with self.subTest(value=value):
                self.declare(f"{{path: {STATE}, timeout: {value}}}")
                self.refused("coraza", "hooks.state.timeout: must be a whole"
                             " number of seconds from 1 to 600")

    def test_the_shape_of_hooks_state(self):
        self.declare(STATE)
        self.refused("coraza", "hooks.state: must be a mapping")
        self.declare("{timeout: 5, when: now}")
        self.refused("coraza", "hooks.state.path: required",
                     "hooks.state.when: unknown key")

    def test_an_appliance_has_no_state_hook(self):
        self.edit("appliances", "web", "base: core\n",
                  f"base: core\nhooks:\n  state: {{path: {STATE}}}\n")
        self.refused("web", "hooks.state: a key of an overlay manifest, not"
                     " of an appliance")


if __name__ == "__main__":
    unittest.main()
