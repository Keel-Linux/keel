# Copyright (c) 2026 KeelLinux maintainers
"""Who may begin enforcement (decision 0097, section 5)

`keel spec apply --system` is an apply a person runs (the first boot
hook and confconsole run the same command for the person who installs or
configures the node). keel mesh applies the whole spec with no person:
keel-mesh-sync.timer every 15 minutes, and keel-mesh-members on a path.
So the flag that lets rule B begin enforcement comes from the command
line only, and the mesh's apply never passes it.
"""

import argparse
import inspect
import unittest
from unittest import mock

from keel import commands
from keel.mesh import node
from keel.system.plan import plan


class TestAttended(unittest.TestCase):
    def test_keel_mesh_applies_unattended(self):
        with mock.patch("keel.mesh.node.apply_system",
                        return_value=0) as apply:
            node.live_apply({"version": 1}, "/r", 60)
        self.assertIs(apply.call_args.kwargs["attended"], False)

    def test_keel_spec_apply_is_attended(self):
        args = argparse.Namespace(spec="/r/i.yaml", conf="/r/c",
                                  system_only=True, root="/r")
        with mock.patch("keel.commands.read_spec",
                        return_value=({"version": 1}, 0)), \
                mock.patch("keel.commands.apply_system",
                           return_value=1) as apply:
            commands.spec_apply(args)
        self.assertIs(apply.call_args.kwargs["attended"], True)

    def test_apply_system_hands_the_flag_to_the_plan(self):
        for attended in (True, False):
            with mock.patch("keel.commands.manifest_facts",
                            return_value=None), \
                    mock.patch("keel.system.filesync.undeclared_problem",
                               return_value=None), \
                    mock.patch("keel.system.observe"), \
                    mock.patch("keel.system.plan") as planned:
                planned.return_value.steps = ()
                commands.apply_system({"version": 1}, "/r", True,
                                      attended=attended)
            self.assertIs(planned.call_args.kwargs["attended"], attended)

    def test_the_plan_is_unattended_unless_told(self):
        for function in (plan, commands.apply_system):
            self.assertIs(inspect.signature(function).parameters[
                "attended"].default, False)


if __name__ == "__main__":
    unittest.main()
