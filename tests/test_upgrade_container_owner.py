# Copyright (c) 2026 KeelLinux maintainers
"""A node that goes from keel 0.23.62 to a newer keel keeps its spec

Before keel#238, keel did not see a released Proxmox template as a
container, so `keel inspect` wrote `network.managed_by: file` on it. Since
keel#238, keel reads systemd's record of the container, and the same spec
gave `keel diff` exit 14 and `keel spec apply` exit 16 on 6 running nodes
(evidence of 2026-11-01). An upgrade must not break a running node: the
spec keeps working, and keel says what to change.
"""

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from os.path import dirname, join
from unittest import mock

import yaml

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel import exits
from keel.cli import main
from keel.inspect import constants
from keel.system import effects
from keel.system.network import plan_network
from keel.system.netstate import observe_network

FIXTURES = join(dirname(__file__), "fixtures", "inspect")
REMEDY = "change network.managed_by to host"


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def no_command(argv, **kwargs):
    return subprocess.CompletedProcess(argv, 1, "", "not here\n")


class TestUpgradeOfAContainer(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.root = join(self.tmpdir, "root")
        shutil.copytree(join(FIXTURES, "turnkey"), self.root, symlinks=True)
        self.spec = join(self.tmpdir, "instance.yaml")
        # the old keel: inspect sees no container, and writes `file`
        code, _, err = run_cli(
            "inspect", "--root", self.root, "--output", self.spec,
            "--secrets-dir", join(self.tmpdir, "secrets"))
        self.assertEqual(code, exits.OK, err)
        with open(self.spec) as fob:
            self.assertIn("managed_by: file", fob.read())
        code, out, err = run_cli("diff", "--spec", self.spec,
                                 "--root", self.root)
        self.assertNotIn("network.managed_by: drift", out)
        self.before = code

    def boot_as_a_container(self) -> None:
        """What keel#238 reads: systemd's record, on the same root"""
        path = join(self.root, constants.SYSTEMD_CONTAINER)
        os.makedirs(dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write("lxc\n")

    def test_keel_diff_gives_the_same_exit_as_before_the_upgrade(self):
        self.boot_as_a_container()
        code, out, _ = run_cli("diff", "--spec", self.spec,
                               "--root", self.root)
        self.assertEqual(code, self.before, out)
        self.assertNotIn("network.managed_by: drift", out)

    def test_keel_diff_says_what_to_change(self):
        self.boot_as_a_container()
        _, out, _ = run_cli("diff", "--spec", self.spec, "--root", self.root)
        line = next(one for one in out.splitlines()
                    if one.startswith("network.managed_by:"))
        self.assertIn(REMEDY, line)

    def test_the_plan_refuses_nothing_and_says_what_to_change(self):
        self.boot_as_a_container()
        doc = spec.load(self.spec)
        state = observe_network(self.root, doc)
        steps = plan_network(doc["network"], state, False, frozenset())
        said = " ".join(action.describe() for step in steps
                        for action in step.actions)
        self.assertEqual(state.owner, "host")
        self.assertIn(REMEDY, said)
        self.assertNotIn("refused", said)

    def test_keel_spec_apply_does_not_fail_on_the_network(self):
        self.boot_as_a_container()
        # an owner on the root's account file is no matter of this test
        doc = spec.load(self.spec)
        doc.pop("users", None)
        with open(self.spec, "w") as fob:
            yaml.safe_dump(doc, fob)
        with mock.patch.object(effects.subprocess, "run",
                               side_effect=no_command):
            code, out, err = run_cli(
                "spec", "apply", "--spec", self.spec, "--system-only",
                "--root", self.root)
        self.assertNotIn("network: refused", out + err)
        self.assertIn(REMEDY, out)
        self.assertEqual(code, exits.OK, out + err)

    def test_the_corrected_spec_has_no_note(self):
        self.boot_as_a_container()
        with open(self.spec) as fob:
            text = fob.read()
        with open(self.spec, "w") as fob:
            fob.write(text.replace("managed_by: file", "managed_by: host"))
        _, out, _ = run_cli("diff", "--spec", self.spec, "--root", self.root)
        self.assertIn("network.managed_by: same (host)", out)
        self.assertNotIn(REMEDY, out)


class TestNoContainer(unittest.TestCase):
    def test_a_machine_that_is_no_container_keeps_the_file_owner(self):
        with tempfile.TemporaryDirectory() as root:
            found = observe_network(root, {"network": {
                "managed_by": "file",
                "interfaces": {"eth0": {"ipv6": {"method": "auto"}}}}})
        self.assertEqual(found.owner, "file")

    def test_drift_host_declared_on_a_machine_stays_drift(self):
        from keel.diff.compare import compare_section, owner_of_a_container
        from keel.diff.report import DRIFT
        fields = compare_section(
            "network", {"managed_by": "host"}, {"managed_by": "file"}, {})
        found = owner_of_a_container(fields)
        self.assertEqual(found[0].status, DRIFT)


if __name__ == "__main__":
    unittest.main()
