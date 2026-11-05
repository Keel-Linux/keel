# Copyright (c) 2026 KeelLinux maintainers
"""keel-database-follow.service on the cloud advanced witness (0057, 0076)

The witness is a Keel Core node: etcd enabled, the VIP overlay disabled,
no appliance.vip and no database. Its VIP state directory exists all the
same, since it routes the claims of the pairs of the mesh, so
keel-database-follow.path starts the service. The unit must not end
failed there (keel#211, reported again with exit 16): its ExecCondition,
`keel database follow --needed`, skips it, and the follow itself has
nothing to follow and exits 0.
"""

import contextlib
import io
import os
import tempfile
import unittest
from os.path import dirname, join
from unittest import mock

from keel import cli, exits
from keel.system import dbfollow

UNIT = join(dirname(dirname(os.path.abspath(__file__))), "debian",
            "keel.keel-database-follow.service")
WITNESS = """version: 1
appliance: {name: core}
installation: {mode: cloud_advanced}
overlays: {installer: enabled, wireguard: enabled, etcd: enabled,
           crowdsec: enabled, vip: disabled}
network:
  overlay:
    wireguard:
      address: fd00:6b65:1::3/64
"""


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch("os.geteuid", return_value=0):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TheWitness(unittest.TestCase):
    def setUp(self):
        self.root = self.enterContext(tempfile.TemporaryDirectory())
        self.spec = join(self.root, "instance.yaml")
        self.write(WITNESS)
        # another pair's claim routed here makes the directory
        os.makedirs(join(self.root, "var/lib/keel/vip"))

    def write(self, text: str) -> None:
        with open(self.spec, "w") as fob:
            fob.write(text)

    def follow(self, *more: str) -> tuple[int, str, str]:
        return run_cli("database", "follow", "--spec", self.spec, "--root",
                       self.root, *more)

    def test_the_follow_itself_has_nothing_to_follow_and_exits_0(self):
        code, out, err = self.follow()
        self.assertEqual(code, exits.OK, out + err)
        self.assertIn("nothing to follow", out)
        self.assertNotIn("refused", out)

    def test_the_condition_skips_the_unit_on_the_witness(self):
        code, out, _ = self.follow("--needed")
        self.assertEqual(code, dbfollow.NOT_NEEDED)
        self.assertIn("nothing to follow", out)

    def test_the_condition_lets_a_paired_node_and_an_unreadable_spec_run(self):
        self.write(WITNESS.replace("installation:",
                                   "  vip: fd00:6b65:1::ffff:1\n"
                                   "installation:").replace(
            "appliance: {name: core}\n", "appliance:\n  name: core\n"))
        code, out, err = self.follow("--needed")
        self.assertEqual(code, exits.OK, out + err)
        # the follow then says why it cannot read the spec: the condition
        # never hides a failure
        self.write("version: [\n")
        code, out, err = self.follow("--needed")
        self.assertEqual(code, exits.OK, out + err)
        self.write("version: 1\nappliance: {name: core, vip: 12}\n")
        code, out, err = self.follow("--needed")
        self.assertEqual(code, exits.OK, out + err)

    def test_the_condition_needs_root_like_the_follow(self):
        with mock.patch("os.geteuid", return_value=1000):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                code = cli.main(["database", "follow", "--needed",
                                 "--spec", self.spec])
        self.assertEqual(code, exits.APPLY_NEEDS_ROOT)

    def test_the_unit_runs_the_condition_before_the_follow(self):
        with open(UNIT) as fob:
            lines = [line.strip() for line in fob]
        self.assertIn("ExecCondition=/usr/bin/keel database follow --needed",
                      lines)
        self.assertLess(lines.index("ExecCondition=/usr/bin/keel database"
                                    " follow --needed"),
                        lines.index("ExecStart=/usr/bin/keel database"
                                    " follow"))


if __name__ == "__main__":
    unittest.main()
