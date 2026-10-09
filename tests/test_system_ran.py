# Copyright (c) 2026 KeelLinux maintainers
"""apply says the action that ran (keel#120, findings N4 and N5)

A database certificate that is not due is kept, and the line says so,
not "done". An overlay change says whether it ran live with wg set or
bounced the interface with wg-quick down, then up. The effects tell
execute (`Effects.ran`); everything else still says "done".
"""

import shutil
import tempfile
import unittest
from unittest import mock

from helpers import spec  # noqa: F401

import keel.commands  # noqa: F401, I001
from keel.network import marker
from keel.system import effects as effects_module
from keel.system.actions import EnsureDatabaseTls, Plan, Step, SwitchNetwork
from keel.system.effects import Effects
from keel.system.execute import execute

TLS = EnsureDatabaseTls("fd00:1::2", "fd00:1::ffff:1", "fd00:1::3",
                        "/etc/keel/instance.yaml")
SWITCH = SwitchNetwork(iface="wg0", path="etc/wireguard/wg0.conf",
                       content="[Interface]\n", window=120,
                       addresses=("fd00:1::2",), gateways=(),
                       old_gateways=(), kind=marker.OVERLAY)


class RootCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.effects = Effects(self.root)

    def line(self, action) -> str:
        outcome = execute(Plan((Step("field", (action,)),)), self.effects)
        return outcome.lines[0]


class TestDatabaseCertificate(RootCase):
    def ensured(self, said):
        with mock.patch("keel.mesh.etcd.own_key", return_value="k"), \
                mock.patch("keel.mesh.vippair.read", return_value=None), \
                mock.patch("keel.system.dbtls.ensure", return_value=said):
            return self.line(TLS)

    def test_a_certificate_not_due_is_kept_and_said_so(self):
        found = self.ensured(None)
        self.assertTrue(found.endswith(": kept: the certificate is not due"
                                       " for renewal, and no file changed"),
                        found)

    def test_a_renewed_one_is_done(self):
        self.assertTrue(self.ensured("the database certificate for x").
                        endswith(": done"))


class TestOverlay(RootCase):
    def changed(self, seen_value):
        def change(root, pending, text, run, seen=None):
            if seen is not None and seen_value:
                seen.append(seen_value)
            return None
        with mock.patch.object(effects_module.switch, "change",
                               side_effect=change):
            return self.line(SWITCH)

    def test_the_line_says_which_way_ran(self):
        self.assertTrue(self.changed("added").endswith(
            ": done with wg set, live: peers added, no other peer"
            " touched"))
        self.assertTrue(self.changed("changed").endswith(
            ": done with wg set, live: the other peers kept their"
            " sessions"))
        self.assertTrue(self.changed(None).endswith(
            ": done with wg-quick down, then up"))

    def test_the_plan_line_names_no_way(self):
        self.assertNotIn("wg-quick", SWITCH.describe())
        self.assertNotIn("wg set", SWITCH.describe())

    def test_the_next_action_starts_with_nothing_said(self):
        self.effects.ran = "old"
        with mock.patch.object(self.effects, "run", return_value=None):
            from keel.system.actions import Run
            self.assertTrue(self.line(Run(("true",), "x")).endswith(
                ": done"))


if __name__ == "__main__":
    unittest.main()
