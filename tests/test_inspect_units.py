# Copyright (c) 2026 KeelLinux maintainers
"""What systemd says about the units of an overlay (decision 0041)

Read the same way for inspect, diff and apply: on the live system by
asking systemctl, under --root from the links systemctl would have made.
"""

import os
import subprocess
import tempfile
import unittest
from os.path import join

from helpers import spec  # noqa: F401

from keel.inspect.tree import Tree
from keel.inspect.units import UnitState, overlay_state, read_units


def answers(table: dict):
    """A stand in for subprocess.run that answers systemctl from TABLE"""
    calls = []

    def run(argv, **kwargs):
        calls.append(tuple(argv))
        key = (argv[1], argv[2])
        if key not in table:
            raise OSError(2, "No such file or directory")
        word, code = table[key]
        return subprocess.CompletedProcess(argv, code, f"{word}\n", "")
    run.calls = calls
    return run


class TestLive(unittest.TestCase):
    def test_both_words_are_asked_of_systemctl(self):
        run = answers({("is-enabled", "crowdsec.service"): ("disabled", 1),
                       ("is-active", "crowdsec.service"): ("inactive", 3)})
        found = read_units(Tree("/"), ("crowdsec.service",), True, run)
        self.assertEqual(found, {"crowdsec.service": UnitState(
            "crowdsec.service", "disabled", "inactive")})
        self.assertEqual(run.calls, [
            ("systemctl", "is-enabled", "crowdsec.service"),
            ("systemctl", "is-active", "crowdsec.service")])

    def test_no_systemctl_is_unknown(self):
        found = read_units(Tree("/"), ("etcd.service",), True, answers({}))
        state = found["etcd.service"]
        self.assertEqual((state.enabled, state.active), ("unknown", None))

    def test_an_empty_answer_is_unknown(self):
        run = answers({("is-enabled", "etcd.service"): ("", 1),
                       ("is-active", "etcd.service"): ("", 3)})
        state = read_units(Tree("/"), ("etcd.service",), True,
                           run)["etcd.service"]
        self.assertEqual((state.enabled, state.active), ("unknown",
                                                         "unknown"))


class TestUnderARoot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        os.makedirs(join(self.root, "etc/systemd/system/multi-user.target"
                         ".wants"))

    def link(self, path: str, target: str) -> None:
        os.symlink(target, join(self.root, path))

    def test_a_wants_link_is_enabled_and_activity_unknown(self):
        self.link("etc/systemd/system/multi-user.target.wants/etcd.service",
                  "/usr/lib/systemd/system/etcd.service")
        self.link("etc/systemd/system/crowdsec.service", "/dev/null")
        found = read_units(Tree(self.root),
                           ("etcd.service", "crowdsec.service",
                            "anubis.service"), False)
        self.assertEqual(found["etcd.service"],
                         UnitState("etcd.service", "enabled", None))
        self.assertEqual(found["crowdsec.service"].enabled, "masked")
        self.assertEqual(found["anubis.service"].enabled, "disabled")


class TestWords(unittest.TestCase):
    def test_what_counts_as_enabled_masked_and_running(self):
        self.assertTrue(UnitState("a", "enabled-runtime", None).is_enabled)
        self.assertFalse(UnitState("a", "static", None).is_enabled)
        self.assertTrue(UnitState("a", "static", None).is_fixed)
        self.assertTrue(UnitState("a", "masked-runtime", None).is_masked)
        self.assertTrue(UnitState("a", "enabled", "activating").is_running)
        self.assertFalse(UnitState("a", "enabled", "failed").is_running)
        self.assertFalse(UnitState("a", "enabled", None).is_running)
        self.assertEqual(UnitState("a", "enabled", None).describe(),
                         "a enabled")
        self.assertEqual(UnitState("a", "disabled", "failed").describe(),
                         "a disabled and failed")


class TestOverlayState(unittest.TestCase):
    ON = UnitState("crowdsec.service", "enabled", "active")
    BOUNCER_ON = UnitState("crowdsec-firewall-bouncer.service", "enabled",
                           "active")
    OFF = UnitState("crowdsec.service", "disabled", "inactive")
    BOUNCER_OFF = UnitState("crowdsec-firewall-bouncer.service", "disabled",
                            "failed")

    def test_every_unit_enabled_and_running_is_enabled(self):
        self.assertEqual(overlay_state([self.ON, self.BOUNCER_ON]),
                         ("enabled", ""))

    def test_every_unit_disabled_and_stopped_is_disabled(self):
        self.assertEqual(overlay_state([self.OFF, self.BOUNCER_OFF]),
                         ("disabled", ""))

    def test_a_static_unit_that_runs_is_enabled_as_apply_leaves_it(self):
        self.assertEqual(overlay_state([
            self.ON, UnitState("b.service", "static", "active")]),
            ("enabled", ""))

    def test_under_a_root_the_links_decide(self):
        self.assertEqual(overlay_state([
            UnitState("etcd.service", "enabled", None)]), ("enabled", ""))

    def test_anything_else_is_named_unit_by_unit(self):
        self.assertEqual(
            overlay_state([self.ON, self.BOUNCER_OFF]),
            (None, "crowdsec.service enabled and active,"
             " crowdsec-firewall-bouncer.service disabled and failed"))
        self.assertEqual(
            overlay_state([UnitState("crowdsec.service", "disabled",
                                     "active")]),
            (None, "crowdsec.service disabled and active"))
        self.assertEqual(
            overlay_state([UnitState("crowdsec.service", "enabled",
                                     "failed")]),
            (None, "crowdsec.service enabled and failed"))


if __name__ == "__main__":
    unittest.main()
