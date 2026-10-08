# Copyright (c) 2026 KeelLinux maintainers
"""etcd restarted one member at a time: keel-overlay-etcd's gate around
etcd.service (`keel mesh etcd gate stop|started`) and `keel mesh
upgrade-check`, on a fake etcd with a clock (tests/vip_helpers.py)"""

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from etcd_helpers import KEYS, MESH, address
from vip_helpers import VIP, FakeKv

from keel import exits
from keel.mesh import etcdgate, etcdstate, identity
from keel.mesh import vip as vipstate
from keel.mesh.etcdclient import EtcdError, Member
from keel.mesh.etcdstate import Cluster

LOCK = etcdgate.lock_key(MESH.hex())
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


class FakeEtcd(FakeKv):
    """FakeKv with the members etcd lists and each one's health"""

    def __init__(self, clock):
        super().__init__(clock)
        self.listed = [Member(str(i + 1), f"m{i}",
                              (f"https://[{address(i)}]:2380",),
                              (etcdstate.client_url(address(i)),), False)
                       for i in range(3)]
        self.healthy = {address(i): True for i in range(3)}

    def members(self):
        self.check("members")
        return list(self.listed)

    def health(self, url):
        for one, healthy in self.healthy.items():
            if f"[{one}]" in url:
                return (healthy, "" if healthy else "no leader")
        return False, "unknown"

    def delete(self, key):
        self.check("delete")
        FakeKv.delete(self, key)


class Gate(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        identity.adopt(self.root, MESH)
        etcdstate.save_cluster(self.root, Cluster(
            "new", tuple(etcdstate.Member(KEYS[i], address(i))
                         for i in range(3)), MESH.hex()))
        self.ticks = [0.0]
        self.kv = FakeEtcd(lambda: self.ticks[0])
        self.said: list[str] = []

    def sleep(self, seconds: float) -> None:
        self.ticks[0] += seconds

    def stop(self, index: int = 0, wait: float = 30, **kw) -> int:
        return etcdgate.before_stop(
            self.root, address(index), self.said.append, client=self.kv,
            wait=wait, monotonic=lambda: self.ticks[0], sleep=self.sleep,
            now=lambda: NOW, **kw)

    def started(self, index: int = 0, wait: float = 30) -> int:
        return etcdgate.after_start(
            self.root, address(index), self.said.append, local=self.kv,
            client=self.kv, wait=wait, monotonic=lambda: self.ticks[0],
            sleep=self.sleep)

    def lock(self):
        return etcdgate.locked_by(self.kv, MESH.hex())


class TestStop(Gate):
    def test_every_other_member_healthy_it_takes_the_lock(self):
        self.assertEqual(self.stop(), exits.OK)
        self.assertEqual(self.lock()["member"], address(0))
        self.assertEqual(self.ticks[0], 0.0)
        # on a lease, so a member that never comes back frees it
        self.assertEqual(len(self.kv.leases), 1)
        self.sleep(etcdgate.LOCK_TTL + 1)
        self.assertIsNone(self.lock())

    def test_another_member_not_healthy_holds_it_back(self):
        self.kv.healthy[address(2)] = False
        self.assertEqual(self.stop(wait=20), exits.APPLY_FAILED)
        self.assertGreaterEqual(self.ticks[0], 20)
        self.assertIsNone(self.lock())
        text = "\n".join(self.said)
        self.assertIn(f"m2 at {address(2)} is not healthy: no leader", text)
        self.assertIn("stops anyway", text)
        # said once while waiting, not at every poll
        self.assertEqual(text.count("waiting before this member stops"), 1)

    def test_it_goes_once_the_other_is_back(self):
        self.kv.healthy[address(2)] = False

        def sleep(seconds):
            self.sleep(seconds)
            if self.ticks[0] >= 6:
                self.kv.healthy[address(2)] = True
        code = etcdgate.before_stop(
            self.root, address(0), self.said.append, client=self.kv,
            wait=60, monotonic=lambda: self.ticks[0], sleep=sleep,
            now=lambda: NOW)
        self.assertEqual(code, exits.OK)
        self.assertEqual(self.ticks[0], 6)

    def test_two_at_once_one_passes(self):
        """B took the lock first and is down: A waits"""
        self.assertEqual(self.stop(1), exits.OK)
        self.kv.healthy[address(1)] = False
        self.assertEqual(self.stop(0, wait=10), exits.APPLY_FAILED)
        self.assertIn(f"etcd member at {address(1)} is restarting",
                      "\n".join(self.said))
        self.assertEqual(self.lock()["member"], address(1))
        # B back and released: A passes
        self.kv.healthy[address(1)] = True
        self.assertEqual(self.started(1), exits.OK)
        self.assertIsNone(self.lock())
        self.assertEqual(self.stop(0), exits.OK)

    def test_a_lock_taken_between_the_check_and_the_swap(self):
        original = self.kv.swap

        def swap(compare, puts):
            self.kv.put(LOCK, json.dumps({"member": address(2)}).encode())
            self.kv.swap = original
            return original(compare, puts)
        self.kv.swap = swap
        self.assertEqual(self.stop(wait=4), exits.APPLY_FAILED)
        self.assertEqual(self.lock()["member"], address(2))
        self.assertEqual(self.kv.leases, {})

    def test_its_own_lock_left_from_before_is_taken_again(self):
        self.assertEqual(self.stop(), exits.OK)
        self.assertEqual(self.stop(), exits.OK)
        self.assertEqual(self.lock()["member"], address(0))

    def test_etcd_not_answering_or_failing_the_lock(self):
        self.kv.refuse = "all"
        self.assertEqual(self.stop(wait=4), exits.APPLY_FAILED)
        self.assertIn("etcd does not answer", "\n".join(self.said))
        self.kv.refuse = "grant"
        self.assertEqual(self.stop(wait=4), exits.APPLY_FAILED)
        self.assertIn("took the restart lock first", "\n".join(self.said))

    def test_a_lock_that_cannot_be_read_is_a_problem(self):
        self.kv.refuse = "prefix"
        self.assertEqual(self.stop(wait=2), exits.APPLY_FAILED)
        self.assertIn("(unknown: prefix", "\n".join(self.said))

    def test_a_lock_that_is_not_keel_s_is_a_problem(self):
        self.kv.put(LOCK, b"garbage")
        self.assertEqual(self.stop(wait=2), exits.APPLY_FAILED)
        self.assertIn("(not keel's) is restarting", "\n".join(self.said))

    def test_learners_do_not_count(self):
        self.kv.listed.append(Member("9", "", ("https://[fd00::9]:2380",),
                                     (), True))
        self.assertEqual(self.stop(), exits.OK)

    def test_shutdown_and_no_cluster_do_not_wait(self):
        self.kv.healthy[address(2)] = False
        self.assertEqual(self.stop(output=lambda argv: "stopping\n"),
                         exits.OK)
        self.assertIn("shutting down", "\n".join(self.said))
        with mock.patch.object(etcdstate, "cluster", return_value=None):
            self.assertEqual(self.stop(), exits.OK)
        self.assertEqual(self.ticks[0], 0.0)


class TestStarted(Gate):
    def test_back_in_the_majority_it_releases_its_lock(self):
        self.stop()
        self.assertEqual(self.started(), exits.OK)
        self.assertIsNone(self.lock())
        self.assertIn("restart lock released", self.said[-1])

    def test_it_never_releases_another_member_s_lock(self):
        self.stop(1)
        self.assertEqual(self.started(0), exits.OK)
        self.assertEqual(self.lock()["member"], address(1))

    def test_not_back_within_its_wait(self):
        self.stop()
        self.kv.refuse = "prefix"
        self.assertEqual(self.started(wait=10), exits.APPLY_FAILED)
        self.assertIn("not back in the majority", self.said[-1])
        self.kv.refuse = None
        # the lock ends with its lease
        self.sleep(etcdgate.LOCK_TTL)
        self.assertIsNone(self.lock())

    def test_back_after_a_while(self):
        self.stop()
        self.kv.refuse = "prefix"
        original = self.sleep

        def sleep(seconds):
            original(seconds)
            if self.ticks[0] >= 4:
                self.kv.refuse = None
        self.assertEqual(etcdgate.after_start(
            self.root, address(0), self.said.append, local=self.kv,
            client=self.kv, wait=30, monotonic=lambda: self.ticks[0],
            sleep=sleep), exits.OK)

    def test_the_release_failing_is_said(self):
        self.stop()
        self.kv.refuse = "delete"
        self.assertEqual(self.started(), exits.APPLY_FAILED)
        self.assertIn("not released", self.said[-1])

    def test_no_cluster(self):
        with mock.patch.object(etcdstate, "cluster", return_value=None):
            self.assertEqual(self.started(), exits.OK)


class TestUpgradeCheck(Gate):
    def check(self, index: int = 0) -> tuple[int, str]:
        lines: list[str] = []
        code = etcdgate.upgrade_check(self.root, address(index),
                                      lines.append, client=self.kv)
        return code, "\n".join(lines)

    def test_all_healthy(self):
        code, said = self.check()
        self.assertEqual(code, exits.OK)
        self.assertIn("upgrade this node", said)

    def test_another_member_down_or_restarting(self):
        self.kv.healthy[address(2)] = False
        code, said = self.check()
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn(f"not now: etcd member m2 at {address(2)}", said)
        self.kv.healthy[address(2)] = True
        self.stop(1)
        code, said = self.check()
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn(f"{address(1)} is restarting", said)
        # the restarting member itself is told it may go on
        self.assertEqual(self.check(1)[0], exits.OK)

    def test_it_says_the_node_holds_a_vip(self):
        claim = mock.Mock(address=address(0))
        held = vipstate.Held(VIP, claim, False, "7")
        with mock.patch.object(vipstate, "held_all", return_value=[held]):
            code, said = self.check()
        self.assertEqual(code, exits.OK)
        self.assertIn(f"vip {VIP}: this node holds it", said)
        with mock.patch.object(vipstate, "held_all", return_value=[
                vipstate.Held(VIP, claim, True, "7")]):
            self.assertNotIn("holds it", self.check()[1])

    def test_etcd_that_cannot_be_asked(self):
        with mock.patch.object(etcdgate, "client_of",
                               side_effect=EtcdError("no certificate")):
            code = etcdgate.upgrade_check(self.root, address(0),
                                          lambda line: None)
        self.assertEqual(code, exits.MESH_REFUSED)
        with mock.patch.object(etcdstate, "cluster", return_value=None):
            self.assertEqual(self.check()[0], exits.OK)


class TestTheClient(Gate):
    def test_this_member_first_then_the_others(self):
        with mock.patch("keel.mesh.etcdclient.context"):
            client = etcdgate.client_of(self.root)
        self.assertEqual(client.endpoints[0],
                         etcdstate.client_url(etcdstate.LOOPBACK))
        self.assertEqual(len(client.endpoints), 4)
        self.assertEqual(client.timeout, etcdgate.CALL_TIMEOUT)


class TestTheCommands(Gate):
    def test_the_commands_reach_the_gate(self):
        from keel import cli
        spec = os.path.join(self.root, "instance.yaml")
        with open(spec, "w") as fob:
            fob.write("version: 1\n")
        args = ["--root", self.root, "--spec", spec]
        with mock.patch("keel.mesh.commands.own_address",
                        return_value=address(0)), \
                mock.patch("keel.system.needs_root", return_value=None), \
                mock.patch.object(etcdgate, "before_stop",
                                  return_value=exits.OK) as stop, \
                mock.patch.object(etcdgate, "after_start",
                                  return_value=exits.OK) as started, \
                mock.patch.object(etcdgate, "upgrade_check",
                                  return_value=exits.MESH_REFUSED) as check:
            self.assertEqual(cli.main(["mesh", "etcd", "gate", "stop",
                                       "--wait", "5", *args]), exits.OK)
            self.assertEqual(stop.call_args.kwargs["wait"], 5)
            self.assertEqual(cli.main(["mesh", "etcd", "gate", "started",
                                       *args]), exits.OK)
            self.assertEqual(started.call_args.kwargs["wait"],
                             etcdgate.STARTED_WAIT)
            self.assertEqual(cli.main(["mesh", "upgrade-check", *args]),
                             exits.MESH_REFUSED)
            self.assertEqual(check.call_args.args[1], address(0))

    def test_the_gate_s_own_failures(self):
        from keel import cli
        args = ["--root", self.root, "--spec", "/nonexistent.yaml"]
        with mock.patch("keel.system.needs_root", return_value=None):
            self.assertEqual(cli.main(["mesh", "etcd", "gate", "stop",
                                       *args]), exits.APPLY_FAILED)
            self.assertEqual(cli.main(["mesh", "upgrade-check", *args]),
                             exits.SPEC_UNREADABLE)
        with mock.patch("keel.system.needs_root", return_value="not root"):
            self.assertEqual(cli.main(["mesh", "etcd", "gate", "started",
                                       *args]), exits.APPLY_NEEDS_ROOT)

    def test_own_address_is_the_spec_s(self):
        from keel.mesh import commands
        node = mock.Mock()
        node.overlay.return_value = {"address": f"{address(1)}/64"}
        with mock.patch.object(commands, "live_node", return_value=node):
            self.assertEqual(commands.own_address(None), address(1))


if __name__ == "__main__":
    unittest.main()
