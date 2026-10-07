# Copyright (c) 2026 KeelLinux maintainers
"""keel-vip.service split as keel#75 splits an invite: the root helper
and the unprivileged controller over their unix socket, in one process
(keel.mesh.vipbridge); the units themselves run in the netns test"""

import json
import os
import socket
import tempfile
import threading
import time
from datetime import datetime, timezone
from unittest import mock

from vip_helpers import KEYS, MESH, VIP, Pair, address

from keel import exits
from keel.mesh import bridge, etcdstate, vipbridge, vipetcd, vipnode
from keel.mesh.bridge import BridgeError
from keel.mesh.vipnode import VipError

NOW = datetime.now(timezone.utc)


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)


class TestTheRootSide(Pair):
    def ask(self, ops, **message) -> dict:
        return vipbridge.answered(ops, json.dumps(message).encode())

    def test_every_operation_and_what_is_refused(self):
        self.nodes()
        ops = vipetcd.Ops(self.all[0])
        facts = self.ask(ops, op="facts")["ok"]
        self.assertEqual((facts["own_key"], facts["vip"]), (KEYS[0], VIP))
        self.assertEqual(self.ask(ops, op="held"), {"ok": []})
        signed = self.ask(ops, op="sign", vip=VIP, epoch=1)["ok"]
        self.assertIsNone(self.ask(ops, op="hold", raw=signed,
                                   lease="5")["ok"])
        held = self.ask(ops, op="held")["ok"]
        self.assertEqual(vipbridge.held_of(held[0]).lease, "5")
        self.assertIs(self.ask(ops, op="carried", vip=VIP)["ok"], False)
        self.assertIs(self.ask(ops, op="carry", vip=VIP, age=1.0)["ok"],
                      True)
        self.assertIsNone(self.ask(ops, op="drop", vip=VIP, fence=False,
                                   why="x")["ok"])
        self.assertIsNone(self.ask(ops, op="take", raw=signed)["ok"])
        # what the controller may not have
        self.assertIn("error", self.ask(ops, op="sign", vip=VIP, epoch=1))
        self.assertIn("error", self.ask(ops, op="nonsense"))
        self.assertIn("error", vipbridge.answered(ops, b"{"))
        self.assertIn("error", self.ask(ops, op="take", raw="!!"))
        self.assertIs(self.ask(ops, op="carry", vip=VIP, age=60.0)["ok"],
                      False)


class TestTheBridge(Pair):
    def test_the_controller_asks_the_root_side_over_its_socket(self):
        self.nodes()
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        stop = threading.Event()
        ops = vipetcd.Ops(self.all[0])

        def root_side():
            with theirs:
                while (data := bridge.line(theirs)) is not None:
                    bridge.send(theirs, vipbridge.answered(ops, data))
        server = threading.Thread(target=root_side)
        server.start()
        remote = vipbridge.Remote(ours, stop)
        self.assertEqual(remote.facts().own_key, KEYS[0])
        made = remote.sign(VIP, 1)
        remote.hold(made.raw, "5")
        self.assertEqual(remote.held()[0].holder, KEYS[0])
        self.assertTrue(remote.carry(VIP, 1.0))
        self.assertTrue(remote.carried(VIP))
        remote.drop(VIP, True, "a test")
        self.assertIsNone(remote.take(made.raw))
        with self.assertRaises(VipError):
            remote.sign(VIP, 1)
        ours.shutdown(socket.SHUT_WR)
        server.join(10)
        with self.assertRaisesRegex(VipError, "gone"):
            remote.facts()
        self.assertTrue(stop.is_set())

    def test_a_socket_that_fails(self):
        ours, theirs = socket.socketpair()
        theirs.close()
        ours.close()
        stop = threading.Event()
        with self.assertRaisesRegex(VipError, "gone"):
            vipbridge.Remote(ours, stop).facts()


class TestServeAndControl(Pair):
    def setUp(self):
        super().setUp()
        self.nodes()
        here = self.all[0]
        etcdstate.make_root(here.root, MESH.hex(), address(0))
        etcdstate.leaves(here.root, address(0), NOW)
        # a short path: a unix socket's is at most 107 bytes
        self.run_dir = tempfile.mkdtemp(prefix="vb-", dir="/tmp")
        self.addCleanup(lambda: os.path.exists(self.run_dir) and
                        __import__("shutil").rmtree(self.run_dir))
        self.path = os.path.join(self.run_dir, "s")

    def test_serve_hands_the_credentials_and_answers(self):
        here = self.all[0]
        got = {}

        def controller():
            sock = bridge.helper(self.path, os.getuid())
            with sock:
                message, fds, _, _ = socket.recv_fds(sock, 65536, 3)
                got["endpoint"] = json.loads(message)["endpoint"]
                got["fds"] = len(fds)
                got["context"] = vipbridge.context(
                    *(f"/proc/self/fd/{one}" for one in fds))
                for one in fds:
                    os.close(one)
                remote = vipbridge.Remote(sock, threading.Event())
                got["facts"] = remote.facts()

        class Started:
            stopped = False

            def trusted(self, pid, uid):
                return True

            def stop(self):
                Started.stopped = True
        thread = threading.Thread(target=controller)
        thread.start()
        vipnode.hold(here, vipnode.signed_claim(here, VIP, 1), True)
        self.assertTrue(self.carried(0))
        code = vipbridge.serve(here, threading.Event(),
                               start=lambda where: Started(),
                               path=self.path, sleep=time.sleep)
        thread.join(10)
        self.assertEqual(code, exits.OK)
        self.assertEqual(got["fds"], 3)
        self.assertEqual(got["facts"].vip, VIP)
        self.assertIn("[::1]", got["endpoint"])
        self.assertTrue(Started.stopped)
        # whatever ends it, the VIP is dropped
        self.assertFalse(self.carried(0))

    def test_serve_without_credentials_or_a_controller(self):
        said = self.said[1]
        self.assertEqual(vipbridge.serve(self.all[1], threading.Event()),
                         exits.APPLY_FAILED)
        self.assertIn("no etcd client certificate", said[-1])

        def failing(where):
            raise BridgeError("systemd-run: no")
        self.assertEqual(vipbridge.serve(self.all[0], threading.Event(),
                                         start=failing, path=self.path),
                         exits.APPLY_FAILED)
        self.assertIn("the controller stopped", self.text(0))

    def test_control_refuses_capabilities_and_bad_parameters(self):
        status = os.path.join(self.run_dir, "status")
        with open(status, "w") as fob:
            fob.write("CapEff:\t0000000000001000\n")
        said: list[str] = []
        self.assertEqual(vipbridge.control(self.path, said.append, status),
                         exits.APPLY_FAILED)
        self.assertIn("without capabilities", said[0])
        with open(status, "w") as fob:
            fob.write("CapEff:\t0000000000000000\n")
        with mock.patch.object(bridge, "helper", return_value=None):
            self.assertEqual(vipbridge.control(self.path, said.append,
                                               status), exits.APPLY_FAILED)
        self.assertIn("no root helper", said[-1])
        ours, theirs = socket.socketpair()
        theirs.sendall(b"not json\n")
        theirs.close()
        with mock.patch.object(bridge, "helper", return_value=ours):
            self.assertEqual(vipbridge.control(self.path, said.append,
                                               status), exits.APPLY_FAILED)
        self.assertIn("nothing the controller can use", said[-1])

    def test_control_runs_the_controller_until_the_root_side_goes(self):
        status = os.path.join(self.run_dir, "status")
        with open(status, "w") as fob:
            fob.write("CapEff:\t0000000000000000\n")
        here = self.all[0]
        ours, theirs = socket.socketpair()
        texts = vipbridge.credentials(here.root)
        from keel.mesh.channel import pem_fds
        with pem_fds(*texts) as fds:
            socket.send_fds(theirs, [b'{"endpoint": "https://[::1]:9"}\n'],
                            fds)
        ops = vipetcd.Ops(here)

        def root_side():
            with theirs:
                for _ in range(2):
                    data = bridge.line(theirs)
                    if data is None:
                        return
                    bridge.send(theirs, vipbridge.answered(ops, data))
        server = threading.Thread(target=root_side)
        server.start()
        said: list[str] = []
        with mock.patch.object(bridge, "helper", return_value=ours), \
                mock.patch.object(vipetcd, "TICK", 0.05), \
                mock.patch.object(vipetcd, "HOLD_TICK", 0.05):
            self.assertEqual(vipbridge.control(self.path, said.append,
                                               status), exits.OK)
        server.join(10)
        self.assertIn("without capabilities", said[0])
        self.assertTrue(any("root side is gone" in one for one in said))


class TestTheUnit(Pair):
    def test_the_controller_s_unit(self):
        run = Recorder()
        with mock.patch.dict(os.environ, {"PYTHONPATH": "/opt/keel"}):
            found = vipbridge.start_unit("/run/keel/vip-control/bridge.sock",
                                         run, lambda argv: "")
        argv = run.calls[-1]
        self.assertEqual(run.calls[0], ("systemctl", "stop", vipbridge.UNIT))
        for one in ("--property=DynamicUser=yes",
                    "--property=CapabilityBoundingSet=",
                    "--property=RuntimeDirectory=keel/vip-control",
                    f"--property=NetworkNamespacePath=/proc/{os.getpid()}"
                    "/ns/net", "--setenv=PYTHONPATH=/opt/keel"):
            self.assertIn(one, argv)
        self.assertEqual(argv[-3:], ("vip", "control",
                                     "/run/keel/vip-control/bridge.sock"))
        self.assertEqual(found.name, vipbridge.UNIT)
        failing = Recorder()
        with self.assertRaises(BridgeError):
            vipbridge.start_unit("/x", lambda argv: failing(argv) or (
                "no" if argv[0] == "systemd-run" else None),
                lambda argv: "")
        self.assertEqual(vipbridge.socket_path("/"),
                         "/run/keel/vip-control/bridge.sock")
        unit, runtime = vipbridge.names("/r")
        self.assertTrue(unit.startswith("keel-vip-control-"))
        self.assertEqual(vipbridge.socket_path("/r"),
                         f"/run/{runtime}/bridge.sock")
        self.assertIsNotNone(vipnode.boottime())
