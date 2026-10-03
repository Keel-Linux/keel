# Copyright (c) 2026 KeelLinux maintainers
"""The bridge between the unprivileged listener and the root side

The whole path in one process: Bridge.run binds its unix socket and
"starts" the listener as a thread running keel.mesh.bridge.listen, which
receives its parameters and the invite's certificate and TLS key as
memfds over SCM_RIGHTS, serves real TLS on [::1], and forwards to the
Admitter; then each refusal of the bridge: a peer that is not the
listener, one that never connects, messages it should not send, a
listener with capabilities. And the unit the listener runs as.
"""

import base64
import json
import os
import shutil
import socket
import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest import mock

from mesh_helpers import (
    INVITER,
    KEY,
    OWN,
    FakeNode,
    confirm_body,
    join_body,
    reserved,
    signature,
)
from test_mesh_channel import free_port
from test_network_window import Recorder

from keel import exits
from keel.mesh import bridge, certificate, channel, protocol
from keel.mesh.admit import Admitter
from keel.mesh.bridge import Bridge, BridgeError, Remote, Unit
from keel.mesh.channel import Refused
from keel.mesh.listener import Params

NO_CAPABILITIES = "Name:\tpython3\nCapEff:\t0000000000000000\n"


class Started:
    """The listener as a thread of this process"""

    def __init__(self, status, trust=True):
        self.status = status
        self.trust = trust
        self.stopped = False
        self.codes = []
        self.logged = []

    def __call__(self, path):
        self.thread = threading.Thread(target=lambda: self.codes.append(
            bridge.listen(path, lambda: datetime.now(timezone.utc),
                          self.logged.append, self.status, poll=0.05)),
            daemon=True)
        self.thread.start()
        return self

    def trusted(self, pid, uid):
        return self.trust and pid == os.getpid()

    def stop(self):
        self.stopped = True


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.status = os.path.join(self.root, "status")
        with open(self.status, "w") as fob:
            fob.write(NO_CAPABILITIES)
        self.port = free_port()
        now = datetime.now(timezone.utc)
        self.invite = reserved(self.root, port=self.port,
                               expires=now + timedelta(hours=1))
        self.node = FakeNode()
        self.logged = []
        self.admitter = Admitter(self.root, self.invite, INVITER, OWN,
                                 self.node, lambda: now, self.logged.append)
        self.params = Params(self.invite.invite_id,
                             self.invite.expires, "::", self.port,
                             "fd00:6b65:1::1")

    def bridge(self, started):
        return Bridge(self.admitter, self.params, self.invite.certificate,
                      self.invite.tls_key,
                      bridge.socket_path(self.root, self.invite.invite_id),
                      started, self.logged.append)

    def post(self, body=None, key=KEY):
        now = protocol.seconds(datetime.now(timezone.utc))
        return channel.post(
            "::1", self.port, protocol.JOIN,
            join_body(time=now) if body is None else body, key,
            certificate.fingerprint(self.invite.certificate),
            connect_timeout=2, answer_timeout=10)

    def wait_for_port(self):
        """From a source of its own: one connection per source"""
        for _ in range(200):
            try:
                socket.create_connection(
                    ("127.0.0.1", self.port), 0.1,
                    source_address=("127.0.0.9", 0)).close()
                return
            except OSError:
                threading.Event().wait(0.02)
        self.fail("the listener never bound its port")


class TestTheWholePath(Case):
    def run_bridge(self):
        started = Started(self.status)
        running = threading.Thread(target=self.bridge(started).run,
                                   daemon=True)
        running.start()
        self.wait_for_port()
        return started, running

    def ended(self, started, running):
        running.join(10)
        self.assertFalse(running.is_alive())
        self.assertEqual(started.codes, [exits.OK])
        self.assertTrue(started.stopped)
        self.assertFalse(os.path.exists(bridge.socket_path(
            self.root, self.invite.invite_id)))
        self.assertIn("without capabilities", started.logged[0])
        self.assertIn("the listener (pid", self.logged[0])

    def test_a_join_through_the_unprivileged_side(self):
        # a window of a second: the listener stops waiting soon after
        self.node.made = replace(self.node.made, window=1)
        started, running = self.run_bridge()
        answer = protocol.join_answer(self.post().body)
        self.assertEqual((answer.public_key, answer.window), (INVITER, 1))
        self.assertEqual(len(self.node.admitted), 1)
        self.ended(started, running)

    def test_forged_requests_cancel_the_invite_through_it(self):
        started, running = self.run_bridge()
        for _ in range(5):
            with self.assertRaises(Refused):
                self.post(key=bytes(32))
        self.ended(started, running)
        self.assertTrue(self.admitter.cancelled)
        self.assertEqual(self.node.admitted, [])


class TestRefused(Case):
    def test_a_peer_that_is_not_the_listener_is_skipped(self):
        started = Started(self.status, trust=False)
        with mock.patch.object(bridge, "CONNECT_WAIT", 0.5), \
                self.assertRaises(BridgeError) as caught:
            self.bridge(started).run()
        self.assertIn("did not connect", str(caught.exception))
        self.assertIn("skipped process", self.logged[0])
        self.assertTrue(started.stopped)

    def test_a_listener_that_never_binds(self):
        idle = mock.Mock()
        with mock.patch.object(bridge, "CONNECT_WAIT", 0.1), \
                self.assertRaises(BridgeError) as caught:
            self.bridge(lambda path: idle).run()
        self.assertIn("did not connect", str(caught.exception))
        idle.stop.assert_called_once_with()

    def test_a_listener_no_helper_comes_to(self):
        logged = []
        path = bridge.socket_path(self.root, self.invite.invite_id)
        with mock.patch.object(bridge, "CONNECT_WAIT", 0.1):
            self.assertEqual(bridge.listen(path, None, logged.append,
                                           self.status), exits.APPLY_FAILED)
        self.assertIn("no root helper came", logged[0])

    def test_the_listener_s_socket_is_its_own(self):
        path = bridge.socket_path(self.root, self.invite.invite_id)
        modes = []

        def connect():
            while not os.path.exists(path):
                threading.Event().wait(0.01)
            modes.append(os.stat(path).st_mode & 0o777)
            modes.append(os.stat(os.path.dirname(path)).st_mode & 0o777)
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(path)
                client.recv(1)
        threading.Thread(target=connect, daemon=True).start()
        with bridge.helper(path, os.getuid()) as conn:
            self.assertIsNotNone(conn)
        self.assertEqual(modes, [0o600, 0o700])
        self.assertFalse(os.path.exists(path))

    def test_a_helper_neither_root_nor_itself_is_dropped(self):
        if os.getuid() == 0:
            self.skipTest("as root, every peer is root")
        path = bridge.socket_path(self.root, self.invite.invite_id)

        def connect():
            while not os.path.exists(path):
                threading.Event().wait(0.01)
            with socket.socket(socket.AF_UNIX) as client:
                client.connect(path)
                client.recv(1)
        threading.Thread(target=connect, daemon=True).start()
        with mock.patch.object(bridge, "CONNECT_WAIT", 0.3):
            self.assertIsNone(bridge.helper(path, os.getuid() + 1))

    def test_a_listener_with_capabilities_refuses_to_run(self):
        with open(self.status, "w") as fob:
            fob.write("CapEff:\t000001ffffffffff\n")
        logged = []
        self.assertEqual(bridge.listen("/nonexistent", None, logged.append,
                                       self.status), exits.APPLY_FAILED)
        self.assertIn("without capabilities", logged[0])
        self.assertIn("0x1ffffffffff", logged[0])

    def test_messages_the_listener_should_not_send(self):
        for data in (b"not json\n", b'{"op": "rm"}\n',
                     b'{"op": "cancel", "reason": "x"}\n',
                     b'{"op": "forward", "path": "/v1/join"}\n',
                     b'{"op": "forward", "path": "/v1/join", "body": "@",'
                     b' "local": "::1", "peer": "::1"}\n',
                     b'{"op": "forward", "path": "/v1/join", "body": null,'
                     b' "local": "x", "peer": "::1"}\n'):
            with self.subTest(data=data):
                with self.assertRaises(BridgeError):
                    bridge.answered(self.admitter, data)
        self.assertFalse(self.admitter.cancelled)

    def test_a_forward(self):
        found = bridge.answered(self.admitter, json.dumps({
            "op": "forward", "path": "/v1/join", "signature": None,
            "body": None, "local": "::1", "peer": "::1"}).encode())
        self.assertEqual((found["status"], found["final"]), (413, False))

    def test_a_lying_listener_gets_nothing_through_the_bridge(self):
        """It forges a join with a key of its choosing, and a confirmation
        with the addresses the tunnel would have: neither is taken"""
        forged = join_body(public_key="9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8"
                           "nDjKohEE=")
        found = bridge.answered(self.admitter, json.dumps({
            "op": "forward", "path": "/v1/join", "signature": "00" * 32,
            "body": base64.b64encode(forged).decode(), "local": "::1",
            "peer": "::1"}).encode())
        self.assertEqual(found["status"], 403)
        self.assertEqual(self.node.admitted, [])
        self.admitter.forward(protocol.JOIN, signature(
            protocol.JOIN, join_body()), join_body(), "::", "::1")
        self.node.handshake_at = None
        self.admitter.sleep = lambda seconds: None
        body = confirm_body()
        found = bridge.answered(self.admitter, json.dumps({
            "op": "forward", "path": "/v1/confirm",
            "signature": signature(protocol.CONFIRM, body),
            "body": base64.b64encode(body).decode(),
            "local": "fd00:6b65:1::1", "peer": "fd00:6b65:1::3"}).encode())
        self.assertEqual(found["status"], 409)
        self.assertEqual(self.node.origins, [])

    def test_a_message_longer_than_the_cap(self):
        left, right = socket.socketpair()
        with left, right:
            right.sendall(b"x" * 64)
            with mock.patch.object(bridge, "MAX_MESSAGE", 16), \
                    self.assertRaises(BridgeError):
                bridge.line(left)


class TestRemote(unittest.TestCase):
    def test_the_root_side_gone(self):
        left, right = socket.socketpair()
        right.close()
        with left:
            found = Remote(left).forward("/v1/join", None, b"{}", "::1",
                                         "::1")
            self.assertEqual(found.status, 503)

    def test_the_root_side_closed_its_end(self):
        left, right = socket.socketpair()
        with left, right:
            right.shutdown(socket.SHUT_WR)
            self.assertEqual(Remote(left).forward(
                "/v1/join", None, b"{}", "::1", "::1").status, 503)

    def test_a_closed_socket(self):
        left, right = socket.socketpair()
        right.close()
        left.close()
        self.assertEqual(Remote(left).forward("/", None, None, "::1",
                                              "::1").status, 503)


class TestUnit(unittest.TestCase):
    def test_the_listener_s_unit_is_unprivileged_and_sandboxed(self):
        run = Recorder()
        found = bridge.start_unit("0123456789abcdef", "/run/x.sock", 60, run,
                                  lambda argv: None)
        [argv] = run.calls
        self.assertEqual(argv[:5], (
            "systemd-run", "--unit=keel-mesh-listen@0123456789abcdef",
            "--collect", "--quiet", "--property=RuntimeMaxSec=60"))
        for one in ("DynamicUser=yes", "NoNewPrivileges=yes",
                    "PrivateTmp=yes", "ProtectSystem=strict",
                    "ProtectHome=yes", "CapabilityBoundingSet=",
                    "AmbientCapabilities=", "SystemCallFilter=@system-service",
                    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
                    "MemoryMax=64M", "LimitNOFILE=64",
                    "RuntimeDirectory=keel/mesh-listen-0123456789abcdef",
                    "RuntimeDirectoryMode=0700"):
            self.assertIn(f"--property={one}", argv)
        self.assertEqual(argv[-3:], ("mesh", "listen", "/run/x.sock"))
        found.stop()
        self.assertEqual(run.calls[-1], (
            "systemctl", "stop", "keel-mesh-listen@0123456789abcdef"))

    def test_the_socket_is_in_the_listener_s_runtime_directory(self):
        self.assertEqual(bridge.socket_path("/", "0123456789abcdef"),
                         "/run/keel/mesh-listen-0123456789abcdef/bridge.sock")

    def test_a_unit_that_cannot_start(self):
        with self.assertRaises(BridgeError):
            bridge.start_unit("0123456789abcdef", "/run/x.sock", 60,
                              Recorder(fail={"systemd-run": 1}),
                              lambda argv: None)

    def test_trusted_only_as_the_unit_s_main_process_and_never_root(self):
        asked = []

        def main_pid(argv):
            asked.append(argv)
            return "4242\n"
        found = Unit("keel-mesh-listen@0123456789abcdef", Recorder(),
                     main_pid)
        self.assertTrue(found.trusted(4242, 61234))
        self.assertEqual(asked[0], (
            "systemctl", "show", "--property=MainPID", "--value",
            "keel-mesh-listen@0123456789abcdef"))
        self.assertFalse(found.trusted(4242, 0))
        self.assertFalse(found.trusted(4243, 61234))
        self.assertFalse(Unit("u", Recorder(), lambda argv: None).trusted(
            4242, 61234))

    def test_the_parameters_round_trip(self):
        until = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
        for joined in (None, ("k", "fd00::3", until)):
            params = Params("0123456789abcdef", until, "::", 51820,
                            "fd00::1", joined)
            self.assertEqual(bridge.params_of(bridge.params_json(params)),
                             params)

    def test_capabilities(self):
        self.assertEqual(bridge.capabilities(NO_CAPABILITIES), 0)
        self.assertEqual(bridge.capabilities("Name: x\n"), -1)


if __name__ == "__main__":
    unittest.main()
