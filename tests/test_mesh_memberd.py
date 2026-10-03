# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.memberd: the members' channel, root helper and listener

The root side's answers as a function, the queue of announcements, the
bridge's messages, the listener's unit, and the whole path in one
process: the root helper and the unprivileged listener over their unix
socket, a member's pull and announcement over TCP on the loopback, the
announcement applied by the worker.
"""

import base64
import json
import os
import shutil
import socket
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from unittest import mock

from mesh_helpers import INVITER, JOINER, OTHER
from mesh_sync_helpers import Case, admitted, inviter_roster
from test_network_window import Recorder

from keel import exits
from keel.mesh import memberd, memberlink, members, signing
from keel.mesh.bridge import BridgeError
from keel.mesh.memberd import Members, Pending


def roster(key=INVITER):
    return members.Roster(None, key, key, "fd00:6b65:1::1", ())


class TestPending(unittest.TestCase):
    def test_given_once_it_settled(self):
        now = [100.0]
        found = Pending(settle=10, clock=lambda: now[0])
        found.put("a", roster())
        self.assertEqual(found.take(0.01), [])
        now[0] += 5
        found.put("b", roster())
        now[0] += 9
        self.assertEqual(found.take(0.01), [])
        now[0] += 1
        self.assertEqual([one for one, _ in found.take(0.01)], ["a", "b"])

    def test_the_latest_per_sender_bounded(self):
        found = Pending(limit=2, settle=0)
        self.assertTrue(found.put("a", roster(INVITER)))
        self.assertTrue(found.put("a", roster(JOINER)))
        self.assertTrue(found.put("b", roster()))
        self.assertFalse(found.put("c", roster()))
        self.assertTrue(found.put("b", roster()))
        taken = found.take(0)
        self.assertEqual([(source, one.public_key) for source, one in taken],
                         [("a", JOINER), ("b", INVITER)])
        self.assertEqual(found.take(0.01), [])


class TestMembers(unittest.TestCase):
    def setUp(self):
        self.logged = []
        self.pending = Pending(limit=1, settle=0)
        self.roster = roster()
        self.handler = Members(self.give, self.member_of, self.pending,
                               self.logged.append)

    def give(self):
        if self.roster is None:
            raise ValueError("no key")
        return self.roster

    @staticmethod
    def member_of(source):
        return {"fd00::1": INVITER, "fd00::3": JOINER}.get(source)

    def body(self, key=INVITER):
        return members.dumps(roster(key))

    def test_answers(self):
        for args, status in (
                (("GET", "/v1/members", b"", "fd00::9"), 403),
                (("GET", "/v1/members", b"", "fd00::1"), 200),
                (("PUT", "/v1/members", b"", "fd00::1"), 404),
                (("POST", "/v1/announce", None, "fd00::1"), 404),
                (("POST", "/v1/announce", b"{}", "fd00::1"), 400),
                (("POST", "/v1/announce", self.body(JOINER), "fd00::1"),
                 403),
                (("POST", "/v1/announce", self.body(), "fd00::1"), 202),
                (("POST", "/v1/announce", self.body(JOINER), "fd00::3"),
                 503)):
            with self.subTest(args=args[:2] + args[3:]):
                self.assertEqual(self.handler.handle(*args).status, status)
        self.roster = None
        self.assertEqual(self.handler.handle("GET", "/v1/members", b"",
                                             "fd00::1").status, 503)
        self.assertIn("not a peer of this node", self.logged[0])

    def test_the_bridge_s_messages(self):
        found = memberd.answered(self.handler, json.dumps({
            "op": "member", "method": "GET", "path": "/v1/members",
            "body": base64.b64encode(b"").decode(),
            "source": "fd00::1"}).encode())
        self.assertEqual(found["status"], 200)
        found = memberd.answered(self.handler, json.dumps({
            "op": "member", "method": "POST", "path": "/v1/announce",
            "body": None, "source": "fd00::1"}).encode())
        self.assertEqual(found["status"], 404)
        for data in (b"x", b"{}", json.dumps({"op": "member"}).encode(),
                     json.dumps({"op": "member", "method": "GET",
                                 "path": "/", "body": "!",
                                 "source": "fd00::1"}).encode(),
                     json.dumps({"op": "member", "method": "GET",
                                 "path": "/", "body": None,
                                 "source": "x"}).encode()):
            with self.subTest(data=data), self.assertRaises(BridgeError):
                memberd.answered(self.handler, data)


class TestRemote(unittest.TestCase):
    def test_a_question_and_the_root_side_gone(self):
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        stop = threading.Event()
        remote = memberd.Remote(ours, stop)

        def root():
            memberd.line(theirs)
            memberd.send(theirs, {"status": 200, "body": base64.b64encode(
                b"ok").decode()})
            memberd.line(theirs)
            theirs.close()
        thread = threading.Thread(target=root)
        thread.start()
        found = remote.handle("GET", "/v1/members", b"", "fd00::1")
        self.assertEqual((found.status, found.body), (200, b"ok"))
        found = remote.handle("POST", "/v1/announce", None, "fd00::1")
        thread.join(5)
        self.assertEqual(found.status, 503)
        self.assertTrue(stop.is_set())
        ours.close()
        self.assertEqual(remote.handle("GET", "/v1/members", b"",
                                       "fd00::1").status, 503)


class TestMessage(unittest.TestCase):
    def test_a_message_the_end_and_a_stop(self):
        ours, theirs = socket.socketpair()
        self.addCleanup(ours.close)
        stop = threading.Event()
        theirs.sendall(b'{"a": 1}\n\n{"b"')
        self.assertEqual(memberd.message(ours, stop, 0.01), b'{"a": 1}\n')
        self.assertEqual(memberd.message(ours, stop, 0.01), b"\n")
        theirs.close()
        # a message cut short, then the end
        self.assertIsNone(memberd.message(ours, stop, 0.01))
        self.assertIsNone(memberd.message(ours, stop, 0.01))
        ours2, theirs2 = socket.socketpair()
        self.addCleanup(ours2.close)
        self.addCleanup(theirs2.close)
        threading.Timer(0.05, stop.set).start()
        self.assertIsNone(memberd.message(ours2, stop, 0.01))


class TestUnit(unittest.TestCase):
    def test_the_listener_runs_as_a_sandboxed_transient_unit(self):
        run = Recorder()
        found = memberd.start_unit("/run/keel/mesh-members/bridge.sock", run,
                                   lambda argv: "42\n")
        self.assertEqual(run.calls[0], ("systemctl", "stop",
                                        "keel-mesh-members-listen"))
        argv = run.calls[1]
        self.assertIn("--property=DynamicUser=yes", argv)
        self.assertIn("--property=CapabilityBoundingSet=", argv)
        self.assertIn("--property=RuntimeDirectory=keel/mesh-members", argv)
        self.assertIn("--property=RuntimeDirectoryMode=0700", argv)
        self.assertEqual(argv[-2:], ("members-listen",
                                     "/run/keel/mesh-members/bridge.sock"))
        self.assertTrue(found.trusted(42, 61000))
        self.assertFalse(found.trusted(42, 0))

    def test_a_unit_that_cannot_start(self):
        with self.assertRaises(BridgeError):
            memberd.start_unit("/x", lambda argv: "failed"
                               if argv[0] == "systemd-run" else None,
                               lambda argv: None)


def status_file(text: str) -> str:
    fd, found = tempfile.mkstemp()
    with os.fdopen(fd, "w") as fob:
        fob.write(text)
    return found


class TestListen(unittest.TestCase):
    def setUp(self):
        self.logged = []
        self.clean = status_file("CapEff:\t0000000000000000\n")
        self.addCleanup(os.remove, self.clean)

    def listen(self, status, **kwargs):
        return memberd.listen("/nonexistent/x.sock",
                              lambda: datetime.now(timezone.utc),
                              self.logged.append, status=status, **kwargs)

    def test_a_listener_with_capabilities_refuses_to_run(self):
        caps = status_file("CapEff:\t0000000000003000\n")
        self.addCleanup(os.remove, caps)
        self.assertEqual(self.listen(caps), exits.APPLY_FAILED)
        self.assertIn("without capabilities", self.logged[0])

    def test_no_root_helper(self):
        with mock.patch("keel.mesh.memberd.bridge.helper",
                        return_value=None):
            self.assertEqual(self.listen(self.clean), exits.APPLY_FAILED)
        self.assertIn("no root helper", self.logged[0])

    def test_parameters_it_cannot_use(self):
        for sent in (b"", b"x\n", b'{"iface": "lo"}\n'):
            ours, theirs = socket.socketpair()
            theirs.sendall(sent)
            theirs.close()
            with self.subTest(sent=sent), \
                    mock.patch("keel.mesh.memberd.bridge.helper",
                               return_value=ours):
                self.assertEqual(self.listen(self.clean),
                                 exits.APPLY_FAILED)
        self.assertIn("no parameters", self.logged[-1])


class Started:
    """The listener's unit, as a thread of this process"""

    def __init__(self, path, status, stop):
        self.stop_listener = stop
        self.thread = threading.Thread(target=memberd.listen, args=(
            path, lambda: datetime.now(timezone.utc), lambda line: None,
            status, 0.05, stop))
        self.thread.start()
        self.stopped = False

    def trusted(self, pid, uid):
        return pid == os.getpid()

    def stop(self):
        self.stopped = True


def free_port() -> int:
    with socket.socket(socket.AF_INET6) as found:
        found.bind(("::1", 0))
        return found.getsockname()[1]


class TestTheWholePath(Case):
    def setUp(self):
        super().setUp()
        self.run_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.run_dir)
        self.status = status_file("CapEff:\t0000000000000000\n")
        self.addCleanup(os.remove, self.status)

    def test_a_pull_and_an_announcement_through_both_processes(self):
        port = free_port()
        stop, listener_stop = threading.Event(), threading.Event()
        started = []

        def start(path):
            started.append(Started(path, self.status, listener_stop))
            return started[0]
        codes = []
        member = mock.patch("keel.mesh.memberd.sync.member_of",
                            side_effect=lambda node, source:
                            INVITER if source == "::1" else None)
        member.start()
        self.addCleanup(member.stop)
        root = threading.Thread(target=lambda: codes.append(memberd.serve(
            self.syncer, stop, start=start, where=lambda: ("lo", "::1"),
            port=port, path=os.path.join(self.run_dir, "bridge.sock"),
            settle=0.1)))
        root.start()
        for _ in range(200):
            try:
                found = memberlink.fetch("::1", "lo", port)
                break
            except memberlink.LinkError:
                stop.wait(0.05)
        self.assertEqual(found.public_key, JOINER)
        self.assertEqual(found.sign_key, self.signer)
        memberlink.tell("::1", "lo", inviter_roster(admitted()), port)
        for _ in range(200):
            if len(self.peers()) == 2:
                break
            stop.wait(0.05)
        self.assertEqual(self.peers()[1]["public_key"], OTHER)
        # the root helper's stop ends it between messages
        stop.set()
        root.join(10)
        listener_stop.set()
        started[0].thread.join(10)
        self.assertEqual(codes, [exits.OK])
        self.assertTrue(started[0].stopped)
        self.assertIn("an announcement from ::1: 2 member(s)", self.err)

    def test_no_signing_key_no_overlay_no_listener(self):
        with mock.patch("keel.mesh.memberd.signing.ensure",
                        side_effect=signing.SigningError("no openssl")):
            self.assertEqual(memberd.serve(self.syncer, threading.Event()),
                             exits.APPLY_FAILED)
        stop = threading.Event()
        threading.Timer(0.1, stop.set).start()
        with open(self.node.path, "w") as fob:
            fob.write("version: 1\n")
        with mock.patch("keel.mesh.memberd.WAIT_OVERLAY", 0.02):
            self.assertEqual(memberd.serve(self.syncer, stop), exits.OK)

        def fail(path):
            raise BridgeError("the listener could not start: no systemd")
        self.assertEqual(memberd.serve(self.syncer, threading.Event(),
                                       start=fail,
                                       where=lambda: ("lo", "::1")),
                         exits.APPLY_FAILED)
        self.assertIn("no systemd", self.err[-1])

    def test_the_default_listener_is_its_unit(self):
        with mock.patch("keel.mesh.memberd.start_unit",
                        side_effect=BridgeError("x")) as started:
            memberd.serve(self.syncer, threading.Event(),
                          where=lambda: ("lo", "::1"))
        self.assertEqual(started.call_args.args[0],
                         memberd.socket_path(self.root))


if __name__ == "__main__":
    unittest.main()
