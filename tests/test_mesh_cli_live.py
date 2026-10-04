# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh create, join, accept, serve, status through keel.cli.main

The handlers are thin: root on the live system, the token or the line
read (from standard input with -), the live Node built, and the flow
called. Each flow is replaced here at its seam (keel.mesh.joining.run,
inviting.accept, ...) and tested on its own in test_mesh_joining.py,
test_mesh_inviting.py and test_mesh_create_status.py.
"""

import shutil
import signal
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from os.path import join
from unittest import mock

from mesh_helpers import NOW, reserved
from mesh_wire import token
from test_mesh_cli import run_cli

from keel import exits
from keel.mesh import commands, identity, invites, inviting
from keel.mesh.endpoint import Choice
from keel.mesh.token import encode
from keel.network import session

SPEC = """\
version: 1
network:
  interfaces:
    eth0:
      ipv6: {method: static, address: '2001:db8:2::20/64'}
"""


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.spec = join(self.root, "instance.yaml")
        with open(self.spec, "w") as fob:
            fob.write(SPEC)
        clients = mock.patch("keel.mesh.commands.operator_clients",
                             return_value=("2001:db8:9::5",))
        clients.start()
        self.addCleanup(clients.stop)

    def mesh(self, *argv, stdin=""):
        return run_cli("mesh", *argv, "--spec", self.spec, "--root",
                       self.root, stdin=stdin)

    def line(self):
        invite = reserved(self.root)
        return encode(token(invite, expires=datetime.now(timezone.utc)
                            + timedelta(hours=1)))


class TestNeedsRoot(Case):
    def test_each_command_that_changes_the_machine(self):
        for argv in (("create",), ("accept", "keel1a:x"),
                     ("serve", "0123456789abcdef"),
                     ("join", "keel1:x"), ("sync",), ("members",),
                     ("create", "--adopt"), ("remove", "fd00::7")):
            with self.subTest(argv=argv), \
                    mock.patch("os.geteuid", return_value=1000):
                code, out, err = run_cli("mesh", *argv)
                self.assertEqual((code, out), (exits.APPLY_NEEDS_ROOT, ""))
                self.assertIn("must run as root", err)


class TestHandlers(Case):
    def test_create(self):
        with mock.patch("keel.mesh.commands.create.create",
                        return_value=exits.OK) as made:
            code, _, _ = self.mesh("create", "--network-window", "60")
        self.assertEqual(code, exits.OK)
        node = made.call_args.args[0]
        self.assertEqual((node.root, node.path, node.window, node.clients),
                         (self.root, self.spec, 60, ("2001:db8:9::5",)))

    def test_join(self):
        line = self.line()
        with mock.patch("keel.mesh.commands.joining.run",
                        return_value=exits.OK) as joined, \
                mock.patch("keel.mesh.commands.live.output",
                           return_value=""):
            code, _, err = self.mesh("join", line)
        self.assertEqual(code, exits.OK, err)
        joiner, endpoint = joined.call_args.args
        self.assertEqual(endpoint, "2001:db8:2::20")
        self.assertEqual(joiner.token.invite_id,
                         invites.ids(self.root)[0])
        self.assertIsInstance(joiner.clock(), datetime)

    def test_join_reads_the_token_from_standard_input(self):
        line = self.line()
        with mock.patch("keel.mesh.commands.joining.run",
                        return_value=exits.OK) as joined, \
                mock.patch("keel.mesh.commands.live.output",
                           return_value=None):
            code, _, _ = self.mesh("join", "-", "--endpoint", "2001:db8::7",
                                   stdin=line)
        self.assertEqual(code, exits.OK)
        self.assertEqual(joined.call_args.args[1], "2001:db8::7")

    def test_a_token_given_as_an_argument_is_warned_about(self):
        line = self.line()
        with mock.patch("keel.mesh.commands.joining.run",
                        return_value=exits.OK), \
                mock.patch("keel.mesh.commands.live.output",
                           return_value=""):
            _, _, err = self.mesh("join", line)
        self.assertIn("Warning: the token is an argument, so it shows in"
                      " the process list", err)
        with mock.patch("keel.mesh.commands.joining.run",
                        return_value=exits.OK), \
                mock.patch("keel.mesh.commands.live.output",
                           return_value=""):
            _, _, err = self.mesh("join", "-", stdin=line)
        self.assertNotIn("Warning", err)

    def test_join_finds_its_endpoint_on_the_uplink(self):
        with open(self.spec, "w") as fob:
            fob.write("version: 1\n")
        found = Choice(("2001:db8:7::9",), ("endpoint 2001:db8:7::9, found"
                                            " on eth0",))
        with mock.patch("keel.mesh.commands.joining.run",
                        return_value=exits.OK) as joined, \
                mock.patch("keel.mesh.commands.endpoint.detect",
                           return_value=found):
            code, _, err = self.mesh("join", "-", stdin=self.line())
        self.assertEqual(code, exits.OK)
        self.assertEqual(joined.call_args.args[1], "2001:db8:7::9")
        self.assertIn("endpoint 2001:db8:7::9, found on eth0", err)

    def test_join_without_an_endpoint_says_why(self):
        with open(self.spec, "w") as fob:
            fob.write("version: 1\n")
        found = Choice((), (), ("10.0.0.5 is a private address",))
        with mock.patch("keel.mesh.commands.joining.run",
                        return_value=exits.OK) as joined, \
                mock.patch("keel.mesh.commands.endpoint.detect",
                           return_value=found):
            code, _, err = self.mesh("join", "-", stdin=self.line())
        self.assertEqual(code, exits.OK)
        self.assertIsNone(joined.call_args.args[1])
        self.assertIn("no endpoint is sent, as from a node behind NAT:"
                      " 10.0.0.5 is a private address", err)

    def test_listen_needs_no_root(self):
        with mock.patch("os.geteuid", return_value=61234), \
                mock.patch("keel.mesh.commands.bridge.listen",
                           return_value=exits.OK) as listened:
            code, _, _ = run_cli("mesh", "listen", "/run/keel/mesh/x.sock")
        self.assertEqual(code, exits.OK)
        self.assertEqual(listened.call_args.args[0], "/run/keel/mesh/x.sock")

    def test_join_with_a_bad_token_or_endpoint(self):
        code, _, err = self.mesh("join", "keel1:abc")
        self.assertEqual(code, exits.MESH_TOKEN_INVALID)
        code, _, err = self.mesh("join", self.line(), "--endpoint", "x")
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("does not appear to be an IPv4 or IPv6", err)

    def test_accept(self):
        with mock.patch("keel.mesh.commands.inviting.accept",
                        return_value=exits.OK) as accepted:
            self.assertEqual(self.mesh("accept", "-",
                                       stdin="keel1a:x")[0], exits.OK)
        inviter, text = accepted.call_args.args
        self.assertEqual(text, "keel1a:x")
        self.assertEqual(inviter.node.root, self.root)
        self.assertEqual(inviter.clock().tzinfo, timezone.utc)

    def test_serve(self):
        """SIGTERM, from systemctl stop or RuntimeMaxSec, ends it through
        the cleanup that removes the invite"""
        before = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, before)
        with mock.patch("keel.mesh.commands.inviting.serve_invite",
                        return_value=exits.OK) as served:
            code, _, _ = self.mesh("serve", "0123456789abcdef")
        self.assertEqual(code, exits.OK)
        self.assertEqual(served.call_args.args[1], "0123456789abcdef")
        self.assertEqual(signal.getsignal(signal.SIGTERM),
                         inviting.terminated)

    def test_sync(self):
        with mock.patch("keel.mesh.commands.sync.pull",
                        return_value=exits.OK) as pulled:
            self.assertEqual(self.mesh("sync")[0], exits.OK)
            self.assertEqual(self.mesh("sync", "--from", "fd00:6b65:1::01",
                                       "--from", "fd00:6b65:1::7")[0],
                             exits.OK)
        syncer, hosts = pulled.call_args_list[0].args
        self.assertEqual((syncer.node.root, hosts), (self.root, ()))
        self.assertEqual(pulled.call_args_list[1].args[1],
                         ("fd00:6b65:1::1", "fd00:6b65:1::7"))

    def test_sync_adopt(self):
        with mock.patch("keel.mesh.commands.adopt.adopt_from",
                        return_value=exits.OK) as adopted:
            self.assertEqual(self.mesh("sync", "--adopt",
                                       "fd00:6b65:1::1")[0], exits.OK)
        self.assertEqual(adopted.call_args.args[1], "fd00:6b65:1::1")

    def test_sync_with_an_address_that_is_not_an_overlay_one(self):
        for argv in (("--from", "x"), ("--adopt", "192.0.2.1")):
            with self.subTest(argv=argv):
                code, _, err = self.mesh("sync", *argv)
                self.assertEqual(code, exits.MESH_REFUSED)
                self.assertIn("not an IPv6 address", err)

    def test_members(self):
        """the root helper, until SIGTERM sets its stop and ends it
        through its cleanup"""
        before = signal.getsignal(signal.SIGTERM)
        self.addCleanup(signal.signal, signal.SIGTERM, before)

        def serve(syncer, stop):
            with self.assertRaises(SystemExit):
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            self.assertTrue(stop.is_set())
            return exits.OK
        with mock.patch("keel.mesh.commands.memberd.serve",
                        side_effect=serve) as served:
            self.assertEqual(self.mesh("members")[0], exits.OK)
        self.assertEqual(served.call_args.args[0].node.root, self.root)

    def test_members_listen_needs_no_root(self):
        with mock.patch("os.geteuid", return_value=61234), \
                mock.patch("keel.mesh.commands.memberd.listen",
                           return_value=exits.OK) as listened:
            code, _, _ = run_cli("mesh", "members-listen",
                                 "/run/keel/mesh-members/bridge.sock")
        self.assertEqual(code, exits.OK)
        self.assertEqual(listened.call_args.args[0],
                         "/run/keel/mesh-members/bridge.sock")

    def test_remove(self):
        with mock.patch("keel.mesh.commands.remove.remove",
                        return_value=exits.OK) as removed:
            self.assertEqual(self.mesh("remove", "fd00::7")[0], exits.OK)
        syncer, which, _ = removed.call_args.args
        self.assertEqual((syncer.node.root, which), (self.root, "fd00::7"))

    def test_create_adopt(self):
        with mock.patch("keel.mesh.commands.adopt.adopt_mesh",
                        return_value=exits.OK) as adopted, \
                mock.patch("keel.mesh.commands.create.create") as made:
            self.assertEqual(self.mesh("create", "--adopt")[0], exits.OK)
        made.assert_not_called()
        self.assertEqual(adopted.call_args.args[0].node.root, self.root)

    def test_the_identity_of_an_invite(self):
        with mock.patch("keel.mesh.commands.adopt.invite_identity",
                        return_value=bytes(16)) as asked:
            made = commands.invite_identity(self.root, self.spec)
            self.assertEqual(made, identity.read(self.root))
            asked.assert_not_called()
            with mock.patch("keel.mesh.commands.ROOT_DEFAULT", self.root):
                self.assertEqual(commands.invite_identity(self.root,
                                                          self.spec),
                                 bytes(16))
        self.assertEqual(asked.call_args.args[0].node.path, self.spec)

    def test_status(self):
        with open(self.spec, "a") as fob:
            fob.write("  overlay:\n    wireguard:\n"
                      "      address: fd00:6b65:1::1/64\n")
        code, out, _ = self.mesh("status")
        self.assertEqual(code, exits.OK)
        self.assertIn("this node: fd00:6b65:1::1/64 on wg0", out)
        self.assertIn("not the live system", out)

    def test_status_without_a_spec_or_with_a_broken_one(self):
        code, out, _ = run_cli("mesh", "status", "--spec",
                               join(self.root, "none.yaml"), "--root",
                               self.root)
        self.assertEqual(code, exits.OK)
        self.assertIn("in no mesh", out)
        with open(self.spec, "w") as fob:
            fob.write("version: [")
        self.assertEqual(self.mesh("status")[0], exits.SPEC_UNREADABLE)

    def test_status_on_the_live_system_asks_wg(self):
        with mock.patch("keel.mesh.commands.ROOT_DEFAULT", self.root), \
                mock.patch("keel.mesh.commands.live.output",
                           return_value=None) as asked:
            self.mesh("status")
        self.assertEqual(asked.call_count, 0)
        with open(self.spec, "a") as fob:
            fob.write("  overlay:\n    wireguard:\n"
                      "      address: fd00:6b65:1::1/64\n")
        with mock.patch("keel.mesh.commands.ROOT_DEFAULT", self.root), \
                mock.patch("keel.mesh.commands.live.output",
                           return_value=None) as asked:
            self.mesh("status")
        self.assertGreater(asked.call_count, 0)


class TestListening(Case):
    def test_the_unit_started_and_the_port_opened(self):
        made = reserved(self.root)
        with mock.patch("keel.mesh.commands.inviting.start",
                        return_value=None) as started, \
                mock.patch("keel.mesh.commands.ports.open_port",
                           return_value="opened") as opened:
            found = commands.listening(made, "spec.yaml", "/", NOW)
        self.assertEqual(found, ("opened", exits.OK))
        self.assertTrue(started.call_args.args[1].endswith("/spec.yaml"))
        # as long as the listener may wait for a late join's confirmation
        self.assertEqual(opened.call_args.args[:2],
                         (51820, 3600 + inviting.LINGER))

    def test_a_unit_that_cannot_start_removes_the_invite(self):
        made = reserved(self.root)
        with mock.patch("keel.mesh.commands.inviting.start",
                        return_value="systemd-run exited 1"), \
                mock.patch("keel.mesh.commands.invites.remove") as removed:
            found = commands.listening(made, "spec.yaml", "/", NOW)
        self.assertEqual(found, ("", exits.APPLY_FAILED))
        removed.assert_called_once_with("/", made.invite_id)

    def test_off_the_live_system_nothing_starts(self):
        made = reserved(self.root)
        text, code = commands.listening(made, "spec.yaml", self.root, NOW)
        self.assertEqual(code, exits.OK)
        self.assertIn("no listener started", text)


class TestOperatorClients(unittest.TestCase):
    def test_the_client_of_this_ssh_session(self):
        for origin, found in (
                (session.Origin(session.SSH, "ssh", 1.0, "2001:db8::1",
                                "2001:db8::9"), ("2001:db8::9",)),
                (session.Origin(session.CONSOLE_KIND, "tty1"), ())):
            with self.subTest(kind=origin.kind), \
                    mock.patch("keel.mesh.commands.session.origin",
                               return_value=origin):
                self.assertEqual(commands.operator_clients(), found)

    def test_out_and_err(self):
        with mock.patch("builtins.print") as printed:
            commands.out("a")
            commands.err("b")
        self.assertEqual(printed.call_count, 2)


if __name__ == "__main__":
    unittest.main()
