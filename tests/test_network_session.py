# Copyright (c) 2026 KeelLinux maintainers
"""Where keel network confirm runs from, read off a fixture /proc

And the thin live layer (keel.network.live), and the two commands through
the CLI, with the live probes replaced.
"""

import contextlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from os.path import join
from unittest import mock

from helpers import spec  # noqa: F401

from keel import commands, exits
from keel.cli import main
from keel.network import live, marker, session
from keel.system import Effects
from keel.system.actions import SwitchNetwork

TICKS = os.sysconf("SC_CLK_TCK")
SOCKETS = (
    "0 0 [::ffff:192.0.2.20]:22 [::ffff:192.0.2.9]:51000"
    ' users:(("sshd-session",pid=300,fd=4),("sshd-session",pid=301,fd=4))\n'
    "0 0 [2001:db8:1::20%eth0]:443 [2001:db8:9::5]:40000"
    ' users:(("nginx",pid=77,fd=9))\n'
)


class FakeProc:
    def __init__(self, test):
        self.path = tempfile.mkdtemp()
        test.addCleanup(shutil.rmtree, self.path)

    def add(self, pid, comm, ppid, started=1.0, stdin=None):
        base = join(self.path, str(pid))
        os.makedirs(join(base, "fd"))
        rest = ["S", str(ppid)] + ["0"] * 17 + [str(int(started * TICKS))]
        with open(join(base, "stat"), "w") as fob:
            fob.write(f"{pid} ({comm} x) " + " ".join(rest) + " 0 0\n")
        with open(join(base, "comm"), "w") as fob:
            fob.write(comm + "\n")
        if stdin:
            os.symlink(stdin, join(base, "fd", "0"))
        return self


class TestOrigin(unittest.TestCase):
    def test_an_ssh_session_under_sudo_dates_from_its_oldest_sshd(self):
        proc = (FakeProc(self).add(1, "systemd", 0)
                .add(200, "sshd", 1, 5.0)
                .add(300, "sshd-session", 200, 90.0)
                .add(301, "sshd-session", 300, 91.0)
                .add(400, "bash", 301, 92.0)
                .add(500, "sudo", 400, 93.0)
                .add(600, "keel", 500, 94.0))
        found = session.origin(proc.path, 600, lambda: SOCKETS)
        self.assertEqual(found, session.Origin(
            session.SSH, "an SSH session", 90.0, "192.0.2.20", "192.0.2.9"))

    def test_an_ssh_session_whose_socket_is_not_listed(self):
        proc = FakeProc(self).add(1, "systemd", 0).add(
            300, "sshd-session", 1, 90.0).add(600, "keel", 300)
        found = session.origin(proc.path, 600, lambda: None)
        self.assertEqual(found.kind, session.SSH)
        self.assertIsNone(found.local)

    def test_a_process_attached_from_the_host(self):
        proc = FakeProc(self).add(1, "init", 0).add(50, "bash", 0).add(
            60, "keel", 50)
        self.assertEqual(session.origin(proc.path, 60, lambda: "").kind,
                         session.HOST)

    def test_a_console_terminal(self):
        proc = FakeProc(self).add(1, "init", 0).add(
            60, "keel", 1, stdin="/dev/ttyS0")
        found = session.origin(proc.path, 60, lambda: "")
        self.assertEqual((found.kind, found.detail),
                         (session.CONSOLE_KIND, "the console /dev/ttyS0"))

    def test_a_tmux_shell_on_a_pseudo_terminal_is_unknown(self):
        proc = FakeProc(self).add(1, "init", 0).add(20, "tmux: server", 1).add(
            60, "keel", 20, stdin="/dev/pts/3")
        self.assertEqual(session.origin(proc.path, 60, lambda: "").kind,
                         session.UNKNOWN)

    def test_a_vanished_process_ends_the_walk(self):
        proc = FakeProc(self).add(60, "keel", 55)
        self.assertEqual(session.origin(proc.path, 60, lambda: "").kind,
                         session.UNKNOWN)

    def test_addresses_are_made_plain(self):
        self.assertEqual(session.address("[fe80::1%eth0]:22"), "fe80::1")
        self.assertEqual(session.address("192.0.2.5:22"), "192.0.2.5")


def completed(stdout="", code=0, stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class TestLive(unittest.TestCase):
    def patch(self, **kwargs):
        return mock.patch.object(live.subprocess, "run", **kwargs)

    def test_run(self):
        with self.patch(return_value=completed()):
            self.assertIsNone(live.run(("true",)))
        with self.patch(return_value=completed(code=2, stderr="bad\n")):
            self.assertEqual(live.run(("x",)), "x exited 2: bad")
        with self.patch(side_effect=OSError(2, "No such file")):
            self.assertEqual(live.run(("x",)), "cannot run x: No such file")

    def test_output(self):
        with self.patch(return_value=completed("out")):
            self.assertEqual(live.output(("x",)), "out")
        with self.patch(return_value=completed("out", code=1)):
            self.assertIsNone(live.output(("x",)))
        with self.patch(side_effect=OSError(2, "gone")):
            self.assertIsNone(live.output(("x",)))

    def test_addresses_and_sockets(self):
        text = ("2: eth0    inet6 2001:db8:1::20/64 scope global\n"
                "2: eth0    inet 192.0.2.20/24 brd 192.0.2.255 scope global\n"
                "short\n")
        with self.patch(return_value=completed(text)):
            self.assertEqual(live.addresses("eth0"),
                             ["2001:db8:1::20", "192.0.2.20"])
            self.assertEqual(live.sockets(), text)

    def test_route_via(self):
        with self.patch(return_value=completed(
                "2001:db8:9::5 from :: via fe80::2 dev eth0 src x\n")):
            self.assertEqual(live.route_via("2001:db8:9::5"), "fe80::2")
        with self.patch(return_value=completed("192.0.2.9 dev eth0 src x\n")):
            self.assertIsNone(live.route_via("192.0.2.9"))
        with self.patch(return_value=completed("x via\n")):
            self.assertIsNone(live.route_via("x"))

    def test_probes(self):
        found = live.probes()
        self.assertIs(found.route_via, live.route_via)


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class TestCommands(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        os.makedirs(join(self.root, "etc", "network"))
        with open(join(self.root, "etc/network/interfaces"), "w") as fob:
            fob.write("new\n")
        marker.save(self.root, "old\n")
        marker.write(self.root, marker.Pending(
            "eth0", "etc/network/interfaces", 120).up("b1", 1.0))

    def test_confirm_from_a_console(self):
        origin = session.Origin(session.CONSOLE_KIND, "the console tty1")
        with mock.patch.object(commands.session, "origin",
                               return_value=origin), \
                mock.patch.object(commands.live, "run", return_value=None), \
                mock.patch.object(marker, "boot_id", return_value="b1"):
            code, out, _ = run_cli("network", "confirm", "--root", self.root)
        self.assertEqual(code, exits.OK)
        self.assertIn("confirmed from the console tty1", out)

    def test_confirm_refused_exits_21(self):
        origin = session.Origin(session.UNKNOWN, "a tmux shell")
        with mock.patch.object(commands.session, "origin",
                               return_value=origin), \
                mock.patch.object(marker, "boot_id", return_value="b1"):
            code, _, err = run_cli("network", "confirm", "--root", self.root)
        self.assertEqual(code, exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("refused: a tmux shell", err)

    def test_revert_at_boot_and_then_nothing(self):
        code, out, _ = run_cli("network", "revert", "--boot", "--root",
                               self.root)
        self.assertEqual(code, exits.OK)
        self.assertIn("before networking starts", out)
        with open(join(self.root, "etc/network/interfaces")) as fob:
            self.assertEqual(fob.read(), "old\n")

    def test_revert_failure_exits_16(self):
        os.remove(join(self.root, marker.SAVED))
        code, _, err = run_cli("network", "revert", "--root", self.root)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("saved copy", err)

    def test_both_need_root_on_the_live_system(self):
        with mock.patch("os.geteuid", return_value=1000):
            for action in ("confirm", "revert"):
                code, _, err = run_cli("network", action)
                self.assertEqual(code, exits.APPLY_NEEDS_ROOT)
                self.assertIn(f"network {action}", err)

    def test_the_window_and_skip_flags(self):
        for argv, message in (
            (["--network-window", "5"], "at least 30 seconds"),
            (["--network-window", "soon"], "not a number of seconds"),
            (["--skip-network"], "--skip-network requires"),
        ):
            err = io.StringIO()
            with self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(err):
                main(["spec", "apply", *argv])
            self.assertIn(message, err.getvalue())

    def test_effects_carry_a_switch_to_keel_network(self):
        marker.clear(self.root)
        action = SwitchNetwork("eth0", "etc/network/interfaces", "new2\n",
                               120, (), (), ())
        with mock.patch("keel.network.switch.change",
                        return_value=None) as change:
            self.assertIsNone(Effects(self.root).apply(action))
        pending, text = change.call_args.args[1:3]
        self.assertEqual((pending.iface, pending.window, text),
                         ("eth0", 120, "new2\n"))


if __name__ == "__main__":
    unittest.main()
