# Copyright (c) 2026 KeelLinux maintainers
"""The sockets a node listens on, and whose they are (decision 0097, B)

Rule B looks at the process, not at the port: a node goes to enforce by
itself only when each socket on an address that is not a loopback
belongs to a unit of the resolved manifest. The parse of `ss` and the
classification are pure; the live read is one `ss` and the cgroup file
of each process.
"""

import os
import subprocess
import unittest
from os.path import join
from tempfile import TemporaryDirectory

from keel.inspect.tree import Tree
from keel.system.listeners import (
    Listener,
    classify,
    declared_units,
    observe_listeners,
    parse_ss,
    unit_of,
    unopened,
)

SS = """\
udp   UNCONN 0      0                 10.88.5.212%eth0:68        0.0.0.0:*
udp   UNCONN 0      0                          0.0.0.0:12321     0.0.0.0:*    users:(("miniserv.pl",pid=310,fd=6))
udp   UNCONN 0      0                             [::]:51820        [::]:*
udp   UNCONN 0      0                          0.0.0.0:5353      0.0.0.0:*    users:(("avahi-daemon",pid=200,fd=12))
tcp   LISTEN 0      128                        0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=101,fd=3))
tcp   LISTEN 0      128                           [::]:22           [::]:*    users:(("sshd",pid=101,fd=4))
tcp   LISTEN 0      100                      127.0.0.1:25        0.0.0.0:*    users:(("master",pid=400,fd=13))
tcp   LISTEN 0      4096                 [fd00:1::1]:3306           [::]:*    users:(("mariadbd",pid=500,fd=20))
tcp   LISTEN 0      4096               [fd00:1::1]%wg0:51821          [::]:*    users:(("keel",pid=600,fd=5))
tcp   LISTEN 0      511                              *:443              *:*    users:(("nginx",pid=700,fd=7),("nginx",pid=701,fd=7))
tcp   LISTEN 0      4096                          [::]:9999           [::]:*    users:(("nc",pid=800,fd=3))
tcp   LISTEN 0      4096                 127.0.0.53%lo:53         0.0.0.0:*
"""
UNITS = {101: "ssh.service", 310: "webmin.service", 200: "avahi-daemon.service",
         400: "postfix@-.service", 500: "mariadb.service",
         600: "keel-mesh-members.service", 700: "nginx.service",
         701: "nginx.service", 800: "session-3.scope"}


def listeners() -> tuple[Listener, ...]:
    return tuple(found.with_units(tuple(UNITS[pid] for pid in found.pids))
                 for found in parse_ss(SS))


class TestParse(unittest.TestCase):
    def test_each_line_with_its_address_device_port_and_processes(self):
        found = parse_ss(SS)
        self.assertEqual(len(found), 12)
        self.assertEqual(found[0], Listener("udp", "10.88.5.212", "eth0",
                                            68, ()))
        self.assertEqual(found[2], Listener("udp", "::", None, 51820, ()))
        self.assertEqual(found[4].pids, (101,))
        self.assertEqual(found[7].address, "fd00:1::1")
        self.assertEqual((found[8].device, found[8].port), ("wg0", 51821))
        self.assertEqual(found[9].address, "*")
        self.assertEqual(found[9].pids, (700, 701))
        self.assertEqual(found[11].device, "lo")

    def test_a_line_it_cannot_read_is_an_error_not_a_skip(self):
        with self.assertRaisesRegex(ValueError, "cannot read the ss line"):
            parse_ss("tcp LISTEN 0 1 nonsense\n")

    def test_a_blank_line_is_skipped_and_a_bad_address_refused(self):
        self.assertEqual(parse_ss("\n"), ())
        with self.assertRaisesRegex(ValueError, "cannot read the ss line"):
            parse_ss("tcp LISTEN 0 1 [::1 [::]:*\n")

    def test_a_device_bound_socket_says_its_device(self):
        found = parse_ss("udp UNCONN 0 0 10.0.0.2%eth0:68 0.0.0.0:*\n")
        self.assertEqual(found[0].describe(),
                         "udp 10.0.0.2%eth0:68 of no process ss could read")

    def test_a_name_that_is_no_address_is_not_the_loopback(self):
        from keel.system.listeners import loopback
        self.assertFalse(loopback(Listener("tcp", "localhost", None, 1,
                                           ())))
        self.assertTrue(loopback(Listener("tcp", "::ffff:127.0.0.1", None,
                                          1, ())))

    def test_an_unbound_port_is_left_out(self):
        self.assertEqual(parse_ss(
            "udp UNCONN 0 0 0.0.0.0:* 0.0.0.0:*\n"), ())

    def test_the_unit_of_a_process_from_its_cgroup(self):
        self.assertEqual(unit_of("0::/system.slice/mariadb.service\n"),
                         "mariadb.service")
        self.assertEqual(unit_of(
            "0::/system.slice/system-postgresql.slice/"
            "postgresql@17-main.service\n"), "postgresql@17-main.service")
        self.assertEqual(unit_of(
            "12:cpu:/x\n1:name=systemd:/system.slice/ssh.service\n"),
            "ssh.service")
        self.assertIsNone(unit_of("0::/\n"))
        self.assertIsNone(unit_of(""))


class TestClassify(unittest.TestCase):
    def classify(self, units=("ssh.service", "webmin.service",
                              "postfix.service", "mariadb.service",
                              "nginx.service"), **kwargs):
        args = {"ssh": (22,), "allow": frozenset(), "opened": frozenset(
            {(22, "tcp"), (443, "tcp"), (12321, "tcp"), (3306, "tcp")}),
            "overlay": ("wg0", 51820)}
        args.update(kwargs)
        return classify(listeners(), frozenset(units), **args)

    def test_undeclared_processes_are_named_and_the_rest_known(self):
        found = self.classify()
        self.assertEqual([item.describe() for item in found.undeclared], [
            "udp 0.0.0.0:5353 of avahi-daemon.service (avahi-daemon)",
            "tcp [::]:9999 of session-3.scope (nc)",
        ])

    def test_a_declared_process_s_unopened_port_is_information(self):
        """UDP 12321 of miniserv.pl: the manifest declares TCP only"""
        self.assertEqual([item.describe() for item in self.classify().closed],
                         ["udp 0.0.0.0:12321 of webmin.service"
                          " (miniserv.pl)"])

    def test_everything_declared_is_clean(self):
        found = self.classify(units=(
            "ssh.service", "webmin.service", "postfix.service",
            "mariadb.service", "nginx.service", "avahi-daemon.service",
            "session-3.scope"))
        self.assertEqual(found.undeclared, ())
        self.assertTrue(found.clean)

    def test_allow_declares_the_administrator_s_port(self):
        found = self.classify(allow=frozenset({(9999, "tcp"),
                                               (5353, "udp")}))
        self.assertEqual(found.undeclared, ())

    def test_a_socket_with_no_process_is_unknown(self):
        """a socket ss shows with no process (not root, or the kernel's)
        is undeclared, except WireGuard's own port and the DHCP client"""
        found = classify(parse_ss(
            "tcp LISTEN 0 1 0.0.0.0:8000 0.0.0.0:*\n"
            "udp UNCONN 0 0 [::]:51820 [::]:*\n"
            "udp UNCONN 0 0 [fe80::1]%eth0:546 [::]:*\n"),
            frozenset(), ssh=(22,), allow=frozenset(),
            opened=frozenset(), overlay=("wg0", 51820))
        self.assertEqual([item.describe() for item in found.undeclared],
                         ["tcp 0.0.0.0:8000 of no process ss could read"])

    def test_without_an_overlay_the_wireguard_port_is_not_known(self):
        found = classify(parse_ss("udp UNCONN 0 0 [::]:51820 [::]:*\n"),
                         frozenset(), ssh=(22,), allow=frozenset(),
                         opened=frozenset(), overlay=None)
        self.assertEqual(len(found.undeclared), 1)

    def test_a_template_instance_belongs_to_its_unit(self):
        """postgresql.service starts postgresql@17-main.service, whose
        cgroup holds the server"""
        found = classify((Listener("tcp", "::", None, 5432, (9,),
                                   ("postgres",),
                                   ("postgresql@17-main.service",)),),
                         declared_units_of(("postgresql.service",)),
                         ssh=(22,), allow=frozenset(),
                         opened=frozenset(), overlay=None)
        self.assertEqual(found.undeclared, ())

    def test_the_running_init_fence_is_keel_s_while_it_is_enabled(self):
        """the real test of PR 307: simplehttpd.py on 60080 and 60443 kept
        rule B in report on an interactive first boot"""
        fence = (Listener("tcp", "*", None, 60080, (5,), ("simplehttpd.py",),
                          ("turnkey-init-fence.service",)),
                 Listener("tcp", "*", None, 60443, (5,), ("simplehttpd.py",),
                          ("turnkey-init-fence.service",)))
        found = classify(fence, frozenset(), ssh=(22,), allow=frozenset(),
                         opened=frozenset(), overlay=None,
                         fence=(60080, 60443))
        self.assertTrue(found.clean)
        self.assertEqual(found.closed, ())
        unknown = classify(fence, frozenset(), ssh=(22,), allow=frozenset(),
                           opened=frozenset(), overlay=None)
        self.assertEqual(len(unknown.undeclared), 2)

    def test_a_pending_invite_s_listener_is_keel_s(self):
        found = classify((Listener("tcp", "::", None, 40123, (7,),
                                   ("python3",),
                                   ("keel-mesh-invite@a1b2.service",)),),
                         frozenset(), ssh=(22,), allow=frozenset(),
                         opened=frozenset(), overlay=("wg0", 51820))
        self.assertTrue(found.clean)

    def test_ssh_ports_are_sshd_s_whatever_holds_them(self):
        """an active ssh.socket is held by systemd itself (init.scope)"""
        found = classify((Listener("tcp", "::", None, 2222, (1,),
                                   ("systemd",), ("init.scope",)),),
                         frozenset(), ssh=(2222,), allow=frozenset(),
                         opened=frozenset(), overlay=None)
        self.assertTrue(found.clean)


class TestUnopened(unittest.TestCase):
    def test_what_enforce_would_close_by_port(self):
        found = unopened(listeners(), frozenset({(22, "tcp"), (443, "tcp"),
                                                 (3306, "tcp")}), "wg0")
        self.assertEqual([item.describe() for item in found], [
            "udp 0.0.0.0:12321 of webmin.service (miniserv.pl)",
            "udp [::]:51820 of no process ss could read",
            "udp 0.0.0.0:5353 of avahi-daemon.service (avahi-daemon)",
            "tcp [::]:9999 of session-3.scope (nc)",
        ])

    def test_without_an_overlay_no_device_is_left_out(self):
        found = unopened(parse_ss("tcp LISTEN 0 1 [::]:9999 [::]:*\n"),
                         frozenset(), None)
        self.assertEqual(len(found), 1)


def declared_units_of(units) -> frozenset:
    return frozenset(units)


class TestDeclaredUnits(unittest.TestCase):
    def test_the_units_of_the_enabled_processes(self):
        class Owned:
            def __init__(self, unit, overlay):
                self.item = {"unit": unit}
                self.overlay = overlay

        class Resolved:
            processes = (Owned("ssh.service", None),
                         Owned("etcd.service", "etcd"),
                         Owned("crowdsec.service", "crowdsec"))
        self.assertEqual(declared_units(Resolved(), {"etcd": "enabled",
                                                     "crowdsec": "disabled"}),
                         frozenset({"ssh.service", "etcd.service"}))


class TestObserve(unittest.TestCase):
    def test_live_reads_ss_and_each_cgroup(self):
        with TemporaryDirectory(dir=os.environ.get("TMPDIR")) as root:
            os.makedirs(join(root, "proc/101"))
            with open(join(root, "proc/101/cgroup"), "w") as fob:
                fob.write("0::/system.slice/ssh.service\n")
            calls = []

            def run(argv, **kwargs):
                calls.append(tuple(argv))
                return subprocess.CompletedProcess(
                    argv, 0, "tcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*"
                    ' users:(("sshd",pid=101,fd=3))\n'
                    "tcp LISTEN 0 1 0.0.0.0:80 0.0.0.0:*"
                    ' users:(("gone",pid=102,fd=3))\n', "")
            found, why = observe_listeners(Tree(root), True, run)
        self.assertEqual(calls, [("ss", "-H", "-l", "-n", "-p", "-t", "-u")])
        self.assertEqual(why, "ss")
        self.assertEqual(found[0].units, ("ssh.service",))
        self.assertEqual(found[1].units, ())

    def test_no_ss_or_a_failed_ss_or_not_live_is_unknown(self):
        def missing(argv, **kwargs):
            raise OSError(2, "No such file or directory")

        def failed(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, "", "denied")

        def garbled(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, "x y\n", "")
        tree = Tree("/nonexistent")
        self.assertEqual(observe_listeners(tree, True, missing),
                         (None, "ss cannot run: No such file or directory"))
        self.assertEqual(observe_listeners(tree, True, failed),
                         (None, "ss failed: denied"))
        found, why = observe_listeners(tree, True, garbled)
        self.assertIsNone(found)
        self.assertIn("cannot read the ss line", why)
        self.assertEqual(observe_listeners(tree, False),
                         (None, "not the live system: no socket is seen"))


if __name__ == "__main__":
    unittest.main()
