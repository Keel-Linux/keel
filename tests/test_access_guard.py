# Copyright (c) 2026 KeelLinux maintainers
"""The SSH guard at each load of keel's file (decision 0098, answer 6)

An apply closes SSH on IPv4 only where the node has a global IPv6
address and an IPv6 default route. firewall/firewall-ssh-guard runs
after each load that is not an apply (the boot, nftables.service, the
watch's restore): where the file closes IPv4 22 and that condition no
longer holds, it opens IPv4 22 again with one rule of its own and says
so in the journal. keel firewall check reads that rule as keel's.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from os.path import abspath, dirname, join

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel.manifest.firewall import SSH_LINE
from keel.system import fwcheck

GUARD = join(dirname(dirname(abspath(__file__))), "firewall",
             "firewall-ssh-guard")
GLOBAL = "20010db8000000000000000000000001 02 40 00 80 eth0\n"
ULA = "fd123456789a00010000000000000001 05 40 00 80 keel-access\n"
TENTATIVE = "20010db8000000000000000000000002 02 40 00 c0 eth0\n"
DEFAULT = ("00000000000000000000000000000000 00"
           " 00000000000000000000000000000000 00"
           " fe800000000000000000000000000001 00000400 00000001 00000000"
           " 00450003 eth0\n")
NARROWED = (f"#!/usr/sbin/nft -f\n# state: enforce\n{SSH_LINE}\n"
            "\t\tmeta nfproto ipv6 tcp dport { 22, 2222 } accept\n")


class TestGuard(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.calls = join(self.dir, "calls")
        self.nft = join(self.dir, "nft")
        with open(self.nft, "w") as fob:
            fob.write(f'#!/bin/sh\necho "$*" >> {self.calls}\n'
                      'case "$1" in list) echo "${LISTED:-}";; esac\n')
        os.chmod(self.nft, 0o755)

    def put(self, name: str, text: str) -> str:
        path = join(self.dir, name)
        with open(path, "w") as fob:
            fob.write(text)
        return path

    def guard(self, inet6: str, route6: str, text: str = NARROWED,
              listed: str = "") -> subprocess.CompletedProcess:
        env = {"PATH": os.environ["PATH"], "KEEL_NFT": self.nft,
               "KEEL_FIREWALL_FILE": self.put("rules.nft", text),
               "KEEL_IF_INET6": self.put("if_inet6", inet6),
               "KEEL_ROUTE6": self.put("ipv6_route", route6),
               "LISTED": listed}
        return subprocess.run(["sh", GUARD], env=env, capture_output=True,
                              text=True)

    def inserted(self) -> list[str]:
        if not os.path.exists(self.calls):
            return []
        with open(self.calls) as fob:
            return [line.strip() for line in fob if "insert" in line]

    def test_nothing_while_the_condition_holds(self):
        done = self.guard(GLOBAL, DEFAULT)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(self.inserted(), [])

    def test_ipv4_22_opens_again_when_ipv6_is_gone(self):
        for inet6, route6 in ((ULA + TENTATIVE, DEFAULT), (GLOBAL, ""),
                              (GLOBAL, DEFAULT.replace("eth0", "lo"))):
            with self.subTest(inet6=inet6, route6=route6):
                if os.path.exists(self.calls):
                    os.remove(self.calls)
                done = self.guard(inet6, route6)
                self.assertEqual(done.returncode, 0)
                self.assertEqual(self.inserted(), [
                    "insert rule inet keel input meta nfproto ipv4 tcp"
                    ' dport { 22, 2222 } accept comment "keel-ssh-guard"'])
                self.assertIn("opened IPv4", done.stderr)

    def test_once_and_only_for_a_narrowed_file(self):
        self.guard(ULA, "", listed='... comment "keel-ssh-guard"')
        self.assertEqual(self.inserted(), [])
        self.guard(ULA, "", text="#!/usr/sbin/nft -f\n# state: enforce\n")
        self.assertEqual(self.inserted(), [])
        self.assertEqual(subprocess.run(
            ["sh", GUARD], env={"PATH": os.environ["PATH"],
                                "KEEL_FIREWALL_FILE": "/nonexistent"},
            capture_output=True).returncode, 0)

    def test_shellcheck(self):
        if shutil.which("shellcheck") is None:
            self.skipTest("no shellcheck")
        done = subprocess.run(["shellcheck", GUARD], capture_output=True,
                              text=True)
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_the_units_and_the_watch_run_it(self):
        root = dirname(dirname(abspath(__file__)))
        for path in ("debian/keel.keel-firewall.service",
                     "systemd/nftables.service.d/keel-firewall.conf",
                     "firewall/firewall-watch"):
            with open(join(root, path)) as fob:
                self.assertIn("firewall-ssh-guard", fob.read(), path)
        with open(join(root, "debian/keel.install")) as fob:
            self.assertIn("firewall/firewall-ssh-guard /usr/lib/keel",
                          fob.read())


class TestCheckReadsTheGuard(unittest.TestCase):
    def test_the_guard_rule_is_keel_s_own(self):
        text = ("table inet keel {\n\tchain input {\n"
                "\t\ttype filter hook input priority filter; policy drop;\n"
                "\t\tct state established,related accept\n\t}\n}\n")
        listing = ("table inet keel {\n\tchain input {\n"
                   "\t\ttype filter hook input priority filter;"
                   " policy drop;\n"
                   "\t\tmeta nfproto ipv4 tcp dport 22 accept comment"
                   ' "keel-ssh-guard"\n'
                   "\t\tct state established,related accept\n\t}\n}\n")
        self.assertIsNone(fwcheck.rules_differ(listing, text))


if __name__ == "__main__":
    unittest.main()
