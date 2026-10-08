# Copyright (c) 2026 KeelLinux maintainers
"""What debian/control promises about inithooks (keel#45)

keel keeps no dependency on inithooks (firstboot.d/10keel-system says
why), but the conf it renders needs an inithooks that reads it: an
IPv4 nameserver in IP6_DNS* is fatal to an older 01ipconfig, which then
leaves the image's file in place, and IP6_SLAAC is ignored by it. So the
package Breaks the older ones instead of Depending on any.
"""

import re
import shutil
import subprocess
import unittest
from os.path import abspath, dirname, join

CONTROL = join(dirname(dirname(abspath(__file__))), "debian", "control")
FIRST = "2.3.6+keel9~"


def field(name: str) -> str:
    """One field of the binary package stanza, its lines joined"""
    with open(CONTROL) as fob:
        stanza = fob.read().split("\n\nPackage:", 1)[1]
    match = re.search(rf"^{name}:(.*(?:\n .*)*)", stanza, re.MULTILINE)
    return " ".join(match.group(1).split()) if match else ""


class TestControl(unittest.TestCase):
    def test_older_inithooks_is_broken_not_depended_on(self):
        self.assertIn(f"inithooks (<< {FIRST})", field("Breaks"))
        self.assertNotIn("inithooks", field("Depends"))

    @unittest.skipUnless(shutil.which("dpkg"), "dpkg is not installed")
    def test_the_bound_covers_every_older_keel_build_and_no_newer(self):
        for version, broken in (("2.3.6", True), ("2.3.6+keel8", True),
                                ("2.3.6+keel9", False),
                                ("2.3.6+keel10", False),
                                ("2.3.7", False)):
            with self.subTest(version=version):
                lower = subprocess.run(
                    ["dpkg", "--compare-versions", version, "lt", FIRST],
                    check=False).returncode == 0
                self.assertEqual(lower, broken)


    def test_an_etcd_overlay_without_etcdctl_is_broken(self):
        """keel asks etcd with etcdctl (keel#83), which keel-overlay-etcd
        brings from 0.4.0: an older overlay is upgraded with keel"""
        self.assertIn("keel-overlay-etcd (<< 0.4.0~)", field("Breaks"))
        self.assertNotIn("etcd", field("Depends"))


if __name__ == "__main__":
    unittest.main()
