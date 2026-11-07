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


class TestFollowUnit(unittest.TestCase):
    """keel database follow at boot asks the other members for a newer
    claim when there is no etcd (keel#154): over wg0, so after it"""

    def test_the_boot_follow_runs_after_wg0(self):
        unit = join(dirname(CONTROL), "keel.keel-database-follow.service")
        with open(unit) as fob:
            after = [line for line in fob if line.startswith("After=")]
        self.assertTrue(any("wg-quick@wg0.service" in line.split()
                            or "wg-quick@wg0.service" in line
                            for line in after), after)


class TestFollowRetries(unittest.TestCase):
    """A refusal in the join window (the certificate not in place yet,
    the holder not answering over TLS) is retried, so a replica that
    streams does not stay failed (BR2 CT 9365, 2026-11-06); the retries
    are bounded, so a lasting refusal (a diverged node) still ends failed"""

    def unit(self) -> dict[str, str]:
        path = join(dirname(CONTROL), "keel.keel-database-follow.service")
        found = {}
        with open(path) as fob:
            for line in fob:
                key, sep, value = line.strip().partition("=")
                if sep and not line.startswith("#"):
                    found[key] = value
        return found

    def test_a_failed_follow_is_started_again(self):
        unit = self.unit()
        self.assertEqual(unit.get("Restart"), "on-failure")
        self.assertTrue(unit.get("RestartSec"))

    def test_the_retries_are_bounded(self):
        unit = self.unit()
        self.assertTrue(unit.get("StartLimitIntervalSec"))
        self.assertGreater(int(unit.get("StartLimitBurst", "0")), 1)


class TestTheSecretsDirectory(unittest.TestCase):
    """/etc/keel/secrets did not exist after the first boot, so an
    operator who gave the monitor a token file (decision 0063) made it by
    hand first. The postinst makes it, mode 0700 (root: dpkg runs it as
    root), and leaves one that exists as it is"""

    POSTINST = join(dirname(CONTROL), "keel.postinst")

    def run_postinst(self, root: str):
        import subprocess
        return subprocess.run(
            ["sh", self.POSTINST, "configure"], capture_output=True,
            text=True, check=False,
            env={"PATH": "/usr/bin:/bin", "DPKG_ROOT": root})

    def test_the_postinst_makes_it_root_only(self):
        import os
        import tempfile
        root = tempfile.mkdtemp()
        done = self.run_postinst(root)
        self.assertEqual(done.returncode, 0, done.stderr)
        secrets = join(root, "etc/keel/secrets")
        self.assertTrue(os.path.isdir(secrets))
        self.assertEqual(os.stat(secrets).st_mode & 0o777, 0o700)

    def test_a_directory_that_exists_is_left_as_it_is(self):
        import os
        import tempfile
        root = tempfile.mkdtemp()
        secrets = join(root, "etc/keel/secrets")
        os.makedirs(secrets)
        os.chmod(secrets, 0o750)
        done = self.run_postinst(root)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(os.stat(secrets).st_mode & 0o777, 0o750)


class TestFastStop(unittest.TestCase):
    """keel#219: a stop of postgresql@.service that arrives while its start
    still runs does not run ExecStop, and systemd sends SIGTERM to the
    postmaster. SIGTERM is a smart shutdown: it waits for every client, so
    an idle client (the poll of Odoo's serve.py, keel's own psql) holds the
    stop up to TimeoutStopSec, which Debian sets to 1 h. Measured on a real
    standby with one idle client: SIGTERM, the postmaster alive after 12 s;
    SIGINT, gone in under 5 s."""

    def dropin(self):
        repo = dirname(dirname(CONTROL))
        path = join(repo, "systemd", "postgresql@.service.d",
                    "keel-stop.conf")
        with open(path) as fob:
            return [line.strip() for line in fob
                    if line.strip() and not line.startswith("#")]

    def test_the_drop_in_sends_a_fast_shutdown_signal(self):
        self.assertIn("KillSignal=SIGINT", self.dropin())

    def test_the_drop_in_bounds_the_stop_to_two_minutes(self):
        self.assertIn("TimeoutStopSec=120s", self.dropin())

    def test_the_drop_in_is_in_the_service_section_and_installed(self):
        self.assertEqual(self.dropin()[0], "[Service]")
        with open(join(dirname(CONTROL), "keel.install")) as fob:
            installed = fob.read()
        self.assertIn("systemd/postgresql@.service.d/keel-stop.conf"
                      " /usr/lib/systemd/system/postgresql@.service.d",
                      installed)


class TestStartGuard(unittest.TestCase):
    """keel#156: the PostgreSQL unit runs keel database guard as root
    before each start, from a drop-in the package installs"""

    def test_the_drop_in_runs_the_guard_as_root_and_is_installed(self):
        repo = dirname(dirname(CONTROL))
        dropin = join(repo, "systemd", "postgresql@.service.d",
                      "keel-guard.conf")
        with open(dropin) as fob:
            lines = [line.strip() for line in fob]
        self.assertIn("ExecStartPre=+/usr/bin/keel database guard", lines)
        with open(join(dirname(CONTROL), "keel.install")) as fob:
            installed = fob.read()
        self.assertIn("systemd/postgresql@.service.d/keel-guard.conf"
                      " /usr/lib/systemd/system/postgresql@.service.d",
                      installed)
