# Copyright (c) 2026 KeelLinux maintainers
"""An upgrade of keel runs no keel unit on a tree of two versions (keel#349)

A timer started keel-mesh-sync.service in the second that dpkg replaced
keel's files: the Python modules of two versions were on disk, the unit
failed with an ImportError, and the node stayed degraded. The preinst
stops each timer before the unpack (tests/upgrade.bats runs it); each
service a timer starts does not run while the preinst's marker is
there; and the scripts dh_installsystemd generates start the timers
again only after the marker is gone.
"""

import configparser
import glob
import os
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEBIAN = os.path.join(REPO, "debian")
MARKER = "/run/keel/upgrading"


def unit(name: str) -> configparser.RawConfigParser:
    found = configparser.RawConfigParser(strict=False, interpolation=None)
    found.optionxform = str
    with open(os.path.join(DEBIAN, f"keel.{name}")) as fob:
        # a key can occur more than once in a unit: keep each value
        text = fob.read()
    found.read_string(text)
    found.text = text
    return found


def timers() -> list[str]:
    return sorted(os.path.basename(path)[len("keel."):]
                  for path in glob.glob(os.path.join(DEBIAN, "keel.*.timer")))


def read(name: str) -> str:
    with open(os.path.join(DEBIAN, name)) as fob:
        return fob.read()


def words(script: str, variable: str) -> list[str]:
    """The units a maintainer script names in variable="..." """
    found = re.search(rf'^{variable}="([^"]*)"', script, re.M)
    assert found, variable
    return found.group(1).split()


class TestTimerServices(unittest.TestCase):
    def test_there_are_timers(self):
        self.assertIn("keel-mesh-sync.timer", timers())

    def test_each_service_a_timer_starts_waits_for_the_upgrade(self):
        for timer in timers():
            service = timer[:-len(".timer")] + ".service"
            text = unit(service).text
            self.assertRegex(
                text, rf"(?m)^ConditionPathExists=!{MARKER}$", service)

    def test_the_condition_is_in_the_unit_section(self):
        for timer in timers():
            service = timer[:-len(".timer")] + ".service"
            head = unit(service).text.split("[Service]")[0]
            self.assertIn(f"ConditionPathExists=!{MARKER}", head, service)


class TestPreinst(unittest.TestCase):
    def setUp(self):
        self.script = read("keel.preinst")

    def test_the_preinst_stops_every_timer(self):
        self.assertEqual(sorted(words(self.script, "timers")), timers())

    def test_the_preinst_waits_for_every_oneshot_a_timer_starts(self):
        oneshots = sorted(
            timer[:-len(".timer")] + ".service" for timer in timers()
            if unit(timer[:-len(".timer")] + ".service")["Service"]
            .get("Type") == "oneshot")
        self.assertEqual(sorted(words(self.script, "oneshots")), oneshots)

    def test_the_preinst_stops_the_timer_started_services_that_stay(self):
        simple = sorted(
            timer[:-len(".timer")] + ".service" for timer in timers()
            if unit(timer[:-len(".timer")] + ".service")["Service"]
            .get("Type", "simple") != "oneshot")
        self.assertEqual(simple, ["keel-database-position.service"])
        self.assertEqual(sorted(words(self.script, "daemons")), simple)

    def test_the_preinst_writes_the_marker_the_units_read(self):
        self.assertIn(f"KEEL_UPGRADE_MARKER:-{MARKER}}}", self.script)

    def test_the_preinst_keeps_the_debhelper_token(self):
        self.assertIn("#DEBHELPER#", self.script)


class TestPostinst(unittest.TestCase):
    def test_the_marker_goes_before_debhelper_restarts_the_timers(self):
        script = read("keel.postinst")
        self.assertIn(f"KEEL_UPGRADE_MARKER:-{MARKER}}}", script)
        self.assertLess(script.index('rm -f "$marker"'),
                        script.index("#DEBHELPER#"))

    def test_the_stopped_timers_start_after_the_daemon_reload(self):
        script = read("keel.postinst")
        self.assertGreater(script.index("deb-systemd-invoke start"),
                           script.index("#DEBHELPER#"))

    def test_a_failed_unpack_clears_the_marker(self):
        script = read("keel.postrm")
        self.assertIn("abort-upgrade", script)
        self.assertIn(f"KEEL_UPGRADE_MARKER:-{MARKER}}}", script)


class TestGeneratedScripts(unittest.TestCase):
    """The scripts dh_installsystemd generates from debian/rules: on an
    upgrade they stop no timer at the wrong time and start the timers
    again in the postinst, after the daemon-reload"""

    @classmethod
    def setUpClass(cls):
        if shutil.which("dh_installsystemd") is None:
            if os.environ.get("CI"):
                raise AssertionError("dh_installsystemd (debhelper) is"
                                     " missing in CI")
            raise unittest.SkipTest("debhelper is not installed")
        cls.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        shutil.copytree(DEBIAN, os.path.join(cls.tmp.name, "debian"))
        done = subprocess.run(["make", "-s", "-f", "debian/rules",
                               "override_dh_installsystemd"],
                              cwd=cls.tmp.name, capture_output=True,
                              text=True)
        assert done.returncode == 0, done.stderr
        generated = os.path.join(cls.tmp.name, "debian", ".debhelper",
                                 "generated", "keel")
        cls.scripts = {}
        for name in ("preinst", "postinst", "prerm"):
            path = os.path.join(generated, f"{name}.service")
            with open(path) as fob:
                cls.scripts[name] = fob.read()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_no_generated_preinst_or_prerm_stops_a_timer_on_upgrade(self):
        for name in ("preinst", "prerm"):
            for section in self.scripts[name].split("# End automatically"):
                if "upgrade" in section:
                    self.assertNotIn(".timer", section, name)

    def test_the_postinst_restarts_the_timers_the_package_starts(self):
        restarted = re.findall(r"deb-systemd-invoke \$_dh_action (.*) >",
                               self.scripts["postinst"])
        named = " ".join(restarted)
        for timer in timers():
            if timer == "keel-firewall-watch.timer":
                # --no-start (decision 0073): keel's postinst starts it
                # again only when the preinst stopped it
                self.assertNotIn(timer, named)
            else:
                self.assertIn(f"'{timer}'", named)


if __name__ == "__main__":
    unittest.main()
