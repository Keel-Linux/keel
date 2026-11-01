# Copyright (c) 2026 KeelLinux maintainers
"""The units of keel database dump: the tick, and what the tick runs"""

import configparser
import os
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def unit(name: str) -> configparser.RawConfigParser:
    found = configparser.RawConfigParser(strict=False)
    found.optionxform = str
    found.read(os.path.join(REPO, "debian", f"keel.{name}"))
    return found


class TestUnits(unittest.TestCase):
    def test_the_timer_ticks_hourly_and_the_spec_decides(self):
        timer = unit("keel-database-dump.timer")
        self.assertEqual(timer["Timer"]["OnCalendar"], "hourly")
        self.assertEqual(timer["Timer"]["Persistent"], "true")
        self.assertEqual(timer["Install"]["WantedBy"], "timers.target")

    def test_the_service_runs_the_due_form_at_a_low_priority(self):
        service = unit("keel-database-dump.service")["Service"]
        self.assertEqual(service["ExecStart"],
                         "/usr/bin/keel database dump --if-due")
        self.assertEqual(service["Type"], "oneshot")
        self.assertEqual(service["UMask"], "0077")
        self.assertEqual(service["Nice"], "10")
        self.assertEqual(service["IOSchedulingClass"], "idle")
        self.assertIn("TimeoutStartSec", service)

    def test_the_package_installs_the_timer(self):
        with open(os.path.join(REPO, "debian", "rules")) as fob:
            self.assertIn("dh_installsystemd --name=keel-database-dump\n",
                          fob.read())

    def test_docs_name_only_what_exists(self):
        for name in ("replication.md", "replication-postgresql.md"):
            with open(os.path.join(REPO, "docs", name)) as fob:
                text = fob.read()
            self.assertIn("keel-database-dump.timer", text, name)
            self.assertIn("database.server.dump", text, name)
