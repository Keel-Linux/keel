# Copyright (c) 2026 KeelLinux maintainers
"""A lost table comes back (decision 0097, section 4)

`keel firewall check` compares the digest of keel's ruleset file with
the digest of the `inet keel` table the kernel holds, as keel diff does.
Monit runs it every cycle; a table that is absent or differs for 2
cycles restarts keel-firewall.service, which loads the file again, and
every failure and recovery runs keel notify. So a `systemctl restart
nftables.service` by hand, which flushes the whole ruleset, leaves the
node open for a few cycles only.
"""

import os
from os.path import join
from unittest import mock

from manifest_helpers import ManifestCase
from test_manifest_monit import CORE_OFF, NOTIFY, RenderCase

from keel import exits
from keel.manifest.firewall import PATH, render as render_ruleset
from keel.manifest.catalog import Catalog
from keel.manifest.constants import APPLIANCE
from keel.manifest.resolve import resolve
from keel.system import fwcheck

BLOCK = (
    'check program keel-firewall with path "/usr/bin/python3 -B -m keel'
    ' firewall check"\n'
    '    start program = "/usr/bin/systemctl start keel-firewall.service"\n'
    '    restart program = "/usr/bin/systemctl restart'
    ' keel-firewall.service"\n'
    "    if status != 0 for 2 cycles then restart\n")


class TestMonit(RenderCase):
    def test_a_check_that_loads_the_table_again(self):
        found = self.render(CORE_OFF, "core", firewall=True)
        self.assertIn(BLOCK, found.text)
        self.assertIn("keel-firewall", found.services)
        self.assertIn(" ".join(NOTIFY) + " --level critical --check service"
                      " --name keel-firewall --unit keel-firewall.service",
                      found.text)
        self.assertMonitAccepts(found.text)

    def test_no_check_where_the_firewall_is_off(self):
        found = self.render(CORE_OFF, "core")
        self.assertNotIn("keel-firewall", found.text)


class TestCheck(ManifestCase):
    def ruleset(self) -> str:
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        found = render_ruleset(resolved, CORE_OFF, None)
        os.makedirs(os.path.dirname(join(self.root, PATH)))
        with open(join(self.root, PATH), "w") as fob:
            fob.write(found.text)
        return found.digest

    def check(self, held):
        with mock.patch("keel.system.fwcheck.table_digest",
                        return_value=held):
            return fwcheck.check(self.root)

    def test_no_file_of_keel_s_is_nothing_to_check(self):
        self.assertEqual(self.check(None), (exits.OK, (
            f"{self.root}/{PATH}: no ruleset of keel's, nothing to"
            " compare")))

    def test_the_table_the_file_says(self):
        digest = self.ruleset()
        self.assertEqual(self.check(digest), (exits.OK, (
            f"table inet keel is the one {self.root}/{PATH} says"
            f" ({digest})")))

    def test_an_absent_or_other_table_is_drift(self):
        digest = self.ruleset()
        self.assertEqual(self.check(None), (exits.DRIFT_FOUND, (
            f"table inet keel is not loaded; {self.root}/{PATH} says"
            f" {digest}: systemctl restart keel-firewall.service loads"
            " it")))
        self.assertEqual(self.check("0000")[0], exits.DRIFT_FOUND)

    def test_a_file_that_cannot_be_read_is_drift(self):
        os.makedirs(join(self.root, PATH))
        code, message = self.check(None)
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("cannot be read", message)

    def test_the_command(self):
        digest = self.ruleset()
        with mock.patch("keel.system.fwcheck.table_digest",
                        return_value=digest):
            code, out, _ = self.cli("firewall", "check")
        self.assertEqual(code, 0)
        self.assertIn("table inet keel is the one", out)
        with mock.patch("keel.system.fwcheck.table_digest",
                        return_value=None):
            code, _, err = self.cli("firewall", "check")
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("is not loaded", err)
