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
import shlex
import subprocess
import tempfile
import unittest
from os.path import join
from unittest import mock

from manifest_helpers import ManifestCase
from test_manifest_monit import CORE_OFF, NOTIFY, RenderCase

from keel import exits
from keel.manifest.firewall import HEADER, PATH, digest_of
from keel.manifest.firewall import render as render_ruleset
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


class Nft:
    """nft as the check asks it: -c of the file, the listing of keel's
    table, and the load of --restore"""

    def __init__(self, check=0, listing=None, load=0):
        self.check, self.listing, self.load = check, listing, load
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        if argv[:2] == ["nft", "-c"]:
            return subprocess.CompletedProcess(argv, self.check, "",
                                               "Error: syntax error")
        if argv[:2] == ["nft", "list"]:
            if self.listing is None:
                return subprocess.CompletedProcess(argv, 1, "", "No such")
            return subprocess.CompletedProcess(argv, 0, self.listing, "")
        return subprocess.CompletedProcess(argv, self.load, "", "denied")


RULES = 8


def listing(digest: str, policy: str = "drop", rules: int = RULES) -> str:
    body = "".join(f"\t\ttcp dport {1000 + n} accept\n"
                   for n in range(rules))
    return (f'table inet keel {{\n\tcomment "keel-manifest {digest}"\n'
            "\tchain input {\n\t\ttype filter hook input priority filter;"
            f" policy {policy};\n{body}\t}}\n}}\n")


class TestCheck(ManifestCase):
    """Decision 0097, section 4, and the real test of PR 307: the check
    trusted the digest comment, so a broken file with its comment
    intact passed. It now checks the file's rules against the digest,
    nft -c of the file, and the loaded table's digest and policy."""

    def ruleset(self, edit=None) -> str:
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        found = render_ruleset(resolved, CORE_OFF, None)
        os.makedirs(os.path.dirname(join(self.root, PATH)), exist_ok=True)
        with open(join(self.root, PATH), "w") as fob:
            fob.write(edit(found.text) if edit else found.text)
        return found.digest

    def check(self, nft):
        return fwcheck.check(self.root, nft)

    def test_the_core_ruleset_has_the_rules_the_listing_counts(self):
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        found = render_ruleset(resolved, CORE_OFF, None)
        self.assertEqual(fwcheck.file_rules(found.text), RULES)

    def test_no_file_of_keel_s_is_nothing_to_check(self):
        found = self.check(Nft())
        self.assertEqual((found.code, found.message), (exits.OK, (
            f"{self.root}/{PATH}: no ruleset of keel's, nothing to"
            " compare")))

    def test_the_table_the_file_says(self):
        digest = self.ruleset()
        nft = Nft(listing=listing(digest))
        found = self.check(nft)
        self.assertEqual((found.code, found.message), (exits.OK, (
            f"table inet keel is the one {self.root}/{PATH} says"
            f" ({digest})")))
        self.assertIn(("nft", "-c", "-f", f"{self.root}/{PATH}"), nft.calls)

    def test_an_absent_or_other_table_is_drift_and_restorable(self):
        digest = self.ruleset()
        found = self.check(Nft())
        self.assertEqual((found.code, found.message), (exits.DRIFT_FOUND, (
            f"table inet keel is not loaded; {self.root}/{PATH} says"
            f" {digest}")))
        self.assertTrue(found.restorable)
        self.assertEqual(self.check(Nft(listing=listing("0000"))).code,
                         exits.DRIFT_FOUND)

    def test_a_table_with_another_policy_is_drift(self):
        digest = self.ruleset()
        found = self.check(Nft(listing=listing(digest, "accept")))
        self.assertEqual(found.code, exits.DRIFT_FOUND)
        self.assertIn("policy accept, and the file says drop", found.message)

    def test_a_flushed_or_grown_chain_is_drift(self):
        """`nft flush chain inet keel input` and `nft insert rule ...`
        keep the comment: the number of rules tells"""
        digest = self.ruleset()
        for rules in (0, RULES + 1):
            with self.subTest(rules=rules):
                found = self.check(Nft(listing=listing(digest,
                                                       rules=rules)))
                self.assertEqual(found.code, exits.DRIFT_FOUND)
                self.assertIn(f"holds {rules} rule(s), and the file has"
                              f" {RULES}", found.message)
                self.assertTrue(found.restorable)

    def test_an_empty_or_cut_file_is_drift(self):
        """a power loss before the data reached the disk"""
        for text in ("", HEADER + "\n"):
            with self.subTest(text=text):
                self.ruleset(lambda _: text)
                found = self.check(Nft())
                self.assertEqual(found.code, exits.DRIFT_FOUND)
                self.assertIn("not a ruleset keel wrote", found.message)
                self.assertFalse(found.restorable)

    def test_a_broken_file_with_its_comment_intact_is_drift(self):
        """the case the real test found: a line nft cannot read"""
        digest = self.ruleset(lambda text: text.replace(
            "\t\tct state invalid drop\n", "\t\t!garbage\n"))
        found = self.check(Nft(listing=listing(digest)))
        self.assertEqual(found.code, exits.DRIFT_FOUND)
        self.assertIn("the rules in the file are not the ones its digest"
                      " names", found.message)
        self.assertFalse(found.restorable)

    def test_a_file_nft_refuses_is_drift_and_not_restorable(self):
        digest = self.ruleset()
        found = self.check(Nft(check=1, listing=listing(digest)))
        self.assertEqual(found.code, exits.DRIFT_FOUND)
        self.assertIn("nft -c refuses", found.message)
        self.assertFalse(found.restorable)

    def test_a_file_that_cannot_be_read_is_drift(self):
        os.makedirs(join(self.root, PATH))
        found = self.check(Nft())
        self.assertEqual(found.code, exits.DRIFT_FOUND)
        self.assertIn("cannot be read", found.message)

    def test_restore_loads_a_lost_table(self):
        self.ruleset()
        nft = Nft()
        with mock.patch("keel.system.fwcheck.subprocess.run", nft):
            code, out, err = self.cli("firewall", "check", "--restore")
        self.assertEqual(code, exits.OK, err)
        self.assertIn(("nft", "-f", f"{self.root}/{PATH}"), nft.calls)
        self.assertIn("loaded again", err)

    def test_restore_says_nothing_when_all_is_well(self):
        digest = self.ruleset()
        nft = Nft(listing=listing(digest))
        with mock.patch("keel.system.fwcheck.subprocess.run", nft):
            code, out, err = self.cli("firewall", "check", "--restore")
        self.assertEqual((code, out, err), (exits.OK, "", ""))
        self.assertNotIn(("nft", "-f", f"{self.root}/{PATH}"), nft.calls)

    def test_restore_of_a_broken_file_loads_nothing_and_fails(self):
        self.ruleset()
        nft = Nft(check=1)
        with mock.patch("keel.system.fwcheck.subprocess.run", nft):
            code, _, err = self.cli("firewall", "check", "--restore")
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertNotIn(("nft", "-f", f"{self.root}/{PATH}"), nft.calls)
        self.assertIn("nft -c refuses", err)

    def test_a_failed_restore_fails(self):
        self.ruleset()
        with mock.patch("keel.system.fwcheck.subprocess.run", Nft(load=1)):
            code, _, err = self.cli("firewall", "check", "--restore")
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("denied", err)

    def test_no_nft_is_drift_and_a_restore_says_why(self):
        self.ruleset()

        def missing(argv, **kwargs):
            raise OSError(2, "No such file or directory")
        found = self.check(missing)
        self.assertEqual(found.code, exits.DRIFT_FOUND)
        self.assertIn("nft cannot run", found.message)
        self.assertIsNone(fwcheck.table_listing(missing))
        self.assertIn("nft cannot run", fwcheck.restore(self.root, missing))

    def test_the_command(self):
        digest = self.ruleset()
        with mock.patch("keel.system.fwcheck.subprocess.run",
                        Nft(listing=listing(digest))):
            code, out, _ = self.cli("firewall", "check")
        self.assertEqual(code, 0)
        self.assertIn("table inet keel is the one", out)
        with mock.patch("keel.system.fwcheck.subprocess.run", Nft()):
            code, _, err = self.cli("firewall", "check")
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("is not loaded", err)


class TestDigest(ManifestCase):
    def test_the_digest_of_the_rules_in_a_file(self):
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        for state in ("enforce", "report"):
            found = render_ruleset(resolved, CORE_OFF, None, state=state)
            self.assertEqual(digest_of(found.text), found.digest)
            self.assertNotEqual(digest_of(found.text.replace(
                "12321", "12322")), found.digest)
        self.assertIsNone(digest_of("table inet mine {}\n"))

    def test_a_file_of_keel_0_23_97_has_its_old_digest(self):
        """no state line: the digest of the sets and the rules alone"""
        import hashlib
        body = "\t\tiif \"lo\" accept\n"
        old_digest = hashlib.sha256(body.encode()).hexdigest()[:16]
        text = (HEADER + "\ntable inet keel\ndelete table inet keel\n"
                f'table inet keel {{\n\tcomment "keel-manifest {old_digest}"\n'
                "\tchain input {\n\t\ttype filter hook input priority"
                " filter; policy drop;\n" + body + "\t}\n}\n")
        self.assertEqual(digest_of(text), old_digest)


DROPIN_COMMAND = ("-/bin/sh -c '[ ! -e /etc/keel/firewall/keel-manifest.nft ]"
                  " || exec /usr/sbin/nft -f"
                  " /etc/keel/firewall/keel-manifest.nft'")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DROPIN = os.path.join(REPO, "systemd", "nftables.service.d",
                      "keel-firewall.conf")
WATCH = os.path.join(REPO, "debian", "keel.keel-firewall-watch")


def lines(path: str) -> list[str]:
    with open(path) as fob:
        return [line.strip() for line in fob
                if line.strip() and not line.startswith("#")]


class TestTableLoss(unittest.TestCase):
    """The real test of PR 307: published specs have no monitor section,
    so Monit never ran the check, and after `systemctl restart
    nftables.service` the node was open until an apply or a reboot.
    The protection now depends on nothing in the spec:

    - a drop-in for nftables.service loads keel's file right after each
      start, reload and stop of that unit (whose file flushes the whole
      ruleset): the open window is the time between nftables' own nft
      run and keel's, milliseconds;
    - keel-firewall-watch.timer runs `keel firewall check --restore`
      every 30 s (5 s accuracy), for a flush by hand: at most about
      35 s and one run of keel."""

    def test_the_drop_in_loads_keel_s_file_after_each_flush(self):
        found = lines(DROPIN)
        self.assertEqual(found[0], "[Service]")
        for key in ("ExecStartPost", "ExecReload", "ExecStopPost"):
            with self.subTest(key=key):
                self.assertIn(f"{key}={DROPIN_COMMAND}", found)

    def test_the_drop_in_s_command_loads_only_a_file_that_is_there(self):
        """run for real with sh, nft replaced by a recorder"""
        with tempfile.TemporaryDirectory(
                dir=os.environ.get("TMPDIR")) as tmp:
            log = os.path.join(tmp, "nft.log")
            nft = os.path.join(tmp, "nft")
            with open(nft, "w") as fob:
                fob.write(f'#!/bin/sh\necho "$@" >> {log}\n')
            os.chmod(nft, 0o755)
            ruleset = os.path.join(tmp, "keel-manifest.nft")
            command = DROPIN_COMMAND.lstrip("-").replace(
                "/usr/sbin/nft", nft).replace(f"/{PATH}", ruleset)
            argv = shlex.split(command)
            self.assertEqual(subprocess.run(argv).returncode, 0)
            self.assertFalse(os.path.exists(log))
            open(ruleset, "w").close()
            self.assertEqual(subprocess.run(argv).returncode, 0)
            with open(log) as fob:
                self.assertEqual(fob.read(), f"-f {ruleset}\n")

    def test_the_drop_in_is_installed(self):
        with open(os.path.join(REPO, "debian", "keel.install")) as fob:
            self.assertIn("systemd/nftables.service.d/keel-firewall.conf"
                          " /usr/lib/systemd/system/nftables.service.d",
                          fob.read())

    def test_the_timer_restores_every_30_seconds(self):
        timer = lines(WATCH + ".timer")
        for line in ("OnBootSec=30s", "OnUnitActiveSec=30s",
                     "AccuracySec=5s", "WantedBy=timers.target"):
            self.assertIn(line, timer)
        service = lines(WATCH + ".service")
        for line in ("Type=oneshot",
                     f"ConditionPathExists=/{PATH}",
                     "ExecStart=/usr/bin/keel firewall check --restore",
                     "LogLevelMax=notice", "SyslogLevel=warning"):
            self.assertIn(line, service)

    def test_an_upgrade_starts_neither_the_timer_nor_anything(self):
        """decision 0073: the next apply starts the timer"""
        with open(os.path.join(REPO, "debian", "rules")) as fob:
            self.assertIn("dh_installsystemd --name=keel-firewall-watch"
                          " --no-start\n", fob.read())
