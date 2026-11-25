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
import shutil
import subprocess
import sys
import tempfile
import unittest
from os.path import join
from unittest import mock

from manifest_helpers import ManifestCase
from test_manifest_monit import CORE_OFF, NOTIFY, RenderCase

from keel import exits
from keel.manifest.firewall import HEADER, PATH, Allow, digest_of
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

    def __init__(self, check=0, listing=None, load=0, after=None):
        self.check, self.listing, self.load = check, listing, load
        # the listing once a load succeeded
        self.after = after
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(tuple(argv))
        if argv[:2] == ["nft", "-c"]:
            return subprocess.CompletedProcess(argv, self.check, "",
                                               "Error: syntax error")
        if "list" in argv:
            if self.listing is None:
                return subprocess.CompletedProcess(argv, 1, "", "No such")
            return subprocess.CompletedProcess(argv, 0, self.listing, "")
        if self.load == 0 and self.after is not None:
            self.listing = self.after
        return subprocess.CompletedProcess(argv, self.load, "", "denied")


# the core ruleset's input chain as `nft -s list table inet keel` prints
# it after a load
CORE_RULES = (
    'iif "lo" accept',
    "ct state established,related accept",
    "ct state invalid drop",
    "meta l4proto ipv6-icmp accept",
    "icmp type echo-request accept",
    "ip6 saddr fe80::/10 udp dport 546 accept",
    "udp dport 68 accept",
    "tcp dport { 22, 12320, 12321 } accept",
)
RULES = len(CORE_RULES)


def listing(digest: str, policy: str = "drop", rules: int = RULES,
            body: tuple[str, ...] = CORE_RULES) -> str:
    lines = (list(body) + ["accept"] * rules)[:rules]
    chain = "".join(f"\t\t{line}\n" for line in lines)
    return (f'table inet keel {{\n\tcomment "keel-manifest {digest}"\n'
            "\tchain input {\n\t\ttype filter hook input priority filter;"
            f" policy {policy};\n{chain}\t}}\n}}\n")


class TestCheck(ManifestCase):
    """Decision 0097, section 4, and the real test of PR 307: the check
    trusted the digest comment, so a broken file with its comment
    intact passed. It now checks the file's rules against the digest,
    nft -c of the file, and the loaded table's digest and policy."""

    def setUp(self):
        super().setUp()
        self.spec("version: 1\nappliance: {name: core}\n")

    def spec(self, text: str) -> None:
        os.makedirs(join(self.root, "etc/keel"), exist_ok=True)
        with open(join(self.root, "etc/keel/instance.yaml"), "w") as fob:
            fob.write(text)

    def test_a_sound_table_with_a_spec_that_cannot_be_parsed_fails(self):
        """the sixth real test: the copy kept the node closed, and check
        said 0 while the spec did not parse"""
        digest = self.ruleset()
        for broken in ("broken: [unclosed\n", None):
            with self.subTest(spec=broken):
                if broken is None:
                    os.remove(join(self.root, "etc/keel/instance.yaml"))
                else:
                    self.spec(broken)
                found = self.check(Nft(listing=listing(digest)))
                self.assertEqual(found.code, exits.DRIFT_FOUND)
                self.assertIn("cannot be read or parsed", found.message)
                self.assertFalse(found.restorable)

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
        self.assertEqual(found.code, exits.OK)
        self.assertIn("NOT APPLIED", found.message)

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

    def test_a_rule_swapped_for_accept_is_drift(self):
        """the second review: one port rule replaced by `accept` keeps
        the count; the rules themselves are compared"""
        digest = self.ruleset()
        swapped = CORE_RULES[:-1] + ("accept",)
        found = self.check(Nft(listing=listing(digest, body=swapped)))
        self.assertEqual(found.code, exits.DRIFT_FOUND)
        self.assertIn("rule 8 of table inet keel is 'accept', and the file"
                      " says 'tcp dport { 22, 12320, 12321 } accept'",
                      found.message)
        self.assertTrue(found.restorable)

    def test_the_forms_nft_prints_are_the_file_s(self):
        """nft drops /32 and /128 and may reorder an anonymous set"""
        self.assertEqual(
            fwcheck.canonical('iifname { "lxcbr0", "docker0" } ip saddr'
                              " { 198.51.100.7, 192.0.2.0/24 } accept"),
            fwcheck.canonical('iifname { "docker0", "lxcbr0" } ip saddr'
                              " { 192.0.2.0/24, 198.51.100.7/32 } accept"))
        self.assertEqual(fwcheck.canonical("ip6 saddr 2001:db8::5/128 accept"),
                         "ip6 saddr 2001:db8::5 accept")
        self.assertNotEqual(fwcheck.canonical("tcp dport 22 accept"),
                            fwcheck.canonical("accept"))

    def test_an_empty_or_cut_file_is_drift(self):
        """a power loss before the data reached the disk: the apply
        writes such a file again, and the check says so"""
        for text in ("", HEADER + "\n", HEADER[:9]):
            with self.subTest(text=text):
                self.ruleset(lambda _: text)
                found = self.check(Nft())
                self.assertEqual(found.code, exits.DRIFT_FOUND)
                self.assertIn("is empty or cut short (it loads no table):"
                              " keel spec apply --system writes it again",
                              found.message)
                self.assertFalse(found.restorable)

    def test_a_foreign_file_is_said_as_foreign(self):
        self.ruleset(lambda _: "table inet mine {}\n")
        found = self.check(Nft())
        self.assertEqual(found.code, exits.DRIFT_FOUND)
        self.assertIn("is not keel's (no header of keel's): keel spec apply"
                      " does not replace it; move it away", found.message)

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
        digest = self.ruleset()
        nft = Nft(after=listing(digest))
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
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("denied", err)

    def watch(self, nft, now):
        from keel.system import fwwatch
        return fwwatch.watch(self.root, nft, lambda: now)

    def test_a_broken_file_is_said_once_per_change_and_hourly(self):
        """the second review (N10) and the third (F3): the line is said
        once per change and once an hour, and the run stays non-zero
        while the problem lasts, so a failed unit shows it all along"""
        self.ruleset()
        nft = Nft(check=1)
        self.assertEqual(self.watch(nft, 1000)[0], exits.DRIFT_FOUND)
        self.assertEqual(self.watch(nft, 1030), (exits.DRIFT_FOUND, []))
        self.assertEqual(self.watch(nft, 4599), (exits.DRIFT_FOUND, []))
        code, lines = self.watch(nft, 4601)
        self.assertEqual((code, len(lines)), (exits.DRIFT_FOUND, 1))

    def test_a_lost_table_beside_a_broken_file_is_said_at_once(self):
        """the third review (F3): the table's state is part of the
        problem, so its loss is a new one"""
        digest = self.ruleset()
        code, lines = self.watch(Nft(check=1, listing=listing(digest)), 1000)
        self.assertIn("table inet keel holds", lines[0])
        code, lines = self.watch(Nft(check=1), 1030)
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("table inet keel is not loaded", lines[0])

    def test_the_mark_is_the_listing_the_check_accepted(self):
        """the third review (F2): a change between the check and the
        mark wrote the changed table's hash, and the watch then slept"""
        import hashlib
        from keel.system import fwwatch
        digest = self.ruleset()
        good = listing(digest)
        nft = Nft(listing=good)
        real = nft.__call__
        calls = []

        def changing(argv, **kwargs):
            out = real(argv, **kwargs)
            if "list" in argv:
                calls.append(1)
                nft.listing = listing(digest, body=CORE_RULES[:-1]
                                      + ("accept",))
            return out
        self.assertEqual(fwwatch.watch(self.root, changing,
                                       lambda: 1000)[0], exits.OK)
        with open(join(self.root, fwwatch.MARK)) as fob:
            self.assertEqual(fob.read().split(" ")[0],
                             hashlib.sha256(good.encode()).hexdigest())

    def test_a_file_changed_during_the_check_writes_no_mark(self):
        from keel.system import fwwatch
        digest = self.ruleset()
        target = join(self.root, PATH)
        nft = Nft(listing=listing(digest))
        real = nft.__call__

        def touching(argv, **kwargs):
            if argv[:2] == ["nft", "-c"]:
                os.utime(target, (1, 1))
            return real(argv, **kwargs)
        self.assertEqual(fwwatch.watch(self.root, touching,
                                       lambda: 1000)[0], exits.OK)
        self.assertFalse(os.path.exists(join(self.root, fwwatch.MARK)))

    def test_a_new_problem_and_the_recovery_are_said(self):
        digest = self.ruleset()
        self.assertEqual(self.watch(Nft(check=1), 1000)[0],
                         exits.DRIFT_FOUND)
        code, lines = self.watch(Nft(load=1), 1010)
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("denied", lines[0])
        code, lines = self.watch(Nft(listing=listing(digest)), 1020)
        self.assertEqual((code, lines[-1:]), (exits.OK, [
            "recovered: table inet keel is the one keel's file says"
            " again"]))
        self.assertEqual(self.watch(Nft(listing=listing(digest)), 1050),
                         (exits.OK, []))

    def test_the_watch_repairs_a_broken_file(self):
        """the fourth real test: the watch never wrote the file again"""
        from keel.system import fwwatch
        digest = self.ruleset(lambda _: "")
        fixed = listing(digest)

        def repaired(root, live=True, run=None):
            self.ruleset()
            return exits.OK, ["written again"]
        with mock.patch("keel.system.fwrepair.repair",
                        side_effect=repaired) as repair:
            code, lines = fwwatch.watch(self.root, Nft(listing=fixed),
                                        lambda: 1000)
        repair.assert_called_once()
        self.assertEqual(code, exits.OK)
        self.assertIn("written again", lines)

    def test_a_repair_that_fails_keeps_the_watch_failed(self):
        from keel.system import fwwatch
        self.ruleset(lambda _: "")
        with mock.patch("keel.system.fwrepair.repair",
                        return_value=(exits.APPLY_FAILED,
                                      ["the closed fallback table is"
                                       " loaded"])):
            code, lines = fwwatch.watch(self.root, Nft(), lambda: 1000)
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertIn("the closed fallback table is loaded", lines[0])

    def test_a_good_run_clears_a_boot_unit_that_failed(self):
        """keel#310: the spec put back after a boot in the fallback; the
        watch found all well, and keel-firewall.service stayed failed
        until an apply. A good run of the watch restarts it (it loads
        the same sound file), so the node is not degraded any more"""
        from keel.system import fwwatch
        digest = self.ruleset()
        nft = Nft(listing=listing(digest))
        with mock.patch("keel.system.fwwatch.LIVE_ROOT", self.root), \
                mock.patch("keel.system.fwstate.unit_failed",
                           return_value=True):
            code, lines = fwwatch.watch(self.root, nft, lambda: 1000)
        self.assertEqual(code, exits.OK)
        self.assertIn(("systemctl", "restart", "--no-block",
                       "keel-firewall.service"), nft.calls)
        self.assertIn("keel-firewall.service restarted", " ".join(lines))
        nft.calls.clear()
        with mock.patch("keel.system.fwwatch.LIVE_ROOT", self.root), \
                mock.patch("keel.system.fwstate.unit_failed",
                           return_value=False):
            fwwatch.watch(self.root, nft, lambda: 1030)
        self.assertNotIn("systemctl", [c[0] for c in nft.calls])

    def test_a_good_check_writes_the_mark_the_shell_compares(self):
        from keel.system import fwwatch
        digest = self.ruleset()
        self.watch(Nft(listing=listing(digest)), 1000)
        with open(join(self.root, fwwatch.MARK)) as fob:
            mark = fob.read().strip()
        found = os.stat(join(self.root, PATH))
        self.assertEqual(mark.split(" ")[1:], [
            str(found.st_ino), str(found.st_size),
            str(int(found.st_mtime)), str(int(found.st_ctime))])
        self.watch(Nft(check=1), 1010)
        self.assertFalse(os.path.exists(join(self.root, fwwatch.MARK)))

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


class TestCheckReal(ManifestCase):
    """The check against what nft really prints: each ruleset loaded in a
    network namespace of its own (tests/wgtools.py), listed with nft -s;
    nothing on the machine running the tests changes"""

    def setUp(self):
        super().setUp()
        from wgtools import namespace_prefix
        nft = os.environ.get("KEEL_NFT") or shutil.which("nft") or (
            "/usr/sbin/nft" if os.path.exists("/usr/sbin/nft") else None)
        self.prefix = namespace_prefix() if nft else None
        if self.prefix is None:
            if os.environ.get("CI"):
                self.fail("nft in a namespace of its own is needed in CI")
            self.skipTest("no nft, or no namespace of its own")
        self.nft = nft

    def loaded(self, text: str, after: str = "") -> str:
        path = join(self.root, "rules.nft")
        with open(path, "w") as fob:
            fob.write(text)
        done = subprocess.run(
            [*self.prefix, "sh", "-c",
             f"{self.nft} -f {path} && {after}{self.nft} -s list table"
             " inet keel"], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_every_form_keel_renders_reads_back_as_the_file(self):
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        states = {"installer": "enabled", "wireguard": "enabled",
                  "etcd": "enabled", "crowdsec": "enabled"}
        for state in ("enforce", "report"):
            with self.subTest(state=state):
                found = render_ruleset(
                    resolved, states, {"address": "fd00:1::1/64"},
                    ("lxcbr0", "docker0"), state=state, ssh=(22, 2222),
                    allow=(Allow(8080, "tcp"),
                           Allow(5432, "tcp", ("192.0.2.0/24",
                                               "2001:db8::/32",
                                               "198.51.100.7/32")),
                           Allow(9000, "udp", ("2001:db8:1::5",))),
                    fence=(60080, 60443))
                listed = self.loaded(found.text)
                self.assertIsNone(fwcheck.rules_differ(listed, found.text),
                                  listed)
                swapped = self.loaded(found.text, (
                    f"{self.nft} replace rule inet keel input handle"
                    f" $({self.nft} -a list chain inet keel input | grep"
                    " 'dport 8080' | sed 's/.*handle //') accept && "))
                self.assertIn("rule", fwcheck.rules_differ(swapped,
                                                           found.text))

    def test_the_access_forms_read_back_as_the_file(self):
        """Decision 0098: the access rules, their drop, SSH on IPv6
        alone, and a forward chain before the input chain"""
        from keel.manifest.firewall import Access
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        states = {"installer": "enabled", "wireguard": "enabled",
                  "etcd": "enabled", "crowdsec": "enabled"}
        for state in ("enforce", "report"):
            with self.subTest(state=state):
                found = render_ruleset(
                    resolved, states, {"address": "fd00:1::1/64"},
                    state=state, ssh=(22,),
                    access=Access("keel-access", 51822,
                                  "fd12:3456:789a:1::1", (3306,)),
                    ssh_ipv6_only=True)
                listed = self.loaded(found.text)
                self.assertIsNone(fwcheck.rules_differ(listed, found.text),
                                  listed)
                self.assertIn("chain forward", listed)
                self.assertEqual(digest_of(found.text), found.digest)


class TestWatchShell(TestCheckReal):
    """firewall/firewall-watch for real, in a network namespace of its
    own: after a good check (`keel firewall check --restore`, which
    writes the mark) it starts no Python; a changed table or file, or
    no mark, hands over to keel (a recorder here)"""

    def scenario(self, between: str, spec: str = "") -> str:
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        found = render_ruleset(resolved, CORE_OFF, None)
        target = join(self.root, PATH)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as fob:
            fob.write(found.text)
        log = join(self.root, "keel.log")
        recorder = join(self.root, "keel")
        with open(recorder, "w") as fob:
            fob.write(f'#!/bin/sh\necho "$@" >> {log}\n')
        os.chmod(recorder, 0o755)
        watch = join(REPO, "firewall", "firewall-watch")
        nftdir = os.path.dirname(self.nft)
        os.makedirs(join(self.root, "etc/keel"), exist_ok=True)
        with open(join(self.root, "etc/keel/instance.yaml"), "w") as fob:
            fob.write("version: 1\nappliance: {name: core}\n")
        script = (
            f"export PATH={nftdir}:$PATH"
            f" KEEL_FIREWALL_FILE={target}"
            f" KEEL_FIREWALL_MARK={self.root}/run/keel/firewall-watch.ok"
            f" KEEL_BIN={recorder} KEEL_NFT={self.nft}"
            f" KEEL_SPEC_FILE={spec or join(self.root, 'instance.yaml')}"
            f" KEEL_FIREWALL_RECORD={self.root}/var/lib/keel/firewall/state"
            f" KEEL_FIREWALL_COPY={self.root}/var/lib/keel/firewall/"
            f"last-good.nft KEEL_ROOT_UID=$(id -u)"
            f" PYTHONPATH={REPO};"
            f" {self.nft} -f {target} &&"
            f" {sys.executable} -m keel firewall check --restore"
            f" --root {self.root} && {between} sh {watch}")
        done = subprocess.run([*self.prefix, "sh", "-c", script],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        try:
            with open(log) as fob:
                return fob.read()
        except FileNotFoundError:
            return ""

    def test_all_well_starts_no_python(self):
        self.assertEqual(self.scenario(""), "")

    def test_a_flushed_chain_hands_over_to_keel(self):
        self.assertEqual(self.scenario(
            f"{self.nft} flush chain inet keel input &&"),
            "firewall check --restore\n")

    def test_a_new_file_hands_over_to_keel(self):
        target = join(self.root, PATH)
        self.assertEqual(self.scenario(f"cp {target} {target}.n && mv"
                                       f" {target}.n {target} &&"),
                         "firewall check --restore\n")

    def test_no_evidence_runs_nothing_ten_times(self):
        """upgrade from 0.23.97, the timer enabled: no file, no record, no
        table; ten runs of the shell watch, each exit 0, keel never run,
        so the unit never fails and the system is not degraded"""
        target = join(self.root, PATH)
        spec = join(self.root, "instance.yaml")
        with open(spec, "w") as fob:
            fob.write("version: 1\nappliance: {name: core}\n")
        watch = join(REPO, "firewall", "firewall-watch")
        loop = ("for i in 1 2 3 4 5 6 7 8 9 10; do sh " + watch
                + " || exit 9; done;")
        self.assertEqual(self.scenario(
            f"rm {target} && {self.nft} delete table inet keel &&"
            f" {loop}", spec), "")

    def record(self, text: str, dir_mode: int = 0o700,
               mode: int = 0o600) -> None:
        record = join(self.root, "var/lib/keel/firewall/state")
        os.makedirs(os.path.dirname(record), exist_ok=True)
        with open(record, "w") as fob:
            fob.write(text)
        os.chmod(record, mode)
        os.chmod(os.path.dirname(record), dir_mode)

    def test_no_file_with_a_table_hands_over_to_keel_unless_off(self):
        """the fourth real test: file and record lost, the table still
        loaded: keel says it. Off comes from keel's record alone, never
        from text in the spec (the fifth real test: a comment that said
        `state: off` silenced the watch)"""
        target = join(self.root, PATH)
        self.assertEqual(self.scenario(f"rm {target} &&"),
                         "firewall check --restore\n")
        os.remove(join(self.root, "keel.log"))
        self.record("off\n")
        self.assertEqual(self.scenario(f"rm {target} &&"), "")

    def test_a_record_that_fails_the_trust_test_goes_to_keel(self):
        """the sixth real test: an unprivileged owner of keel's directory
        planted `off`, and the shell watch stayed silent on an open
        node; the shell now applies Python's trust test"""
        target = join(self.root, PATH)
        for dir_mode, mode in ((0o777, 0o600), (0o700, 0o644)):
            with self.subTest(dir=oct(dir_mode), file=oct(mode)):
                self.record("off\n", dir_mode, mode)
                self.assertEqual(self.scenario(f"rm {target} &&"),
                                 "firewall check --restore\n")
                os.remove(join(self.root, "keel.log"))

    def test_a_missing_spec_still_watches(self):
        """the sixth real test: a unit condition on the spec skipped the
        watch, with the table lost and the node open"""
        target = join(self.root, PATH)
        self.assertEqual(self.scenario(
            f"rm {self.root}/etc/keel/instance.yaml && rm {target} &&"),
            "firewall check --restore\n")


class TestLoadedAtBoot(TestCheckReal):
    """keel-firewall.service fails, and the node is degraded, when the
    file loads no table inet keel with its own policy: an empty file
    loaded nothing and the unit said success (the second real test)"""

    def boot(self, text: str, after: str = "") -> int:
        target = join(self.root, "keel-manifest.nft")
        with open(target, "w") as fob:
            fob.write(text)
        verify = join(REPO, "firewall", "firewall-loaded")
        done = subprocess.run(
            [*self.prefix, "sh", "-c",
             f"{self.nft} -f {target}; {after}"
             f" KEEL_FIREWALL_FILE={target} KEEL_NFT={self.nft}"
             f" sh {verify}"], capture_output=True, text=True)
        return done.returncode

    def rendered(self, state="enforce") -> str:
        catalog = Catalog(self.root)
        resolved, _ = resolve(catalog, catalog.read(APPLIANCE, "core"))
        return render_ruleset(resolved, CORE_OFF, None, state=state).text

    def test_no_file_passes_the_repair_decided(self):
        """keel firewall repair runs before: with no file it has said off
        or failed the unit itself"""
        verify = join(REPO, "firewall", "firewall-loaded")
        done = subprocess.run(
            ["sh", verify], env={**os.environ, "KEEL_FIREWALL_FILE":
                                 join(self.root, "absent.nft")},
            capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_loaded_file_passes_in_each_state(self):
        for state in ("enforce", "report"):
            self.assertEqual(self.boot(self.rendered(state)), 0)

    def test_an_empty_or_cut_file_fails(self):
        for text in ("", HEADER + "\n", self.rendered()[:200]):
            with self.subTest(size=len(text)):
                self.assertNotEqual(self.boot(text), 0)

    def test_a_table_that_is_not_there_fails(self):
        self.assertNotEqual(self.boot(
            self.rendered(), f"{self.nft} delete table inet keel;"), 0)


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

    def test_the_scripts_are_installed_and_executable(self):
        with open(os.path.join(REPO, "debian", "keel.install")) as fob:
            installed = fob.read()
        for name in ("firewall-watch", "firewall-loaded",
                     "firewall-ssh-guard"):
            script = os.path.join(REPO, "firewall", name)
            self.assertTrue(os.access(script, os.X_OK))
            self.assertIn(f"firewall/{name} /usr/lib/keel\n", installed)

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
        self.assertFalse([line for line in service
                          if line.startswith("ConditionPathExists=")])
        for line in ("Type=oneshot",
                     "ExecStart=/usr/lib/keel/firewall-watch",
                     "LogLevelMax=notice", "SyslogLevel=warning"):
            self.assertIn(line, service)



class TestMaintainerScripts(unittest.TestCase):
    """The second review: the generated preinst stopped
    keel-firewall-watch.timer on every upgrade, and --no-start never
    started it again. The scripts dh_installsystemd generates from
    debian/rules are read here, not the rules file: an upgrade must
    neither stop, start nor restart keel's firewall units (0073)."""

    @classmethod
    def setUpClass(cls):
        if shutil.which("dh_installsystemd") is None:
            if os.environ.get("CI"):
                raise AssertionError("dh_installsystemd (debhelper) is"
                                     " missing in CI")
            raise unittest.SkipTest("debhelper is not installed")
        cls.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        shutil.copytree(os.path.join(REPO, "debian"),
                        os.path.join(cls.tmp.name, "debian"))
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

    def sections(self, script: str) -> list[str]:
        return self.scripts[script].split("# End automatically added")

    def test_an_upgrade_stops_no_firewall_unit(self):
        for section in self.sections("preinst"):
            if "keel-firewall" in section:
                self.assertNotIn("stop", section)

    def test_an_upgrade_starts_or_restarts_no_firewall_unit(self):
        for section in self.sections("postinst"):
            if "keel-firewall" in section:
                for verb in ("deb-systemd-invoke", "start", "restart"):
                    self.assertNotIn(verb, section)

    def test_the_units_are_enabled_for_the_next_boot(self):
        for unit in ("keel-firewall.service", "keel-firewall-watch.timer"):
            self.assertIn(f"deb-systemd-helper enable '{unit}'",
                          self.scripts["postinst"])


class TestRemoval(unittest.TestCase):
    """The third review (F5): with --no-start, debhelper writes no stop
    of the watch timer on removal; keel's prerm stops it on remove, and
    on upgrade stops nothing"""

    def prerm(self, verb: str) -> str:
        if not os.path.isdir("/run/systemd/system"):
            self.skipTest("no systemd here: the prerm acts only under it")
        with tempfile.TemporaryDirectory(
                dir=os.environ.get("TMPDIR")) as tmp:
            log = os.path.join(tmp, "invoked")
            fake = os.path.join(tmp, "deb-systemd-invoke")
            with open(fake, "w") as fob:
                fob.write(f'#!/bin/sh\necho "$@" >> {log}\n')
            os.chmod(fake, 0o755)
            env = {**os.environ, "PATH": f"{tmp}:{os.environ['PATH']}"}
            env.pop("DPKG_ROOT", None)
            done = subprocess.run(
                ["sh", os.path.join(REPO, "debian", "keel.prerm"), verb],
                env=env, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            try:
                with open(log) as fob:
                    return fob.read()
            except FileNotFoundError:
                return ""

    def test_remove_stops_the_watch(self):
        self.assertEqual(self.prerm("remove"), "stop keel-firewall-watch"
                         ".timer keel-firewall-watch.service\n")

    def test_an_upgrade_stops_nothing(self):
        self.assertEqual(self.prerm("upgrade"), "")
