# Copyright (c) 2026 KeelLinux maintainers
"""A node that was in enforce is never open without a loud signal
(decision 0097; the fourth real test of this change)

`keel firewall repair` runs the firewall step the apply runs, unattended,
from the spec on disk: an empty, cut or missing file on a node whose
record (or loaded table) says enforce is written again in enforce and
loaded. keel-firewall.service runs it before its load at boot, and the
watch runs it on a broken file. Where the step cannot write the file (the
spec unreadable, sshd's ports unknown), a closed fallback table is loaded
instead (drop; loopback, established, ICMPv6, the DHCP client; sshd's
ports; the WireGuard port and the overlay's interface where the node has
a mesh), and the run fails, so the unit stays failed and the node
degraded until an apply. A missing file on a node whose spec does not
say off is a failure for keel firewall check and the watch.
"""

import os
import subprocess
from os.path import join
from unittest import mock

from manifest_helpers import ManifestCase

from keel import exits
from keel.manifest.firewall import PATH, file_state
from keel.system import fwcheck, fwrecord, fwrepair

SPEC = ("version: 1\nappliance: {name: core}\ninstallation: {mode: simple}\n"
        "overlays: {installer: enabled, wireguard: disabled, etcd: disabled,"
        " crowdsec: disabled}\n")


class RepairCase(ManifestCase):
    def setUp(self):
        super().setUp()
        owner = mock.patch("keel.system.fwrecord.ROOT_UID", os.getuid())
        owner.start()
        self.addCleanup(owner.stop)
        self.spec(SPEC)
        os.makedirs(join(self.root, "etc/ssh"), exist_ok=True)
        with open(join(self.root, "etc/ssh/sshd_config"), "w") as fob:
            fob.write("Port 22\n")

    def spec(self, text: str) -> None:
        os.makedirs(join(self.root, "etc/keel"), exist_ok=True)
        with open(join(self.root, fwrepair.SPEC), "w") as fob:
            fob.write(text)

    def ruleset(self, text: str) -> None:
        os.makedirs(os.path.dirname(join(self.root, PATH)), exist_ok=True)
        with open(join(self.root, PATH), "w") as fob:
            fob.write(text)

    def file(self) -> str | None:
        try:
            with open(join(self.root, PATH)) as fob:
                return fob.read()
        except FileNotFoundError:
            return None

    def repair(self, nft=None):
        nft = nft or Loads()
        return fwrepair.repair(self.root, live=False, run=nft), nft


class Loads:
    """nft as the fallback loads it: -c and -f of a file"""

    def __init__(self, code=0):
        self.code = code
        self.loaded = []

    def __call__(self, argv, **kwargs):
        if "-f" in argv:
            with open(argv[-1]) as fob:
                self.loaded.append(fob.read())
        return subprocess.CompletedProcess(argv, self.code, "", "")


class TestRepair(RepairCase):
    def test_an_empty_file_of_an_enforcing_node_is_written_in_enforce(self):
        fwrecord.write(self.root, "enforce")
        for text in ("", "#!/usr/sbin/nft -f\n# writ"):
            with self.subTest(text=text):
                self.ruleset(text)
                (code, lines), _ = self.repair()
                self.assertEqual(code, exits.OK, lines)
                self.assertEqual(file_state(self.file()), "enforce")
                self.assertIn("written again", " ".join(lines))

    def test_a_missing_file_of_an_enforcing_node_is_written(self):
        fwrecord.write(self.root, "enforce")
        (code, lines), _ = self.repair()
        self.assertEqual(code, exits.OK, lines)
        self.assertEqual(file_state(self.file()), "enforce")

    def test_a_sound_file_is_left_alone(self):
        fwrecord.write(self.root, "enforce")
        self.repair()
        before = self.file()
        (code, lines), _ = self.repair()
        self.assertEqual((code, lines), (exits.OK, []))
        self.assertEqual(self.file(), before)

    def test_off_in_the_spec_is_nothing_to_repair(self):
        self.spec(SPEC + "firewall: {state: off}\n")
        self.assertEqual(self.repair()[0], (exits.OK, []))
        self.assertIsNone(self.file())

    def test_no_spec_is_nothing_to_repair(self):
        os.remove(join(self.root, fwrepair.SPEC))
        self.assertEqual(self.repair()[0], (exits.OK, []))

    def test_no_evidence_and_no_file_is_not_applied_not_a_failure(self):
        """a node upgraded from 0.23.97, or a new node before its first
        apply: no file, no record, no table. 0073: an upgrade changes
        nothing by itself; 0097: such a node is NOT APPLIED, a state.
        Nothing is written, loaded or failed"""
        (code, lines), nft = self.repair()
        self.assertEqual((code, lines), (exits.OK, []))
        self.assertIsNone(self.file())
        self.assertEqual(nft.loaded, [])

    def test_a_missing_file_with_a_record_is_written_again(self):
        fwrecord.write(self.root, "report")
        (code, lines), _ = self.repair()
        self.assertEqual(code, exits.OK, lines)
        self.assertEqual(file_state(self.file()), "report")

    def test_at_boot_a_node_never_applied_does_not_fail_its_unit(self):
        """a new node boots before its first apply: no file, no record,
        no table; the unit must not stay failed after that apply (the
        watch and keel firewall check say a missing file)"""
        code, lines = fwrepair.repair(self.root, live=False, run=Loads(),
                                      boot=True)
        self.assertEqual((code, lines), (exits.OK, []))

    def test_a_step_that_cannot_write_loads_the_closed_fallback(self):
        """sshd's ports read from no file: the step says NOT APPLIED"""
        fwrecord.write(self.root, "enforce")
        self.ruleset("")
        os.remove(join(self.root, "etc/ssh/sshd_config"))
        (code, lines), nft = self.repair()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("closed fallback", " ".join(lines))
        fallback = nft.loaded[0]
        self.assertIn("policy drop;", fallback)
        self.assertIn("tcp dport 22 accept", fallback)
        self.assertIn('iif "lo" accept', fallback)
        self.assertNotIn("policy accept", fallback)

    def test_the_fallback_keeps_the_mesh(self):
        text = fwrepair.fallback((22, 2222), ("wg0", 51820))
        self.assertIn("tcp dport { 22, 2222 } accept", text)
        self.assertIn("udp dport 51820 accept", text)
        self.assertIn('iifname "wg0" accept', text)
        self.assertNotIn("wg0", fwrepair.fallback((22,), None))


class TestSpecOrCopy(RepairCase):
    """the fifth real test: a spec that did not parse turned off the
    repair and the fallback, and the node rebooted open and silent"""

    def broken_spec(self):
        self.spec(SPEC + "broken: [unclosed\n")

    def good_copy(self) -> str:
        fwrecord.write(self.root, "enforce")
        self.repair()
        with open(join(self.root, PATH)) as fob:
            text = fob.read()
        fwrecord.write_copy(self.root, text)
        fwrecord.write(self.root, "enforce", fwrecord.ruleset_hash(text))
        return text

    def test_a_copy_that_is_not_the_last_apply_s_is_not_restored(self):
        """the sixth real test: an old copy opened a removed port again,
        and a report copy put an enforce node in report"""
        self.good_copy()
        # the record names the ruleset of a later apply than the copy's
        fwrecord.write(self.root, "enforce", "2" * 64)
        os.remove(join(self.root, PATH))
        with mock.patch("keel.system.fwinstall.subprocess.run", Loads()):
            self.broken_spec()
            (code, lines), nft = self.repair()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("is not the ruleset of the last apply", " ".join(lines))
        self.assertIn("keel-fallback", nft.loaded[0])
        self.assertIsNone(self.file())

    def test_a_report_node_with_a_stale_copy_fails_and_loads_nothing(self):
        text = self.good_copy()
        fwrecord.write(self.root, "report", "1" * 64)
        os.remove(join(self.root, PATH))
        self.broken_spec()
        (code, lines), nft = self.repair()
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertEqual(nft.loaded, [])

    def test_the_last_good_copy_is_restored_first_with_no_spec(self):
        text = self.good_copy()
        self.broken_spec()
        for broken in (None, "", text[:100]):
            with self.subTest(size=None if broken is None else len(broken)):
                if broken is None:
                    os.remove(join(self.root, PATH))
                else:
                    self.ruleset(broken)
                with mock.patch("keel.system.fwinstall.subprocess.run",
                                Loads()):
                    (code, lines), _ = self.repair()
                # closed by the copy, and a failure until the spec is
                # put right (the sixth real test: check exit 0)
                self.assertEqual(code, exits.DRIFT_FOUND, lines)
                self.assertEqual(self.file(), text)
                self.assertIn("restored from keel's last good copy",
                              " ".join(lines))
                self.assertIn("cannot be read or parsed", " ".join(lines))

    def test_a_broken_spec_with_enforce_and_no_copy_closes_and_fails(self):
        fwrecord.write(self.root, "enforce")
        self.broken_spec()
        (code, lines), nft = self.repair()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("cannot be read or parsed", " ".join(lines))
        self.assertIn("policy drop;", nft.loaded[0])

    def test_a_missing_spec_with_enforce_closes_too(self):
        fwrecord.write(self.root, "enforce")
        os.remove(join(self.root, fwrepair.SPEC))
        (code, lines), nft = self.repair()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("policy drop;", nft.loaded[0])

    def test_a_broken_spec_with_report_fails_loudly_and_opens_nothing(self):
        fwrecord.write(self.root, "report")
        self.broken_spec()
        (code, lines), nft = self.repair()
        self.assertEqual(code, exits.DRIFT_FOUND)
        self.assertEqual(nft.loaded, [])

    def test_an_untrusted_record_and_a_broken_file_close(self):
        """the fifth real test: the boot moved the node to report"""
        fwrecord.write(self.root, "enforce")
        self.ruleset("")
        with mock.patch("keel.system.fwrecord.ROOT_UID", os.getuid() + 1):
            (code, lines), nft = self.repair()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("policy drop;", nft.loaded[0])
        self.assertNotEqual(file_state(self.file()), "report")

    def test_check_with_a_broken_spec_and_enforce_is_drift(self):
        fwrecord.write(self.root, "enforce")
        self.broken_spec()
        found = fwcheck.check(self.root, Loads())
        self.assertEqual(found.code, exits.DRIFT_FOUND)
        self.assertIn("cannot be read or parsed", found.message)


class TestCheckMissing(RepairCase):
    """the fourth real test: file and record lost, check exit 0"""

    def test_a_missing_file_with_evidence_is_drift(self):
        """a trusted record says the node had a firewall"""
        fwrecord.write(self.root, "enforce")
        found = fwcheck.check(self.root, Loads())
        self.assertEqual(found.code, exits.DRIFT_FOUND)
        self.assertIn("no ruleset file, and keel's record says enforce",
                      found.message)

    def test_a_missing_file_with_no_evidence_is_not_applied(self):
        """the same exit as before this change (0), and said plainly"""
        found = fwcheck.check(self.root, Loads())
        self.assertEqual(found.code, exits.OK)
        self.assertIn("NOT APPLIED", found.message)
        self.assertIn("keel spec apply --system writes it", found.message)

    def test_a_missing_file_with_off_or_no_spec_is_fine(self):
        self.spec(SPEC + "firewall: {state: off}\n")
        self.assertEqual(fwcheck.check(self.root, Loads()).code, exits.OK)
        os.remove(join(self.root, fwrepair.SPEC))
        self.assertEqual(fwcheck.check(self.root, Loads()).code, exits.OK)


class TestCommand(RepairCase):
    def test_the_command_repairs_and_says_so(self):
        fwrecord.write(self.root, "enforce")
        self.ruleset("")
        code, out, err = self.cli("firewall", "repair")
        self.assertEqual(code, exits.OK, err)
        self.assertIn("written again", out)
        self.assertEqual(file_state(self.file()), "enforce")

    def test_the_command_is_silent_with_no_evidence(self):
        for extra in ((), ("--boot",)):
            code, out, err = self.cli("firewall", "repair", *extra)
            self.assertEqual((code, out, err), (exits.OK, "", ""))


class TestUpgradeFrom0_23_97(RepairCase):
    """upgrade from 0.23.97 with the timer enabled: 10 watch runs, the
    unit never failed, the system not degraded (no file, no record, no
    loaded table: the watch is silent and exits 0)"""

    def test_ten_watch_runs_never_fail_and_say_nothing(self):
        from keel.system import fwwatch

        def no_table(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, "", "No such file")
        for run in range(10):
            with self.subTest(run=run):
                self.assertEqual(fwwatch.watch(self.root, no_table,
                                               lambda: 1000 + 30 * run),
                                 (exits.OK, []))
        self.assertIsNone(self.file())
        self.assertFalse(os.path.exists(join(self.root, fwwatch.STATE)))
