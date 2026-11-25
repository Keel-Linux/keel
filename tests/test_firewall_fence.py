# Copyright (c) 2026 KeelLinux maintainers
"""The ruleset agrees with the node after the init fence goes away
(decision 0097, section 2, item 4)

While the unit of the init fence is enabled, keel's ruleset accepts the
fence ports for redirected packets only (`ct status dnat`). The first
boot hook 10keel-system applies while the fence is enabled, so the file
it writes, and the table it loads, hold that rule. Then
97turnkey-init-fence-disable disables the fence and stops it. Before
this change nothing wrote the file again, and `keel diff` said drift on
each new node (derived.firewall, exit 14) until a person applied.

Now keel's drop-in turnkey-init-fence.service.d/10-keel-firewall.conf runs
`keel firewall refresh` after each stop of the fence. When the fence is
no longer enabled, that runs the apply's firewall step, unattended, from
the spec on disk: the file is written again without the fence rule, and
loaded. While the fence is enabled (a shutdown, a stop by hand) it does
nothing.
"""

import os
import shlex
import subprocess
from os.path import join

from test_firewall_repair import SPEC, Loads, RepairCase

from keel import exits
from keel.inspect.tree import Tree
from keel.system import fwrecord, fwrepair
from keel.system.actions import Note
from keel.system.firewall import plan_firewall
from keel.system.fwstate import FENCE_DEFAULTS, FENCE_UNIT

FENCE_RULE = "ct status dnat tcp dport { 60080, 60443 } accept"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DROPIN = join(REPO, "systemd", "turnkey-init-fence.service.d",
              "10-keel-firewall.conf")
DROPIN_COMMAND = "-/usr/bin/keel firewall refresh"


class FenceCase(RepairCase):
    def setUp(self):
        super().setUp()
        path = join(self.root, FENCE_DEFAULTS)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write("HTTP_PORTS=(80)\nHTTPS_PORTS=(443 12321 12322)\n"
                      "HTTP_FENCE_PORT=60080\nHTTPS_FENCE_PORT=60443\n")

    def enable_fence(self) -> None:
        link = join(self.root, FENCE_UNIT)
        os.makedirs(os.path.dirname(link), exist_ok=True)
        os.symlink("/usr/lib/systemd/system/turnkey-init-fence.service",
                   link)

    def disable_fence(self) -> None:
        os.remove(join(self.root, FENCE_UNIT))

    def first_boot(self) -> None:
        """What 10keel-system leaves: enforce, written while the fence
        is enabled, with the fence rule in the file"""
        self.enable_fence()
        fwrecord.write(self.root, "enforce")
        (code, lines), _ = self.repair()
        self.assertEqual(code, exits.OK, lines)
        self.assertIn(FENCE_RULE, self.file())

    def firewall_diff(self) -> str:
        _, out, err = self.cli("diff", "--spec",
                                  join(self.root, fwrepair.SPEC))
        found = [line for line in out.splitlines()
                 if line.startswith("derived.firewall:")]
        self.assertEqual(len(found), 1, out + err)
        return found[0]

    def refresh(self, nft=None):
        nft = nft or Loads()
        return fwrepair.refresh(self.root, live=False, run=nft), nft


class TestDriftAfterTheFence(FenceCase):
    def test_the_first_boot_file_agrees_while_the_fence_is_enabled(self):
        self.first_boot()
        self.assertIn("derived.firewall: same", self.firewall_diff())

    def test_with_no_refresh_the_file_is_drift_once_the_fence_is_gone(self):
        """the defect: what keel-nextcloud PR 8, run 19, saw"""
        self.first_boot()
        self.disable_fence()
        self.assertIn("derived.firewall: drift", self.firewall_diff())


class TestRefresh(FenceCase):
    def test_after_the_fence_the_file_loses_the_fence_rule(self):
        self.first_boot()
        self.disable_fence()
        (code, lines), _ = self.refresh()
        self.assertEqual(code, exits.OK, lines)
        self.assertNotIn("ct status dnat", self.file())
        self.assertEqual(fwrecord.read(Tree(self.root))[0], "enforce")
        self.assertIn("derived.firewall: same", self.firewall_diff())

    def test_a_second_refresh_and_an_attended_plan_change_nothing(self):
        self.first_boot()
        self.disable_fence()
        self.refresh()
        before = self.file()
        (code, lines), _ = self.refresh()
        self.assertEqual(code, exits.OK, lines)
        self.assertEqual(self.file(), before)
        self.assertIn(f"unchanged (/{fwrepair.PATH})", " ".join(lines))
        actions = self.attended_actions()
        self.assertTrue(all(isinstance(action, Note) for action in actions),
                        [action.describe() for action in actions])

    def test_while_the_fence_is_enabled_nothing_runs(self):
        """a shutdown, or a stop by hand: the fence comes back at the
        next boot, and its rule stays"""
        self.first_boot()
        before = self.file()
        (code, lines), nft = self.refresh()
        self.assertEqual((code, lines), (exits.OK, []))
        self.assertEqual(self.file(), before)
        self.assertEqual(nft.loaded, [])

    def test_a_node_with_no_firewall_of_keel_s_is_left_alone(self):
        """no file, no record, no table: NOT APPLIED, a state; a stop
        of the fence never begins a firewall"""
        (code, lines), _ = self.refresh()
        self.assertEqual((code, lines), (exits.OK, []))
        self.assertIsNone(self.file())

    def test_off_in_the_spec_is_left_alone(self):
        self.first_boot()
        self.disable_fence()
        self.spec(SPEC + "firewall: {state: off}\n")
        before = self.file()
        self.assertEqual(self.refresh()[0], (exits.OK, []))
        self.assertEqual(self.file(), before)

    def test_no_spec_says_why_and_loads_no_fallback(self):
        """the stop of the fence never closes a node: the old ruleset
        stays, and the line says what to run"""
        self.first_boot()
        self.disable_fence()
        os.remove(join(self.root, fwrepair.SPEC))
        before = self.file()
        (code, lines), nft = self.refresh()
        self.assertEqual(code, exits.OK)
        self.assertIn("keel spec apply --system", " ".join(lines))
        self.assertEqual(self.file(), before)
        self.assertEqual(nft.loaded, [])
        self.assertFalse(os.path.exists(join(self.root, fwrepair.FALLBACK)))

    def test_with_the_lock_free_the_refresh_takes_it_and_runs(self):
        """the path the ExecStopPost takes on the live system"""
        self.first_boot()
        self.disable_fence()
        code, lines = fwrepair.refresh(self.root, live=False, run=Loads(),
                                       lock=True)
        self.assertEqual(code, exits.OK, lines)
        self.assertNotIn("ct status dnat", self.file())
        from keel.system import fwlock
        with fwlock.held(self.root, 0.1) as held:
            self.assertTrue(held)

    def test_the_drop_in_runs_before_the_certificate_s(self):
        """keel#320's keel-certificate.conf starts a unit whose apply
        holds the firewall lock: the refresh comes first"""
        self.assertLess(os.path.basename(DROPIN), "keel-certificate.conf")

    def test_a_held_lock_skips_the_run_and_says_so(self):
        self.first_boot()
        self.disable_fence()
        from keel.system import fwlock
        with fwlock.held(self.root, 1.0) as held:
            self.assertTrue(held)
            code, lines = fwrepair.refresh(self.root, live=False,
                                           run=Loads(), lock=True,
                                           wait=0.1)
        self.assertEqual(code, exits.OK)
        self.assertIn("an apply holds the firewall lock", " ".join(lines))

    def test_the_command_refreshes(self):
        self.first_boot()
        self.disable_fence()
        code, _, err = self.cli("firewall", "refresh")
        self.assertEqual(code, exits.OK, err)
        self.assertNotIn("ct status dnat", self.file())

    def attended_actions(self):
        from keel.commands import manifest_facts
        from keel.spec.validate_appliance import with_defaults
        from keel.system import appstate
        doc = fwrepair.spec_doc(self.root)
        full, _ = with_defaults(doc, manifest_facts(doc, self.root))
        appliance = appstate.observe_appliance(self.root, full)
        steps = plan_firewall(full, appliance.resolved, appliance.firewall,
                              False, frozenset(), attended=True)
        return [action for step in steps for action in step.actions]


class TestDropIn(FenceCase):
    def test_the_drop_in_refreshes_after_each_stop_of_the_fence(self):
        with open(DROPIN) as fob:
            found = [line.strip() for line in fob
                     if line.strip() and not line.startswith("#")]
        self.assertEqual(found, ["[Service]",
                                 f"ExecStopPost={DROPIN_COMMAND}"])

    def test_the_drop_in_is_installed_beside_any_other(self):
        """its own file: keel#320's keel-certificate.conf in the same
        directory merges in any order"""
        with open(join(REPO, "debian", "keel.install")) as fob:
            self.assertIn(
                "systemd/turnkey-init-fence.service.d/10-keel-firewall.conf"
                " /usr/lib/systemd/system/turnkey-init-fence.service.d\n",
                fob.read())

    def test_the_command_of_the_drop_in_is_one_keel_knows(self):
        argv = shlex.split(DROPIN_COMMAND.lstrip("-"))
        self.assertEqual(argv[1:], ["firewall", "refresh"])
        done = subprocess.run(
            ["python3", "-m", "keel", "firewall", "refresh", "--help"],
            cwd=REPO, capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)

