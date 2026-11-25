# Copyright (c) 2026 KeelLinux maintainers
"""keel#328: only an apply a person runs closes SSH on IPv4 (0098, 6 B)

The first boot's hooks run keel spec apply (10keel-system, and the
console's steps of 75keel-role with no terminal), which counts as
attended for rule B of decision 0097. For SSH it does not: nobody is
there. keel reads the first boot's run as inithooks does
(libinithooks/init_lock.py boot_pending): RUN_FIRSTBOOT=true in
/etc/default/inithooks and no /run/inithooks-complete. An unattended run
keeps what keel's file says, never narrows, and never undoes the close
of a person while IPv6 is gone for a moment (the guard opens IPv4 22
live then).
"""

import dataclasses
import os
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)
from test_access_network import ACCESS
from test_system_firewall import FirewallCase
from test_system_firewall import doc as fwdoc

from keel.diff import appliance as diffappliance
from keel.diff.report import SAME
from keel.inspect.tree import File, Tree
from keel.manifest.firewall import PATH, SSH_LINE
from keel.system import fwstate
from keel.system.actions import Note
from keel.system.firewall import ssh_narrowed

NARROW = "meta nfproto ipv6 tcp dport 22 accept"


def declared() -> dict:
    found = fwdoc()
    found["network"]["access"] = ACCESS
    return found


class SshCase(FirewallCase):
    def state(self, **fields):
        return super().state(**{"ssh_ipv6": True, "global_ipv6": True,
                                **fields})

    def written(self, found) -> str | None:
        return next((one.content for one in found
                     if hasattr(one, "content")), None)

    def said(self, found) -> str:
        return " ".join(one.summary for one in found
                        if isinstance(one, Note))

    def narrowed_file(self) -> str:
        first = self.actions(spec=declared(), state=self.state())
        text = self.written(first)
        self.assertIn(SSH_LINE, text)
        return text


class TestBootRun(SshCase):
    def put(self, path: str, text: str) -> None:
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fob:
            fob.write(text)

    def test_the_first_boot_run_is_read_as_inithooks_reads_it(self):
        tree = Tree(self.root)
        self.assertFalse(fwstate.boot_run(tree))
        for text in ("RUN_FIRSTBOOT=true\n", "export RUN_FIRSTBOOT=TRUE\n",
                     'RUN_FIRSTBOOT="true"  # first boot\n',
                     "REDIRECT_OUTPUT=false\nRUN_FIRSTBOOT='True'\n"):
            self.put(fwstate.INITHOOKS_DEFAULT, text)
            self.assertTrue(fwstate.boot_run(tree), text)
        self.put(fwstate.INITHOOKS_COMPLETE, "")
        self.assertFalse(fwstate.boot_run(tree))
        os.remove(os.path.join(self.root, fwstate.INITHOOKS_COMPLETE))
        for text in ("RUN_FIRSTBOOT=false\n", "#RUN_FIRSTBOOT=true\n",
                     "RUN_FIRSTBOOT=true\nRUN_FIRSTBOOT=false\n"):
            self.put(fwstate.INITHOOKS_DEFAULT, text)
            self.assertFalse(fwstate.boot_run(tree), text)

    def test_only_the_live_system_has_a_first_boot_run(self):
        self.put(fwstate.INITHOOKS_DEFAULT, "RUN_FIRSTBOOT=true\n")
        tree = Tree(self.root)
        with mock.patch.multiple(
                fwstate, ssh_ports=mock.DEFAULT, observe_listeners=mock.DEFAULT,
                sshd_ports=mock.DEFAULT, fence_ports=mock.DEFAULT) as found:
            found["ssh_ports"].return_value = ((22,), "x")
            found["observe_listeners"].return_value = (None, "x")
            found["sshd_ports"].return_value = ()
            found["fence_ports"].return_value = ((), "")
            self.assertFalse(fwstate.observe_firewall(tree, False).boot_run)


class TestFirstBoot(SshCase):
    def test_the_first_boot_s_apply_keeps_ipv4_22(self):
        """keel#328: 10keel-system runs keel spec apply, attended"""
        found = self.actions(spec=declared(),
                             state=self.state(boot_run=True))
        text = self.written(found)
        self.assertNotIn(SSH_LINE, text)
        self.assertNotIn(NARROW, text)
        self.assertIn("the first boot", self.said(found))
        self.assertNotIn("IPv4 is closed", self.said(found))

    def test_rule_b_still_moves_at_the_first_boot(self):
        """only SSH waits for a person; the state rule B writes does not
        change (PR 323)"""
        booting = self.written(self.actions(
            spec=declared(), state=self.state(boot_run=True)))
        person = self.written(self.actions(spec=declared(),
                                           state=self.state()))
        self.assertEqual(booting.split("policy ")[1].split(";")[0],
                         person.split("policy ")[1].split(";")[0])

    def test_said_by_ssh_narrowed(self):
        found, said = ssh_narrowed(self.state(boot_run=True), False)
        self.assertFalse(found)
        self.assertIn("the first boot", said)

    def test_an_apply_a_person_runs_after_the_boot_closes_it(self):
        found = self.actions(spec=declared(), state=self.state())
        self.assertIn(SSH_LINE, self.written(found))

    def test_a_narrowed_file_stays_narrowed_at_the_first_boot(self):
        text = self.narrowed_file()
        found = self.actions(spec=declared(), state=self.state(
            boot_run=True, file=File("/r/x", text), copy=text,
            recorded="enforce"))
        self.assertIsNone(self.written(found))


class TestUnattended(SshCase):
    def test_an_unattended_run_never_narrows(self):
        for fields in ({}, {"boot_run": True}):
            found = self.actions(spec=declared(), state=self.state(**fields),
                                 attended=False)
            text = self.written(found)
            self.assertNotIn(SSH_LINE, text)

    def test_an_ipv6_loss_does_not_undo_a_person_s_close(self):
        """keel mesh applies every 15 minutes with no person: a moment
        with no IPv6 default route must not write IPv4 22 open again in
        the file; the guard opens it live meanwhile"""
        text = self.narrowed_file()
        lost = self.state(global_ipv6=False,
                          global_ipv6_source="no IPv6 default route",
                          file=File("/r/x", text), copy=text,
                          recorded="enforce")
        found = self.actions(spec=declared(), state=lost, attended=False)
        self.assertIsNone(self.written(found))
        self.assertTrue(ssh_narrowed(lost, False)[0])

    def test_a_person_with_no_ipv6_opens_it_again(self):
        text = self.narrowed_file()
        lost = self.state(global_ipv6=False,
                          global_ipv6_source="no IPv6 default route",
                          file=File("/r/x", text), copy=text,
                          recorded="enforce")
        found = self.actions(spec=declared(), state=lost)
        self.assertNotIn(SSH_LINE, self.written(found))

    def test_sshd_off_ipv6_opens_it_again_even_unattended(self):
        text = self.narrowed_file()
        for value in (False, None):
            off = self.state(ssh_ipv6=value, file=File("/r/x", text),
                             copy=text, recorded="enforce")
            self.assertFalse(ssh_narrowed(off, False)[0], value)


class TestDiff(SshCase):
    def fields(self, state):
        # keel diff reads keel's file from the root, the state from
        # observe_firewall
        full = os.path.join(self.root, PATH)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fob:
            fob.write(state.file.text)
        with mock.patch.object(diffappliance, "observe_firewall",
                               return_value=state):
            return diffappliance.firewall_fields(
                declared(), self.resolved, {}, Tree(self.root))

    def test_a_node_no_person_narrowed_is_not_drift(self):
        """keel diff compares with what the file says of SSH: the close
        is a person's act, not a field of the spec"""
        booted = self.written(self.actions(
            spec=declared(), state=self.state(boot_run=True)))
        state = self.state(file=File("/r/x", booted), copy=booted,
                           recorded="enforce")
        found = {one.field: one for one in self.fields(state)}
        self.assertEqual(found["derived.firewall"].status, SAME)

    def test_a_narrowed_node_is_not_drift_either(self):
        text = self.narrowed_file()
        state = self.state(file=File("/r/x", text), copy=text,
                           recorded="enforce")
        found = {one.field: one for one in self.fields(state)}
        self.assertEqual(found["derived.firewall"].status, SAME)
        found = {one.field: one for one in self.fields(dataclasses.replace(
            state, global_ipv6=False))}
        self.assertEqual(found["derived.firewall"].status, SAME)
