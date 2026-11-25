# Copyright (c) 2026 KeelLinux maintainers
"""keel#330 and keel#303: CrowdSec and fail2ban never ban keel's own
networks

An administrator's computer on the access network (decision 0098,
section 4.7) and a node of the mesh (decision 0086, answer 1) lost their
place after a few failed logins or 401 answers. keel writes the access
/64 and the mesh /64 in a CrowdSec whitelist of its own, and the access
/64 in the `ignoreip` of fail2ban, only where the spec declares them and
the package is on the node; keel diff compares both files with what
apply writes.
"""

import os
import shutil
import tempfile
import unittest

from helpers import spec  # noqa: F401  (puts the repository on sys.path)
from test_access_network import ACCESS

from keel.diff.report import DRIFT, SAME
from keel.system import trusted
from keel.system.actions import Attempt, Note, RemoveFile, WriteFile

ACCESS_NET = "fd12:3456:789a:1::/64"
MESH = {"address": "fde4:fee2:c919::1/64", "listen_port": 51820,
        "ipv4_address": "10.99.0.1/24"}
MESH_NET = "fde4:fee2:c919::/64"
LIVE = frozenset({"systemctl"})


def doc(access=True, mesh=False) -> dict:
    network: dict = {}
    if access:
        network["access"] = ACCESS
    if mesh:
        network["overlay"] = {"wireguard": MESH}
    return {"version": 1, "network": network}


class RootCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def put(self, path: str, text: str) -> None:
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fob:
            fob.write(text)

    def packages(self, crowdsec=True, fail2ban=True) -> None:
        if crowdsec:
            os.makedirs(os.path.join(self.root, trusted.CROWDSEC_DIR),
                        exist_ok=True)
        if fail2ban:
            os.makedirs(os.path.join(self.root, trusted.FAIL2BAN_DIR),
                        exist_ok=True)

    def plan(self, declared: dict, live=True) -> dict:
        state = trusted.observe_trusted(self.root)
        return {step.field: step.actions for step in trusted.plan_trusted(
            declared, state, live, LIVE if live else frozenset())}


class TestPrefixes(unittest.TestCase):
    def test_the_access_and_the_mesh_prefix(self):
        self.assertEqual(trusted.crowdsec_prefixes(doc()), (ACCESS_NET,))
        self.assertEqual(trusted.crowdsec_prefixes(doc(access=False,
                                                       mesh=True)),
                         (MESH_NET,))
        self.assertEqual(trusted.crowdsec_prefixes(doc(mesh=True)),
                         (ACCESS_NET, MESH_NET))
        self.assertEqual(trusted.crowdsec_prefixes(doc(access=False)), ())
        self.assertEqual(trusted.fail2ban_prefixes(doc(mesh=True)),
                         (ACCESS_NET,))
        self.assertEqual(trusted.fail2ban_prefixes(doc(access=False,
                                                       mesh=True)), ())

    def test_an_address_keel_cannot_read_counts_for_nothing(self):
        broken = doc(mesh=True)
        broken["network"]["access"] = {"address": "not an address"}
        broken["network"]["overlay"]["wireguard"] = {"address": "x"}
        self.assertEqual(trusted.crowdsec_prefixes(broken), ())

    def test_the_files(self):
        text = trusted.render_crowdsec((ACCESS_NET, MESH_NET))
        self.assertTrue(text.startswith(trusted.HEADER))
        self.assertIn("whitelist:\n", text)
        self.assertIn(f'    - "{ACCESS_NET}"\n', text)
        self.assertIn(f'    - "{MESH_NET}"\n', text)
        self.assertIn("name: keel/whitelist\n", text)
        text = trusted.render_fail2ban((ACCESS_NET,))
        self.assertTrue(text.startswith(trusted.HEADER))
        # a later [DEFAULT] ignoreip replaces the earlier one: the
        # loopback of the image's jail.local stays in it
        self.assertIn(f"[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 {ACCESS_NET}\n",
                      text)
        self.assertIsNone(trusted.render_crowdsec(()))
        self.assertIsNone(trusted.render_fail2ban(()))


class TestPlan(RootCase):
    def test_written_and_reloaded_where_the_packages_are(self):
        self.packages()
        found = self.plan(doc(mesh=True))
        crowdsec = found[trusted.CROWDSEC_FIELD]
        self.assertIsInstance(crowdsec[0], WriteFile)
        self.assertEqual(crowdsec[0].path, trusted.CROWDSEC_PATH)
        self.assertEqual(crowdsec[0].mode, 0o644)
        self.assertIn(MESH_NET, crowdsec[0].content)
        self.assertIsInstance(crowdsec[1], Attempt)
        self.assertEqual(crowdsec[1].argv, (
            "systemctl", "try-reload-or-restart", "crowdsec.service"))
        fail2ban = found[trusted.FAIL2BAN_FIELD]
        self.assertEqual(fail2ban[0].path, trusted.FAIL2BAN_PATH)
        self.assertNotIn(MESH_NET, fail2ban[0].content)
        self.assertEqual(fail2ban[1].argv, (
            "systemctl", "try-reload-or-restart", "fail2ban.service"))

    def test_a_simple_node_with_an_access_network_gets_both(self):
        """keel#330: not only a node of a mesh"""
        self.packages()
        found = self.plan(doc())
        self.assertIn(ACCESS_NET, found[trusted.CROWDSEC_FIELD][0].content)
        self.assertIn(ACCESS_NET, found[trusted.FAIL2BAN_FIELD][0].content)

    def test_nothing_where_a_package_is_not_there(self):
        self.packages(crowdsec=False)
        found = self.plan(doc())
        self.assertNotIn(trusted.CROWDSEC_FIELD, found)
        self.assertIn(trusted.FAIL2BAN_FIELD, found)
        os.rmdir(os.path.join(self.root, trusted.FAIL2BAN_DIR))
        self.assertEqual(self.plan(doc()), {})

    def test_nothing_declared_and_nothing_written_is_no_step(self):
        self.packages()
        self.assertEqual(self.plan(doc(access=False)), {})

    def test_the_same_file_is_unchanged(self):
        self.packages()
        self.put(trusted.CROWDSEC_PATH,
                 trusted.render_crowdsec((ACCESS_NET,)))
        self.put(trusted.FAIL2BAN_PATH,
                 trusted.render_fail2ban((ACCESS_NET,)))
        for actions in self.plan(doc()).values():
            self.assertEqual([type(one) for one in actions], [Note])
            self.assertIn("unchanged", actions[0].summary)

    def test_keel_s_file_goes_with_the_section(self):
        self.packages()
        self.put(trusted.CROWDSEC_PATH,
                 trusted.render_crowdsec((ACCESS_NET,)))
        self.put(trusted.FAIL2BAN_PATH,
                 trusted.render_fail2ban((ACCESS_NET,)))
        found = self.plan(doc(access=False))
        for field in (trusted.CROWDSEC_FIELD, trusted.FAIL2BAN_FIELD):
            self.assertIsInstance(found[field][0], RemoveFile)
            self.assertIsInstance(found[field][1], Attempt)

    def test_a_file_keel_did_not_write_is_left_alone(self):
        self.packages()
        self.put(trusted.FAIL2BAN_PATH, "[DEFAULT]\nignoreip = ::1\n")
        found = self.plan(doc())[trusted.FAIL2BAN_FIELD]
        self.assertEqual([type(one) for one in found], [Note])
        self.assertIn("keel did not write it", found[0].summary)
        found = self.plan(doc(access=False))[trusted.FAIL2BAN_FIELD]
        self.assertEqual([type(one) for one in found], [Note])

    def test_under_a_root_written_and_not_reloaded(self):
        self.packages()
        found = self.plan(doc(), live=False)
        for actions in found.values():
            self.assertEqual([type(one) for one in actions], [WriteFile])


class TestJailLocal(RootCase):
    def test_the_ignoreip_of_jail_local_is_kept(self):
        """a later [DEFAULT] ignoreip replaces the one before it: what the
        operator put in jail.local stays in keel's"""
        self.packages()
        self.put(trusted.JAIL_LOCAL, "[DEFAULT]\nignoreip    = 127.0.0.1/8"
                 " ::1  192.0.2.7  # office\nbantime = 3600\n[sshd]\n"
                 "ignoreip = 198.51.100.1\n")
        found = self.plan(doc())[trusted.FAIL2BAN_FIELD][0]
        self.assertIn(f"ignoreip = 127.0.0.1/8 ::1 192.0.2.7 {ACCESS_NET}\n",
                      found.content)

    def test_the_loopback_where_jail_local_says_nothing(self):
        self.packages()
        self.put(trusted.JAIL_LOCAL, "[sshd]\nenabled = true\n")
        found = self.plan(doc())[trusted.FAIL2BAN_FIELD][0]
        self.assertIn(f"ignoreip = 127.0.0.1/8 ::1 {ACCESS_NET}\n",
                      found.content)

    def test_the_access_prefix_is_not_twice(self):
        self.assertEqual(trusted.ignoreip(
            f"[DEFAULT]\nignoreip = ::1 {ACCESS_NET}\n"), ("::1",
                                                          ACCESS_NET))


class TestDiff(RootCase):
    def fields(self, declared: dict) -> dict:
        return {one.field: one
                for one in trusted.trusted_fields(declared, self.root)}

    def test_missing_same_another_and_left_over(self):
        self.packages()
        found = self.fields(doc(mesh=True))
        self.assertEqual(found[trusted.CROWDSEC_FIELD].status, DRIFT)
        self.assertEqual(found[trusted.FAIL2BAN_FIELD].status, DRIFT)
        self.put(trusted.CROWDSEC_PATH,
                 trusted.render_crowdsec((ACCESS_NET, MESH_NET)))
        self.put(trusted.FAIL2BAN_PATH,
                 trusted.render_fail2ban((ACCESS_NET,)))
        found = self.fields(doc(mesh=True))
        self.assertEqual(found[trusted.CROWDSEC_FIELD].status, SAME)
        self.assertEqual(found[trusted.FAIL2BAN_FIELD].status, SAME)
        # the access address moved: the files must follow it
        moved = doc(mesh=True)
        moved["network"]["access"] = {**ACCESS,
                                      "address": "fd12:3456:789a:2::1/64"}
        found = self.fields(moved)
        self.assertEqual(found[trusted.CROWDSEC_FIELD].status, DRIFT)
        self.assertEqual(found[trusted.FAIL2BAN_FIELD].status, DRIFT)
        found = self.fields(doc(access=False))
        self.assertEqual(found[trusted.CROWDSEC_FIELD].status, DRIFT)
        self.assertIn("removes", found[trusted.CROWDSEC_FIELD].note)

    def test_no_field_without_a_package_or_a_declaration(self):
        self.assertEqual(self.fields(doc()), {})
        self.packages()
        self.assertEqual(self.fields(doc(access=False)), {})

    def test_diff_root_carries_them(self):
        from keel.diff import observe
        self.packages()
        found = observe.diff_root(doc(), self.root)
        names = {one.field for one in found.fields}
        self.assertIn(trusted.CROWDSEC_FIELD, names)
        self.assertIn(trusted.FAIL2BAN_FIELD, names)


class TestTheApplyPlansIt(RootCase):
    def test_system_plan_has_the_steps(self):
        from keel.system import observe as observe_system
        from keel.system import plan as plan_system
        self.packages()
        state = observe_system(self.root, doc())
        fields = {step.field for step in plan_system(doc(), state).steps}
        self.assertIn(trusted.CROWDSEC_FIELD, fields)
        self.assertIn(trusted.FAIL2BAN_FIELD, fields)


if __name__ == "__main__":
    unittest.main()
