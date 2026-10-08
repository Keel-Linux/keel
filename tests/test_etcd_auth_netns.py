# Copyright (c) 2026 KeelLinux maintainers
"""keel#83 under the design case of decision 0050: the live layout moved

tests/etcd_auth_netns.py, as root in a network namespace of its own
(tests/wgtools.py says how), with the real wg-quick, the real etcd 3.5
and etcdctl (on PATH, or their directory named by KEEL_ETCD_DIR), keel's
members' channel and VIP controller, on links of 250 ms ±25 ms with 2%
loss, measured first. Three members start in the layout before keel#83
(an intermediate per member); `keel mesh etcd reissue` moves them while
the VIP is held and every member's quorum is watched; then etcd refuses
a member outside the VIP's pair its writes, no member can mint a
certificate, a renewal goes through the root (and waits while the root
cannot be reached), and the rollback turns auth off. In CI a missing
tool fails instead of skipping; it runs in its own job, "etcd-auth /
trixie", which sets KEEL_ETCD_AUTH_NETNS.
"""

import json
import os
import shutil
import subprocess
import sys
import unittest

import wgtools
from test_etcd_netns import etcd_dir

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "etcd_auth_netns.py")


class TestTheLiveLayoutMoved(unittest.TestCase):
    found: dict = {}

    def setUp(self):
        if os.environ.get("CI") and \
                not os.environ.get("KEEL_ETCD_AUTH_NETNS"):
            self.skipTest("runs in the etcd-auth / trixie job")
        tools = wgtools.require(self)
        etcd = etcd_dir()
        if etcd is None or not (shutil.which("etcdctl") or os.access(
                os.path.join(etcd, "etcdctl"), os.X_OK)):
            if os.environ.get("CI"):
                self.fail("etcd and etcdctl are not installed in CI")
            self.skipTest("etcd or etcdctl not found (set KEEL_ETCD_DIR)")
        if not os.path.exists("/sys/module/wireguard") and \
                not os.environ.get("CI"):
            self.skipTest("the wireguard kernel module is not loaded")
        if not shutil.which("tc") and not os.environ.get("CI"):
            self.skipTest("tc not found (iproute2)")
        if not self.found:
            self.found.update(self.run_driver(f"{tools}:{etcd}"))

    def run_driver(self, path: str) -> dict:
        prefix = wgtools.namespace_prefix()
        if prefix is None:
            if os.environ.get("CI"):
                self.fail("no way to run wg-quick as root in a namespace")
            self.skipTest("neither root, user namespaces nor sudo -n")
        done = subprocess.run(
            prefix + ["env", f"PATH={path}:{os.environ.get('PATH', '')}",
                      f"PYTHONPATH={REPO}:{REPO}/tests",
                      f"TMPDIR={os.environ.get('TMPDIR') or '/tmp'}",
                      sys.executable, DRIVER],
            capture_output=True, text=True, check=False, timeout=2400)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                print(line, file=sys.stderr)
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-3000:]}\n"
                  f"{done.stderr[-3000:]}")

    def test_0_it_ran_to_its_end(self):
        self.assertNotIn("error", self.found, self.found.get("trace"))
        self.assertIsNotNone(self.found["etcd_formed_s"], self.found)

    def test_the_links_are_the_design_case(self):
        """Measured before the scenario, as tests/test_etcd_netns.py
        judges it"""
        link = self.found["link"]
        self.assertEqual(self.found["netem_leg"], ["125ms", "12.5ms", "2%"])
        self.assertIn("rtt_min_ms", link, link)
        self.assertGreater(link["rtt_min_ms"], 220, link)
        self.assertLess(link["rtt_min_ms"], 280, link)
        self.assertLess(link["rtt_median_ms"], 300, link)
        self.assertGreater(link["loss"], 0.005, link)
        self.assertLess(link["loss"], 0.08, link)

    def test_it_starts_in_the_live_layout(self):
        self.assertEqual(self.found["legacy_files"], [True, True, True])
        self.assertEqual(self.found["promote"]["code"], 0,
                         self.found["promote"])
        self.assertIsNotNone(self.found["a_holds_s"])

    def test_etcdctl_meets_the_vip_s_renewal(self):
        """A renewal is a keep-alive and a linearizable read: both,
        process included, well within the controller's call timeout"""
        cost = self.found["overhead"]
        self.assertLess(cost["spawn"]["median_ms"], 200, cost)
        self.assertLess(cost["keepalive"]["max_ms"],
                        cost["call_timeout_s"] * 1000, cost)
        self.assertLess(cost["read"]["max_ms"],
                        cost["call_timeout_s"] * 1000, cost)
        self.assertLess(cost["renewal_ms_max"],
                        cost["release_after_s"] * 1000 / 2, cost)

    def test_the_move_keeps_the_quorum(self):
        moved = self.found["reissue"]
        self.assertEqual(moved["code"], 0, moved)
        quorum = self.found["during"]["quorum"]
        for name, seen in quorum.items():
            with self.subTest(member=name):
                self.assertGreater(seen["samples"],
                                   self.found["reissue_s"] // 2, seen)
                # one leader, one term: nothing restarted, no election
                self.assertEqual(len(seen["leaders"]), 1, seen)
                self.assertEqual(len(seen["terms"]), 1, seen)
                # a linearizable read needs the quorum; at 2% loss a
                # read now and then times out
                self.assertLessEqual(seen["read_failed"],
                                     max(2, seen["samples"] // 20), seen)
        self.assertEqual(len({one["leaders"][0] for one in quorum.values()
                              if one["leaders"]}), 1, quorum)

    def test_the_move_leaves_the_vip_s_holder_alone(self):
        during = self.found["during"]
        self.assertEqual(during["holders"], [["A"]], during)
        self.assertGreater(during["samples"], 0)
        # C's pings every 50 ms: no gap a lost packet or two cannot make
        self.assertIsNotNone(during["ping_gap_s"])
        self.assertLess(during["ping_gap_s"], 1.5, during)
        before, after = self.found["epoch_before"], self.found["epoch_after"]
        self.assertEqual(before, after)
        self.assertIsNotNone(before["epoch"])

    def test_every_member_holds_a_certificate_the_root_signed(self):
        serials = sorted(self.found["legacy_serials"].values())
        for name, found in self.found["credentials"].items():
            with self.subTest(member=name):
                self.assertEqual(found["legacy"], [], found)
                self.assertTrue(found["root_signed"], found)
                self.assertFalse(found["is_ca"], found)
                self.assertEqual(found["cn"], found["name"], found)
                self.assertEqual(found["sans"][1:], ["::1"], found)
                self.assertEqual(found["root_key"], name == "A", found)
                # every intermediate is revoked, on every member
                self.assertEqual(sorted(set(found["crl"]) & set(serials)),
                                 serials, found)
        self.assertEqual(self.found["auth"], {"enabled": True})

    def test_a_member_outside_the_pair_cannot_write_the_vip_s_keys(self):
        c = self.found["rbac_c"]
        self.assertTrue(c["read"].startswith("done"), c)
        for one in ("put", "delete", "revoke", "swap"):
            with self.subTest(call=one):
                self.assertIn("permission denied", c[one], c)
        b = self.found["rbac_b"]
        self.assertEqual(b["swap"], "done: False", b)

    def test_no_member_gets_a_certificate_for_another_s_address(self):
        """keel#83's review: B asks the root for C's address and key with
        a request of its own, and for C's address with C's key; refused,
        and B's own renewal still goes through"""
        found = self.found["steal_b"]
        self.assertIn("refused", found["as_c"], found)
        self.assertIn("evidence", found["as_c"], found)
        self.assertIn("refused", found["c_address_own_key"], found)
        self.assertIn("another member's", found["c_address_own_key"], found)
        self.assertTrue(found["own"].startswith("done"), found)

    def test_no_member_can_mint_a_certificate(self):
        found = self.found["mint_c"]
        self.assertEqual(found["ca_keys"], [], found)
        self.assertTrue(found["minted_root"].startswith("refused"), found)
        self.assertNotIn("permission denied", found["minted_root"], found)
        # its own certificate is its own user, never etcd's root
        self.assertIn("permission denied", found["own_as_root"], found)

    def test_a_renewal_goes_through_the_root_and_waits_for_it(self):
        renewed = self.found["renew_c"]
        self.assertTrue(renewed["renewed"], renewed)
        self.assertTrue(renewed["root_signed"], renewed)
        self.assertTrue(renewed["reads"].startswith("done"), renewed)
        waits = self.found["renew_c_holder_cut"]
        self.assertFalse(waits["renewed"], waits)
        self.assertIn("cannot be reached", waits["error"], waits)
        back = self.found["renew_c_holder_back"]
        self.assertTrue(back["renewed"], back)
        self.assertTrue(back["reads"].startswith("done"), back)

    def test_never_two_holders(self):
        self.assertEqual(self.found["double_holder_samples"], [])

    def test_the_rollback_turns_auth_off(self):
        self.assertEqual(self.found["rollback"]["code"], 0,
                         self.found["rollback"])
        found = self.found["rbac_c_rolled_back"]
        self.assertEqual(found["swap"], "done: False", found)


if __name__ == "__main__":
    unittest.main()
