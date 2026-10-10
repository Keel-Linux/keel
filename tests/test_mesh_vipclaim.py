# Copyright (c) 2026 KeelLinux maintainers
"""The claim's compare-and-swap, tried again when etcd does not answer
it in time (keel#135), on the fake etcd of tests/vip_helpers.py

A transaction that times out may have committed. So before any second
try the counter is read: this node's own claim at the expected epoch is
taken as made; another claim stops the claim; nothing new is tried again
with the same comparison, never a blind write. The leases of the tries
that did not win are revoked, so a late transaction with one of them
fails in etcd.
"""

from unittest import mock

from test_mesh_vipetcd import MESH_HEX, WithEtcd
from vip_helpers import VIP

from keel.mesh import vipetcd, vipnode, vippromote
from keel.mesh.etcdclient import EtcdError
from keel import exits

TIMEOUT = EtcdError("etcdctl txn: no answer within 10.5 s")


class ClaimCase(WithEtcd):
    def sign(self, index: int):
        return lambda vip, epoch, lease: vipnode.signed_claim(
            self.all[index], vip, epoch, lease)

    def swaps(self, *plan: str):
        """kv.swap as etcd answers it, one entry per call: "ok" (as
        etcd), "commit-timeout" (committed, the answer lost),
        "timeout" (not committed), "other" (another node's claim lands,
        then the answer is lost); then as etcd"""
        real = self.kv.swap
        steps = list(plan)
        self.swapped: list[str] = []

        def swap(compare, puts, deletes=()):
            step = steps.pop(0) if steps else "ok"
            self.swapped.append(step)
            if step == "ok":
                return real(compare, puts, deletes)
            if step == "commit-timeout":
                real(compare, puts, deletes)
                raise TIMEOUT
            if step == "other":
                now = vipetcd.seen(self.kv, MESH_HEX).get(VIP) or \
                    vipetcd.Seen(VIP)
                self.kv.swap = real
                try:
                    vipetcd.claim(self.kv, MESH_HEX, VIP, now, 0,
                                  self.sign(1), self.monotonic)
                finally:
                    self.kv.swap = swap
                raise TIMEOUT
            self.sleep(10.5)
            raise TIMEOUT
        self.kv.swap = swap

    def claim(self, index: int = 0):
        now = vipetcd.seen(self.kv, MESH_HEX).get(VIP) or vipetcd.Seen(VIP)
        return vipetcd.claim(self.kv, MESH_HEX, VIP, now, 0,
                             self.sign(index), self.monotonic)

    def counter(self):
        return vipetcd.seen(self.kv, MESH_HEX)[VIP]


class TestTheClaimTriedAgain(ClaimCase):
    def test_a_txn_that_committed_and_timed_out_is_taken(self):
        self.swaps("commit-timeout")
        made = self.claim()
        self.assertIsNotNone(made)
        self.assertEqual(self.swapped, ["commit-timeout"])
        now = self.counter()
        self.assertEqual(now.epoch.raw, made[0].raw)
        self.assertEqual(now.epoch.lease, made[1])
        self.assertIn(made[1], self.kv.leases)

    def test_a_txn_that_did_not_commit_is_tried_again_the_same_way(self):
        before = (vipetcd.seen(self.kv, MESH_HEX).get(VIP)
                  or vipetcd.Seen(VIP)).revision
        compares = []
        real = self.kv.swap

        def spy(compare, puts, deletes=()):
            compares.append(compare)
            return real(compare, puts, deletes)
        self.kv.swap = spy
        self.swaps("timeout")
        made = self.claim()
        self.assertIsNotNone(made)
        self.assertEqual(self.swapped, ["timeout", "ok"])
        self.assertEqual(made[0].epoch, 1)
        # the same comparison, on the revision read before the first try
        self.assertEqual(len(compares), 1)
        self.assertEqual(int(compares[0][0]["mod_revision"]), before)

    def test_another_claim_that_landed_stops_it(self):
        self.swaps("other")
        self.assertIsNone(self.claim())
        self.assertEqual(self.swapped, ["other"])
        self.assertEqual(self.counter().epoch.holder,
                         vipnode.signed_claim(self.all[1], VIP, 1).holder)
        # this node's lease went: a late transaction with it fails
        self.assertEqual(len(self.kv.leases), 1)

    def test_the_tries_are_bounded_and_their_leases_revoked(self):
        self.swaps("timeout", "timeout", "timeout", "timeout")
        with self.assertRaisesRegex(EtcdError, "no answer within"):
            self.claim()
        self.assertEqual(len(self.swapped), vipetcd.CLAIM_TRIES)
        self.assertEqual(self.kv.leases, {})
        self.assertNotIn(VIP, vipetcd.seen(self.kv, MESH_HEX))

    def test_a_lease_too_old_for_another_try_is_replaced(self):
        self.swaps("timeout", "timeout")
        made = self.claim()
        self.assertIsNotNone(made)
        # 21 s after the first lease was asked for: a new one, signed in
        self.assertEqual(self.counter().epoch.lease, made[1])
        self.assertEqual(list(self.kv.leases), [made[1]])
        self.assertGreater(made[2], 1000.0)

    def test_a_read_that_fails_after_a_timeout_is_tried_again(self):
        now = vipetcd.seen(self.kv, MESH_HEX).get(VIP) or vipetcd.Seen(VIP)
        self.swaps("commit-timeout")
        real = self.kv.prefix
        calls = []

        def prefix(key):
            calls.append(key)
            if len(calls) == 1:
                raise EtcdError("etcdctl get: no answer within 10.5 s")
            return real(key)
        self.kv.prefix = prefix
        made = vipetcd.claim(self.kv, MESH_HEX, VIP, now, 0, self.sign(0),
                             self.monotonic)
        self.kv.prefix = real
        self.assertIsNotNone(made)
        self.assertEqual(self.counter().epoch.raw, made[0].raw)
        self.assertEqual(self.swapped[0], "commit-timeout")


class TestPromoteTriesTheClaimAgain(ClaimCase):
    def test_a_promote_whose_txn_timed_out_after_its_commit_holds_it(self):
        """keel#135: the promote failed on "no answer within 10.5 s",
        and the claim it had made had no node to renew its lease, so
        keel-vip.service never added the address (the second failure)"""
        self.swaps("commit-timeout")
        code, said = self.promote(0)
        self.assertEqual(code, exits.OK, said)
        held = vipnode.current(self.all[0], VIP)
        self.assertIsNotNone(held.lease)
        self.assertEqual(held.lease, self.counter().epoch.lease)
        self.assertTrue(self.carried(0))
        self.assertEqual(self.holds(), [0])

    def test_a_claim_of_its_own_found_in_etcd_is_held_with_its_lease(self):
        """What an older keel left: its own claim in etcd, its file
        without the lease; raced() now records the lease, so the
        controller renews it and carries the address"""
        made = self.claim()
        self.assertIsNone(vipnode.current(self.all[0], VIP).claim)
        with mock.patch.object(vippromote, "carried_soon",
                               side_effect=self.carry_soon):
            said: list[str] = []
            code = vippromote.raced(self.all[0], VIP, self.all[0].own_key(),
                                    said.append)
        self.assertEqual(code, exits.OK, said)
        self.assertEqual(vipnode.current(self.all[0], VIP).lease, made[1])
        self.assertTrue(self.carried(0))


class TestTheBoundsAndTheLastRead(ClaimCase):
    def reads_fail(self, which: set[int]):
        """kv.prefix failing at the calls numbered in `which`"""
        real = self.kv.prefix
        calls = []

        def prefix(key):
            calls.append(key)
            if len(calls) in which:
                raise EtcdError("etcdctl get: no answer within 10.5 s")
            return real(key)
        self.kv.prefix = prefix

    def test_no_try_starts_after_the_window(self):
        self.swaps("timeout")
        with mock.patch.object(vipetcd, "CLAIM_WITHIN", 5.0):
            with self.assertRaisesRegex(EtcdError, "no answer within"):
                self.claim()
        self.assertEqual(self.swapped, ["timeout"])
        self.assertEqual(self.kv.leases, {})

    def test_the_last_read_finds_its_own_claim(self):
        now = vipetcd.seen(self.kv, MESH_HEX).get(VIP) or vipetcd.Seen(VIP)
        self.swaps("timeout", "timeout", "commit-timeout")
        # the read after the third try does not answer; the last one does
        self.reads_fail({3})
        made = vipetcd.claim(self.kv, MESH_HEX, VIP, now, 0, self.sign(0),
                             self.monotonic)
        self.assertIsNotNone(made)
        self.assertEqual(self.counter().epoch.raw, made[0].raw)
        self.assertEqual(list(self.kv.leases), [made[1]])

    def test_the_last_read_finds_another_claim(self):
        now = vipetcd.seen(self.kv, MESH_HEX).get(VIP) or vipetcd.Seen(VIP)
        self.swaps("timeout", "timeout", "other")
        # the other node's claim reads the counter too (call 3)
        self.reads_fail({4})
        self.assertIsNone(vipetcd.claim(self.kv, MESH_HEX, VIP, now, 0,
                                        self.sign(0), self.monotonic))
        self.assertEqual(len(self.kv.leases), 1)

    def test_a_lost_compare_with_an_unchanged_counter_ends_it(self):
        real = self.kv.swap
        self.kv.swap = lambda compare, puts, deletes=(): False
        self.assertIsNone(self.claim())
        self.kv.swap = real
        self.assertEqual(self.kv.leases, {})

    def test_a_claim_signing_that_fails_on_a_new_lease_revokes_all(self):
        self.swaps("timeout")
        signs = []

        def sign(vip, epoch, lease):
            signs.append(lease)
            if len(signs) > 1:
                from keel.mesh.vipnode import VipError
                raise VipError("the signing key is gone")
            return vipnode.signed_claim(self.all[0], vip, epoch, lease)
        now = vipetcd.seen(self.kv, MESH_HEX).get(VIP) or vipetcd.Seen(VIP)
        from keel.mesh.vipnode import VipError
        with self.assertRaises(VipError):
            vipetcd.claim(self.kv, MESH_HEX, VIP, now, 0, sign,
                          self.monotonic)
        self.assertEqual(self.kv.leases, {})


class TestRacedRefusesWhatItCannotTake(ClaimCase):
    def raced(self) -> tuple[int, str]:
        said: list[str] = []
        code = vippromote.raced(self.all[0], VIP, self.all[0].own_key(),
                                said.append)
        return code, "\n".join(said)

    def test_a_claim_that_does_not_verify_is_not_taken(self):
        self.claim()
        with mock.patch.object(vipnode, "verified", return_value="forged"):
            code, said = self.raced()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("not taken: forged", said)
        self.assertIsNone(vipnode.current(self.all[0], VIP).claim)

    def test_a_claim_older_than_the_file_is_not_taken(self):
        self.claim()
        from keel.mesh.vipnode import VipError
        with mock.patch.object(vipnode, "hold",
                               side_effect=VipError("epoch 4 is known")):
            code, said = self.raced()
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("epoch 4 is known", said)


class TestThePromoteCarriesItAtOnce(ClaimCase):
    """keel#138: after the compare-and-swap the promote waited for the
    controller's next renewal before the VIP was on wg0 (5.6 s write gap
    at 250 ms). The lease was granted and the claim written with it by
    the majority, after the moment `asked`: the promote carries the
    address itself, for what is left of the release time after that
    moment, and the controller extends it once it renewed"""

    def test_the_address_is_on_wg0_when_the_promote_returns(self):
        with mock.patch.object(vippromote, "carried_soon",
                               side_effect=lambda here, vip: self.carried(
                                   self.all.index(here))):
            said: list[str] = []
            code = vippromote.promote(self.all[0], False, said.append)
        self.assertEqual(code, exits.OK, said)
        self.assertTrue(self.carried(0))
        lifetime = self.nets[0].lifetimes[f"{VIP}/128"]
        self.assertIsNotNone(lifetime)
        self.assertLessEqual(lifetime, vipetcd.RELEASE_AFTER)

    def test_too_old_a_lease_is_left_to_the_controller(self):
        real = vipetcd.claim

        def slow(*args, **kwargs):
            made = real(*args, **kwargs)
            self.sleep(vipetcd.RELEASE_AFTER)
            return made
        with mock.patch.object(vipetcd, "claim", side_effect=slow), \
                mock.patch.object(vippromote, "carried_soon",
                                  side_effect=self.carry_soon):
            said: list[str] = []
            code = vippromote.promote(self.all[0], False, said.append)
        self.assertEqual(code, exits.OK, said)
        self.assertTrue(self.carried(0))
