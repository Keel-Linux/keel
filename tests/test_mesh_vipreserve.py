# Copyright (c) 2026 KeelLinux maintainers
"""A VIP reserved in etcd when its pair is made (decision 0051, keel#97):
one pair per VIP across the mesh, whatever region each member is in.

The reservation is signed by the member that made it, and every reader
checks the signature (keel#102): another member cannot forge or take
over a pair's reservation without the alert. It lives on a lease of
24 h until both members signed the pair record, and `keel vip unpair`
releases it."""

import json
from unittest import mock

from etcd_helpers import KEYS, MESH, address
from vip_helpers import VIP, Pair

from keel import exits
from keel.mesh import (
    etcdstate,
    signing,
    vipmsg,
    vipnode,
    vippair,
    vippromote,
    vipreserve,
)
from keel.mesh import etcdclient
from keel.mesh.etcdclient import EtcdError
from keel.mesh.etcdstate import Cluster, Member
from keel.mesh.memberlink import LinkError

MESH_HEX = MESH.hex()
KEY = f"/keel/{MESH_HEX}/vips/{VIP}/pair"
# the record keeps its members sorted, so one pair has one record
PAIR = vippair.made(MESH_HEX, VIP, (KEYS[0], KEYS[1]))
OTHERS = vippair.made(MESH_HEX, VIP, (KEYS[1], KEYS[2]))


class WithEtcd(Pair):
    """Three cloud advanced members of a formed cluster, not yet paired"""

    def setUp(self):
        super().setUp()
        self.nodes(etcd="enabled", paired=False)
        cluster = Cluster("new", tuple(Member(KEYS[i], address(i))
                                       for i in range(3)), MESH_HEX)
        for one in self.all:
            etcdstate.save_cluster(one.root, cluster)
        patcher = mock.patch("keel.mesh.etcdauth.announce",
                             return_value=["(granted)"])
        self.announce = patcher.start()
        self.addCleanup(patcher.stop)

    def pair(self, index: int, at: str) -> tuple[int, str]:
        said: list[str] = []
        code = vippromote.pair(self.all[index], at, said.append)
        return code, "\n".join(said)

    def unpair(self, index: int, vip: str = VIP) -> tuple[int, str]:
        said: list[str] = []
        code = vippromote.unpair(self.all[index], vip, said.append)
        return code, "\n".join(said)

    def signed_by(self, index: int, pair: vippair.Pair) -> bytes:
        """A reservation `pair` signed by node `index`"""
        return vipreserve.made(pair, KEYS[index], lambda message: (
            signing.sign(self.all[index].root, message))).dumps()

    def held(self) -> dict:
        return json.loads(self.kv.kvs[KEY][0].decode())


class TestKeelVipPairReserves(WithEtcd):
    def test_signed_on_a_lease_then_kept_for_good_once_both_signed(self):
        code, out = self.pair(0, address(1))
        self.assertEqual(code, exits.OK, out)
        value, _, lease = self.kv.kvs[KEY]
        self.assertIsNone(lease)
        found = self.held()
        self.assertEqual(found["reservation"], {
            "mesh_id": MESH_HEX, "vip": VIP, "members": list(PAIR.members),
            "by": KEYS[0]})
        self.assertTrue(signing.verified(
            signing.public(self.all[0].root),
            vipreserve.loads(value).message(), found["signature"]))
        # reserved on a lease of 24 h, read by the member asked to sign,
        # then taken off its lease by a second swap
        self.assertEqual(self.kv.calls, ["prefix", "grant", "swap",
                                         "prefix", "prefix", "swap"])
        self.assertEqual(vipreserve.TTL, 86400)
        self.assertIsNotNone(vippair.read(self.all[1].root, VIP))
        self.announce.assert_called_once()

    def test_a_pair_the_other_member_never_signed_lets_the_vip_go(self):
        self.down.add(address(1))
        code, out = self.pair(0, address(1))
        self.assertEqual(code, exits.MESH_REFUSED, out)
        lease = self.kv.kvs[KEY][2]
        self.assertIsNotNone(lease)
        self.ticks[0] += vipreserve.TTL
        self.kv.prefix(KEY)
        self.assertNotIn(KEY, self.kv.kvs)

    def test_the_same_pair_again_is_the_same_reservation(self):
        self.assertEqual(self.pair(0, address(1))[0], exits.OK)
        code, out = self.pair(1, address(0))
        self.assertEqual(code, exits.OK, out)
        # the first run's two swaps; the second finds it kept already
        self.assertEqual(self.kv.calls.count("swap"), 2)
        self.assertEqual(self.held()["reservation"]["by"], KEYS[0])

    def test_another_pair_s_signed_vip_is_refused_and_nothing_is_signed(self):
        self.kv.put(KEY, self.signed_by(2, OTHERS))
        code, out = self.pair(0, address(1))
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn(f"{VIP} is reserved in etcd by another pair", out)
        self.assertIn(KEYS[2], out)
        self.assertIsNone(vippair.read(self.all[0].root, VIP))
        self.assertIsNone(vippair.read(self.all[1].root, VIP))
        self.announce.assert_not_called()

    def test_an_unsigned_or_forged_reservation_blocks_with_an_alert(self):
        """a member outside the pair writes a value naming the pair, or
        one signed by a key nobody trusts for `by`: keel never takes it
        as the pair's, nor overwrites it"""
        unsigned = json.dumps({"reservation": {
            "mesh_id": MESH_HEX, "vip": VIP, "members": list(PAIR.members),
            "by": KEYS[0]}, "signature": ""}).encode()
        # node 2 signs, and names node 0 as the one who reserved
        forged = vipreserve.Reservation(
            MESH_HEX, VIP, PAIR.members, KEYS[0])
        forged = vipreserve.Reservation(
            MESH_HEX, VIP, PAIR.members, KEYS[0],
            signing.sign(self.all[2].root, forged.message())).dumps()
        # signed by a member it does not name
        outsider = self.signed_by(2, PAIR)
        for value in (unsigned, forged, outsider, b"{"):
            with self.subTest(value=value[:40]):
                self.kv.put(KEY, value)
                code, out = self.pair(0, address(1))
                self.assertEqual(code, exits.MESH_REFUSED)
                self.assertIn(f"ALERT: the reservation of {VIP} in etcd",
                              out)
                self.assertIn(f"etcdctl del {KEY}", out)
                self.assertEqual(self.kv.kvs[KEY][0], value)
                self.assertIsNone(vippair.read(self.all[1].root, VIP))

    def test_etcd_not_answering_refuses_the_pair(self):
        self.kv.refuse = "prefix"
        code, out = self.pair(0, address(1))
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("could not be reserved in etcd", out)
        self.assertIsNone(vippair.read(self.all[1].root, VIP))

    def test_a_reservation_written_between_the_read_and_the_swap(self):
        """the swap fails on a key that appeared meanwhile; whose it is
        decides: the same members go on, others are refused"""
        original = self.kv.swap

        def race(compare, puts, deletes=()):
            if KEY not in self.kv.kvs:
                self.kv.put(KEY, self.signed_by(*self.racer))
            return original(compare, puts, deletes)
        self.kv.swap = race
        self.racer = (1, PAIR)
        self.assertEqual(self.pair(0, address(1))[0], exits.OK)
        # the losing swap's lease was revoked
        self.assertEqual(self.kv.calls.count("revoke"), 1)
        self.setUp()
        self.kv.swap = race
        self.racer = (2, OTHERS)
        code, out = self.pair(0, address(1))
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("another pair", out)

    def test_a_reservation_gone_between_the_swap_and_the_read(self):
        with mock.patch.object(self.kv, "swap", return_value=False):
            code, out = self.pair(0, address(1))
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("changed while it was made", out)


class TestOperatorTimeouts(WithEtcd):
    """keel#94: keel vip pair and unpair are an operator's commands, and
    the member asked to sign answers one: each call to etcd has keel's
    usual timeout, not the controller's short one, which a lease grant on
    a link of 250 ms with 2% loss can outlast"""

    def timeouts(self, act) -> set[float]:
        seen: list[float] = []
        check = self.kv.check
        # one fake for every client: as etcdclient.local makes a new one
        self.kv.timeout = etcdclient.TIMEOUT

        def recorded(call: str) -> None:
            seen.append(self.kv.timeout)
            check(call)
        with mock.patch.object(self.kv, "check", side_effect=recorded):
            act()
        self.assertTrue(seen)
        return set(seen)

    def test_pair_and_the_signature_use_keel_s_usual_timeout(self):
        found = self.timeouts(lambda: self.assertEqual(
            self.pair(0, address(1))[0], exits.OK))
        self.assertEqual(found, {etcdclient.TIMEOUT})

    def test_unpair_uses_keel_s_usual_timeout(self):
        self.assertEqual(self.pair(0, address(1))[0], exits.OK)
        for one in self.all[:2]:
            with open(one.node.path) as fob:
                text = fob.read()
            with open(one.node.path, "w") as fob:
                fob.write(text.replace(f"  vip: {VIP}\n", ""))
        found = self.timeouts(lambda: self.assertEqual(
            self.unpair(1)[0], exits.OK))
        self.assertEqual(found, {etcdclient.TIMEOUT})


class TestTheMemberAskedToSign(WithEtcd):
    """with etcd, the other member signs only a pair whose VIP is
    reserved for it: an initiator that skips the reservation, or one
    that another pair holds, gets no signature (keel#102)"""

    def ask(self) -> str:
        draft = vippair.made(MESH_HEX, VIP, (KEYS[0], KEYS[1]))
        mine = vippair.sign(self.all[0].root, draft, KEYS[0])
        with self.assertRaises(LinkError) as raised:
            self.all[0].say(vipmsg.PAIR, address(1), {"pair": mine.dumps()})
        self.assertIsNone(vippair.read(self.all[1].root, VIP))
        return str(raised.exception)

    def test_no_reservation_no_signature(self):
        self.assertIn(f"{VIP} is not reserved in etcd for this pair",
                      self.ask())

    def test_another_pair_s_or_a_forged_one_no_signature(self):
        self.kv.put(KEY, self.signed_by(2, OTHERS))
        self.assertIn("reserved in etcd by another pair", self.ask())
        self.kv.put(KEY, b"{")
        self.assertIn("ALERT", self.ask())

    def test_etcd_not_answering_no_signature(self):
        self.kv.refuse = "prefix"
        self.assertIn("etcd did not answer", self.ask())
        with mock.patch.object(vipnode.Here, "local",
                               side_effect=EtcdError("no certificate")):
            self.assertIn("etcd cannot be asked (no certificate)",
                          self.ask())


class TestKeptForGood(WithEtcd):
    def test_a_lease_that_ended_before_both_signed_is_reserved_again(self):
        self.assertIsNone(vipreserve.kept(
            self.kv, PAIR, KEYS[0], lambda message: signing.sign(
                self.all[0].root, message), vipnode.signer_of(self.all[0])))
        self.assertIsNone(self.kv.kvs[KEY][2])

    def test_another_pair_s_is_never_kept(self):
        self.kv.put(KEY, self.signed_by(2, OTHERS))
        self.assertIn("another pair", vipreserve.kept(
            self.kv, PAIR, KEYS[0], None, vipnode.signer_of(self.all[0])))

    def test_etcd_not_reached_for_the_keep(self):
        real = vipnode.Here.local
        calls = []

        def keep_fails(here):
            """the reserve, the other member's check, then the keep"""
            calls.append(here)
            if len(calls) == 3:
                raise EtcdError("no member answered")
            return real(here)
        with mock.patch.object(vipnode.Here, "local", autospec=True,
                               side_effect=keep_fails):
            code, out = self.pair(0, address(1))
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("(no member answered)", out)

    def test_etcd_or_a_race_on_the_keep_says_run_pair_again(self):
        for fault in ("etcd", "race"):
            with self.subTest(fault=fault):
                self.setUp()
                original = self.kv.swap
                calls = []

                def second_fails(compare, puts, deletes=()):
                    calls.append(compare)
                    if len(calls) == 2 and fault == "race":
                        return False
                    if len(calls) == 2:
                        raise EtcdError("request timed out")
                    return original(compare, puts, deletes)
                self.kv.swap = second_fails
                code, out = self.pair(0, address(1))
                self.assertEqual(code, exits.APPLY_FAILED)
                self.assertIn("is not kept for good", out)
                self.assertIn("Run keel vip pair again", out)
                self.announce.assert_not_called()
                # the record is made on both; the next run keeps it
                self.kv.swap = original
                self.assertEqual(self.pair(0, address(1))[0], exits.OK)
                self.assertIsNone(self.kv.kvs[KEY][2])


class TestKeelVipUnpair(WithEtcd):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.pair(0, address(1))[0], exits.OK)
        for one in self.all[:2]:
            with open(one.node.path) as fob:
                text = fob.read()
            with open(one.node.path, "w") as fob:
                fob.write(text.replace(f"  vip: {VIP}\n", ""))

    def test_a_member_releases_its_pair_s_reservation(self):
        code, out = self.unpair(1)
        self.assertEqual(code, exits.OK, out)
        self.assertIn("released", out)
        self.assertNotIn(KEY, self.kv.kvs)
        # nothing reserved is nothing to release
        self.assertEqual(self.unpair(1)[0], exits.OK)
        # and another pair may reserve the VIP now
        self.assertIsNone(vipreserve.reserve(
            self.kv, OTHERS, KEYS[2], lambda message: signing.sign(
                self.all[2].root, message), vipnode.signer_of(self.all[2])))

    def test_refused_while_the_spec_declares_it(self):
        with open(self.all[0].node.path) as fob:
            text = fob.read()
        with open(self.all[0].node.path, "w") as fob:
            fob.write(text.replace("appliance:\n",
                                   f"appliance:\n  vip: {VIP}\n"))
        code, out = self.unpair(0)
        self.assertEqual(code, exits.MESH_REFUSED, out)
        self.assertIn(f"this node's appliance.vip is {VIP}", out)
        self.assertIn(KEY, self.kv.kvs)

    def test_a_node_outside_the_pair_never_releases_it(self):
        code, out = self.unpair(2)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("only its members release it", out)
        self.assertIn(KEY, self.kv.kvs)

    def test_an_unverified_reservation_is_never_deleted(self):
        self.kv.put(KEY, b"{")
        code, out = self.unpair(0)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("ALERT", out)
        self.assertEqual(self.kv.kvs[KEY][0], b"{")

    def test_deleted_only_at_the_revision_it_was_read_at(self):
        with mock.patch.object(self.kv, "swap", return_value=False):
            code, out = self.unpair(0)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("run keel vip unpair again", out)
        self.assertIn(KEY, self.kv.kvs)

    def test_etcd_not_answering_and_a_bad_vip(self):
        self.kv.refuse = "prefix"
        code, out = self.unpair(0)
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("etcd did not answer", out)
        code, out = self.unpair(0, "not-a-vip")
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("keel vip unpair:", out)

    def test_without_etcd_nothing_is_reserved(self):
        with mock.patch("keel.mesh.vippromote.with_etcd", return_value=False):
            code, out = self.unpair(0)
        self.assertEqual(code, exits.OK)
        self.assertIn("nothing is released", out)


class TestTheKeyItself(Pair):
    def test_one_vip_s_key_is_not_another_s_prefix(self):
        """fd..::ffff:10's key never reads as fd..::ffff:1's"""
        longer = VIP + "0"
        self.nodes(paired=False)
        self.kv.put(vipreserve.key_of(MESH_HEX, longer), b"{")
        self.assertIsNone(vipreserve.read(self.kv, MESH_HEX, VIP))

    def test_what_loads_refuses(self):
        good = {"reservation": {"mesh_id": MESH_HEX, "vip": VIP,
                                "members": list(PAIR.members),
                                "by": KEYS[0]}, "signature": "AAAA"}
        self.assertIsNotNone(vipreserve.loads(json.dumps(good).encode()))
        for bad in (
                {**good, "signature": "@@"},
                {**good, "reservation": {**good["reservation"],
                                         "members": ["x", "y"]}},
                {**good, "reservation": {**good["reservation"], "by": 7}},
                []):
            with self.subTest(bad=bad):
                self.assertIsNone(vipreserve.loads(json.dumps(bad).encode()))
