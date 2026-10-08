# Copyright (c) 2026 KeelLinux maintainers
"""A pair made before the VIP range keeps its VIP (keel#102)

Before 0.23.3 a VIP was an address of the /112 of its members, such as
fd00:6b65:1::100; since then a new VIP is in the overlay's VIP range,
`<prefix>::ffff:n`. A pair whose signed record already names a VIP
outside the range keeps validating, applying and claiming it after the
upgrade, and keel diff says so in one information line; a new pair
outside the range is refused, by the node that asks and by the node
that would sign.
"""

import os

from etcd_helpers import KEYS
from vip_helpers import VIP, Pair, address

from keel import exits
from keel.commands import read_spec
from keel.diff.appliance import vip_fields
from keel.diff.report import NOT_COMPARED
from keel.mesh import vipmsg, vipnode, vippair, vippromote
from keel.mesh.memberlink import LinkError
from keel.spec import load

LEGACY = "fd00:6b65:1::100"


class Upgraded(Pair):
    """Three nodes declaring LEGACY; the first two keep the pair record
    they signed before the upgrade, the third keeps none"""

    def setUp(self):
        super().setUp()
        self.nodes(vips=(LEGACY, LEGACY, LEGACY), paired=False)
        self.pair_up(0, 1, LEGACY)

    def doc(self, index: int) -> dict:
        return load(self.all[index].node.path)


class TestItKeepsValidating(Upgraded):
    def test_the_members_spec_is_valid_a_new_node_s_is_not(self):
        for index in (0, 1):
            with self.subTest(index=index):
                doc, code = read_spec(self.all[index].node.path, False,
                                      self.all[index].root)
                self.assertEqual(code, exits.OK)
                self.assertEqual(doc["appliance"]["vip"], LEGACY)
        doc, code = read_spec(self.all[2].node.path, False,
                              self.all[2].root)
        self.assertEqual((doc, code), (None, exits.SPEC_INVALID))

    def test_applying_writes_the_spec_on_a_member(self):
        """keel.mesh.node validates every spec it writes, as apply does"""
        self.assertEqual(self.all[0].node.problems(self.doc(0)), [])
        found = self.all[2].node.problems(self.doc(2))
        self.assertEqual(len(found), 1)
        self.assertIn("outside the VIP range fd00:6b65:1::ffff:0/112",
                      found[0])

    def test_keel_diff_says_it_in_one_information_line(self):
        found = vip_fields(self.doc(0), self.all[0].root)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].field, found[0].status, found[0].declared),
                         ("appliance.vip.range", NOT_COMPARED, LEGACY))
        self.assertIn("paired before the range (0.23.3)", found[0].reason)
        self.assertIn("fd00:6b65:1::ffff:0/112", found[0].line())
        # a VIP in the range, no record, no VIP, no overlay: nothing
        self.assertEqual(vip_fields(self.doc(2), self.all[2].root), [])
        in_range = self.doc(0)
        in_range["appliance"]["vip"] = VIP
        self.assertEqual(vip_fields(in_range, self.all[0].root), [])
        self.assertEqual(vip_fields({"appliance": {}}, self.all[0].root), [])
        self.assertEqual(vip_fields({"appliance": {"vip": LEGACY}},
                                    self.all[0].root), [])


class TestItKeepsClaiming(Upgraded):
    def test_a_promote_claims_and_every_node_takes_it(self):
        said: list[str] = []
        code = vippromote.promote(self.all[0], False, said.append)
        self.assertEqual(code, exits.OK, said)
        self.assertTrue(f"{LEGACY}/128" in self.nets[0].addresses)
        # the node that keeps no record takes it: its VIP is where every
        # record signed before the range had it
        for index in (1, 2):
            with self.subTest(index=index):
                held = vipnode.current(self.all[index], LEGACY)
                self.assertEqual(held.holder, KEYS[0])
        self.assertIsNotNone(vippair.read(self.all[2].root, LEGACY))

    def test_the_pair_may_sign_its_record_again(self):
        said: list[str] = []
        code = vippromote.pair(self.all[1], address(0), said.append)
        self.assertEqual(code, exits.OK, said)

    def test_a_record_outside_every_member_s_112_is_not_taken(self):
        """the fallback is the place records had before the range, no
        wider: a VIP elsewhere in the prefix is refused"""
        far = vippair.made(self.all[0].mesh_id(), "fd00:6b65:1:0:9::5",
                           (KEYS[0], KEYS[1]))
        for index in (0, 1):
            far = vippair.sign(self.all[index].root, far, KEYS[index])
        self.assertIn("outside the VIP range",
                      vipnode.record_problem(self.all[2], far))


class TestANewPairOutsideTheRange(Pair):
    def setUp(self):
        super().setUp()
        self.nodes(vips=(LEGACY, LEGACY), paired=False)

    def test_refused_by_the_node_that_asks(self):
        said: list[str] = []
        code = vippromote.pair(self.all[0], address(1), said.append)
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("outside the VIP range", said[-1])

    def test_refused_by_the_node_that_would_sign(self):
        """an older keel, or a hand-made message, asks the other member
        to sign a VIP outside the range: it refuses"""
        draft = vippair.made(self.all[0].mesh_id(), LEGACY,
                             (KEYS[0], KEYS[1]))
        mine = vippair.sign(self.all[0].root, draft, KEYS[0])
        with self.assertRaises(LinkError) as raised:
            self.all[0].say(vipmsg.PAIR, address(1), {"pair": mine.dumps()})
        self.assertIn("outside the VIP range", str(raised.exception))
        self.assertIsNone(vippair.read(self.all[1].root, LEGACY))

    def test_no_kept_record_is_no_legacy(self):
        self.assertEqual(vippair.kept_vips(self.all[0].root), ())
        os.makedirs(os.path.join(self.all[0].root, "var/lib/keel/vip"),
                    exist_ok=True)
        with open(os.path.join(self.all[0].root, "var/lib/keel/vip",
                               f"{LEGACY}.pair"), "w") as fob:
            fob.write("{")
        with open(os.path.join(self.all[0].root, "var/lib/keel/vip",
                               "x.json"), "w") as fob:
            fob.write("{")
        self.assertEqual(vippair.kept_vips(self.all[0].root), ())
        self.assertIn("is damaged", vipnode.new_pair_problem(
            self.all[0], vippair.made(self.all[0].mesh_id(), LEGACY,
                                      (KEYS[0], KEYS[1]))))
