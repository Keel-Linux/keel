# Copyright (c) 2026 KeelLinux maintainers
"""A pair of files only: the folders follow the VIP (decision 0076)

Keel Web in a cloud mode has no database to follow, but it declares
appliance.vip and replicates its site files with syncthing. The node
that holds the VIP sends, the other receives, and a promote flips them.
The pair, the VIP's state, the promote and the members' channel are the
real ones of tests/vip_helpers.py; what the manifest replicates is
stood in by filesync.replicates_files, and the flip itself is
keel.system.filesync's (tests/test_system_filesync_flip.py), recorded
here. Before 0076 such a node was refused: "this node declares no
database.server".
"""

import os
import unittest
from unittest import mock

from test_system_dbfollow import FollowTestCase, Server
from vip_helpers import VIP, address

from keel.mesh import vip as vipstate
from keel.mesh import vippromote
from keel.system import dbfollow, dbpair, dbwatch, filefollow


class FilePairCase(FollowTestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch("keel.system.filesync.replicates_files",
                             return_value=True)
        self.replicates = patcher.start()
        self.addCleanup(patcher.stop)

    def files_pair(self, claim: int | None = 0, mode: str = "cloud_simple"):
        self.nodes(mode=mode)
        if claim is not None:
            vippromote.promote(self.all[claim], False,
                               self.said[claim].append)

    def flipped(self, index: int, **kwargs):
        """One follow of node `index`; what it said, and the role the
        folders were flipped to"""
        with mock.patch("keel.system.filesync.follow_flip") as flip:
            found = self.follow(index, Server(), **kwargs)
        self.assertEqual(flip.call_count, 1, found.lines)
        return found, flip.call_args.args[3]


class TheDirectionFollowsTheVip(FilePairCase):
    def test_the_holder_sends_and_the_other_node_receives(self):
        self.files_pair()
        found, role = self.flipped(0)
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(role, dbpair.PRIMARY)
        self.assertEqual(self.role_file(0),
                         f"role=primary\nreplicates=files\nvip={VIP}\n")
        self.assertTrue(any("folders send the files" in line
                            for line in found.lines), found.lines)
        found, role = self.flipped(1)
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(role, dbpair.REPLICA)
        self.assertIn("role=replica\nreplicates=files\n", self.role_file(1))
        self.assertTrue(any("folders receive the files" in line
                            for line in found.lines), found.lines)

    def test_a_promote_flips_the_direction_and_back(self):
        self.files_pair()
        self.assertEqual(self.flipped(0)[1], dbpair.PRIMARY)
        self.assertEqual(self.flipped(1)[1], dbpair.REPLICA)
        self.assertEqual(vippromote.promote(self.all[1], False,
                                            self.said[1].append), 0,
                         self.text(1))
        self.assertEqual(self.flipped(1)[1], dbpair.PRIMARY)
        self.assertEqual(self.flipped(0)[1], dbpair.REPLICA)
        self.assertEqual(vippromote.promote(self.all[0], False,
                                            self.said[0].append), 0,
                         self.text(0))
        self.assertEqual(self.flipped(0)[1], dbpair.PRIMARY)
        self.assertEqual(self.flipped(1)[1], dbpair.REPLICA)

    def test_cloud_advanced_is_a_cloud_mode_too(self):
        self.files_pair(mode="cloud_advanced")
        self.assertEqual(self.flipped(0)[1], dbpair.PRIMARY)

    def test_with_no_claim_yet_the_folders_stay_paused(self):
        self.files_pair(claim=None)
        found, role = self.flipped(0)
        self.assertIsNone(found.problem, found.lines)
        self.assertIsNone(role)
        self.assertTrue(any("keel vip promote" in line
                            for line in found.lines), found.lines)
        self.assertEqual(self.role_file(0), "")

    def test_a_holder_whose_vip_is_not_on_wg0_pauses(self):
        """keel#104: and with no peer to answer, keel vip check (keel#154)
        cannot carry it again either"""
        self.files_pair()
        self.nets[0].addresses.clear()
        self.down.update({address(1), address(2)})
        found, role = self.flipped(0)
        self.assertIsNone(found.problem, found.lines)
        self.assertIsNone(role)
        self.assertTrue(any("not proven" in line for line in found.lines))

    def test_a_holder_whose_vip_left_wg0_carries_it_again_when_asked(self):
        """keel#154: the other members answer and none knows a newer
        claim, so the holder carries the VIP again and sends"""
        self.files_pair()
        self.nets[0].addresses.clear()
        self.assertEqual(self.flipped(0)[1], dbpair.PRIMARY)
        self.assertTrue(self.carried(0))

    def test_a_holder_in_doubt_pauses(self):
        self.files_pair()
        vipstate.mark_unconfirmed(self.all[0].root, VIP, True)
        found, role = self.flipped(0)
        self.assertIsNone(role)
        self.assertTrue(any("not proven" in line for line in found.lines))

    def test_without_the_pair_record_it_is_refused_and_paused(self):
        self.nodes(mode="cloud_simple", paired=False)
        found, role = self.flipped(0)
        self.assertIn("keel vip pair", found.problem)
        self.assertIsNone(role)


class WhatIsNotAFilePair(FilePairCase):
    def test_simple_mode_keeps_the_refusal(self):
        self.files_pair(claim=None, mode="simple")
        found, role = self.flipped(0)
        self.assertEqual(found.problem, dbfollow.NO_SERVER)
        self.assertIsNone(role)

    def test_an_appliance_that_replicates_no_file_keeps_the_refusal(self):
        self.files_pair()
        self.replicates.return_value = False
        found, _ = self.flipped(0)
        self.assertEqual(found.problem, dbfollow.NO_SERVER)

    def test_the_witness_still_has_nothing_to_follow(self):
        self.nodes(vips=(None, None), paired=False, mode="cloud_advanced")
        found, role = self.flipped(2, nothing_without_vip=True)
        self.assertIsNone(found.problem, found.lines)
        self.assertIsNone(role)


class TheWatch(FilePairCase):
    def watch(self, index: int):
        here = self.all[index]
        lines: list[str] = []
        with mock.patch.object(dbfollow, "follow") as follow, \
                mock.patch("keel.system.filesync_watch.watch_counts"), \
                mock.patch("keel.system.dbdump.watch"), \
                mock.patch.object(dbwatch, "certificate") as certificate, \
                mock.patch("keel.system.filefollow.vipnet.carried",
                           side_effect=lambda iface, vip, output:
                           f"{vip}/128" in self.nets[index].addresses):
            code = dbwatch.watch(here.root, here.node.path, lines.append,
                                 lines.append)
        return code, follow, certificate, lines

    def test_a_role_file_that_disagrees_with_the_vip_is_followed(self):
        self.files_pair()
        code, follow, certificate, lines = self.watch(0)
        self.assertEqual(code, 0, lines)
        self.assertEqual(follow.call_count, 1, lines)
        # no database: no certificate of the database to renew
        certificate.assert_not_called()
        self.flipped(0)
        _, follow, _, lines = self.watch(0)
        follow.assert_not_called()

    def test_a_holder_whose_vip_left_wg0_is_followed(self):
        self.files_pair()
        self.flipped(0)
        self.nets[0].addresses.clear()
        _, follow, _, lines = self.watch(0)
        self.assertEqual(follow.call_count, 1, lines)

    def test_no_claim_is_nothing_to_follow(self):
        self.files_pair(claim=None)
        _, follow, _, lines = self.watch(0)
        follow.assert_not_called()

    def test_the_replica_is_followed_on_its_role_file_alone(self):
        self.files_pair()
        self.flipped(1)
        _, follow, _, lines = self.watch(1)
        follow.assert_not_called()

    def test_a_vip_that_is_not_an_address_is_no_file_pair(self):
        doc = {"installation": {"mode": "cloud_simple"},
               "appliance": {"name": "web", "vip": "not one"}}
        self.assertFalse(filefollow.applies(self.parent, doc))

    def test_the_mismatch_needs_a_file_pair(self):
        self.files_pair()
        doc = self.all[0].node.document()
        pair = dbpair.observe_pair(self.all[0].root, doc)
        self.replicates.return_value = False
        self.assertFalse(filefollow.mismatch(self.all[0].root, doc, pair,
                                             self.nets[0].output))
        self.assertFalse(filefollow.mismatch(self.all[0].root, doc, None,
                                             self.nets[0].output))


if __name__ == "__main__":
    unittest.main()
