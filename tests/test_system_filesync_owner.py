# Copyright (c) 2026 KeelLinux maintainers
"""keel.system.filesync_owner: a promoted node restores the application
owner over the replicated trees (keel#225)

In the first batch of a replication, a directory can be made before its
parent gets the application owner, so it and all below it stay owned by
the syncthing user. The flip to primary repairs that before the
application takes writes.
"""

import os
import tempfile
import unittest
from unittest import mock

from filesync_helpers import CONTENT, MEDIA, FakeApi
from test_system_filesync_flip import FlipCase, Here

from keel.system import filesync, filesync_owner

APP = (33, 33)
SYNC = (999, 999)


class Tree:
    """A tree on disk whose owners are a table: the test does not run
    as root, so lstat is told the owners and lchown is recorded"""

    def __init__(self, test, owners):
        self.owners = owners
        self.chowned = {}
        self.real = os.lstat
        test.enterContext(mock.patch.object(
            filesync_owner.os, "lstat", self.lstat))
        test.enterContext(mock.patch.object(
            filesync_owner.os, "lchown", self.lchown))

    def lstat(self, path):
        real = self.real(path)
        uid, gid = self.owners.get(path, APP)
        fields = list(real)
        fields[4], fields[5] = uid, gid
        return os.stat_result(fields)

    def lchown(self, path, uid, gid):
        self.chowned[path] = (uid, gid)
        self.owners[path] = (uid, gid)


class TestTheRepair(unittest.TestCase):
    def setUp(self):
        self.base = self.enterContext(
            tempfile.TemporaryDirectory())
        self.top = os.path.join(self.base, "uploads")
        self.deep = os.path.join(self.top, "2026", "10")
        os.makedirs(self.deep)
        self.file = os.path.join(self.deep, "a.jpg")
        open(self.file, "w").close()
        self.outside = os.path.join(self.top, "kept.txt")
        open(self.outside, "w").close()

    def repair(self, owners):
        tree = Tree(self, owners)
        done = filesync_owner.repair(self.top, SYNC[0])
        return tree, done

    def test_a_directory_made_before_its_parent_gets_the_owner_back(self):
        tree, done = self.repair({
            self.top: APP,
            os.path.join(self.top, "2026"): APP,
            self.deep: SYNC, self.file: SYNC})
        self.assertEqual(tree.chowned, {self.deep: APP, self.file: APP})
        self.assertEqual(done, 2)

    def test_a_whole_wrong_subtree_is_repaired(self):
        year = os.path.join(self.top, "2026")
        tree, done = self.repair({
            self.top: APP, year: SYNC, self.deep: SYNC, self.file: SYNC})
        self.assertEqual(set(tree.chowned), {year, self.deep, self.file})
        self.assertEqual(done, 3)

    def test_an_entry_of_another_owner_is_left_alone(self):
        tree, done = self.repair({
            self.top: APP, self.outside: (0, 0), self.deep: SYNC})
        self.assertEqual(tree.chowned, {self.deep: APP})
        self.assertEqual(done, 1)

    def test_a_tree_that_is_right_changes_nothing(self):
        tree, done = self.repair({self.top: APP})
        self.assertEqual(tree.chowned, {})
        self.assertEqual(done, 0)

    def test_a_root_the_syncthing_user_owns_is_not_a_model(self):
        tree, done = self.repair({self.top: SYNC, self.deep: SYNC})
        self.assertEqual(tree.chowned, {})
        self.assertEqual(done, 0)

    def test_a_link_is_never_followed(self):
        link = os.path.join(self.top, "link")
        os.symlink(self.base, link)
        tree, _ = self.repair({self.top: APP, link: SYNC})
        self.assertEqual(tree.chowned, {link: APP})

    def test_a_missing_root_is_not_an_error(self):
        self.assertEqual(
            filesync_owner.repair(os.path.join(self.base, "none"), 999), 0)

    def test_an_entry_that_vanishes_during_the_walk_is_skipped(self):
        Tree(self, {self.top: APP, self.deep: SYNC})

        def gone(path, uid, gid):
            raise FileNotFoundError(path)
        with mock.patch.object(filesync_owner.os, "lchown", gone):
            self.assertEqual(filesync_owner.repair(self.top, 999), 0)


class TestTheFlip(FlipCase):
    def put_tree(self):
        for path in (CONTENT, MEDIA):
            os.makedirs(os.path.join(self.root, path.lstrip("/")),
                        exist_ok=True)

    def test_a_primary_flip_repairs_each_replicated_path(self):
        self.put_tree()
        with mock.patch("keel.system.filesync_owner.repair",
                        return_value=3) as repair:
            found, _, _ = self.flip("primary", here=Here())
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(
            sorted(call.args[0] for call in repair.call_args_list),
            sorted(os.path.join(self.root, p.lstrip("/"))
                   for p in (CONTENT, MEDIA)))
        self.assertTrue(any("restored" in line for line in found.lines))

    def test_a_replica_flip_and_a_pause_repair_nothing(self):
        self.put_tree()
        for role in ("replica", None):
            with mock.patch("keel.system.filesync_owner.repair") as repair:
                self.flip(role, here=Here())
            repair.assert_not_called()

    def test_a_repair_that_fails_is_a_follow_problem_and_is_retried(self):
        self.put_tree()
        with mock.patch("keel.system.filesync_owner.repair",
                        side_effect=PermissionError("denied")):
            found, _, _ = self.flip("primary", here=Here())
        self.assertIn("denied", found.problem)
        self.assertTrue(self.exists(filesync.PENDING))

    def test_the_repair_runs_after_the_folders_stop_receiving(self):
        self.put_tree()
        api = FakeApi()
        seen = []

        def look(*args):
            seen.append({f["type"] for f in api.folders.values()})
            return 0
        with mock.patch("keel.system.filesync_owner.repair", look):
            self.flip("primary", here=Here(), api=api)
        self.assertEqual(seen, [{"sendonly"}] * 2)


if __name__ == "__main__":
    unittest.main()
