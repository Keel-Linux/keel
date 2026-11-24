# Copyright (c) 2026 KeelLinux maintainers
"""keel's record of the firewall state it last wrote (decision 0097)

/var/lib/keel/firewall/state says enforce or report, apart from the
ruleset file, so that a node in enforce stays in enforce when its file
is lost or cut. The fourth real test broke it: a symlink was read and
written through, and a record of another owner, writable by anyone, was
trusted. It is now read with no symlink followed, and only as a regular
file root owns that no group or other may write, in a directory of the
same kind; anything else is no record, with a plain warning. It is
written by a rename, so a link at its path is replaced, never followed.

Only root can write such a record, which is the power the spec has: a
record that says enforce on a fresh node gives enforce at once, and no
more mechanism guards against it.
"""

import os
import stat
import tempfile
import unittest
from os.path import join
from unittest import mock

from keel.inspect.tree import Tree
from keel.system import fwrecord
from keel.system.actions import RecordState
from keel.system.effects import Effects

RECORD = fwrecord.RECORD


class RecordCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.root = self.tmp.name
        # the test's files are the user's; on a node, root's
        patch = mock.patch("keel.system.fwrecord.ROOT_UID", os.getuid())
        patch.start()
        self.addCleanup(patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def write(self, text: str, mode: int = 0o644) -> str:
        path = join(self.root, RECORD)
        os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
        with open(path, "w") as fob:
            fob.write(text)
        os.chmod(path, mode)
        return path

    def read(self):
        return fwrecord.read(Tree(self.root))


class TestRead(RecordCase):
    def test_a_sound_record(self):
        self.write("enforce\n")
        self.assertEqual(self.read(), ("enforce", ""))

    def test_no_record(self):
        self.assertEqual(self.read(), (None, ""))

    def test_an_unknown_word_is_no_record(self):
        for text in ("", "ENFORCE\n", "\x00\x01garbage"):
            with self.subTest(text=text):
                self.write(text)
                state, warning = self.read()
                self.assertIsNone(state)
                self.assertIn("is not a state keel writes", warning)

    def test_a_record_others_may_write_is_not_trusted(self):
        for mode in (0o666, 0o664, 0o646):
            with self.subTest(mode=oct(mode)):
                self.write("enforce\n", mode)
                state, warning = self.read()
                self.assertIsNone(state)
                self.assertIn("group or others may write it", warning)

    def test_a_record_of_another_owner_is_not_trusted(self):
        self.write("enforce\n")
        with mock.patch("keel.system.fwrecord.ROOT_UID", os.getuid() + 1):
            state, warning = self.read()
        self.assertIsNone(state)
        self.assertIn("root does not own it", warning)

    def test_a_symlink_is_not_followed(self):
        target = join(self.root, "target")
        with open(target, "w") as fob:
            fob.write("enforce\n")
        os.makedirs(os.path.dirname(join(self.root, RECORD)), mode=0o755)
        os.symlink(target, join(self.root, RECORD))
        state, warning = self.read()
        self.assertIsNone(state)
        self.assertIn("not a regular file", warning)

    def test_a_directory_others_may_write_is_not_trusted(self):
        path = self.write("enforce\n")
        os.chmod(os.path.dirname(path), 0o777)
        state, warning = self.read()
        self.assertIsNone(state)
        self.assertIn("its directory", warning)


class TestWrite(RecordCase):
    def apply(self, state: str) -> str | None:
        return Effects(self.root).apply(RecordState(state, "record"))

    def test_written_root_only_writable(self):
        self.assertIsNone(self.apply("enforce"))
        path = join(self.root, RECORD)
        found = os.lstat(path)
        self.assertTrue(stat.S_ISREG(found.st_mode))
        self.assertEqual(stat.S_IMODE(found.st_mode), 0o644)
        self.assertEqual(self.read(), ("enforce", ""))

    def test_a_link_at_its_path_is_replaced_not_followed(self):
        """the fourth real test: keel wrote into the link's target"""
        target = join(self.root, "target")
        with open(target, "w") as fob:
            fob.write("report\n")
        os.makedirs(os.path.dirname(join(self.root, RECORD)), mode=0o755)
        os.symlink(target, join(self.root, RECORD))
        self.assertIsNone(self.apply("enforce"))
        with open(target) as fob:
            self.assertEqual(fob.read(), "report\n")
        self.assertFalse(os.path.islink(join(self.root, RECORD)))
        self.assertEqual(self.read(), ("enforce", ""))

    def test_a_wrong_mode_is_put_right(self):
        self.write("enforce\n", 0o666)
        self.assertIsNone(self.apply("enforce"))
        self.assertEqual(self.read(), ("enforce", ""))


class TestPurge(unittest.TestCase):
    def test_purge_removes_the_record_and_remove_keeps_it(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(join(repo, "debian", "keel.postrm")) as fob:
            text = fob.read()
        self.assertIn('if [ "$1" = "purge" ]; then', text)
        self.assertIn("rm -f \"${DPKG_ROOT:-}/var/lib/keel/firewall/state\"",
                      text)
        self.assertIn("#DEBHELPER#", text)


if __name__ == "__main__":
    unittest.main()
