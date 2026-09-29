# Copyright (c) 2026 KeelLinux maintainers
"""Tree.present: a file's presence, without reading it (review of #40)"""

import os
import tempfile
import unittest
from os.path import join

from helpers import spec  # noqa: F401

from keel.inspect.tree import NOT_PRESENT, PERMISSION_DENIED, Tree


class TestPresent(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(join(self.root, "var", "lib", "tklbam"))
        with open(join(self.root, "var/lib/tklbam/sub_apikey"), "w") as fob:
            fob.write("HUBKEY-7f3a9\n")

    def test_a_present_file_is_not_read(self):
        found = Tree(self.root).present("var/lib/tklbam/sub_apikey")
        self.assertTrue(found.readable)
        self.assertEqual(found.text, "")
        self.assertIsNone(found.problem)

    def test_an_absent_file(self):
        found = Tree(self.root).present("var/lib/tklbam/nothing")
        self.assertFalse(found.readable)
        self.assertEqual(found.problem, NOT_PRESENT)

    @unittest.skipIf(os.geteuid() == 0, "root reads a directory it may not")
    def test_a_directory_that_cannot_be_searched_is_not_a_no(self):
        folder = join(self.root, "var", "lib", "tklbam")
        os.chmod(folder, 0)
        try:
            found = Tree(self.root).present("var/lib/tklbam/sub_apikey")
        finally:
            os.chmod(folder, 0o755)
        self.assertEqual(found.problem, PERMISSION_DENIED)

    def test_a_path_through_a_file_says_why(self):
        found = Tree(self.root).present("var/lib/tklbam/sub_apikey/child")
        self.assertIn("not readable", found.problem)


if __name__ == "__main__":
    unittest.main()
