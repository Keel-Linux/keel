# Copyright (c) 2026 KeelLinux maintainers
"""Writing the conf file"""

import os
import tempfile
import unittest
from os.path import join

from helpers import spec


class TestConf(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.conf = join(self.tmpdir, "inithooks.conf")

    def test_write_conf_is_only_readable_by_root(self):
        spec.write_conf("export ROOT_PASS=secret\n", self.conf)
        self.assertEqual(os.stat(self.conf).st_mode & 0o777, 0o600)

    def test_write_conf_tightens_the_mode_of_an_existing_file(self):
        with open(self.conf, "w") as fob:
            fob.write("stale\n")
        os.chmod(self.conf, 0o644)

        spec.write_conf("export HOSTNAME=blog\n", self.conf)

        self.assertEqual(os.stat(self.conf).st_mode & 0o777, 0o600)

    def test_conf_is_populated_ignores_whitespace_only_files(self):
        with open(self.conf, "w") as fob:
            fob.write("\n   \n")
        self.assertFalse(spec.conf_is_populated(self.conf))

    def test_conf_is_populated_is_false_when_absent(self):
        self.assertFalse(spec.conf_is_populated(join(self.tmpdir, "absent")))


if __name__ == "__main__":
    unittest.main()
