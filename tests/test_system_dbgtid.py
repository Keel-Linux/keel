# Copyright (c) 2026 KeelLinux maintainers
"""GTID lists: what a seeded replica takes over from its primary"""

import unittest

from helpers import spec  # noqa: F401

from keel.system import dbgtid


class TestCarried(unittest.TestCase):
    def test_the_first_boot_gtids_go_before_the_position(self):
        found = dbgtid.carried("0-161129940-6,0-1530113555-100",
                               "0-1530113555-100")
        self.assertEqual(found, "0-161129940-6,0-1530113555-100")

    def test_a_gtid_logged_after_the_position_is_not_taken(self):
        found = dbgtid.carried("0-161129940-6,0-1530113555-120",
                               "0-1530113555-100")
        self.assertEqual(found, "0-161129940-6,0-1530113555-100")

    def test_an_empty_state_gives_the_position_alone(self):
        self.assertEqual(dbgtid.carried("", "0-5-9"), "0-5-9")

    def test_nothing_logged_gives_an_empty_list(self):
        self.assertEqual(dbgtid.carried("", ""), "")

    def test_each_domain_keeps_its_position_last(self):
        found = dbgtid.carried("0-1-2,1-1-4,0-9-8", "0-9-8,1-1-5")
        self.assertEqual(found, "0-1-2,0-9-8,1-1-5")

    def test_a_state_that_is_no_gtid_list_raises(self):
        with self.assertRaises(ValueError):
            dbgtid.carried("nonsense", "0-1-1")


if __name__ == "__main__":
    unittest.main()
