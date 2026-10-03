# Copyright (c) 2026 KeelLinux maintainers
"""The address an invite reserves for the new node (decision 0048)

A random free address of the inviter's overlay prefix, avoiding its
own, the peers' allowed_ips and the other pending invites. The draws
are the test's own (`randbelow`), so every answer here is fixed.
"""

import ipaddress
import unittest

from keel.mesh.allocate import ATTEMPTS, AllocationError, free_address


def draws(*offsets):
    """A randbelow that answers `offsets` in turn, then the last again"""
    given = list(offsets)
    asked = []

    def randbelow(n):
        asked.append(n)
        return given.pop(0) if len(given) > 1 else given[0]

    randbelow.asked = asked
    return randbelow


class TestFreeAddress(unittest.TestCase):
    def test_the_draw_is_an_address_of_the_prefix(self):
        found = free_address("fd00:1::1/64", [], draws(0x1234))
        self.assertEqual(found, "fd00:1::1235/64")

    def test_the_draw_spans_the_prefix_but_its_own_address(self):
        rng = draws(5)
        free_address("fd00:1::1/64", [], rng)
        self.assertEqual(rng.asked, [2 ** 64 - 1])

    def test_a_taken_address_is_drawn_again(self):
        # ::1 this node, ::2 a peer, ::3 a pending invite
        rng = draws(0, 1, 2, 6)
        found = free_address("fd00:1::1/64",
                             ["fd00:1::2/128", "fd00:1::3"], rng)
        self.assertEqual(found, "fd00:1::7/64")
        self.assertEqual(len(rng.asked), 4)

    def test_a_peer_prefix_wider_than_one_address_is_avoided_whole(self):
        found = free_address("fd00:1::1/64", ["fd00:1::/120"],
                             draws(0x10, 0x100))
        self.assertEqual(found, "fd00:1::101/64")

    def test_the_real_draw_lands_inside_and_free(self):
        prefix = ipaddress.IPv6Network("fd00:1::/64")
        taken_now = ["fd00:1::2/128"]
        found = {free_address("fd00:1::1/64", taken_now) for _ in range(20)}
        for one in found:
            address = ipaddress.IPv6Interface(one)
            self.assertEqual(address.network, prefix)
            self.assertNotIn(str(address.ip),
                             ("fd00:1::", "fd00:1::1", "fd00:1::2"))
        self.assertGreater(len(found), 1)

    def test_what_lies_outside_the_prefix_does_not_count(self):
        found = free_address("fd00:1::1/64", ["fd00:2::2/128", "10.66.0.2/32",
                                              "fd01::/16"], draws(1))
        self.assertEqual(found, "fd00:1::2/64")

    def test_a_nearly_full_prefix_gives_its_last_address(self):
        # every draw lands on this node's own ::1; ::3 is left
        rng = draws(0)
        found = free_address("fd00:1::1/126", ["fd00:1::2/128"], rng)
        self.assertEqual(found, "fd00:1::3/126")
        self.assertEqual(len(rng.asked), ATTEMPTS)

    def test_the_search_wraps_around_once(self):
        # every draw lands on ::3, the last; ::2 is the one left
        found = free_address("fd00:1::1/126", ["fd00:1::3/128"], draws(2))
        self.assertEqual(found, "fd00:1::2/126")

    def test_a_full_prefix_is_refused(self):
        with self.assertRaises(AllocationError) as raised:
            free_address("fd00:1::1/126", ["fd00:1::2/128", "fd00:1::3/128"],
                         draws(1))
        self.assertIn("no free address in fd00:1::/126",
                      str(raised.exception))

    def test_a_prefix_a_peer_covers_whole_is_full(self):
        with self.assertRaises(AllocationError):
            free_address("fd00:1::1/64", ["fd00::/16"], draws(5))

    def test_a_prefix_of_one_address_has_none_to_give(self):
        with self.assertRaises(AllocationError):
            free_address("fd00:1::1/128", [], draws(0))


if __name__ == "__main__":
    unittest.main()
