# Copyright (c) 2026 KeelLinux maintainers
"""The address an invite reserves: a random free one of the inviter's
region, the /112 of the overlay its address is in (decisions 0048, 0051).
The draws are the test's own (`randbelow`) where an answer is fixed."""

import ipaddress
import unittest

from keel.mesh.allocate import (
    ATTEMPTS,
    REGION_BITS,
    AllocationError,
    free_address,
    region_of,
    taken,
)


class TestRegionOf(unittest.TestCase):
    def test_the_112_of_the_address_fifth_and_sixth_groups_zero(self):
        self.assertEqual(REGION_BITS, 112)
        self.assertEqual(region_of("fd00:1::1/64"),
                         ipaddress.IPv6Network("fd00:1::/112"))
        self.assertEqual(region_of("fd00:1::2:5/64"),
                         ipaddress.IPv6Network("fd00:1::2:0/112"))
        self.assertEqual(region_of("fd00:1::2:5"),
                         ipaddress.IPv6Network("fd00:1::2:0/112"))

    def test_an_overlay_no_wider_than_a_112_is_one_region(self):
        self.assertEqual(region_of("fd00:1::1/126"),
                         ipaddress.IPv6Network("fd00:1::/126"))


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
    """A random address of the inviter's region: two inviters of one
    region who do not know each other's invites practically never draw
    the same one (keel#102), and etcd's reservation catches the rest
    (keel.mesh.addrreserve)"""

    def test_the_draw_spans_the_region_but_host_zero(self):
        rng = draws(0x1233)
        self.assertEqual(free_address("fd00:1::1/64", [], rng),
                         "fd00:1::1234/64")
        self.assertEqual(rng.asked, [0xffff])

    def test_the_answer_carries_the_overlay_s_length_not_the_region_s(self):
        found = free_address("fd00:1::2:1/64", [], draws(4))
        self.assertEqual(found, "fd00:1::2:5/64")
        self.assertEqual(ipaddress.IPv6Interface(found).network,
                         ipaddress.IPv6Network("fd00:1::/64"))

    def test_a_taken_draw_is_drawn_again(self):
        # ::1 the inviter, ::2 a peer, ::3 a pending invite
        rng = draws(0, 1, 2, 6)
        self.assertEqual(
            free_address("fd00:1::1/64", ["fd00:1::2/128", "fd00:1::3"],
                         rng), "fd00:1::7/64")
        self.assertEqual(len(rng.asked), 4)

    def test_a_used_prefix_blocks_its_whole_range(self):
        self.assertEqual(
            free_address("fd00:1::1/64", ["fd00:1::/120"], draws(0x10, 0x100)),
            "fd00:1::101/64")

    def test_what_lies_outside_the_region_is_ignored(self):
        # another region's addresses, and IPv4
        self.assertEqual(
            free_address("fd00:1::1/64",
                         ["fd00:1::2:2/128", "fd00:2::/64", "10.0.0.0/8"],
                         draws(1)), "fd00:1::2/64")

    def test_a_peer_in_another_region_does_not_move_the_draw_there(self):
        """0051: two regions allocate in their own ranges; the inviter
        stays in its own whatever its peers' regions are"""
        for _ in range(20):
            found = ipaddress.IPv6Interface(
                free_address("fd00:1::1/64", ["fd00:1::2:1/128"]))
            self.assertIn(found.ip, ipaddress.IPv6Network("fd00:1::/112"))

    def test_the_real_draw_lands_inside_the_region_and_free(self):
        region = ipaddress.IPv6Network("fd00:1::3:0/112")
        found = {free_address("fd00:1::3:1/64", ["fd00:1::3:2"])
                 for _ in range(20)}
        for one in found:
            address = ipaddress.IPv6Interface(one).ip
            self.assertIn(address, region)
            self.assertNotIn(str(address), ("fd00:1::3:0", "fd00:1::3:1",
                                            "fd00:1::3:2"))
        self.assertGreater(len(found), 1)

    def test_a_nearly_full_region_gives_its_last_address(self):
        # every draw lands on the inviter's own ::1; ::3 is left
        rng = draws(0)
        self.assertEqual(
            free_address("fd00:1::1/126", ["fd00:1::2/128"], rng),
            "fd00:1::3/126")
        self.assertEqual(len(rng.asked), ATTEMPTS)

    def test_the_search_wraps_around_once(self):
        # every draw lands on ::3, the last; ::2 is the one left
        self.assertEqual(
            free_address("fd00:1::1/126", ["fd00:1::3/128"], draws(2)),
            "fd00:1::2/126")

    def test_a_full_region_is_refused(self):
        with self.assertRaises(AllocationError) as raised:
            free_address("fd00:1::1/126", ["fd00:1::2/128", "fd00:1::3/128"])
        self.assertIn("no free address in fd00:1::/126",
                      str(raised.exception))

    def test_a_region_a_peer_covers_whole_is_full(self):
        with self.assertRaises(AllocationError):
            free_address("fd00:1::1/64", ["fd00::/16"])

    def test_a_prefix_of_one_address_has_none_to_give(self):
        with self.assertRaises(AllocationError):
            free_address("fd00:1::1/128", [])

    def test_the_vip_range_is_no_region_to_invite_from(self):
        """<prefix>::ffff:n holds the VIPs (keel#97); an inviter there
        is refused with what to do, and no other inviter's region
        reaches it"""
        with self.assertRaises(AllocationError) as raised:
            free_address("fd00:1::ffff:1/64", [])
        self.assertIn("VIP range fd00:1::ffff:0/112", str(raised.exception))
        self.assertIn("keel mesh invite on a node outside",
                      str(raised.exception))
        self.assertEqual(free_address("fd00:1::fffe:1/64", [], draws(1)),
                         "fd00:1::fffe:2/64")

    def test_a_long_run_of_taken_addresses_is_skipped_at_once(self):
        used = [f"fd00:1::{n:x}" for n in range(2, 2000)]
        self.assertEqual(free_address("fd00:1::1/64", used, draws(0)),
                         "fd00:1::7d0/64")


class TestTaken(unittest.TestCase):
    def test_every_allowed_ips_prefix_of_every_peer(self):
        overlay = {"peers": [
            {"public_key": "a", "allowed_ips": ["fd00:1::2/128"]},
            {"public_key": "b",
             "allowed_ips": ["fd00:1::3/128", "fd00:1::ffff:1/128"]}]}
        self.assertEqual(taken(overlay),
                         ["fd00:1::2/128", "fd00:1::3/128",
                          "fd00:1::ffff:1/128"])
        self.assertEqual(taken({}), [])


if __name__ == "__main__":
    unittest.main()
