# Copyright (c) 2026 KeelLinux maintainers
"""keel diff: a peer with no WireGuard handshake is drift (keel#117)

keel mesh keeps a peer it added live before the other member has this
node too; keel diff names it until the handshake comes, with the age of
the last one when there is one. `wg show` is replaced at the boundary.
"""

import unittest
from datetime import datetime, timezone

from keel.diff import handshakes
from keel.diff.report import DRIFT, SAME, UNKNOWN

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
ONE = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
TWO = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="
THREE = "9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE="
SPEC = {"network": {"overlay": {"wireguard": {
    "address": "fd00:1::1/64",
    "peers": [{"public_key": key, "allowed_ips": [f"fd00:1::{n}/128"]}
              for n, key in ((2, ONE), (3, TWO), (4, THREE))]}}}}


def wg(argv):
    assert argv == ("wg", "show", "wg0", "latest-handshakes")
    return f"{ONE}\t{int(NOW.timestamp()) - 40}\n{TWO}\t0\nnoise\n"


class TestHandshakes(unittest.TestCase):
    def test_each_peer_named_with_its_handshake(self):
        found = {one.field.split(".")[4]: one
                 for one in handshakes.handshake_fields(SPEC, True, wg, NOW)}
        self.assertEqual(found[ONE].status, SAME)
        self.assertIn("a handshake (40 s ago)", found[ONE].line())
        self.assertEqual(found[TWO].status, DRIFT)
        self.assertIn("observed none; no handshake since wg0 came up",
                      found[TWO].line())
        self.assertEqual(found[THREE].status, DRIFT)
        self.assertIn("wg0 does not hold this peer", found[THREE].line())
        self.assertEqual(
            found[TWO].field,
            f"network.overlay.wireguard.peers.{TWO}.handshake")

    def test_nothing_off_the_live_system_or_without_peers(self):
        self.assertEqual(handshakes.handshake_fields(SPEC, False, wg), [])
        self.assertEqual(handshakes.handshake_fields({}, True, wg), [])

    def test_an_interface_that_gives_no_answer(self):
        [found] = handshakes.handshake_fields(SPEC, True, lambda argv: None)
        self.assertEqual(found.status, UNKNOWN)
        self.assertIn("is the interface up?", found.line())

    def test_the_live_reader_is_wg(self):
        from unittest import mock
        with mock.patch("keel.network.live.output", side_effect=wg):
            self.assertEqual(len(handshakes.handshake_fields(SPEC, True)), 3)


if __name__ == "__main__":
    unittest.main()
