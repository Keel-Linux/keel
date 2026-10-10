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
    return (f"{ONE}\t{int(NOW.timestamp()) - 40}\n{TWO}\t0\n"
            f"{THREE}\t{int(NOW.timestamp()) - 29057}\nnoise\n")


class TestHandshakes(unittest.TestCase):
    def test_each_peer_named_with_its_handshake(self):
        found = {one.field.split(".")[4]: one
                 for one in handshakes.handshake_fields(SPEC, True, wg, NOW)}
        self.assertEqual(found[ONE].status, SAME)
        self.assertIn("a handshake (40 s ago)", found[ONE].line())
        self.assertEqual(found[TWO].status, DRIFT)
        self.assertIn("observed none; no handshake since wg0 came up: the"
                      " member does not answer: it is unreachable",
                      found[TWO].line())
        # keel#140: 8 h old is drift, with its age
        self.assertEqual(found[THREE].status, DRIFT)
        self.assertIn("declared a handshake within 180 s, observed a"
                      " handshake (29057 s ago); older than 180 s: the"
                      " member does not answer", found[THREE].line())
        self.assertNotIn("keel mesh sync on that member", found[TWO].line())

    def test_a_peer_the_interface_does_not_hold(self):
        def wg(argv):
            return f"{ONE}\t{int(NOW.timestamp())}\n"
        found = {one.field.split(".")[4]: one
                 for one in handshakes.handshake_fields(SPEC, True, wg, NOW)}
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


class TestMtu(unittest.TestCase):
    """keel#139: the live MTU against the file's"""

    def setUp(self):
        import os
        import shutil
        import tempfile
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        os.makedirs(os.path.join(self.root, "etc/wireguard"))
        self.conf = os.path.join(self.root, "etc/wireguard/wg0.conf")

    def write(self, text):
        with open(self.conf, "w") as fob:
            fob.write(text)

    def fields(self, mtu=None, live=True):
        def ip(argv):
            assert argv == ("ip", "link", "show", "dev", "wg0")
            return None if mtu is None else (
                f"9: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu {mtu} qdisc"
                " noqueue state UNKNOWN\n")
        return handshakes.mtu_fields(SPEC, self.root, live, ip)

    def test_a_live_mtu_that_is_not_the_file_s_is_drift(self):
        self.write("[Interface]\nMTU = 1280\n")
        [found] = self.fields(1420)
        self.assertEqual(found.status, DRIFT)
        self.assertIn("declared 1280, observed 1420", found.line())
        self.assertIn("keel network mtu", found.line())
        [found] = self.fields(1280)
        self.assertEqual(found.status, SAME)
        [found] = self.fields(None)
        self.assertEqual(found.status, UNKNOWN)

    def test_nothing_without_a_line_a_file_or_the_live_system(self):
        self.assertEqual(self.fields(1420), [])
        self.write("[Interface]\nListenPort = 51820\n")
        self.assertEqual(self.fields(1420), [])
        self.write("[Interface]\nMTU = 1280\n")
        self.assertEqual(self.fields(1420, live=False), [])
        self.assertEqual(handshakes.mtu_fields({}, self.root, True), [])


if __name__ == "__main__":
    unittest.main()
