# Copyright (c) 2026 KeelLinux maintainers
"""The two sources decision 0048 adds to 0018's confirmation

A join's own authenticated session over the overlay, from the peer the
change added, and `keel mesh create` confirming a mesh with no peer
itself. Both confirm only the overlay change keel mesh made (the marker
it read back after its apply), only after the route check, and never an
uplink change.
"""

import unittest

from helpers import spec  # noqa: F401

# keel.inspect before keel.network.confirm, the order keel.cli imports
# them in: alone, this file would meet their import cycle the other way
import keel.inspect  # noqa: F401, I001
from test_network_overlay_window import (
    ENABLE,
    STOP,
    RootCase,
    pending,
    probes,
)
from test_network_window import Recorder

from keel.network import confirm as netconfirm
from keel.network import marker, session

MADE = pending(absent=True).up("b1", 50.0)


def mesh(local="fd00:1::9", peer="fd00:1::2"):
    return session.Origin(session.MESH, "the mesh session of invite"
                          " 0123456789abcdef", 60.0, local, peer)


def own():
    return session.Origin(session.SELF, "keel mesh create")


class TestMeshOrigins(RootCase):
    def setUp(self):
        super().setUp()
        marker.save(self.root, "")
        marker.write(self.root, MADE)

    def confirm(self, origin, expected=MADE, routes=None, clients=()):
        run = Recorder()
        found = netconfirm.confirm(self.root, origin, probes(routes=routes),
                                   run, expected=expected, clients=clients)
        return found, run

    def test_the_join_session_over_the_overlay_confirms(self):
        (confirmed, lines), run = self.confirm(mesh())
        self.assertTrue(confirmed, lines)
        self.assertEqual(lines[0], "confirmed from the mesh session of"
                         " invite 0123456789abcdef")
        self.assertEqual(lines[1], "the overlay was tested: the mesh session"
                         " of invite 0123456789abcdef arrived at fd00:1::9"
                         " on wg0, from fd00:1::2")
        self.assertEqual(run.calls, [STOP, ENABLE])
        self.assertFalse(marker.exists(self.root))

    def test_create_confirms_a_mesh_with_no_peer_itself(self):
        (confirmed, lines), _ = self.confirm(own(), clients=("2001:db8:9::5",))
        self.assertTrue(confirmed, lines)
        self.assertIn("has no peer, so", lines[1])
        self.assertIn("still leave through the uplink", lines[1])

    def test_only_the_change_keel_mesh_made(self):
        for expected in (None, pending(absent=True).up("b1", 49.0),
                         pending(absent=True).up("b0", 50.0)):
            for origin in (mesh(), own()):
                with self.subTest(expected=expected, origin=origin.kind):
                    (confirmed, lines), run = self.confirm(origin, expected)
                    self.assertFalse(confirmed)
                    self.assertIn("not the one keel mesh made", lines[0])
                    self.assertEqual(run.calls, [])
                    self.assertTrue(marker.exists(self.root))

    def test_a_mesh_session_at_another_address_is_refused(self):
        (confirmed, lines), _ = self.confirm(mesh(local="2001:db8:1::20"))
        self.assertFalse(confirmed)
        self.assertIn("arrived at 2001:db8:1::20, not at an address the"
                      " overlay declares", lines[0])

    def test_the_route_check_runs_first(self):
        routes = {"2001:db8:9::5": "wg0"}
        (confirmed, lines), _ = self.confirm(own(), routes=routes,
                                             clients=("2001:db8:9::5",))
        self.assertFalse(confirmed)
        self.assertIn("the route to the operator's SSH client 2001:db8:9::5"
                      " leaves through wg0", lines[0])


def added():
    return session.Origin(session.ADDED, "keel mesh, which added 1"
                          " member(s) live and removed none,")


class TestAddedLive(RootCase):
    """keel#117: a change that only added peers live is kept by keel
    mesh with no handshake, after the route check; no other change is"""

    def confirm(self, made, routes=None):
        marker.save(self.root, "")
        marker.write(self.root, made)
        return netconfirm.confirm(self.root, added(), probes(routes=routes),
                                  Recorder(), expected=made,
                                  clients=("2001:db8:9::5",))

    def test_an_addition_made_live_is_kept(self):
        made = pending(absent=True, added_live=True).up("b1", 50.0)
        confirmed, lines = self.confirm(made)
        self.assertTrue(confirmed, lines)
        self.assertIn("the change only added peers, with wg set on wg0",
                      lines[1])
        self.assertIn("shows as drift in keel mesh status", lines[1])
        self.assertTrue(marker.read(self.root) is None)

    def test_any_other_change_is_refused(self):
        confirmed, lines = self.confirm(MADE)
        self.assertFalse(confirmed)
        self.assertIn("did more than add peers live", lines[0])
        self.assertTrue(marker.exists(self.root))

    def test_the_route_check_still_runs(self):
        made = pending(absent=True, added_live=True).up("b1", 50.0)
        confirmed, lines = self.confirm(made, routes={"2001:db8:9::5":
                                                      "wg0"})
        self.assertFalse(confirmed)
        self.assertIn("leaves through wg0", lines[0])

    def test_the_marker_keeps_it(self):
        made = pending(absent=True, added_live=True).up("b1", 50.0)
        marker.save(self.root, "")
        marker.write(self.root, made)
        self.assertTrue(marker.read(self.root).added_live)


class TestNeverAnUplinkChange(RootCase):
    def test_a_mesh_origin_cannot_confirm_the_uplink(self):
        uplink = marker.Pending(iface="eth0", path="etc/network/interfaces",
                                window=120, addresses=("2001:db8:1::20",))
        marker.save(self.root, "")
        marker.write(self.root, uplink.up("b1", 50.0))
        made = marker.read(self.root)
        for origin in (mesh(local="2001:db8:1::20"), own()):
            with self.subTest(origin=origin.kind):
                confirmed, lines = netconfirm.confirm(
                    self.root, origin, probes(), Recorder(), expected=made)
                self.assertFalse(confirmed)
                self.assertIn("not the one keel mesh made", lines[0])

    def test_without_the_check_the_uplink_refuses_them_too(self):
        uplink = marker.Pending(iface="eth0", path="etc/network/interfaces",
                                window=120).up("b1", 50.0)
        for origin in (mesh(), own()):
            with self.subTest(origin=origin.kind):
                self.assertIn("refused", netconfirm.not_proof(
                    uplink, origin, probes()))


class TestLines(unittest.TestCase):
    def test_overlay_lines_of_each_origin(self):
        self.assertEqual(netconfirm.overlay_lines(
            pending(), own(), probes()), [
                "the overlay has no peer, so nothing can cross it:"
                " keel mesh create confirmed it once the routes to the"
                " gateways and to the operator's session were found to"
                " still leave through the uplink"])


if __name__ == "__main__":
    unittest.main()
