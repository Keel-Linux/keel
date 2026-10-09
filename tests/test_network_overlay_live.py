# Copyright (c) 2026 KeelLinux maintainers
"""A change of the overlay's peers alone, made live (keel#99)

`wg-quick down` deletes the interface, and every session with it: on
an etcd voter, the bounce of keel mesh sync's repair cut the member
from the leader for about 25 s, twice an hour. When the old and the new
file differ in their peers alone, and every address of a peer that
changes is inside the interface's own prefix (so no route changes),
the change and its revert are `wg set` on the interface that is up,
compared with what `wg show wg0 dump` says it holds, so its drift is
corrected too: the peers that stay keep their sessions. Anything else,
an interface that is not up, or a `wg set` that fails, is the bounce,
as before.
Every command goes through a recording runner; tests/test_network_\
overlay_live_netns.py gives the same to the real wg.
"""

from unittest import mock

from helpers import spec  # noqa: F401

# keel.network.confirm and keel.inspect import each other: the package's
# own order, so this file runs alone too
import keel.commands  # noqa: F401, I001
from test_network_overlay_window import CONF, STOP, RootCase, pending
from test_network_window import Recorder

from keel.network import marker, switch, wireguard

ONE = "nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E="
TWO = "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg="
THREE = "9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE="
INTERFACE = ("# Written by keel\n[Interface]\nAddress = fd00:1::1/64\n"
             "ListenPort = 51820\n"
             "PostUp = wg set %i private-key /etc/wireguard/wg0.key\n")


def peer(key, address, endpoint=None, keepalive=None):
    lines = ["", "[Peer]", f"PublicKey = {key}"]
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    lines.append(f"AllowedIPs = {address}")
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines) + "\n"


BEFORE = INTERFACE + peer(ONE, "fd00:1::2/128", "[2001:db8::2]:51820")
AFTER = BEFORE + peer(TWO, "fd00:1::3/128", "[2001:db8::3]:51820", 25)
SET_TWO = ("wg", "set", "wg0", "peer", TWO, "endpoint", "[2001:db8::3]:51820",
           "allowed-ips", "fd00:1::3/128", "persistent-keepalive", "25")
VIP = "fd00:1::ffff:1/128"
PRIVATE = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="


def dump(text, extra=None, port=51820, endpoint=None):
    """`wg show wg0 dump` of an interface up on file `text`; `extra`
    maps a key to addresses set live on top of the file's, `endpoint` a
    key to the endpoint WireGuard learned"""
    lines = [f"{PRIVATE}\t{ONE}\t{port}\toff"]
    for one in wireguard.parse(text).section.get("peers") or []:
        key = one["public_key"]
        nets = list(one.get("allowed_ips") or []) + list(
            (extra or {}).get(key, ()))
        lines.append("\t".join((
            key, "(none)",
            (endpoint or {}).get(key) or one.get("endpoint") or "(none)",
            ",".join(nets) or "(none)", "0", "0", "0",
            str(one.get("persistent_keepalive") or "off"))))
    return "\n".join(lines) + "\n"


class TestCommands(RootCase):
    """switch.live_peers: the `wg set` lines, or None for a bounce"""

    def test_a_peer_added_removed_or_changed(self):
        self.assertEqual(switch.live_peers(BEFORE, AFTER, "wg0",
                                           dump(BEFORE)), [SET_TWO])
        self.assertEqual(switch.live_peers(AFTER, BEFORE, "wg0",
                                           dump(AFTER)), [
            ("wg", "set", "wg0", "peer", TWO, "remove")])
        # a changed peer gets the fields that changed: its session stays
        moved = INTERFACE + peer(ONE, "fd00:1::2/128", "[2001:db8::9]:51820",
                                 25)
        self.assertEqual(switch.live_peers(BEFORE, moved, "wg0",
                                           dump(BEFORE)), [
            ("wg", "set", "wg0", "peer", ONE, "endpoint",
             "[2001:db8::9]:51820", "persistent-keepalive", "25")])
        self.assertEqual(switch.live_peers(moved, BEFORE, "wg0",
                                           dump(moved)), [
            ("wg", "set", "wg0", "peer", ONE, "endpoint",
             "[2001:db8::2]:51820", "persistent-keepalive", "off")])
        # the same peers in another spelling or order, comments aside
        self.assertEqual(switch.live_peers(
            AFTER, "# new header\n" + INTERFACE + peer(
                TWO, "fd00:1::3/128", "[2001:db8::3]:51820", 25)
            + peer(ONE, "fd00:1::2/128", "[2001:db8::2]:51820"), "wg0",
            dump(AFTER)), [])

    def test_whether_the_lines_only_add_peers(self):
        """keel#117: an addition alone cannot cut this node off"""
        self.assertEqual(switch.live_plan(BEFORE, AFTER, "wg0",
                                          dump(BEFORE)), ([SET_TWO], True))
        self.assertFalse(switch.live_plan(AFTER, BEFORE, "wg0",
                                          dump(AFTER))[1])
        moved = INTERFACE + peer(ONE, "fd00:1::2/128", "[2001:db8::9]:51820")
        self.assertFalse(switch.live_plan(BEFORE, moved + peer(
            TWO, "fd00:1::3/128"), "wg0", dump(BEFORE))[1])
        self.assertEqual(switch.live_plan(BEFORE, BEFORE, "wg0",
                                          dump(BEFORE)), ([], False))

    def test_the_interface_s_drift_is_corrected(self):
        """keel#96: the spec and the file name a peer wg0 lacks; and a
        peer wg0 holds that no file names"""
        lacking = dump(INTERFACE)
        self.assertCountEqual(switch.live_peers(BEFORE, AFTER, "wg0",
                                                lacking), [
            ("wg", "set", "wg0", "peer", ONE, "endpoint",
             "[2001:db8::2]:51820", "allowed-ips", "fd00:1::2/128"),
            SET_TWO])
        stray = dump(BEFORE + peer(THREE, "fd00:1::4/128"))
        self.assertEqual(switch.live_peers(BEFORE, BEFORE, "wg0", stray), [
            ("wg", "set", "wg0", "peer", THREE, "remove")])
        # an address the file names and wg0 lacks is set again; one no
        # file names may be another part of keel's, and stays
        wrong = dump(BEFORE).replace("fd00:1::2/128", "fd00:1::7/128")
        self.assertEqual(switch.live_peers(BEFORE, BEFORE, "wg0", wrong), [
            ("wg", "set", "wg0", "peer", ONE, "allowed-ips",
             "fd00:1::2/128,fd00:1::7/128")])

    def test_what_another_part_of_keel_set_live_is_kept(self):
        """a VIP keel.mesh.vipnet routes to a peer, and an endpoint
        WireGuard learned for a peer the file gives none"""
        held = dump(BEFORE, extra={ONE: [VIP]})
        self.assertEqual(switch.live_peers(BEFORE, AFTER, "wg0", held),
                         [SET_TWO])
        wider = INTERFACE + peer(ONE, "fd00:1::2/128, fd00:1::5/128",
                                 "[2001:db8::2]:51820")
        self.assertEqual(switch.live_peers(BEFORE, wider, "wg0", held), [
            ("wg", "set", "wg0", "peer", ONE, "allowed-ips",
             f"fd00:1::2/128,fd00:1::5/128,{VIP}")])
        roaming = INTERFACE + peer(ONE, "fd00:1::2/128")
        self.assertEqual(switch.live_peers(roaming, roaming, "wg0", dump(
            roaming, endpoint={ONE: "[2001:db8::77]:4242"})), [])

    def test_what_is_a_bounce(self):
        port = INTERFACE.replace("51820", "51821") + peer(
            ONE, "fd00:1::2/128", "[2001:db8::2]:51820")
        routed = BEFORE + peer(TWO, "fd00:2::3/128")
        unknown = BEFORE + "MTU = 1380\n"
        twice = BEFORE + peer(ONE, "fd00:1::4/128")
        for old, new in ((BEFORE, port), (BEFORE, routed), (routed, BEFORE),
                         (BEFORE, unknown), ("", AFTER), (BEFORE, twice),
                         (twice, BEFORE),
                         (INTERFACE + "PrivateKey = x\n", INTERFACE)):
            with self.subTest(old=old, new=new):
                self.assertIsNone(switch.live_peers(old, new, "wg0",
                                                    dump(BEFORE)))

    def test_a_change_of_the_mtu_is_a_bounce(self):
        """keel#119: `wg set` cannot change the MTU; wg-quick up sets it,
        so a file of 0.23.7 bounces once to take MTU = 1280"""
        with_mtu = BEFORE.replace("[Interface]\n", "[Interface]\nMTU = 1280\n")
        self.assertIsNone(switch.live_peers(BEFORE, with_mtu, "wg0",
                                            dump(BEFORE)))
        added = with_mtu + peer(TWO, "fd00:1::3/128", "[2001:db8::3]:51820",
                                25)
        self.assertEqual(switch.live_peers(with_mtu, added, "wg0",
                                           dump(BEFORE)),
                         switch.live_peers(BEFORE, AFTER, "wg0",
                                           dump(BEFORE)))

    def test_a_dump_that_cannot_be_read_or_another_port_is_a_bounce(self):
        good = dump(BEFORE)
        for found in ("", "x\ty\n", good.replace("51820\toff", "x\toff"),
                      good + "short\tline\n",
                      good.replace(ONE + "\t(none)", "nokey\t(none)"),
                      good.replace("fd00:1::2/128", "not-a-net"),
                      good.replace("\toff\n", "\tsoon\n"),
                      dump(BEFORE, port=51999)):
            with self.subTest(found=found):
                self.assertIsNone(switch.live_peers(BEFORE, AFTER, "wg0",
                                                    found))

    def test_no_address_or_an_address_that_is_none_is_a_bounce(self):
        bare = "[Interface]\nListenPort = 51820\n"
        self.assertIsNone(switch.live_peers(bare, bare + peer(
            TWO, "fd00:1::3/128"), "wg0", dump(bare)))
        self.assertIsNone(switch.live_peers(BEFORE, BEFORE + peer(
            TWO, "not-an-address"), "wg0", dump(BEFORE)))

    def test_a_file_that_cannot_be_read_is_a_bounce(self):
        with mock.patch.object(switch, "read_current",
                               side_effect=OSError(13, "denied")):
            self.assertFalse(switch.live_change(self.root, "wg0", CONF,
                                                AFTER, Recorder()))

    def test_a_peer_without_addresses(self):
        bare = BEFORE + "\n[Peer]\nPublicKey = " + THREE + "\n"
        self.assertEqual(switch.live_peers(BEFORE, bare, "wg0",
                                           dump(BEFORE)), [
            ("wg", "set", "wg0", "peer", THREE)])
        self.assertEqual(switch.live_peers(bare, bare, "wg0", dump(bare)),
                         [])

    def test_the_dump_is_wg_s(self):
        with mock.patch("keel.network.live.output",
                        return_value="dumped") as output:
            self.assertEqual(switch.wg_dump("wg0"), "dumped")
        output.assert_called_once_with(("wg", "show", "wg0", "dump"))


class TestLiveChange(RootCase):
    def setUp(self):
        super().setUp()
        # the interface holds what the file on disk says, as it is now
        patcher = mock.patch.object(
            switch, "wg_dump", side_effect=lambda iface: dump(
                self.current() or ""))
        self.dumped = patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_peer_added_is_set_live_and_the_file_put_in_place(self):
        self.write(BEFORE)
        run = Recorder()
        self.assertIsNone(switch.change(self.root, pending(), AFTER, run))
        self.assertEqual(self.wg_calls(run), [])
        self.assertIn(SET_TWO, run.calls)
        self.dumped.assert_called_with("wg0")
        self.assertEqual(self.current(), AFTER)
        self.assertEqual(self.mode(), 0o600)
        found = marker.read(self.root)
        self.assertEqual((found.changed_at, found.absent), (50.0, False))
        self.assertEqual(marker.saved(self.root), BEFORE)

    def test_the_marker_says_an_addition_was_made_live(self):
        self.write(BEFORE)
        switch.change(self.root, pending(), AFTER, Recorder())
        self.assertTrue(marker.read(self.root).added_live)

    def test_a_removal_or_a_bounce_is_no_live_addition(self):
        self.write(AFTER)
        switch.change(self.root, pending(), BEFORE, Recorder())
        self.assertFalse(marker.read(self.root).added_live)
        marker.clear(self.root)
        self.write(BEFORE)
        self.dumped.side_effect = lambda iface: None
        switch.change(self.root, pending(), AFTER, Recorder())
        self.assertFalse(marker.read(self.root).added_live)

    def test_its_revert_removes_it_live(self):
        self.write(BEFORE)
        switch.change(self.root, pending(), AFTER, Recorder())
        run = Recorder()
        worked, line = switch.revert(self.root, run)
        self.assertTrue(worked, line)
        self.assertEqual(self.wg_calls(run), [])
        self.assertIn(("wg", "set", "wg0", "peer", TWO, "remove"), run.calls)
        self.assertIn(STOP, run.calls)
        self.assertEqual(self.current(), BEFORE)
        self.assertEqual(line, "restored /etc/wireguard/wg0.conf and wg0 is"
                         " up on it")

    def test_an_interface_that_is_not_up_is_bounced(self):
        self.write(BEFORE)
        self.dumped.side_effect = lambda iface: None
        run = Recorder()
        self.assertIsNone(switch.change(self.root, pending(), AFTER, run))
        self.assertEqual(self.wg_calls(run), [
            ("wg-quick", "down", "wg0"), ("wg-quick", "up", "wg0")])
        self.assertNotIn(SET_TWO, run.calls)
        self.assertEqual(self.current(), AFTER)

    def test_a_wg_set_that_fails_is_bounced_on_the_new_file(self):
        self.write(BEFORE)
        calls = []

        def runner(argv):
            calls.append(argv)
            if argv == SET_TWO:
                return "wg: Unable to modify interface"
            return None
        self.assertIsNone(switch.change(self.root, pending(), AFTER, runner))
        self.assertEqual([one for one in calls if one[0] == "wg-quick"], [
            ("wg-quick", "down", "wg0"), ("wg-quick", "up", "wg0")])
        self.assertLess(calls.index(SET_TWO),
                        calls.index(("wg-quick", "down", "wg0")))
        self.assertEqual(self.current(), AFTER)

    def test_a_rename_that_fails_after_the_live_change_bounces(self):
        self.write(BEFORE)
        run = Recorder()
        replace = switch.os.replace
        failed = []

        def once(src, dst):
            if not failed:
                failed.append(src)
                raise OSError(28, "No space")
            return replace(src, dst)
        with mock.patch.object(switch.os, "replace", side_effect=once):
            written, problem = switch.bounce_overlay(
                self.root, "wg0", CONF, AFTER, run)
        self.assertFalse(written)
        self.assertIn("No space", problem)
        # the interface is put back on the file that is there
        self.assertEqual(self.wg_calls(run), [("wg-quick", "down", "wg0"),
                                              ("wg-quick", "up", "wg0")])
        self.assertEqual(self.current(), BEFORE)

    def test_an_overlay_down_before_is_left_down_by_its_revert(self):
        self.write(AFTER)
        run = Recorder()
        written, _ = switch.bounce_overlay(self.root, "wg0", CONF, BEFORE,
                                           run, up=False)
        self.assertTrue(written)
        self.assertEqual(self.wg_calls(run), [("wg-quick", "down", "wg0")])
        self.dumped.assert_not_called()
