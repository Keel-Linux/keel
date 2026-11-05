# Copyright (c) 2026 KeelLinux maintainers
"""The VIP proposed by keel mesh invite and kept by join, and the JSON
forms of invite and status (decision 0076, docs/mesh.md, "The contract
for confconsole")

Through keel.cli.main against a scratch root, as tests/test_mesh_cli.py
does: the certificate is the real openssl's, the inviter's key a fixed
one. The screens of confconsole read exactly what these tests read.
"""

import json
import os
from datetime import datetime, timezone
from os.path import join
from types import SimpleNamespace
from unittest import mock

from manifest_helpers import build_root, fixture, overlay, put
from test_mesh_cli import INVITER, OVERLAY, Case, run_cli

from keel import exits
from keel.mesh import contract, invites, joining, vippropose
from keel.mesh import token as mesh_token
from keel.mesh.etcdclient import EtcdError, Value

CLOUD = OVERLAY.replace("version: 1\n", """version: 1
installation:
  mode: cloud_simple
""")
# the peer of the fixture's overlay, as its spec names it
PEER = OVERLAY.split("public_key: ", 1)[1].split()[0]
VIP1 = "fd00:6b65:1::ffff:1"
VIP2 = "fd00:6b65:1::ffff:2"
VIP3 = "fd00:6b65:1::ffff:3"
# Keel Core of the format's fixture, with the VIP overlay it ships
VIP_OVERLAY = "  vip: {simple: disabled, cloud_simple: enabled," \
    " cloud_advanced: enabled}\n"


def core(mode: str = "cloud_simple", vip: str | None = None,
         vip_state: str = "enabled") -> str:
    """A Core node's spec in `mode`, every overlay of its chain written"""
    etcd = "enabled" if mode == "cloud_advanced" else "disabled"
    declared = f"  vip: {vip}\n" if vip else ""
    return OVERLAY.replace("version: 1\n", f"""version: 1
appliance:
  name: core
{declared}installation:
  mode: {mode}
overlays:
  installer: enabled
  wireguard: enabled
  etcd: {etcd}
  crowdsec: enabled
  vip: {vip_state}
""")


def token_text(out: str) -> str:
    return out.strip().split("<<< ", 1)[1]


class InviteCase(Case):
    def setUp(self):
        super().setUp()
        self.key_file()
        patcher = mock.patch("keel.mesh.commands.wgkeys.public",
                             return_value=(INVITER, None))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("keel.manifest.machine.ROOT_UID", os.getuid())
        patcher.start()
        self.addCleanup(patcher.stop)
        made = build_root(self.root)
        for name in os.listdir(made):
            os.rename(join(made, name), join(self.root, name))
        put(self.root, "overlays", "vip", overlay("vip"))
        put(self.root, "appliances", "core", fixture(
            "appliances", "core").replace("overlays:\n",
                                          "overlays:\n" + VIP_OVERLAY))
        self.write_spec(CLOUD)

    def parsed(self, out: str) -> mesh_token.Token:
        return mesh_token.parse(token_text(out), datetime.now(timezone.utc))

    def touch(self, relative: str) -> None:
        target = join(self.root, relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w"):
            pass


class TheVipAnInviteCarries(InviteCase):
    def test_a_cloud_mode_proposes_the_first_free_vip(self):
        code, out, err = self.invite()
        self.assertEqual(code, exits.OK, err)
        self.assertTrue(token_text(out).startswith("keel2:"))
        found = self.parsed(out)
        self.assertEqual(found.vip, VIP1)
        self.assertIn(f"the invite carries the VIP {VIP1}: write it as"
                      " appliance.vip on both nodes", err)
        pending = invites.find(self.root, found.invite_id,
                               datetime.now(timezone.utc))
        self.assertEqual(pending.vip, VIP1)

    def test_a_second_invite_carries_the_same_vip(self):
        """cloud advanced: two invites, one pair, one VIP"""
        first = self.parsed(self.invite()[1])
        code, out, err = self.invite("--port", "8443")
        self.assertEqual(code, exits.OK, err)
        self.assertEqual(self.parsed(out).vip, first.vip)

    def test_the_declared_vip_is_the_one_carried(self):
        self.write_spec(core(vip=VIP3))
        code, out, err = self.invite()
        self.assertEqual(code, exits.OK, err)
        self.assertEqual(self.parsed(out).vip, VIP3)

    def test_a_vip_this_node_knows_is_not_proposed(self):
        """one it routes or holds (a state file), one it paired (a pair
        record)"""
        self.touch(f"var/lib/keel/vip/{VIP1}.json")
        self.touch(f"var/lib/keel/vip/{VIP2}.pair")
        code, out, err = self.invite()
        self.assertEqual(code, exits.OK, err)
        self.assertEqual(self.parsed(out).vip, VIP3)

    def test_simple_mode_or_no_mode_carries_none_as_keel1(self):
        for text, said in ((OVERLAY, False),
                           (CLOUD.replace("cloud_simple", "simple"), False)):
            with self.subTest(said=said):
                for name in self.invite_files():
                    os.remove(join(self.root, invites.INVITES, name))
                self.write_spec(text)
                code, out, err = self.invite()
                self.assertEqual(code, exits.OK, err)
                self.assertTrue(token_text(out).startswith("keel1:"))
                self.assertIsNone(self.parsed(out).vip)
                self.assertNotIn("VIP", err)

    def test_the_witness_carries_none_and_says_why(self):
        self.write_spec(core("cloud_advanced", vip_state="disabled"))
        code, out, err = self.invite()
        self.assertEqual(code, exits.OK, err)
        self.assertTrue(token_text(out).startswith("keel1:"))
        self.assertIn("the invite carries no VIP: overlays.vip is disabled",
                      err)


class TheVipsReservedInEtcd(InviteCase):
    def etcd(self, client):
        member = mock.patch("keel.mesh.etcd.Etcd.local", return_value=client)
        formed = mock.patch("keel.mesh.addrreserve.formed",
                            side_effect=lambda root, ready: ready() or True)
        claim = mock.patch("keel.mesh.commands.address_claim",
                           return_value=None)
        for one in (member, formed, claim):
            one.start()
            self.addCleanup(one.stop)

    def test_a_vip_reserved_by_another_pair_is_not_proposed(self):
        mesh = None

        class Client:
            def prefix(self, key):
                nonlocal mesh
                mesh = key
                return [Value(f"{key}{VIP1}/pair", b"{}", 3, None),
                        Value(f"{key}not-an-address/pair", b"{}", 4, None)]
        self.etcd(Client())
        code, out, err = self.invite()
        self.assertEqual(code, exits.OK, err)
        self.assertEqual(self.parsed(out).vip, VIP2)
        self.assertRegex(mesh, r"^/keel/[0-9a-f]{32}/vips/$")

    def test_an_etcd_that_does_not_answer_is_said(self):
        class Client:
            def prefix(self, key):
                raise EtcdError("timed out")
        self.etcd(Client())
        code, out, err = self.invite()
        self.assertEqual(code, exits.OK, err)
        self.assertEqual(self.parsed(out).vip, VIP1)
        self.assertIn("etcd did not answer for the VIPs reserved there"
                      " (timed out)", err)


class TheProposal(InviteCase):
    def test_an_overlay_too_narrow_or_a_full_range_proposes_none(self):
        doc = {"installation": {"mode": "cloud_simple"},
               "network": {"overlay": {"wireguard": {
                   "address": "fd00:6b65:1::1/112"}}}}
        found = vippropose.proposed(self.root, doc, ())
        self.assertIsNone(found.vip)
        self.assertIn("too narrow", found.why)
        doc["network"]["overlay"]["wireguard"]["address"] = \
            "fd00:6b65:1::1/64"
        with mock.patch.object(vippropose, "known", return_value={
                f"fd00:6b65:1::ffff:{host:x}" for host in range(1, 65536)}):
            found = vippropose.proposed(self.root, doc, ())
        self.assertIsNone(found.vip)
        self.assertIn("every address of the VIP range", found.why)

    def test_a_declared_vip_that_is_not_an_address_is_passed_over(self):
        doc = {"installation": {"mode": "cloud_simple"},
               "appliance": {"name": "core", "vip": 7},
               "network": {"overlay": {"wireguard": {
                   "address": "fd00:6b65:1::1/64"}}}}
        self.assertEqual(vippropose.proposed(self.root, doc, ()).vip, VIP1)

    def test_a_received_vip_that_cannot_be_read_is_none(self):
        self.assertIsNone(vippropose.received(self.root))
        self.touch(vippropose.RECORD)
        self.assertIsNone(vippropose.received(self.root))


class InviteJson(InviteCase):
    def test_one_line_of_json_with_the_line_the_token_and_the_vip(self):
        code, out, err = self.invite("--json")
        self.assertEqual(code, exits.OK, err)
        self.assertEqual(out.count("\n"), 1)
        found = json.loads(out)
        self.assertEqual(found["format"], 1)
        self.assertEqual(found["line"], f"keel mesh join - <<< "
                         f"{found['token']}")
        parsed = mesh_token.parse(found["token"], datetime.now(timezone.utc))
        self.assertEqual(found["vip"], VIP1)
        self.assertEqual(found["invite_id"], parsed.invite_id)
        self.assertEqual(found["assigned"], parsed.assigned)
        self.assertEqual(found["https_port"], 51820)
        self.assertEqual(datetime.strptime(found["expires"],
                                           "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc), parsed.expires)
        self.assertEqual(sorted(found), sorted(
            ("format", "line", "token", "vip", "expires", "invite_id",
             "assigned", "https_port")))

    def test_without_a_vip_it_is_null(self):
        self.write_spec(OVERLAY)
        found = json.loads(self.invite("--json")[1])
        self.assertIsNone(found["vip"])

    def test_a_refused_invite_prints_nothing_on_standard_output(self):
        self.invite()
        code, out, err = self.invite("--json")
        self.assertEqual((code, out), (exits.MESH_REFUSED, ""))
        self.assertIn("is pending on TCP port", err)


class TheJoin(InviteCase):
    """join keeps the VIP of a join that confirmed, and writes no spec
    field for it"""

    def joined(self, text: str, code: int):
        joiner = join(self.root, "joiner.yaml")
        with open(joiner, "w") as fob:
            fob.write("version: 1\n")
        with mock.patch.object(joining, "run", return_value=code) as run:
            found = run_cli("mesh", "join", "-", "--endpoint",
                            "2001:db8:2::20", "--spec", joiner, "--root",
                            self.root, stdin=text)
        self.assertEqual(run.call_count, 1)
        with open(joiner) as fob:
            self.assertEqual(fob.read(), "version: 1\n")
        return found

    def test_a_confirmed_join_keeps_the_vip_and_says_it(self):
        made = token_text(self.invite()[1])
        code, out, err = self.joined(made, exits.OK)
        self.assertEqual(code, exits.OK, err)
        self.assertIn(f"vip: {VIP1}, proposed by the inviter for the pair",
                      out)
        self.assertEqual(vippropose.received(self.root), VIP1)
        with open(join(self.root, vippropose.RECORD)) as fob:
            record = json.load(fob)
        self.assertEqual(record["inviter"], "fd00:6b65:1::1")
        self.assertEqual(oct(os.stat(join(self.root, vippropose.RECORD))
                             .st_mode & 0o777), "0o600")

    def test_a_join_that_fails_keeps_nothing(self):
        made = token_text(self.invite()[1])
        code, out, _ = self.joined(made, exits.NETWORK_NOT_CONFIRMED)
        self.assertEqual(code, exits.NETWORK_NOT_CONFIRMED)
        self.assertNotIn("vip:", out)
        self.assertIsNone(vippropose.received(self.root))

    def test_a_keel1_token_keeps_nothing(self):
        self.write_spec(OVERLAY)
        made = token_text(self.invite()[1])
        code, out, _ = self.joined(made, exits.OK)
        self.assertEqual(code, exits.OK)
        self.assertIsNone(vippropose.received(self.root))

    def test_the_dry_run_says_the_vip(self):
        made = token_text(self.invite()[1])
        joiner = join(self.root, "joiner.yaml")
        code, out, err = run_cli("mesh", "join", "-", "--dry-run", "--spec",
                                 joiner, stdin=made)
        self.assertEqual(code, exits.OK, err)
        self.assertIn(f"the token carries the VIP {VIP1}", err)
        self.assertNotIn("vip", out)


class StatusJson(InviteCase):
    def status(self, *extra):
        code, out, err = run_cli("mesh", "status", "--json", "--spec",
                                 self.spec, "--root", self.root, *extra)
        self.assertEqual(code, exits.OK, err)
        self.assertEqual(out.count("\n"), 1)
        return json.loads(out)

    def test_off_the_live_system(self):
        self.invite()
        found = self.status()
        self.assertEqual((found["format"], found["live"], found["mode"]),
                         (1, False, "cloud_simple"))
        self.assertTrue(found["in_mesh"])
        self.assertEqual(found["address"], "fd00:6b65:1::1/64")
        self.assertEqual((found["interface"], found["port"]), ("wg0", 51821))
        self.assertIsNone(found["public_key"])
        self.assertEqual(found["members"], [{
            "public_key": "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg=",
            "address": "fd00:6b65:1::2",
            "allowed_ips": ["fd00:6b65:1::2/128"],
            "endpoint": "[2001:db8:2::20]:51820",
            "handshake_age": None, "reachable": None}])
        self.assertEqual(len(found["invites"]), 1)
        self.assertEqual(found["invites"][0]["vip"], VIP1)
        self.assertFalse(found["invites"][0]["used"])
        self.assertEqual(found["etcd"]["state"], "off")
        self.assertEqual(found["vip"], {"declared": None, "proposed": VIP1,
                                        "role": None, "holder": None})
        self.assertIsNone(found["ready"])

    def test_a_node_in_no_mesh(self):
        self.write_spec("version: 1\n")
        found = self.status()
        self.assertFalse(found["in_mesh"])
        self.assertEqual((found["members"], found["invites"]), ([], []))
        self.assertEqual(found["etcd"]["state"], "off")
        os.remove(self.spec)
        self.assertIsNone(self.status()["mode"])

    def test_the_vip_received_and_declared(self):
        vippropose.keep(self.root, VIP2, "0" * 16, "fd00:6b65:1::1/64",
                        datetime.now(timezone.utc))
        self.write_spec(core(vip=VIP2))
        with mock.patch("keel.system.dbpair.observe_pair",
                        return_value=SimpleNamespace(
                            role="replica", holder_address="fd00:6b65:1::2")):
            found = self.status()
        self.assertEqual(found["vip"], {
            "declared": VIP2, "proposed": VIP2, "role": "replica",
            "holder": "fd00:6b65:1::2"})
        with mock.patch("keel.system.dbpair.observe_pair",
                        return_value=SimpleNamespace(
                            role="primary", holder_address=None)):
            self.assertEqual(self.status()["vip"]["holder"],
                             "fd00:6b65:1::1")
        with mock.patch("keel.system.dbpair.observe_pair",
                        return_value=SimpleNamespace(
                            role=None, holder_address=None)):
            found = self.status()["vip"]
        self.assertEqual((found["role"], found["holder"]), ("replica", None))

    def test_a_vip_that_is_not_an_address_is_not_declared(self):
        with mock.patch("keel.mesh.commands.read_spec",
                        return_value=({"version": 1, "appliance": {
                            "vip": 7}}, 0)):
            self.assertIsNone(self.status()["vip"]["declared"])


class TheLiveReport(InviteCase):
    """status.report and ready, with wg and etcd as the live system
    answers them"""

    NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)

    def report(self, handshake: str):
        from keel.mesh import status
        key = PEER
        answers = {
            "public-key": f"{INVITER}\n",
            "endpoints": f"{key}\t[2001:db8:2::21]:51820\n",
            "latest-handshakes": f"{key}\t{handshake}\n",
        }
        overlay = {"address": "fd00:6b65:1::1/64", "peers": [
            {"public_key": key, "allowed_ips": ["fd00:6b65:1::2/128"]}]}
        return status.report(overlay, self.root, self.NOW,
                             lambda argv: answers[argv[-1]])

    def test_a_recent_handshake_is_reachable_and_ready(self):
        found = self.report(str(int(self.NOW.timestamp()) - 12))
        self.assertEqual(found["public_key"], INVITER)
        member, = found["members"]
        self.assertEqual(member["endpoint"], "[2001:db8:2::21]:51820")
        self.assertEqual(member["handshake_age"], 12)
        self.assertTrue(member["reachable"])
        found["etcd"] = {"state": "off"}
        self.assertTrue(contract.ready(found, "cloud_simple"))
        self.assertFalse(contract.ready(found, "cloud_advanced"))
        found["etcd"] = {"state": "formed", "voters": 3,
                         "healthy_voters": 3}
        self.assertTrue(contract.ready(found, "cloud_advanced"))
        found["etcd"]["healthy_voters"] = 2
        self.assertFalse(contract.ready(found, "cloud_advanced"))

    def test_no_handshake_is_not_reachable_and_not_ready(self):
        found = self.report("0")
        member, = found["members"]
        self.assertIsNone(member["handshake_age"])
        self.assertFalse(member["reachable"])
        self.assertFalse(contract.ready(found, "cloud_simple"))
        found["members"] = []
        self.assertFalse(contract.ready(found, "cloud_simple"))

    def test_the_host_of_a_peer_is_its_first_ipv6_host_route(self):
        from keel.mesh import status
        self.assertEqual(status.host_of(["x", "10.0.0.1/32",
                                         "fd00::/64", "fd00::9/128"]),
                         "fd00::9")
        self.assertIsNone(status.host_of(["fd00::/64"]))

    def test_an_identity_that_cannot_be_read_is_null(self):
        from keel.mesh import status
        with mock.patch("keel.mesh.status.identity.read",
                        side_effect=ValueError("damaged")):
            self.assertIsNone(status.identity_hex(self.root))

    def test_the_live_status_asks_wg_and_etcd(self):
        seen = {}

        def report(overlay, root, now, output):
            seen["output"] = output
            return {"in_mesh": True, "members": [], "invites": []}
        with mock.patch("keel.mesh.contract.status.report", report), \
                mock.patch("keel.mesh.contract.etcdcare.report",
                           return_value={"state": "off"}) as etcd_report:
            found = contract.mesh_status(self.root, self.spec,
                                         {"version": 1}, None, True,
                                         self.NOW, print)
        self.assertIsNotNone(seen["output"])
        self.assertTrue(etcd_report.call_args.args[1])
        self.assertTrue(found["live"])
        self.assertFalse(found["ready"])

