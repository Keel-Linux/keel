# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh etcd reissue (keel.mesh.etcdreissue): a cluster of the
layout before keel#83 moved to certificates the root signs, one member
at a time, its intermediates revoked, then etcd's auth on; with members
in one process and a recording etcd (tests/etcd_helpers.py). The real
etcd at 250 ms with 2% loss is tests/test_etcd_auth_netns.py's."""

import json
import os
import socket
import ssl
import threading
from unittest import mock

from etcd_helpers import KEYS, MESH, FakeEtcd, Mesh, address, voter

from keel import exits
from keel.mesh import (
    etcdauth,
    etcdca,
    etcdform,
    etcdmsg,
    etcdpki,
    etcdreissue,
    etcdserve,
    etcdstate,
)
from keel.mesh.etcdclient import EtcdError


def legacy(root: str, issued: dict | None = None) -> None:
    """What a member of the layout before keel#83 holds besides its
    certificate: an intermediate and the client leaf it issued"""
    for one in etcdstate.LEGACY:
        etcdstate.write(root, one, "x\n")
    if issued is not None:
        etcdstate.write(root, etcdstate.ISSUED, json.dumps(issued))


class Live(Mesh):
    """a holds the root of a cluster of a, b and c, each with an
    intermediate as before keel#83; `serving` is what each member's
    etcd presents: the certificate in its state, read at each
    handshake"""

    def setUp(self):
        super().setUp()
        self.fake = FakeEtcd([voter(0), voter(1), voter(2)])
        self.a, self.b, self.c = self.members(3, etcd=self.fake)
        etcdform.form(self.a, False, lambda line: None)
        self.serials = {}
        for index, one in enumerate(self.all):
            self.serials[index] = etcdpki.serial(etcdstate.read(
                one.root, etcdstate.MEMBER_CERT))
        own_ca = etcdstate.read(self.a.root, etcdstate.ROOT_CERT)
        legacy(self.a.root, {address(1): [["0B", "300101000000Z", KEYS[1]]],
                             address(2): [["0C", "300101000000Z", KEYS[2]]]})
        etcdstate.write(self.a.root, etcdstate.CA_CERT, own_ca)
        self.own_ca = etcdpki.serial(own_ca)
        legacy(self.b.root)
        legacy(self.c.root)
        self.out: list[str] = []
        self.stale_on: set[str] = set()

    def serving(self, etcd_, at: str) -> str | None:
        if at in self.stale_on:
            return None
        index = [address(n) for n in range(3)].index(at)
        return etcdpki.fingerprint(etcdstate.read(
            self.all[index].root, etcdstate.MEMBER_CERT))

    def reissue(self, dry_run=False) -> int:
        return etcdreissue.reissue(self.a, dry_run, self.out.append,
                                   self.serving)


class TestTheMove(Live):
    def test_every_member_moved_the_intermediates_revoked_auth_on(self):
        self.assertEqual(self.reissue(), exits.OK, self.text(0))
        root = etcdstate.read(self.a.root, etcdstate.ROOT_CERT)
        for index, one in enumerate(self.all):
            with self.subTest(member=index):
                cert = etcdstate.read(one.root, etcdstate.MEMBER_CERT)
                self.assertTrue(etcdpki.verified(cert, [], root))
                self.assertNotEqual(etcdpki.serial(cert),
                                    self.serials[index])
                self.assertEqual(etcdpki.subject(cert),
                                 etcdstate.name(address(index)))
                self.assertFalse(etcdstate.legacy(one.root))
                # no member holds a CA key: none can mint a certificate
                self.assertFalse(os.path.exists(os.path.join(
                    one.root, etcdstate.CA_KEY)))
                self.assertEqual(etcdpki.crl_serials(etcdstate.read(
                    one.root, etcdstate.CRL)), {"0B", "0C", self.own_ca})
        # one member at a time, the holder last
        self.assertEqual(self.out[:3], [
            f"etcd: {address(1)} holds a certificate the root signed;"
            " every voter is healthy",
            f"etcd: {address(2)} holds a certificate the root signed;"
            " every voter is healthy",
            "etcd: this node holds a certificate the root signed"])
        self.assertIn("3 intermediate(s) revoked", self.out[3])
        self.assertTrue(self.fake.auth)
        self.assertTrue(etcdauth.enabled(self.a))
        self.assertEqual(self.fake.users_["root"], {"root"})
        for index in range(3):
            self.assertEqual(self.fake.users_[etcdstate.name(
                address(index))], {etcdauth.MEMBER_ROLE})
        self.assertIn("auth enabled; 0 VIP pair(s)", self.out[-1])
        # its certificate was written for etcd on each member, by apply
        for one in (self.b, self.c):
            self.assertEqual(self.applied(one)[-1]["overlays"]["etcd"],
                             "enabled")
        # run again: nothing to move, the same end
        self.out.clear()
        self.assertEqual(self.reissue(), exits.OK)
        self.assertNotIn("holds a certificate", "\n".join(self.out))

    def test_a_dry_run_changes_nothing(self):
        before = etcdstate.read(self.b.root, etcdstate.MEMBER_CERT)
        self.assertEqual(self.reissue(dry_run=True), exits.OK)
        self.assertEqual(self.out, [
            f"would sign {address(1)}'s certificate with the root",
            f"would sign {address(2)}'s certificate with the root",
            "would sign this node's certificate with the root",
            "would revoke the members' intermediates and send the CRL",
            "would enable etcd's auth",
            "dry run: nothing was changed on any member"])
        self.assertEqual(etcdstate.read(self.b.root, etcdstate.MEMBER_CERT),
                         before)
        self.assertFalse(self.fake.auth)
        self.fake.auth = True
        etcdauth.forget(self.a.root)
        self.out.clear()
        self.reissue(dry_run=True)
        self.assertIn("would converge its users and roles", self.out[-2])

    def test_a_member_that_does_not_serve_its_new_certificate_stops_it(self):
        self.stale_on.add(address(2))
        with mock.patch.object(etcdreissue, "WAIT", 4.0):
            self.assertEqual(self.reissue(), exits.MESH_REFUSED)
        self.assertIn(f"{address(2)}'s new certificate: it does not serve"
                      " its new certificate yet; stopped here", self.text(0))
        # b moved, a and the auth not
        self.assertFalse(etcdstate.legacy(self.b.root))
        self.assertTrue(etcdstate.legacy(self.a.root))
        self.assertFalse(self.fake.auth)
        # then it does: run again, it goes on
        self.stale_on.clear()
        self.assertEqual(self.reissue(), exits.OK)
        self.assertTrue(self.fake.auth)

    def test_a_voter_unhealthy_meanwhile_stops_it(self):
        url = f"https://[{address(1)}]:2379"
        sick = iter([(True, "")] * 3 + [(False, "NO_LEADER")] * 100)
        with mock.patch.object(self.fake, "health",
                               side_effect=lambda one: next(sick)
                               if one == url else (True, "")), \
                mock.patch.object(etcdreissue, "WAIT", 4.0):
            self.assertEqual(self.reissue(), exits.MESH_REFUSED)
        self.assertIn(f"not healthy: {address(1)} (NO_LEADER)", self.text(0))


class TestRefused(Live):
    def refused(self, why: str, etcd_=None) -> None:
        self.assertEqual(etcdreissue.reissue(etcd_ or self.a, False,
                                             self.out.append, self.serving),
                         exits.MESH_REFUSED)
        self.assertIn(why, "\n".join(self.said[0] + self.said[1]))
        self.assertFalse(self.fake.auth)

    def test_off_the_holder(self):
        self.refused(f"run it on the root CA's holder ({address(0)})",
                     self.b)
        etcdstate.write(self.b.root, etcdstate.HOLDER, "")
        self.refused("the node that holds it", self.b)

    def test_without_a_cluster_or_while_a_change_waits(self):
        with mock.patch.object(type(self.a.node), "waiting",
                               return_value=True):
            self.refused("a network change waits")
        os.remove(os.path.join(self.a.root, etcdstate.CLUSTER))
        self.refused("in no etcd cluster")

    def test_a_member_on_a_keel_before_keel_83(self):
        old = etcdmsg.Probe(True, "f" * 64, True, address(1), pki=1)
        real = etcdform.probed

        def probed(etcd_, peers):
            found = real(etcd_, peers)
            found[KEYS[1]] = old
            return found
        with mock.patch("keel.mesh.etcdform.probed", side_effect=probed):
            self.refused(f"{address(1)} runs a keel before keel#83")

    def test_a_member_that_does_not_answer(self):
        self.down.add(address(2))
        self.refused(f"{address(2)} did not answer")

    def test_an_etcd_member_this_node_has_no_peer_for(self):
        self.fake.members_.append(voter(4))
        self.refused(f"etcd members this node has no peer for: {address(4)}")

    def test_an_unhealthy_voter(self):
        self.fake.healthy[f"https://[{address(2)}]:2379"] = (False, "")
        self.refused(f"{address(2)} (unhealthy) is not healthy")
        self.fake.members_ = [voter(0), voter(1), voter(2, name=False)]
        self.refused("(not started) is not healthy")
        self.fake.refuse["connect"] = "no member answered"
        with mock.patch.object(etcdreissue, "members",
                               return_value=([], [])):
            self.refused("this member (no member answered) is not healthy")

    def test_a_member_that_refuses_its_certificate_or_the_crl(self):
        real = etcdserve.answer

        def refusing(member, body, key):
            if member is self.c and etcdmsg.loads(body).kind == \
                    etcdmsg.REISSUE:
                return etcdserve.refused(409, "no")
            return real(member, body, key)
        with mock.patch("keel.mesh.etcdserve.answer", side_effect=refusing):
            self.refused(f"{address(2)} did not take its certificate")
        self.assertFalse(etcdstate.legacy(self.b.root))

        def no_crl(member, body, key):
            if member is self.c and etcdmsg.loads(body).kind == \
                    etcdmsg.CRL_KIND:
                return etcdserve.refused(503, "no")
            return real(member, body, key)
        with mock.patch("keel.mesh.etcdserve.answer", side_effect=no_crl):
            self.refused(f"the CRL did not reach {address(2)}")

    def test_its_own_certificate_not_written(self):
        with mock.patch("keel.mesh.etcd.start", return_value=False):
            self.refused("this node's certificate was not written")

    def test_auth_on_but_unreadable_says_how_to_roll_back(self):
        self.fake.refuse["prefix"] = "etcdserver: permission denied"
        with mock.patch("keel.mesh.etcdauth.from_claims", return_value=0):
            self.assertEqual(self.reissue(), exits.MESH_REFUSED)
        self.assertIn("--rollback turns it off", self.text(0))

    def test_state_or_etcd_failing(self):
        self.fake.refuse["role_add"] = "etcdserver: no leader"
        self.assertEqual(self.reissue(), exits.APPLY_FAILED)
        self.assertIn("no leader", self.text(0))


class TestRollback(Live):
    def test_auth_off_the_certificates_stay(self):
        self.assertEqual(self.reissue(), exits.OK)
        cert = etcdstate.read(self.b.root, etcdstate.MEMBER_CERT)
        self.assertEqual(etcdreissue.rollback(self.a, self.out.append),
                         exits.OK)
        self.assertFalse(self.fake.auth)
        self.assertFalse(etcdauth.enabled(self.a))
        self.assertEqual(etcdstate.read(self.b.root, etcdstate.MEMBER_CERT),
                         cert)
        self.assertIn("the certificates stay the root's", self.out[-1])
        # again: nothing to turn off
        self.assertEqual(etcdreissue.rollback(self.a, self.out.append),
                         exits.OK)

    def test_off_the_holder_or_etcd_failing(self):
        self.assertEqual(etcdreissue.rollback(self.b, self.out.append),
                         exits.MESH_REFUSED)
        self.fake.refuse["auth_enabled"] = "no leader"
        self.assertEqual(etcdreissue.rollback(self.a, self.out.append),
                         exits.APPLY_FAILED)


class TestTheReceiver(Live):
    def ask(self, target, kind, body, sender=0):
        message = etcdmsg.signed(self.all[sender].root, kind, MESH.hex(),
                                 KEYS[sender], self.clock(), body)
        return etcdserve.answer(target, message, KEYS[sender])

    def grant_for(self, index):
        return etcdstate.grant_for(self.a.root, etcdstate.member_request(
            self.all[index].root), address(index), KEYS[index])

    def test_a_reissue_taken_once_and_never_for_less(self):
        grant = self.grant_for(1)
        found = self.ask(self.b, etcdmsg.REISSUE,
                         {"grant": etcdmsg.grant_data(grant)})
        self.assertEqual(found.status, 200)
        self.assertFalse(etcdstate.legacy(self.b.root))
        # the same again lasts no longer than the one held
        found = self.ask(self.b, etcdmsg.REISSUE,
                         {"grant": etcdmsg.grant_data(grant)})
        self.assertEqual(found.status, 409)

    def test_reissue_refusals(self):
        self.assertEqual(self.ask(self.b, etcdmsg.REISSUE, {}).status, 400)
        self.assertEqual(self.ask(self.b, etcdmsg.REISSUE,
                                  {"grant": {"chain": []}}).status, 400)
        # another member's certificate
        found = self.ask(self.b, etcdmsg.REISSUE,
                         {"grant": etcdmsg.grant_data(self.grant_for(2))})
        self.assertEqual(found.status, 403)
        bad = etcdmsg.grant_data(self.grant_for(1))
        bad["certificate"] = bad["root"].replace("MII", "MIJ", 1)
        with mock.patch("keel.mesh.etcdpki.not_after",
                        side_effect=etcdpki.PkiError("not a certificate")):
            self.assertEqual(self.ask(self.b, etcdmsg.REISSUE,
                                      {"grant": bad}).status, 400)
        # a member that holds no certificate joins etcd by form instead
        grant = etcdmsg.grant_data(self.grant_for(1))
        os.remove(os.path.join(self.b.root, etcdstate.MEMBER_CERT))
        self.assertEqual(self.ask(self.b, etcdmsg.REISSUE,
                                  {"grant": grant}).status, 409)

    def test_a_crl(self):
        found = etcdca.revoke_legacy(self.a.root, {"0B": "300101000000Z"},
                                     self.clock())
        answer = self.ask(self.b, etcdmsg.CRL_KIND, {"crl": found})
        self.assertEqual(json.loads(answer.body), {"taken": True})
        answer = self.ask(self.b, etcdmsg.CRL_KIND, {"crl": found})
        self.assertEqual(json.loads(answer.body), {"taken": False})
        self.assertEqual(self.ask(self.b, etcdmsg.CRL_KIND,
                                  {"crl": "x"}).status, 400)


class TestServed(Mesh):
    def test_the_certificate_a_member_serves_on_its_client_port(self):
        a, = self.members(1)
        etcdstate.make_root(a.root, MESH.hex(), address(0))
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(os.path.join(a.root, etcdstate.MEMBER_CERT),
                               os.path.join(a.root, etcdstate.MEMBER_KEY))
        server.load_verify_locations(os.path.join(a.root,
                                                  etcdstate.ROOT_CERT))
        server.verify_mode = ssl.CERT_REQUIRED
        listener = socket.socket(socket.AF_INET6)
        listener.bind(("::1", 0))
        listener.listen(1)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]

        def serve():
            conn, _ = listener.accept()
            try:
                with server.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        with mock.patch("keel.mesh.etcdstate.CLIENT_PORT", port):
            found = etcdreissue.served(a, "::1")
        thread.join(5)
        self.assertEqual(found, etcdpki.fingerprint(etcdstate.read(
            a.root, etcdstate.MEMBER_CERT)))
        with mock.patch("keel.mesh.etcdstate.CLIENT_PORT", 1):
            self.assertIsNone(etcdreissue.served(a, "::1"))


class TestCli(Live):
    def test_reissue_and_rollback_through_keel(self):
        from keel.mesh import commands
        args = mock.Mock(rollback=False, dry_run=True)
        with mock.patch("keel.mesh.commands.as_root", return_value=0), \
                mock.patch("keel.mesh.commands.member",
                           return_value=self.a):
            self.assertEqual(commands.mesh_etcd_reissue(args), exits.OK)
            args.rollback = True
            self.assertEqual(commands.mesh_etcd_reissue(args), exits.OK)
        with mock.patch("keel.mesh.commands.as_root", return_value=4):
            self.assertEqual(commands.mesh_etcd_reissue(args), 4)

    def test_an_admin_client_from_the_holder_s_files(self):
        from keel.mesh.etcd import Etcd
        found = etcdreissue.etcdclient_admin(Etcd(self.a.node, self.clock,
                                                  print))
        self.assertTrue(found.tls.certificate.endswith(etcdstate.ADMIN_CERT))
        with self.assertRaisesRegex(EtcdError, "no certificate"):
            etcdreissue.etcdclient_admin(Etcd(self.b.node, self.clock,
                                              print))
        # elsewhere, keel asks as this member
        self.assertTrue(Etcd(self.b.node, self.clock, print).admin(
        ).tls.certificate.endswith(etcdstate.MEMBER_CERT))
