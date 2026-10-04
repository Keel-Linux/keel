# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh join, the new node's side, against a real listener

Two scratch roots, a real Node each and the inviter's real Listener,
joined by a wire in this process (tests/mesh_wire.py): what each spec
holds afterwards, that each window is confirmed by the mesh session
and by nothing else, the fallback's line, and every refusal before
anything is applied.
"""

import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from unittest import mock

import yaml
from mesh_helpers import (
    ASSIGNED,
    INVITER,
    JOINER,
    MESH,
    NOW,
    OTHER,
    SIGNER,
    Clock,
    reserved,
)
from mesh_wire import (
    INVITER_SPEC,
    INVITER_UPLINK,
    JOINER_OVERLAY,
    Armed,
    Wire,
    node,
    probes,
    token,
)

from keel import exits
from keel.mesh import (
    acceptline,
    identity,
    invites,
    joining,
    protocol,
    signing,
    trust,
)
from keel.mesh.admit import Admitter, Joined
from keel.mesh.endpoint import Choice
from keel.mesh.listener import Listener, Params
from keel.mesh.node import NodeError
from keel.mesh.token import hmac_key
from keel.network import marker

JOINER_ENDPOINT = "2001:db8:2::20"


class Saying(Armed):
    """apply, and the lines it prints, as the live one does"""

    def __call__(self, doc, root, window):
        print(f"keel mesh: bring the overlay wg0 up; it reverts in {window}"
              " s unless `keel network confirm` is run from a new session")
        return super().__call__(doc, root, window)


def spec_of(found):
    with open(found.path) as fob:
        return yaml.safe_load(fob)


class Case(unittest.TestCase):
    def setUp(self):
        self.inviter_root = tempfile.mkdtemp()
        self.joiner_root = tempfile.mkdtemp()
        for root in (self.inviter_root, self.joiner_root):
            self.addCleanup(shutil.rmtree, root)
        self.invite = reserved(self.inviter_root)
        self.inviter = node(self.inviter_root, INVITER_SPEC)
        self.joiner = node(self.joiner_root)
        self.clock = Clock()
        self.logged = []
        self.admitter = Admitter(self.inviter_root, self.invite, INVITER,
                                 "fd00:6b65:1::1/64", self.inviter,
                                 self.clock, self.logged.append)
        self.listener = Listener(
            Params(self.invite.invite_id,
                   self.invite.expires, "::", 51820, "fd00:6b65:1::1"),
            self.admitter, self.clock, self.logged.append)
        self.wire = Wire(self.listener, token(self.invite).fingerprint)
        self.out, self.err, self.slept, self.learned = [], [], [], []
        keys = mock.patch.multiple(
            "keel.mesh.joining.wgkeys", generate=mock.DEFAULT,
            public=mock.DEFAULT)
        found = keys.start()
        self.addCleanup(keys.stop)
        found["generate"].return_value = None
        found["public"].return_value = (JOINER, None)
        self.keys = found

    def joining(self, endpoint=JOINER_ENDPOINT, route="eth0", **changed):
        self.found = joining.Joiner(
            self.joiner, token(self.invite, **changed), self.clock,
            self.out.append, self.err.append, post=self.wire,
            sleep=self.slept.append,
            route_dev=lambda host: route,
            learn=lambda host: self.learned.append(host) or exits.OK)
        return joining.run(self.found, endpoint)


class TestJoin(Case):
    def test_both_specs_and_both_windows(self):
        code = self.joining()
        self.assertEqual(code, exits.OK, self.err)
        mine = spec_of(self.joiner)["network"]["overlay"]["wireguard"]
        self.assertEqual(mine, {"address": ASSIGNED, "peers": [{
            "public_key": INVITER, "endpoint": f"[{INVITER_UPLINK}]:51821",
            "allowed_ips": ["fd00:6b65:1::1/128"]}]})
        theirs = spec_of(self.inviter)["network"]["overlay"]["wireguard"]
        self.assertEqual(theirs["peers"], [{
            "public_key": JOINER, "allowed_ips": [f"{JOINER_OVERLAY}/128"],
            "endpoint": f"[{JOINER_ENDPOINT}]:51820"}])
        for root in (self.inviter_root, self.joiner_root):
            self.assertFalse(marker.exists(root))
            self.assertEqual(marker.last(root).outcome, marker.CONFIRMED)
        self.assertEqual(self.out, [
            f"joined the mesh: this node is {ASSIGNED} on wg0",
            f"peer: {INVITER} at fd00:6b65:1::1, through"
            f" [{INVITER_UPLINK}]:51821",
            joining.TWO_NODES])
        self.assertIn("the overlay was tested: the inviter's answer over the"
                      " overlay", "\n".join(self.err))
        self.assertTrue(self.listener.confirmed)
        self.assertEqual(identity.read(self.joiner_root), bytes(range(16)))
        self.assertEqual([path for _, path in self.wire.calls],
                         [protocol.JOIN, protocol.CONFIRM])
        self.assertEqual(self.wire.calls[1][0], "fd00:6b65:1::1")
        # the answer carried the members: nothing to pull
        self.assertEqual(self.learned, [])

    def test_a_node_behind_nat_sends_no_endpoint(self):
        self.assertEqual(self.joining(endpoint=None), exits.OK, self.err)
        theirs = spec_of(self.inviter)["network"]["overlay"]["wireguard"]
        self.assertNotIn("endpoint", theirs["peers"][0])

    def other_member(self, evidenced=True):
        """OTHER, a peer of the inviter, with evidence the inviter signed"""
        with open(self.inviter.path, "a") as fob:
            fob.write(f"      peers:\n      - public_key: {OTHER}\n"
                      "        endpoint: '[2001:db8:3::30]:51820'\n"
                      "        allowed_ips: [fd00:6b65:1::7/128]\n")
        if evidenced:
            signing.ensure(self.inviter_root)
            store = trust.load(self.inviter_root)
            trust.recorded(store, trust.admit(
                self.inviter_root, MESH, "1123456789abcdef", OTHER, SIGNER,
                "fd00:6b65:1::7", "[2001:db8:3::30]:51820", NOW))
            trust.save(self.inviter_root, store)

    def test_a_member_without_evidence_is_not_taken(self):
        self.other_member(evidenced=False)
        self.assertEqual(self.joining(), exits.OK, self.err)
        mine = spec_of(self.joiner)["network"]["overlay"]["wireguard"]
        self.assertEqual(len(mine["peers"]), 1)

    def test_the_inviter_is_this_node_s_trust_root(self):
        self.assertEqual(self.joining(), exits.OK, self.err)
        store = trust.load(self.joiner_root)
        self.assertTrue(store.members[INVITER].root)
        self.assertEqual(store.members[INVITER].sign_key,
                         signing.public(self.inviter_root))
        # and the inviter keeps this node's evidence
        evidence = trust.load(self.inviter_root).evidence(JOINER)
        self.assertEqual(evidence.sign_key, signing.public(self.joiner_root))
        self.assertEqual(evidence.invite_id, self.invite.invite_id)

    def test_evidence_that_is_not_this_node_s_admission(self):
        real = self.wire

        def forged(host, port, path, body, *args, **kwargs):
            reply = real(host, port, path, body, *args, **kwargs)
            if path != protocol.JOIN:
                return reply
            data = protocol.join_answer(reply.body)
            other = protocol.dumps(replace(data, admission=replace(
                data.admission, address="fd00:6b65:1::9")))
            return reply.__class__(other, reply.local, reply.peer)
        self.wire = forged
        self.assertEqual(self.joining(), exits.MESH_REFUSED)
        self.assertIn("no valid evidence of this node's admission",
                      self.err[-1])

    def test_a_damaged_trust_store(self):
        os.makedirs(os.path.join(self.joiner_root, "var/lib/keel/mesh"),
                    exist_ok=True)
        with open(os.path.join(self.joiner_root, trust.TRUST), "w") as fob:
            fob.write("x")
        self.assertEqual(self.joining(), exits.MESH_REFUSED)
        self.assertIn("damaged", self.err[-1])

    def test_no_signing_key_can_be_made(self):
        with mock.patch("keel.mesh.joining.signing.ensure",
                        side_effect=signing.SigningError("no openssl")):
            self.assertEqual(self.joining(), exits.APPLY_FAILED)
        self.assertEqual(self.err[-1], "no openssl")

    def test_the_other_members_the_inviter_knows_are_peers_too(self):
        self.other_member()
        self.assertEqual(self.joining(), exits.OK, self.err)
        mine = spec_of(self.joiner)["network"]["overlay"]["wireguard"]
        self.assertEqual(mine["peers"][1], {
            "public_key": OTHER, "endpoint": "[2001:db8:3::30]:51820",
            "allowed_ips": ["fd00:6b65:1::7/128"]})
        self.assertEqual(len(mine["peers"]), 2)
        self.assertIn("the mesh has 3 nodes", self.out[-1])
        self.assertIn("the inviter announces this node to the 1 other",
                      self.out[-1])

    def test_a_member_this_node_cannot_take_is_left_out(self):
        """its own key, or the inviter's again, even with evidence: never
        written, the join goes on (the rest: test_mesh_members.py)"""
        answer = (protocol.Peer(JOINER, None, "fd00:6b65:1::8"),
                  protocol.Peer(INVITER, None, "fd00:6b65:1::9"))
        signing.ensure(self.inviter_root)
        store = trust.load(self.inviter_root)
        for one in answer:
            trust.recorded(store, trust.admit(
                self.inviter_root, MESH, "1123456789abcdef",
                one.public_key, SIGNER,
                one.address, None, NOW))
        trust.save(self.inviter_root, store)
        with mock.patch.object(self.inviter, "peers", return_value=answer):
            self.assertEqual(self.joining(), exits.OK, self.err)
        mine = spec_of(self.joiner)["network"]["overlay"]["wireguard"]
        self.assertEqual([one["public_key"] for one in mine["peers"]],
                         [INVITER])

    def test_apply_s_revert_warning_only_when_the_confirmation_fails(self):
        """the join confirms itself: `unless keel network confirm` is not
        what the operator has to do"""
        self.joiner.apply = Saying()
        self.assertEqual(self.joining(), exits.OK, self.err)
        said = "\n".join(self.err)
        self.assertNotIn("unless `keel network confirm`", said)
        first = self.err.index("confirming over the overlay…")
        self.assertTrue(self.err[first + 1].startswith("confirmed from"))

    def test_apply_s_revert_warning_when_the_confirmation_fails(self):
        self.joiner.apply = Saying()
        self.joiner.probes = lambda: probes("wg0")
        self.assertEqual(self.joining(), exits.NETWORK_NOT_CONFIRMED)
        said = "\n".join(self.err)
        self.assertIn("confirming over the overlay…", said)
        self.assertIn("reverts in 120 s unless `keel network confirm`", said)

    def test_the_mesh_session_is_retried_while_the_tunnel_comes_up(self):
        calls = []
        real = self.wire

        def flaky(host, port, path, *args, **kwargs):
            calls.append(path)
            if path == protocol.CONFIRM and calls.count(path) < 3:
                raise joining.Unreachable("not yet")
            return real(host, port, path, *args, **kwargs)
        self.wire = flaky
        self.assertEqual(self.joining(), exits.OK, self.err)
        self.assertEqual(self.slept, [joining.RETRY, joining.RETRY])


class TestRefusedBeforeApplying(Case):
    def refused(self, code, words, **kwargs):
        found = self.joining(**kwargs)
        self.assertEqual(found, code, self.err)
        self.assertIn(words, "\n".join(self.err))
        self.assertEqual(self.joiner.apply.documents, [])
        self.assertFalse(os.path.exists(self.joiner.path))
        return found

    def test_no_route_to_the_inviter(self):
        self.refused(exits.MESH_REFUSED, "no route to the inviter",
                     route=None)
        self.assertIn("rendezvous point", self.err[0])

    def test_a_change_waiting(self):
        marker.save(self.joiner_root, "")
        marker.write(self.joiner_root, marker.Pending("eth0", "x", 120))
        self.refused(exits.MESH_REFUSED, "a network change waits")

    def test_another_mesh(self):
        identity.adopt(self.joiner_root, bytes(16))
        self.refused(exits.MESH_REFUSED, "in another mesh")

    def test_a_damaged_identity(self):
        os.makedirs(os.path.join(self.joiner_root, "var/lib/keel/mesh"))
        with open(os.path.join(self.joiner_root, identity.IDENTITY),
                  "w") as fob:
            fob.write("x\n")
        self.refused(exits.MESH_REFUSED, "does not hold a mesh identity")

    def test_a_refused_join_keeps_no_identity(self):
        """a spent token must not tie this node to its mesh"""
        invites.consume(self.inviter_root, self.invite.invite_id, NOW)
        self.joining()
        self.assertIsNone(identity.read(self.joiner_root))

    def test_a_spec_that_cannot_be_read(self):
        with open(self.joiner.path, "w") as fob:
            fob.write("version: [")
        self.assertEqual(self.joining(), exits.MESH_REFUSED)

    def test_a_spec_the_join_would_make_invalid(self):
        with open(self.joiner.path, "w") as fob:
            fob.write("version: 1\nnetwork:\n  interfaces:\n    eth0:\n"
                      "      ipv6: {method: static, address:"
                      " 'fd00:6b65:1::9/48'}\n")
        found = self.joining()
        self.assertEqual(found, exits.MESH_REFUSED)
        self.assertIn("once joined", self.err[0])

    def test_a_node_at_another_address(self):
        with open(self.joiner.path, "w") as fob:
            fob.write("version: 1\nnetwork:\n  overlay:\n    wireguard:\n"
                      "      address: fd00:6b65:1::9/64\n")
        self.assertEqual(self.joining(), exits.MESH_REFUSED)
        self.assertIn("a node joins a mesh once", self.err[0])

    def test_no_key(self):
        self.keys["generate"].return_value = "wg is not installed"
        self.refused(exits.APPLY_FAILED, "wg is not installed")

    def test_the_inviter_refuses(self):
        invites.consume(self.inviter_root, self.invite.invite_id, NOW)
        self.refused(exits.MESH_REFUSED, "the inviter refused the join:"
                     " invite")

    def test_another_certificate(self):
        self.wire.pinned = bytes(32)
        self.refused(exits.MESH_REFUSED, "another certificate")

    def test_an_answer_to_another_request(self):
        real = self.wire

        def other(host, port, path, body, *args, **kwargs):
            reply = real(host, port, path, body, *args, **kwargs)
            data = protocol.join_answer(reply.body)
            forged = protocol.dumps(protocol.JoinAnswer(
                **{**data.__dict__, "nonce": "ff" * 16}))
            return reply.__class__(forged, reply.local, reply.peer)
        self.wire = other
        self.refused(exits.MESH_REFUSED, "not the answer to this request")

    def test_a_malformed_answer(self):
        real = self.wire

        def broken(*args, **kwargs):
            reply = real(*args, **kwargs)
            return reply.__class__(b"{}", reply.local, reply.peer)
        self.wire = broken
        self.refused(exits.MESH_REFUSED, "answer is malformed")


class TestAfterTheAnswer(Case):
    def test_this_side_does_not_come_up(self):
        self.joiner.apply = Armed(code=16, arms=False)
        self.assertEqual(self.joining(), exits.APPLY_FAILED)
        self.assertIn("apply exited 16", self.err[-1])
        self.assertIn("the token is spent", self.err[-1])

    def test_a_spec_that_cannot_be_written(self):
        with mock.patch.object(self.joiner, "write",
                               side_effect=NodeError("cannot be written:"
                                                     " No space left")):
            self.assertEqual(self.joining(), exits.APPLY_FAILED)
        self.assertIn("cannot be written: No space left", self.err[-1])
        self.assertEqual(self.joiner.apply.documents, [])

    def test_the_inviter_never_answers_over_the_overlay(self):
        self.wire.unreachable.add(protocol.CONFIRM)
        clock = self.clock

        def later(seconds):
            clock.now += timedelta(seconds=seconds)
        self.slept = []
        found = joining.Joiner(
            self.joiner, token(self.invite), clock, self.out.append,
            self.err.append, post=self.wire, sleep=later,
            route_dev=lambda host: "eth0")
        self.assertEqual(joining.run(found, JOINER_ENDPOINT),
                         exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("did not answer over the overlay", self.err[-1])
        self.assertTrue(marker.exists(self.joiner_root))

    def test_the_inviter_does_not_keep_its_change(self):
        self.inviter.probes = lambda: probes("wg0")
        self.assertEqual(self.joining(), exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("the inviter did not keep its change", self.err[-1])
        self.assertTrue(marker.exists(self.joiner_root))

    def test_this_node_does_not_keep_its_own(self):
        self.joiner.probes = lambda: probes("wg0")
        self.assertEqual(self.joining(), exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("leaves through wg0", self.err[-1])

    def test_a_refused_mesh_session(self):
        real = self.wire

        def refuse(host, port, path, *args, **kwargs):
            if path == protocol.CONFIRM:
                raise joining.Refused("no")
            return real(host, port, path, *args, **kwargs)
        self.wire = refuse
        self.assertEqual(self.joining(), exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("the mesh session was refused: no", self.err[-1])

    def test_a_confirmation_of_another_session(self):
        real = self.wire

        def other(host, port, path, *args, **kwargs):
            reply = real(host, port, path, *args, **kwargs)
            if path != protocol.CONFIRM:
                return reply
            data = protocol.confirm_answer(reply.body)
            forged = protocol.dumps(protocol.ConfirmAnswer(
                **{**data.__dict__, "nonce": "ff" * 16}))
            return reply.__class__(forged, reply.local, reply.peer)
        self.wire = other
        self.assertEqual(self.joining(), exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("not the answer to this mesh session", self.err[-1])
        self.assertTrue(marker.exists(self.joiner_root))

    def test_a_malformed_confirmation(self):
        real = self.wire

        def broken(host, port, path, *args, **kwargs):
            reply = real(host, port, path, *args, **kwargs)
            if path == protocol.CONFIRM:
                return reply.__class__(b"[]", reply.local, reply.peer)
            return reply
        self.wire = broken
        self.assertEqual(self.joining(), exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("malformed", self.err[-1])


class TestFallback(Case):
    def setUp(self):
        super().setUp()
        self.wire.unreachable.add(protocol.JOIN)

    def accepted(self):
        """What accept leaves the inviter in: the peer applied, the
        listener waiting for the mesh session"""
        signing.ensure(self.inviter_root)
        self.inviter.admit({"public_key": JOINER,
                            "allowed_ips": [f"{JOINER_OVERLAY}/128"]})
        until = NOW + timedelta(seconds=120)
        self.admitter.joined = Joined(JOINER, JOINER_OVERLAY,
                                      marker.read(self.inviter_root), until)
        self.listener.joined = (JOINER, JOINER_OVERLAY, until)

    def test_the_line_for_the_inviter_and_the_wait(self):
        self.accepted()
        code = self.joining()
        self.assertEqual(code, exits.OK, self.err)
        line = self.out[0]
        self.assertTrue(line.startswith("keel mesh accept keel1a:"))
        sealed = acceptline.parse(line.split()[-1])
        self.assertTrue(sealed.authentic(hmac_key(token(
            self.invite).secret)))
        self.assertEqual(sealed.accept.endpoint, f"[{JOINER_ENDPOINT}]:51820")
        self.assertEqual(sealed.accept.address, ASSIGNED)
        self.assertIn("run the line above on the inviter within 15 minutes",
                      self.err[1])
        [(doc, window)] = self.joiner.apply.documents
        self.assertEqual(window, 900)
        self.assertEqual(self.out[-1], joining.TWO_NODES)
        # no answer carried the inviter's members: they are pulled
        self.assertEqual(self.learned, ["fd00:6b65:1::1"])
        self.assertIn("learning the other members from the inviter…",
                      self.err)

    def test_the_members_are_pulled_with_keel_mesh_sync(self):
        found = joining.Joiner(self.joiner, token(self.invite), self.clock,
                               self.out.append, self.err.append)
        with mock.patch("keel.mesh.joining.sync.pull",
                        return_value=exits.OK) as pulled:
            self.assertEqual(found.learned("fd00:6b65:1::1"), exits.OK)
        syncer, hosts = pulled.call_args.args
        self.assertEqual((syncer.node, hosts),
                         (self.joiner, ("fd00:6b65:1::1",)))

    def test_the_inviter_s_signing_key_is_learned_from_its_answer(self):
        self.accepted()
        self.assertEqual(self.joining(), exits.OK, self.err)
        found = trust.load(self.joiner_root).members[INVITER]
        self.assertEqual(found.sign_key, signing.public(self.inviter_root))

    def test_a_trust_store_that_cannot_take_the_inviter(self):
        self.accepted()
        os.makedirs(os.path.join(self.joiner_root, "var/lib/keel/mesh"),
                    exist_ok=True)
        with open(os.path.join(self.joiner_root, trust.TRUST), "w") as fob:
            fob.write("x")
        self.assertEqual(self.joining(), exits.NETWORK_NOT_CONFIRMED)
        self.assertIn("damaged", self.err[-1])
        self.assertEqual(self.learned, [])

    def test_nothing_is_pulled_when_the_join_is_not_confirmed(self):
        """the inviter never ran accept: the mesh session is refused"""
        self.assertEqual(self.joining(), exits.NETWORK_NOT_CONFIRMED)
        self.assertEqual(self.learned, [])

    def test_the_window_is_the_time_left_to_the_expiry(self):
        self.accepted()
        self.clock.now = NOW + timedelta(minutes=55)
        self.joining()
        self.assertEqual(self.joiner.apply.documents[0][1], 300)

    def test_too_close_to_the_expiry(self):
        self.clock.now = NOW + timedelta(minutes=59, seconds=40)
        self.assertEqual(self.joining(), exits.MESH_REFUSED)
        self.assertIn("too soon", self.err[-1])
        self.assertEqual(self.joiner.apply.documents, [])

    def test_both_behind_nat(self):
        self.assertEqual(self.joining(endpoint=None), exits.MESH_REFUSED)
        self.assertIn("neither node can reach the other", self.err[-1])
        self.assertEqual(self.joiner.apply.documents, [])

    def test_this_side_does_not_come_up(self):
        self.joiner.apply = Armed(code=16, arms=False)
        self.assertEqual(self.joining(), exits.APPLY_FAILED)
        self.assertEqual(self.out, [])


class TestOwnEndpoint(unittest.TestCase):
    def test_declared_first(self):
        self.assertEqual(joining.own_endpoint("2001:db8::5", {}, None),
                         "2001:db8::5")

    def test_static_then_found_on_the_uplink(self):
        doc = {"network": {"interfaces": {"eth0": {
            "ipv4": {"method": "static", "address": "192.0.2.5/24"}}}}}
        found = Choice(("2001:db8::9", "198.51.100.1"))
        self.assertEqual(joining.own_endpoint(None, doc, found),
                         "192.0.2.5")
        self.assertEqual(joining.own_endpoint(None, {}, found),
                         "2001:db8::9")
        self.assertIsNone(joining.own_endpoint(None, {}, Choice(())))
        self.assertIsNone(joining.own_endpoint(None, {}, None))

    def test_endpoint_text(self):
        self.assertEqual(joining.endpoint_text("192.0.2.1"), "192.0.2.1")
        self.assertEqual(joining.endpoint_text("2001:db8::1"),
                         "[2001:db8::1]")


class TestOwnKey(unittest.TestCase):
    def test_an_existing_key_is_read_not_made(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        os.makedirs(os.path.join(root, "etc/wireguard"))
        open(os.path.join(root, "etc/wireguard/wg0.key"), "w").close()
        with mock.patch("keel.mesh.joining.wgkeys") as keys:
            keys.public.return_value = (None, "unreadable")
            self.assertEqual(joining.own_key(root, {}), (None, "unreadable"))
            keys.generate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
