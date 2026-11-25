# Copyright (c) 2026 KeelLinux maintainers
"""The enrolment of a computer on the access network (decision 0098)

The waiting enrolments on disk, the unprivileged listener's checks, the
root side's admission, the script for Linux and macOS (shellcheck, and
its proof against keel's), and keel access invite with the machine
replaced by fakes. No test opens a port or changes the machine.
"""

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)
from test_access_network import ACCESS, KEY_A, KEY_B

from keel import exits
from keel.access import enrol, invites, inviting
from keel.mesh.listener import Params

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)
SECRET = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3I"
NODE_KEY = KEY_B
# the new computer's key, not in ACCESS
KEY_D = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="


def invite(**fields) -> invites.Invite:
    base = dict(invite_id="0123456789abcdef", name="desk",
                address="fd12:3456:789a:1::9/128",
                expires=NOW + timedelta(minutes=15), port=50000,
                certificate="CERT", tls_key="KEY",
                hmac_key=invites.derive(SECRET), endpoint="2001:db8::1")
    return invites.Invite(**{**base, **fields})


class RootCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        owner = mock.patch("keel.access.invites.ROOT_UID", os.getuid())
        owner.start()
        self.addCleanup(owner.stop)


class TestInvites(RootCase):
    def test_saved_found_consumed_and_removed(self):
        invites.save(self.root, invite())
        found = invites.find(self.root, "0123456789abcdef", NOW)
        self.assertEqual(found, invite())
        self.assertNotIn(SECRET, repr(found))
        self.assertNotIn("KEY", repr(found))
        path = os.path.join(self.root, invites.DIR, "0123456789abcdef.json")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path) as fob:
            self.assertNotIn(SECRET, fob.read())
        self.assertEqual(invites.pending(self.root, NOW), [found])
        invites.consume(self.root, "0123456789abcdef")
        self.assertTrue(invites.find(self.root, "0123456789abcdef",
                                     NOW).consumed)
        invites.remove(self.root, "0123456789abcdef")
        self.assertIsNone(invites.find(self.root, "0123456789abcdef", NOW))
        invites.remove(self.root, "0123456789abcdef")

    def test_an_expired_or_damaged_or_odd_one_is_none(self):
        invites.save(self.root, invite())
        self.assertIsNone(invites.find(self.root, "0123456789abcdef",
                                       NOW + timedelta(minutes=16)))
        self.assertEqual(invites.pending(self.root, NOW), [])
        self.assertIsNone(invites.find(self.root, "../etc/passwd", NOW))
        os.makedirs(os.path.join(self.root, invites.DIR), exist_ok=True)
        with open(os.path.join(self.root, invites.DIR,
                               "fedcba9876543210.json"), "w") as fob:
            fob.write("{")
        self.assertIsNone(invites.find(self.root, "fedcba9876543210", NOW))
        self.assertEqual(invites.pending(self.root, NOW), [])

    def test_the_proof_is_keyed_by_the_secret(self):
        key = invites.derive(SECRET)
        self.assertEqual(key, hashlib.sha256(
            f"keel-access:{SECRET}".encode()).hexdigest().encode())
        found = invites.proof(key, KEY_A)
        self.assertEqual(found, hmac.new(key, KEY_A.encode(),
                                         hashlib.sha256).hexdigest())
        self.assertNotEqual(found, invites.proof(key, KEY_B))
        self.assertEqual(len(invites.new_id()), 16)
        self.assertGreaterEqual(len(invites.new_secret()), 43)


class Backend:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def forward(self, path, signature, body, local, peer):
        self.calls.append((path, body))
        return self.response


def params(**fields) -> Params:
    return Params(**{**dict(invite_id="0123456789abcdef",
                            expires=NOW + timedelta(minutes=15), host="::",
                            port=50000, overlay="", kind="access"),
                     **fields})


class TestListener(unittest.TestCase):
    def listener(self, response=None):
        self.backend = Backend(response or enrol.Response(200, b"{}",
                                                          final=True))
        self.said = []
        return enrol.AccessListener(params(), self.backend, lambda: NOW,
                                    self.said.append)

    def test_only_the_two_requests_of_this_enrolment_pass(self):
        found = self.listener()
        script = found.handle("GET", "/access/0123456789abcdef/enrol.sh",
                              None, None, "::1", "2001:db8::7")
        self.assertEqual(script.status, 200)
        for method, path, body in (
                ("GET", "/", None), ("POST", "/access/other", b"{}"),
                ("PUT", "/access/0123456789abcdef", b"{}"),
                ("POST", "/access/0123456789abcdef", None),
                ("POST", "/access/0123456789abcdef", b"x" * 2048)):
            self.assertGreaterEqual(found.handle(method, path, None, body,
                                                 "::1", "2001:db8::8")
                                    .status, 400)
        self.assertEqual(len(self.backend.calls), 1)
        self.assertTrue(found.blocked("2001:db8::8"))
        self.assertFalse(found.blocked("2001:db8::7"))

    def test_a_final_answer_ends_it_and_time_does(self):
        found = self.listener()
        self.assertEqual(found.name, "access enrolment 0123456789abcdef")
        self.assertFalse(found.finished)
        found.handle("POST", "/access/0123456789abcdef", None, b"{}", "::1",
                     "2001:db8::7")
        self.assertTrue(found.finished)
        later = enrol.AccessListener(params(expires=NOW), Backend(None),
                                     lambda: NOW, self.said.append)
        self.assertTrue(later.finished)


class FakeNode:
    def __init__(self, doc, code=exits.OK):
        self.doc = doc
        self.code = code
        self.written = None

    def document(self):
        return self.doc

    def change(self, doc, window=None):
        self.written = doc
        if self.code == exits.OK:
            self.doc = doc
        return mock.Mock(code=self.code, lines=())


def admitter(root, node, found=None) -> enrol.AccessAdmitter:
    invites.save(root, found or invite())
    return enrol.AccessAdmitter(
        root=root, invite=found or invite(), node=node,
        node_public=NODE_KEY, endpoint="2001:db8::1", pin="PIN=",
        clock=lambda: NOW, log=lambda line: None)


def body(public=KEY_D, proof=None) -> bytes:
    return json.dumps({"public_key": public, "proof": proof or
                       invites.proof(invites.derive(SECRET), public)}
                      ).encode()


class TestAdmitter(RootCase):
    def doc(self):
        return {"version": 1, "network": {"access": {**ACCESS}}}

    def test_the_script_names_the_node_and_no_secret(self):
        found = admitter(self.root, FakeNode(self.doc())).forward(
            "/access/0123456789abcdef/enrol.sh", None, None, "::1", "x")
        text = found.body.decode()
        self.assertEqual(found.status, 200)
        self.assertIn("url_host='[2001:db8::1]'", text)
        self.assertIn(f"node_key='{NODE_KEY}'", text)
        self.assertIn("node_address='fd12:3456:789a:1::1'", text)
        self.assertNotIn(SECRET, text)
        self.assertNotIn(invites.derive(SECRET).decode(), text)

    def test_a_good_proof_adds_the_computer_once(self):
        node = FakeNode(self.doc())
        found = admitter(self.root, node)
        answer = found.forward("/access/0123456789abcdef", None, body(),
                               "::1", "2001:db8::7")
        self.assertEqual(answer.status, 200, answer.body)
        self.assertTrue(answer.final)
        self.assertEqual(json.loads(answer.body)["address"],
                         "fd12:3456:789a:1::9/128")
        peers = node.written["network"]["access"]["peers"]
        self.assertEqual(peers[-1], {"name": "desk", "public_key": KEY_D,
                                     "address": "fd12:3456:789a:1::9/128",
                                     "enrolled": "2026-11-25"})
        again = found.forward("/access/0123456789abcdef", None, body(),
                              "::1", "2001:db8::7")
        self.assertEqual(again.status, 410)

    def test_a_non_ascii_proof_is_one_bad_proof(self):
        found = admitter(self.root, FakeNode(self.doc()))
        answer = found.forward("/access/0123456789abcdef", None,
                               body(proof="\u00e9" * 64), "::1", "x")
        self.assertEqual(answer.status, 403)
        self.assertFalse(answer.final)
        self.assertEqual(found.forged, 1)

    def test_a_bad_proof_is_refused_and_five_cancel_it(self):
        found = admitter(self.root, FakeNode(self.doc()))
        for _ in range(enrol.MAX_FORGED - 1):
            answer = found.forward("/access/0123456789abcdef", None,
                                   body(proof="0" * 64), "::1", "x")
            self.assertEqual(answer.status, 403)
            self.assertFalse(answer.final)
        answer = found.forward("/access/0123456789abcdef", None,
                               body(proof="0" * 64), "::1", "x")
        self.assertTrue(answer.final)
        self.assertIsNone(invites.find(self.root, "0123456789abcdef", NOW))

    def test_refusals_of_shape_key_and_apply(self):
        doc = self.doc()
        node = FakeNode(doc)
        found = admitter(self.root, node)
        for data, status in ((b"nonsense", 400), (body(public="short"), 400),
                             (json.dumps([1]).encode(), 400)):
            self.assertEqual(found.forward("/access/0123456789abcdef", None,
                                           data, "::1", "x").status, status)
        # the key of a computer already there
        taken = body(public=ACCESS["peers"][0]["public_key"])
        self.assertEqual(found.forward("/access/0123456789abcdef", None,
                                       taken, "::1", "x").status, 409)
        self.assertEqual(found.forward("/nowhere", None, body(), "::1",
                                       "x").status, 404)
        failing = admitter(self.root, FakeNode(self.doc(),
                                               exits.APPLY_FAILED))
        answer = failing.forward("/access/0123456789abcdef", None, body(),
                                 "::1", "x")
        self.assertEqual(answer.status, 500)
        self.assertTrue(answer.final)
        late = admitter(self.root, FakeNode(self.doc()),
                        invite(expires=NOW))
        self.assertEqual(late.forward("/access/0123456789abcdef", None,
                                      body(), "::1", "x").status, 410)


class TestScript(unittest.TestCase):
    def test_the_command_pins_the_key_and_keeps_the_secret_out_of_the_url(
            self):
        line = enrol.command("2001:db8::1", 50000, "PIN=",
                             "0123456789abcdef", SECRET)
        self.assertIn("--pinnedpubkey 'sha256//PIN='", line)
        self.assertIn(" -k ", line)
        self.assertIn("'https://[2001:db8::1]:50000/access/"
                      "0123456789abcdef/enrol.sh'", line)
        url = line.split("https://", 1)[1].split("'", 1)[0]
        self.assertNotIn(SECRET, url)
        # the secret reaches the script on its standard input, by the
        # shell's own printf: in no process's argv; the script runs only
        # once it is whole on disk
        self.assertIn(f"printf '%s\\n' '{SECRET}' | sudo sh \"$f\"", line)
        self.assertNotIn("sh -s --", line)
        self.assertIn(' -o "$f" ', line)
        self.assertTrue(line.startswith('f=$(mktemp) && curl '))
        named = enrol.command("node.example.org:51900", 50000, "PIN=",
                              "0123456789abcdef", SECRET)
        self.assertIn("'https://node.example.org:50000/access/", named)

    def test_the_interface_name_fits_wg_quick(self):
        self.assertEqual(enrol.client_interface("fd12:3456:789a:1::1/64"),
                         "ka-123456789a")

    def text(self) -> str:
        return enrol.script(endpoint="2001:db8::1", port=50000, pin="PIN=",
                            invite_id="0123456789abcdef", node_key=NODE_KEY,
                            access=ACCESS)

    def test_shellcheck_passes(self):
        if shutil.which("shellcheck") is None:
            if os.environ.get("CI"):
                self.fail("shellcheck is needed in CI")
            self.skipTest("no shellcheck")
        done = subprocess.run(["shellcheck", "-s", "sh", "-"],
                              input=self.text(), capture_output=True,
                              text=True)
        self.assertEqual(done.returncode, 0, done.stdout)

    def test_its_proof_is_keel_s(self):
        """The script's own lines for the key and the proof, run with
        the openssl here, give what keel checks"""
        if shutil.which("openssl") is None:
            self.skipTest("no openssl")
        text = self.text()
        start = text.index("# the proof: begin")
        end = text.index("# the proof: end")
        done = subprocess.run(
            ["sh", "-c", text[text.index("padded() {"):text.index(
                "main() {")] + text[start:end] + 'printf %s "$proof"',
             "sh"], capture_output=True, text=True,
            env={"PATH": os.environ["PATH"], "secret": SECRET, "pub": KEY_A})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, invites.proof(invites.derive(SECRET),
                                                    KEY_A))
        # no key on an argv: openssl gets data on its standard input only
        self.assertNotIn("-hmac", text)
        self.assertNotIn("hexkey", text)

    def test_a_cut_off_download_runs_nothing(self):
        text = self.text()
        self.assertIn("\nmain() {\n", text)
        self.assertEqual(text.rstrip().splitlines()[-1], 'main "$@"')
        self.assertIn("IFS= read -r secret", text)

    def test_a_name_endpoint_with_a_port(self):
        text = enrol.script(endpoint="node.example.org:51900", port=50000,
                            pin="PIN=", invite_id="0123456789abcdef",
                            node_key=NODE_KEY, access=ACCESS)
        self.assertIn("url_host='node.example.org'", text)
        self.assertIn("wg_endpoint='node.example.org:51900'", text)
        text = self.text()
        self.assertIn("url_host='[2001:db8::1]'", text)
        self.assertIn("wg_endpoint='[2001:db8::1]:51822'", text)


class TestEndpoint(unittest.TestCase):
    def test_an_ipv6_literal_or_a_name_with_an_optional_port(self):
        for text, wanted in (
                ("2001:db8::1", ("2001:db8::1", None)),
                ("[2001:db8::1]:51900", ("2001:db8::1", 51900)),
                ("Node.Example.org", ("node.example.org", None)),
                ("node.example.org:51900", ("node.example.org", 51900))):
            self.assertEqual(enrol.parse_endpoint(text), wanted, text)
        for text in ("", "192.0.2.1", "192.0.2.1:51820", "x;rm -rf",
                     "a..b", "[2001:db8::1]", "[2001:db8::1]:0",
                     "node:99999", "fe80::1", "::1", "-a.example.org",
                     "[nonsense]:1", "a" * 64 + ".org", "$(id)"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                enrol.parse_endpoint(text)


class TestInvite(RootCase):
    def setUp(self):
        super().setUp()
        self.said, self.ran = [], []
        self.node = FakeNode({"version": 1})

    def inviter(self, **fields):
        base = dict(root=self.root, node=self.node, clock=lambda: NOW,
                    run=self.fake_run, output=lambda argv: "set",
                    out=self.said.append, err=self.said.append,
                    endpoints=lambda: ["2001:db8::1"],
                    public_key=lambda access: (NODE_KEY, ""),
                    certificate=lambda: ("TLSKEY", "CERT"),
                    pin=lambda certificate: "PIN=",
                    random=lambda count: bytes(range(count)),
                    spec_path="/etc/keel/instance.yaml")
        return inviting.Inviter(**{**base, **fields})

    def fake_run(self, argv):
        self.ran.append(argv)
        return None

    def test_a_first_invite_makes_the_section_then_opens_the_port(self):
        code = inviting.invite(self.inviter(), "desk", None)
        self.assertEqual(code, exits.OK, self.said)
        access = self.node.written["network"]["access"]
        self.assertTrue(access["address"].startswith("fd00:102:304:"))
        self.assertTrue(access["address"].endswith("::1/64"))
        found = invites.pending(self.root, NOW)
        self.assertEqual([one.name for one in found], ["desk"])
        self.assertEqual(self.ran[0][:4], ("nft", "add", "element", "inet"))
        self.assertIn("access_invites", self.ran[0])
        self.assertEqual(self.ran[1][0], "systemd-run")
        self.assertIn("--unit=keel-access-invite@" + found[0].invite_id,
                      self.ran[1])
        line = self.said[-1]
        self.assertIn('| sudo sh "$f"', line)
        self.assertIn("https://[2001:db8::1]:", line)

    def test_refusals(self):
        self.assertEqual(inviting.invite(self.inviter(endpoints=lambda: []),
                                         "desk", None), exits.MESH_REFUSED)
        self.assertIn("no global IPv6", self.said[-1])
        self.assertEqual(inviting.invite(self.inviter(), "Bad Name", None),
                         exits.USAGE)
        self.node = FakeNode({"version": 1, "network": {"access": ACCESS}})
        self.assertEqual(inviting.invite(self.inviter(), "laptop", None),
                         exits.USAGE)
        self.assertIn("in use", self.said[-1])
        self.node = FakeNode({"version": 1}, exits.APPLY_FAILED)
        self.assertEqual(inviting.invite(self.inviter(), "desk", None),
                         exits.APPLY_FAILED)
        self.node = FakeNode({"version": 1, "network": {"access": ACCESS}})
        self.assertEqual(inviting.invite(self.inviter(
            public_key=lambda access: (None, "no key")), "desk", None),
            exits.APPLY_FAILED)

    def test_a_free_address_avoids_the_peers_and_the_waiting(self):
        used = {"fd12:3456:789a:1::2"}
        found = inviting.free_address(ACCESS, used, lambda count: bytes(
            [0] * 7 + [2]))
        self.assertIsNone(found)
        found = inviting.free_address(ACCESS, used, lambda count: bytes(
            [0] * 7 + [3]))
        self.assertEqual(found, "fd12:3456:789a:1::3/128")

    def test_the_waiting_list_and_cancel(self):
        invites.save(self.root, invite())
        lines = inviting.waiting(self.root, NOW)
        self.assertEqual(lines, ["0123456789abcdef\tdesk\t"
                                 "fd12:3456:789a:1::9/128\tuntil"
                                 " 2026-11-25T12:15:00Z\tTCP 50000"])
        code = inviting.cancel(self.inviter(), "0123456789abcdef")
        self.assertEqual(code, exits.OK)
        self.assertIn(("systemctl", "stop",
                       "keel-access-invite@0123456789abcdef"), self.ran)
        self.assertIsNone(invites.find(self.root, "0123456789abcdef", NOW))
        self.assertEqual(inviting.cancel(self.inviter(), "0123456789abcdef"),
                         exits.MESH_REFUSED)



class TestServe(TestInvite):
    def test_the_bridge_runs_with_the_access_listener_and_cleans_up(self):
        self.node = FakeNode({"version": 1, "network": {"access": ACCESS}})
        invites.save(self.root, invite())
        seen = {}

        class Bridge:
            def __init__(self, admitter, params, certificate, key, path,
                         start, log):
                seen.update(params=params, path=path, start=start)

            def run(self):
                seen["unit"] = seen["start"]("/run/x")

        with mock.patch("keel.mesh.bridge.Bridge", Bridge), \
                mock.patch("keel.mesh.bridge.start_unit",
                           return_value="unit") as started:
            code = inviting.serve(self.inviter(), "0123456789abcdef")
        self.assertEqual(code, exits.OK)
        self.assertEqual(seen["params"].kind, "access")
        self.assertIn("access-listen-0123456789abcdef", seen["path"])
        self.assertEqual(started.call_args.args[-1], "access")
        self.assertIsNone(invites.find(self.root, "0123456789abcdef", NOW))
        self.assertIn("access_invites", self.ran[-1])
        self.assertEqual(inviting.serve(self.inviter(), "0123456789abcdef"),
                         exits.MESH_REFUSED)

    def test_the_endpoint_of_the_invite_drives_serve(self):
        """--endpoint on a node with no IPv6 default route: serve uses
        the invite's endpoint, and asks the machine for none"""
        self.node = FakeNode({"version": 1, "network": {"access": ACCESS}})
        code = inviting.invite(self.inviter(endpoints=lambda: []), "desk",
                               "node.example.org:51900")
        self.assertEqual(code, exits.OK, self.said)
        found = invites.pending(self.root, NOW)[0]
        self.assertEqual(found.endpoint, "node.example.org:51900")
        seen = {}

        class Bridge:
            def __init__(self, admitter, *rest):
                seen["endpoint"] = admitter.endpoint

            def run(self):
                pass

        with mock.patch("keel.mesh.bridge.Bridge", Bridge):
            code = inviting.serve(self.inviter(endpoints=lambda: []),
                                  found.invite_id)
        self.assertEqual(code, exits.OK)
        self.assertEqual(seen["endpoint"], "node.example.org:51900")

    def test_a_bad_endpoint_is_refused_before_any_use(self):
        code = inviting.invite(self.inviter(), "desk", "192.0.2.1")
        self.assertEqual(code, exits.USAGE)
        self.assertIsNone(self.node.written)
        self.assertEqual(self.ran, [])

    def test_no_key_or_no_address_fails_and_cleans_up(self):
        invites.save(self.root, invite())
        code = inviting.serve(self.inviter(
            public_key=lambda access: (None, "no key")), "0123456789abcdef")
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIsNone(invites.find(self.root, "0123456789abcdef", NOW))


class TestBridgeKind(unittest.TestCase):
    def test_the_kind_goes_over_the_bridge_and_names_the_unit(self):
        from keel.mesh import bridge
        found = bridge.params_of(bridge.params_json(params()))
        self.assertEqual(found.kind, "access")
        self.assertEqual(bridge.unit("ab", "access"), "keel-access-listen@ab")
        self.assertEqual(bridge.unit("ab"), "keel-mesh-listen@ab")
        ran = []
        bridge.start_unit("ab", "/run/p", 60, lambda argv: ran.append(argv),
                          lambda argv: None, "access")
        self.assertIn("--unit=keel-access-listen@ab", ran[0])
        self.assertIn("--property=RuntimeDirectory=keel/access-listen-ab",
                      ran[0])

    def test_the_listener_of_an_access_kind_is_the_access_one(self):
        from keel.mesh import bridge
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        message = bridge.params_json(params()) + b"\n"
        with mock.patch("keel.mesh.bridge.capabilities", return_value=0), \
                mock.patch("builtins.open", mock.mock_open(read_data="")), \
                mock.patch("keel.mesh.bridge.helper", return_value=sock), \
                mock.patch("socket.recv_fds",
                           return_value=(message, [], 0, None)), \
                mock.patch("keel.mesh.bridge.context_from_paths"), \
                mock.patch("keel.mesh.bridge.bound"), \
                mock.patch("keel.mesh.bridge.run") as served:
            code = bridge.listen("/run/x", lambda: NOW, lambda line: None)
        self.assertEqual(code, exits.OK)
        self.assertIsInstance(served.call_args.args[1], enrol.AccessListener)


class TestCommands(RootCase):
    def args(self, **fields):
        import argparse
        return argparse.Namespace(**{**dict(
            root=self.root, spec="/s", name="desk", endpoint=None,
            invite="0123456789abcdef"), **fields})

    def test_each_command_checks_root_then_calls_its_flow(self):
        from keel.access import commands
        for name, flow in (("access_invite", "invite"),
                           ("access_serve", "serve"),
                           ("access_cancel", "cancel")):
            with self.subTest(name=name), \
                    mock.patch("keel.mesh.commands.as_root",
                               return_value=exits.APPLY_NEEDS_ROOT):
                self.assertEqual(getattr(commands, name)(self.args()),
                                 exits.APPLY_NEEDS_ROOT)
            with self.subTest(name=name), \
                    mock.patch("keel.mesh.commands.as_root",
                               return_value=exits.OK), \
                    mock.patch("keel.access.inviting.live"), \
                    mock.patch("signal.signal"), \
                    mock.patch(f"keel.access.inviting.{flow}",
                               return_value=7):
                self.assertEqual(getattr(commands, name)(self.args()), 7)
        with mock.patch("keel.mesh.commands.as_root",
                        return_value=exits.OK), \
                mock.patch("keel.access.inviting.live",
                           return_value=mock.Mock(root=self.root,
                                                  clock=lambda: NOW)):
            self.assertEqual(commands.access_invites(self.args()), exits.OK)
        with mock.patch("keel.mesh.commands.as_root",
                        return_value=exits.APPLY_NEEDS_ROOT):
            self.assertEqual(commands.access_invites(self.args()),
                             exits.APPLY_NEEDS_ROOT)

    def test_the_live_inviter_reads_the_machine(self):
        with mock.patch("keel.mesh.commands.live_node",
                        return_value=FakeNode({"version": 1})):
            found = inviting.live(self.args(), print, print)
        self.assertEqual(found.endpoints(), [])
        self.assertIsNone(found.public_key(ACCESS)[0])
        with mock.patch("keel.mesh.certificate.make",
                        return_value=("K", "C")):
            self.assertEqual(found.certificate(), ("K", "C"))

    def test_the_parser_has_the_four_commands(self):
        from keel.cli import build_parser
        found = build_parser().parse_args(["access", "invite", "--name",
                                           "desk"])
        self.assertEqual(found.handler, "keel.access.commands.access_invite")
        for words in (["serve", "x"], ["invites"], ["cancel", "x"]):
            self.assertTrue(build_parser().parse_args(["access", *words])
                            .handler.startswith("keel.access.commands."))

    def test_the_script_is_package_data(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "pyproject.toml")) as fob:
            text = fob.read()
        self.assertIn('"keel.access" = ["enrol.sh"]', text)
        self.assertIn('"keel.access"]', text)
        self.assertTrue(os.path.exists(enrol.SCRIPT_FILE))

    def test_the_pin_is_curl_s(self):
        if shutil.which("openssl") is None:
            self.skipTest("no openssl")
        from keel.mesh import certificate
        _, cert = certificate.make()
        found = enrol.spki_pin(cert)
        self.assertEqual(len(found), 44)
        self.assertTrue(found.endswith("="))



class TestSocketOfTheListener(unittest.TestCase):
    def test_the_enrolment_listener_is_keel_s_own(self):
        from keel.system.listeners import Listener, classify
        item = Listener("tcp", "::", None, 50000, (9,), ("python3",),
                        ("keel-access-listen@0123456789abcdef.service",))
        found = classify((item,), frozenset(), ssh=(22,), allow=frozenset(),
                         opened=frozenset(), overlay=None)
        self.assertEqual(found.undeclared, ())


if __name__ == "__main__":
    unittest.main()
