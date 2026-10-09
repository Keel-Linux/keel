# Copyright (c) 2026 KeelLinux maintainers
"""keel mesh across three network namespaces, with WireGuard and TLS

tests/mesh_netns.py, as root in a network namespace of its own
(tests/wgtools.py: `unshare -n` as root, `unshare -rn`, or `sudo -n
unshare -n`, which is what Ubuntu's CI runners allow), with the real
wg and wg-quick, which need the wireguard kernel module. Three nodes
joined by veths: B joins A through A's listener, C through the fallback
and `keel mesh accept`, both ping A over the overlay with no `keel
network confirm` typed, A announces C to B and C pulls B from A, so B
and C are peers and ping each other (a full mesh), the spent invite is
refused, no secret reaches
A's journal, and the listener that faced the network held no
capability. In CI a missing tool or namespace fails instead of
skipping.

Twice: on clean links, and on poor ones (POOR: 250 ms of delay with
25 ms of jitter, and 2% loss, on every veth, both ends; `tc` and the
sch_netem module), which Keel must work over.
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import unittest
from datetime import datetime, timezone

import wgtools

from keel import exits
from keel.mesh.token import parse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER = os.path.join(REPO, "tests", "mesh_netns.py")


def secret_forms(token: str) -> list[str]:
    secret = parse(token, datetime(2000, 1, 1, tzinfo=timezone.utc)).secret
    return [token, secret.hex(), base64.b64encode(secret).decode()[:40],
            base64.urlsafe_b64encode(secret).decode()[:40]]


POOR = "250ms 25ms 2%"


class TestThreeNamespaces(unittest.TestCase):
    netem = ""
    reports: dict = {}

    def setUp(self):
        tools = wgtools.require(self)
        if not os.path.exists("/sys/module/wireguard") and \
                not os.environ.get("CI"):
            self.skipTest("the wireguard kernel module is not loaded")
        if self.netem and not shutil.which("tc") and \
                not os.environ.get("CI"):
            self.skipTest("tc not found (iproute2)")
        if self.netem not in self.reports:
            self.reports[self.netem] = self.run_driver(tools)
        self.found = self.reports[self.netem]
        self.assertNotIn("error", self.found, self.found.get("error"))

    def run_driver(self, tools: str) -> dict:
        prefix = wgtools.namespace_prefix()
        if prefix is None:
            if os.environ.get("CI"):
                self.fail("no way to run wg-quick as root in a namespace")
            self.skipTest("neither root, user namespaces nor sudo -n")
        done = subprocess.run(
            prefix + ["env", f"PATH={tools}:{os.environ.get('PATH', '')}",
                      f"PYTHONPATH={REPO}", f"MESH_NETEM={self.netem}",
                      sys.executable, DRIVER],
            capture_output=True, text=True, check=False, timeout=600)
        for line in done.stdout.splitlines():
            if line.startswith("RESULT "):
                return json.loads(line[len("RESULT "):])
        self.fail(f"no result from {DRIVER}:\n{done.stdout[-3000:]}\n"
                  f"{done.stderr[-3000:]}")

    def test_b_joins_through_the_listener(self):
        b = self.found["b"]
        self.assertEqual(b["code"], exits.OK, b)
        self.assertTrue(b["ping"], b)
        self.assertEqual(b["outcome"], "confirmed")
        self.assertEqual(self.found["a_after_b"], "confirmed")
        self.assertEqual(self.found["serve"], [exits.OK])
        self.assertTrue(b["out"][-1].startswith("the mesh is up with 2"))
        self.assertIn("the overlay was tested", "\n".join(b["err"]))

    def test_c_joins_through_the_fallback(self):
        c = self.found["c"]
        self.assertEqual(self.found["accept"], exits.OK)
        self.assertEqual(c["code"], exits.OK, c)
        self.assertTrue(c["out"][0].startswith("keel mesh accept keel1a:"))
        self.assertTrue(c["ping"], c)
        self.assertEqual(c["outcome"], "confirmed")
        self.assertEqual(self.found["a_after_c"], "confirmed")
        # B through the listener, C through accept, with a keepalive
        self.assertEqual(self.found["peers"], [None, 25])
        self.assertEqual(self.found["invites_left"], [])

    def test_the_mesh_is_full(self):
        """C joined through A alone: A announced it to B, and C pulled B
        from A; B and C are each other's peers, confirmed, over the
        overlay (decision 0048, "Until etcd exists")"""
        b, c, checked = (self.found["b"], self.found["c"],
                         self.found["b_after_c"])
        self.assertIn(c["key"], checked["peers"], checked)
        self.assertEqual(checked["outcome"], "confirmed", checked)
        self.assertTrue(checked["ping"], checked)
        self.assertIn(b["key"], c["peers"], c)
        self.assertTrue(c["ping_other"], c)
        self.assertIn(f"announced {c['key']} to 1 of the 1 other member(s)",
                      "\n".join(self.found["journal"]))
        self.assertIn("an announcement from", "\n".join(checked["log"]))
        self.assertIn("learning the other members from the inviter…",
                      c["err"])

    def test_a_spent_invite_is_refused(self):
        code, said = self.found["again"]
        self.assertEqual(code, exits.MESH_REFUSED)
        self.assertIn("no pending invite", said[0])

    def test_the_listener_held_no_capability(self):
        # the two invites' listeners, and A's members' listener
        self.assertEqual(self.found["capabilities"],
                         ["0000000000000000"] * 3)
        self.assertEqual(self.found["netem"], self.netem.split())

    def test_no_secret_in_the_inviter_s_journal(self):
        journal = "\n".join(self.found["journal"])
        self.assertIn("joined and confirmed", journal)
        for token in self.found["tokens"]:
            for form in secret_forms(token):
                self.assertNotIn(form, journal)


class TestThreeNamespacesOnAPoorNetwork(TestThreeNamespaces):
    netem = POOR


if __name__ == "__main__":
    unittest.main()
