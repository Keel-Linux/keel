# Copyright (c) 2026 KeelLinux maintainers
"""Anubis's signing key on a pair (decision 0041, Keel-Linux/common#56)

The key is shared: the primary makes it at its first start of Anubis,
and the other member of the pair asks for it over the members' channel,
as it asks for the replication credential (keel.system.dbsecret). Before,
nothing copied it, and anubis@keel did not start on a database replica.
"""

import os
import unittest
from unittest import mock

import yaml
from vip_helpers import KEYS, MESH, NOW, VIP, Pair, address

from keel.mesh import vipmsg, vipserve
from keel.mesh.vipnode import VipError
from keel.system import anubiskey

SAMPLE = "0f" * 32


def keyed(root: str) -> tuple[str | None, str | None]:
    """The WireGuard key of a test node, by its scratch root's name"""
    for index in range(len(KEYS)):
        if f"/n{index}/" in root:
            return KEYS[index], None
    return None, "no key"


def put_key(root: str, value: str = SAMPLE) -> str:
    path = os.path.join(root, anubiskey.KEY)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        fob.write(value + "\n")
    return path


class TestTheSharedKey(Pair):
    def setUp(self):
        super().setUp()
        patcher = mock.patch("keel.system.dbpair.wgkeys.public",
                             side_effect=lambda path: keyed(path))
        patcher.start()
        self.addCleanup(patcher.stop)

    def doc(self, index: int, role: str = "replica",
            anubis: str = "enabled", **extra) -> dict:
        found = self.all[index].node.document()
        found["overlays"] = {**(found.get("overlays") or {}),
                             "anubis": anubis}
        found["database"] = {"server": {"engine": "mariadb", "role": role}}
        found.update(extra)
        return found

    def observe(self, index: int, doc: dict, ask: bool = True):
        here = self.all[index]
        with mock.patch("keel.system.anubiskey.here_of",
                        return_value=here):
            return anubiskey.observe(here.root, doc, ask, here.node.path)

    def test_the_other_member_of_the_pair_gets_the_primary_s_key(self):
        self.nodes()
        put_key(self.all[0].root)
        self.assertEqual(anubiskey.ask(self.all[1], VIP, address(0)), SAMPLE)
        self.assertIn("signing_key secret given to", "\n".join(self.said[0]))

    def test_a_member_outside_the_pair_gets_nothing(self):
        self.nodes()
        put_key(self.all[0].root)
        with self.assertRaisesRegex(anubiskey.Later, "did not answer"):
            anubiskey.ask(self.all[2], VIP, address(0))
        self.assertIn("not the other member", "\n".join(self.said[0]))

    def test_a_holder_without_a_key_says_so(self):
        self.nodes()
        with self.assertRaisesRegex(anubiskey.Later,
                                    "holds no Anubis key yet"):
            anubiskey.ask(self.all[1], VIP, address(0))
        # a replica that boots before the primary made its key waits
        found = self.observe(1, self.doc(1))
        self.assertEqual((found.value, found.problem), (None, ""))
        self.assertIn("holds no Anubis key yet", found.waiting)
        self.assertIn("a later apply", found.waiting)

    def test_an_answer_that_is_no_key_is_refused(self):
        self.nodes()
        here = self.all[1]
        for body in (b'{"value": "short"}', b'{"value": 42}', b"not json"):
            here.exchange = lambda host, iface, data, body=body: body
            with self.assertRaisesRegex(VipError, "no Anubis key"):
                anubiskey.ask(here, VIP, address(0))

    def test_the_replication_credential_is_still_given_by_its_name(self):
        self.assertIn(anubiskey.NAME, vipmsg.SECRET_NAMES)
        self.assertIn("database/replication", vipmsg.SECRET_NAMES)

    def test_a_key_that_is_a_link_is_read_through_it(self):
        self.nodes()
        root = self.all[0].root
        target = os.path.join(root, "spec-key")
        with open(target, "w") as fob:
            fob.write(SAMPLE + "\n")
        path = os.path.join(root, anubiskey.KEY)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.symlink(target, path)
        self.assertEqual(anubiskey.read(root), SAMPLE)

    def test_a_file_that_is_no_key_is_none(self):
        self.nodes()
        put_key(self.all[0].root, "not a key")
        self.assertIsNone(anubiskey.read(self.all[0].root))
        answer = vipserve.answer(self.all[0], vipmsg.signed(
            self.all[1].root, vipmsg.SECRET, MESH.hex(), KEYS[1], NOW,
            {"vip": VIP, "name": anubiskey.NAME}), KEYS[1])
        self.assertEqual(answer.status, 404)

    def test_a_paired_replica_without_a_key_asks_the_other_member(self):
        self.nodes()
        put_key(self.all[0].root)
        found = self.observe(1, self.doc(1))
        self.assertEqual((found.value, found.problem, found.waiting),
                         (SAMPLE, "", ""))

    def test_a_run_that_changes_nothing_asks_nothing(self):
        self.nodes()
        put_key(self.all[0].root)
        found = self.observe(1, self.doc(1), ask=False)
        self.assertIsNone(found.value)
        self.assertIn("a run that may change the machine", found.waiting)
        self.assertEqual(self.said[0], [])

    def test_a_replica_in_no_pair_yet_waits(self):
        self.nodes(paired=False)
        found = self.observe(1, self.doc(1))
        self.assertIsNone(found.value)
        self.assertIn("keel vip pair", found.waiting)

    def test_an_unreachable_primary_is_waited_for(self):
        self.nodes()
        put_key(self.all[0].root)
        self.down.add(address(0))
        found = self.observe(1, self.doc(1))
        self.assertEqual((found.value, found.problem), (None, ""))
        self.assertIn("did not answer", found.waiting)

    def test_an_answer_that_is_no_key_is_the_problem(self):
        self.nodes()
        here = self.all[1]
        here.exchange = lambda host, iface, data: b'{"value": "short"}'
        with mock.patch("keel.system.anubiskey.here_of",
                        return_value=here):
            found = anubiskey.observe(here.root, self.doc(1), True,
                                      here.node.path)
        self.assertIn("answered no Anubis key", found.problem)

    def test_a_link_whose_target_is_gone_is_asked_and_marked(self):
        self.nodes()
        put_key(self.all[0].root)
        where = os.path.join(self.all[1].root, anubiskey.KEY)
        os.makedirs(os.path.dirname(where), exist_ok=True)
        os.symlink(os.path.join(self.all[1].root, "gone"), where)
        found = self.observe(1, self.doc(1))
        self.assertEqual((found.value, found.dangling), (SAMPLE, True))

    def test_nothing_is_asked_when_it_is_not_this_node_s_to_ask(self):
        self.nodes()
        put_key(self.all[0].root)
        # the key is there already
        put_key(self.all[1].root)
        self.assertIsNone(self.observe(1, self.doc(1)))
        os.remove(os.path.join(self.all[1].root, anubiskey.KEY))
        # the primary of the installation makes its own
        self.assertIsNone(self.observe(1, self.doc(1, role="primary")))
        # Anubis is not enabled
        self.assertIsNone(self.observe(1, self.doc(1, anubis="disabled")))
        # the spec names a file for the key
        self.assertIsNone(self.observe(1, self.doc(1, secrets={
            "anubis_signing_key": {"file": "/etc/keel/secrets/a"}})))
        self.assertEqual(self.said[0], [])

    def test_the_node_spec_on_disk_is_not_rewritten(self):
        self.nodes()
        put_key(self.all[0].root)
        before = open(self.all[1].node.path).read()
        self.observe(1, self.doc(1))
        self.assertEqual(open(self.all[1].node.path).read(), before)
        self.assertNotIn("anubis", yaml.safe_load(before).get(
            "overlays", {}))


if __name__ == "__main__":
    unittest.main()
