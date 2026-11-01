# Copyright (c) 2026 KeelLinux maintainers
"""A pair spec that cannot work is refused before apply changes anything

Decision 0049 derives the primary of a paired node from the pair record, so
`role: replica` with `appliance.vip` and no `replication.primary` is valid on
a node that holds the record. With no record, keel does not know where to
replicate from. Before keel#267, `keel spec validate` said ok, and apply
refused at the database step after the other steps ran.

The rules look at the record, so a running pair is not refused: an upgrade
must not break a running node (keel#266).
"""

import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from os.path import join
from unittest import mock

import yaml

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel import exits
from keel.cli import main
from keel.mesh import vippair
from keel.spec.validate_pair import pair_problems

VIP = "fd2a:9c41:7e03::ffff:1"
OWN = "fd2a:9c41:7e03::2"
PRIMARY = "fd2a:9c41:7e03::1"
REPLICA = {
    "version": 1,
    "network": {"overlay": {"wireguard": {
        "interface": "wg0", "address": f"{OWN}/64", "listen_port": 51820,
        "peers": []}}},
    "appliance": {"name": "core", "vip": VIP},
    "database": {"server": {"engine": "mariadb", "role": "replica",
                            "listen": [OWN, "::1"]}},
}


def replica(**server) -> dict:
    doc = copy.deepcopy(REPLICA)
    doc["database"]["server"].update(server)
    return doc


def from_host(host: str) -> dict:
    return {"replication": {"primary": {"host": host}}}


class TestPairProblems(unittest.TestCase):
    def only(self, doc: dict, fragment: str) -> None:
        found = pair_problems(doc, ())
        self.assertEqual(len(found), 1, found)
        self.assertIn(fragment, found[0])

    def test_a_replica_with_a_vip_no_record_and_no_primary_is_refused(self):
        found = pair_problems(replica(), ())
        self.assertEqual(len(found), 1, found)
        self.assertIn("database.server.replication.primary", found[0])
        self.assertIn(VIP, found[0])
        self.assertIn("keel vip pair", found[0])
        self.assertIn("overlay address", found[0])

    def test_the_pair_record_makes_the_primary_optional(self):
        self.assertEqual(pair_problems(replica(), (VIP,)), [])

    def test_a_declared_primary_needs_no_record(self):
        self.assertEqual(pair_problems(replica(**from_host(PRIMARY)), ()), [])

    def test_a_primary_with_no_record_is_valid(self):
        self.assertEqual(pair_problems(replica(role="primary"), ()), [])

    def test_a_spec_with_no_database_or_no_vip_has_no_pair_problem(self):
        self.assertEqual(pair_problems({"version": 1}, ()), [])
        doc = replica(**from_host(PRIMARY))
        del doc["appliance"]["vip"]
        self.assertEqual(pair_problems(doc, ()), [])

    def test_the_vip_is_not_where_a_replica_replicates_from(self):
        self.only(replica(**from_host(VIP)), "0029")

    def test_a_replica_does_not_replicate_from_itself(self):
        self.only(replica(**from_host(OWN)), "this node's own")

    def test_replicating_from_itself_is_refused_with_no_vip_too(self):
        doc = replica(**from_host(OWN))
        del doc["appliance"]["vip"]
        self.only(doc, "this node's own")

    def test_a_standalone_server_is_not_one_of_a_pair(self):
        self.only(replica(role="standalone"), "standalone")

    def test_a_vip_with_the_vip_overlay_disabled_is_refused(self):
        doc = replica(**from_host(PRIMARY))
        doc["overlays"] = {"vip": "disabled"}
        self.only(doc, "overlays.vip")

    def test_a_vip_with_the_wireguard_overlay_disabled_is_refused(self):
        doc = replica(**from_host(PRIMARY))
        doc["overlays"] = {"wireguard": "disabled"}
        self.only(doc, "overlays.wireguard")

    def test_a_node_with_a_record_is_not_refused_on_any_of_these(self):
        """A running pair works: the holder's claim decides the direction"""
        disabled = replica()
        disabled["overlays"] = {"vip": "disabled"}
        for doc in (replica(**from_host(VIP)), replica(role="standalone"),
                    disabled):
            self.assertEqual(pair_problems(doc, (VIP,)), [])

    def test_two_spellings_of_the_vip_are_one_vip(self):
        self.assertEqual(
            pair_problems(replica(), ("FD2A:9C41:7E03:0::FFFF:1",)), [])


class TestCommands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = join(self.tmp.name, "root")
        os.makedirs(self.root)
        # no manifests under this root: the rules of keel#267 are the matter
        for where in ("keel.commands", "keel.mesh.node"):
            patcher = mock.patch(f"{where}.manifest_facts", return_value=None)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.spec = join(self.tmp.name, "instance.yaml")
        self.conf = join(self.tmp.name, "inithooks.conf")

    def write(self, doc: dict) -> None:
        with open(self.spec, "w") as fob:
            yaml.safe_dump(doc, fob)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def keep_record(self, text: str = "") -> None:
        path = join(self.root, vippair.file_of(VIP))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fob:
            fob.write(text or json.dumps({"damaged": True}))

    def validate(self) -> tuple[int, str, str]:
        return self.run_cli("spec", "validate", "--no-secret-files",
                            "--spec", self.spec, "--root", self.root)

    def test_validate_refuses_with_a_clear_message(self):
        self.write(replica())
        code, _, err = self.validate()
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIn("database.server.replication.primary", err)
        self.assertIn("keel vip pair", err)

    def test_a_system_apply_refuses_and_changes_nothing(self):
        self.write(replica())
        before = sorted(os.walk(self.root))
        code, _, err = self.run_cli(
            "spec", "apply", "--system", "--spec", self.spec,
            "--conf", self.conf, "--root", self.root)
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIn("keel vip pair", err)
        self.assertEqual(sorted(os.walk(self.root)), before)
        self.assertFalse(os.path.exists(self.conf))

    def test_a_system_only_apply_refuses(self):
        self.write(replica())
        code, _, err = self.run_cli(
            "spec", "apply", "--system-only", "--spec", self.spec,
            "--root", self.root)
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIn("keel vip pair", err)

    def test_diff_refuses(self):
        self.write(replica())
        code, _, err = self.run_cli("diff", "--spec", self.spec,
                                    "--root", self.root)
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIn("keel vip pair", err)

    def test_the_conf_phase_is_not_refused(self):
        """A first boot reads the spec before any mesh exists: 00declarative
        must write the conf, or the application hooks write no site"""
        self.write(replica())
        code, out, err = self.run_cli(
            "spec", "apply", "--spec", self.spec, "--conf", self.conf,
            "--root", self.root)
        self.assertEqual(code, exits.OK, err)
        self.assertTrue(os.path.exists(self.conf))

    def test_a_damaged_record_is_a_record(self):
        """A node with a damaged record is a pair: the plan says what to do,
        and its other commands keep working"""
        self.write(replica())
        self.keep_record()
        code, _, err = self.validate()
        self.assertEqual(code, exits.OK, err)

    def test_mesh_commands_do_not_look_at_the_rule(self):
        """keel mesh join and keel mesh sync write a spec before the record
        exists: this rule must not stop them, or the pair never forms"""
        from keel.mesh.node import Node
        self.assertEqual(Node(self.root, self.spec).problems(replica()), [])


if __name__ == "__main__":
    unittest.main()
