# Copyright (c) 2026 KeelLinux maintainers
"""The access relay's socket is keel's own, not a listen of the database
(keel#332)

keel's relay of decision 0098 (keel-access-relay-PORT.socket, held by
systemd) listens on the access address and the database's port. ss shows
it on that port, so database.server.listen counted it and keel diff gave
drift on a pair node. The observation now leaves out each socket a relay
unit of keel's declares. No test runs ss or changes the machine.
"""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel.diff.compare import LISTEN_FIELD, pair_listen
from keel.diff.report import DRIFT, SAME, FieldDiff
from keel.inspect import collect
from keel.inspect.dbreading import listening_on, without_listens
from keel.inspect.tree import File, Tree
from keel.network import access as acc

# the addresses of the real test (keel 0.23.105, test 8)
MESH = "fd85:172:dd97::c5e9"
ACCESS_ADDRESS = "fdea:b7eb:3ebf::1"
ACCESS = {"address": f"{ACCESS_ADDRESS}/64", "peers": []}
DOC = {"database": {"server": {"engine": "mariadb"}}}
SOCKETS = f"""\
LISTEN 0      80     127.0.0.1:3306  0.0.0.0:*
LISTEN 0      80         [::1]:3306     [::]:*
LISTEN 0      80     [{MESH}]:3306     [::]:*
LISTEN 0      4096   [{ACCESS_ADDRESS}]:3306     [::]:*
LISTEN 0      128    [{ACCESS_ADDRESS}]:22     [::]:*
LISTEN 0      128    *:3307     *:*
LISTEN 0      128    [{ACCESS_ADDRESS}]:*     [::]:*
LISTEN 0
"""
RELAY = (ACCESS_ADDRESS, 3306)


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def write(self, path: str, text: str) -> None:
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fob:
            fob.write(text)

    def write_relays(self) -> None:
        for path, text in acc.relay_files(ACCESS, DOC).items():
            self.write(path, text)


class TestRelayListens(TreeCase):
    def test_keel_s_relay_socket_names_its_address_and_port(self):
        self.write_relays()
        self.assertEqual(collect.relay_listens(Tree(self.root)),
                         frozenset({RELAY}))

    def test_a_line_that_is_not_a_socket_names_nothing(self):
        header = acc.HEADER[0]
        self.write(f"{acc.RELAY_DIR}/keel-access-relay-3306.socket",
                   f"{header}\n[Socket]\nListenStream=3306\n"
                   f"ListenStream=[{ACCESS_ADDRESS}]:x\nFreeBind=yes\n")
        self.assertEqual(collect.relay_listens(Tree(self.root)), frozenset())

    def test_no_relay_names_nothing(self):
        self.assertEqual(collect.relay_listens(Tree(self.root)), frozenset())

    def test_a_file_keel_did_not_write_is_not_keel_s(self):
        self.write(f"{acc.RELAY_DIR}/keel-access-relay-3306.socket",
                   f"[Socket]\nListenStream=[{ACCESS_ADDRESS}]:3306\n")
        self.assertEqual(collect.relay_listens(Tree(self.root)), frozenset())


class TestWithoutListens(unittest.TestCase):
    def test_the_relay_s_socket_is_left_out_and_nothing_else(self):
        found = without_listens(File("ss -lntH", SOCKETS),
                                frozenset({RELAY}))
        self.assertEqual(listening_on(found, 3306).value,
                         sorted(["127.0.0.1", "::1", MESH]))
        # the same address on another port stays, and lines that are not
        # an address and a port
        self.assertIn(f"[{ACCESS_ADDRESS}]:22", found.text)
        self.assertIn("*:3307", found.text)
        self.assertIn(f"[{ACCESS_ADDRESS}]:*", found.text)
        self.assertIn("LISTEN 0\n", found.text)

    def test_the_address_compares_in_canonical_form(self):
        long_form = "fdea:b7eb:3ebf:0:0:0:0:1"
        found = without_listens(File("ss -lntH", SOCKETS),
                                frozenset({(long_form, 3306)}))
        self.assertNotIn(f"[{ACCESS_ADDRESS}]:3306", found.text)

    def test_an_unreadable_output_or_no_relay_is_unchanged(self):
        unread = File("ss -lntH", problem="exited 1")
        self.assertIs(without_listens(unread, frozenset({RELAY})), unread)
        whole = File("ss -lntH", SOCKETS)
        self.assertIs(without_listens(whole, frozenset()), whole)


class TestDatabaseServers(TreeCase):
    def test_the_listen_of_a_pair_node_with_an_access_network(self):
        self.write_relays()
        self.write("usr/sbin/mariadbd", "")
        tree = Tree(self.root)
        with mock.patch.object(collect, "run_command",
                               side_effect=lambda tree, argv: File(
                                   " ".join(argv), SOCKETS)):
            (installed,) = [one for one in collect.database_servers(tree)
                            if one.engine.name == "mariadb"]
        self.assertEqual(listening_on(installed.sockets, 3306).value,
                         sorted(["127.0.0.1", "::1", MESH]))

    def test_keel_diff_finds_the_declared_listen_on_a_pair_node(self):
        """The line of the real test, with the relay left out: same"""
        observed = listening_on(
            without_listens(File("ss -lntH", SOCKETS), frozenset({RELAY})),
            3306).value
        declared = {"appliance": {"vip": "fd85:172:dd97::100"},
                    "network": {"overlay": {"wireguard": {
                        "address": f"{MESH}/64"}}},
                    "database": {"server": {
                        "listen": [MESH, "::1", "127.0.0.1"]}}}
        field = FieldDiff(LISTEN_FIELD, DRIFT,
                          declared=[MESH, "::1", "127.0.0.1"],
                          observed=observed)
        self.assertEqual(pair_listen([field], declared)[0].status, SAME)


if __name__ == "__main__":
    unittest.main()
