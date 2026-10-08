# Copyright (c) 2026 KeelLinux maintainers
"""A paired MariaDB node (decisions 0020, 0031, 0049): the pair as the
planner sees it, the GTID comparison, the shared credential over the
members' channel, the database leaf the root signs, and the plan"""

import json
import os
import unittest
from datetime import timedelta
from unittest import mock

from helpers_database import mariadb_reading
from pki_clock import NOW as PKI_NOW
from test_inspect_database import MARIADB_STANDALONE, SOCKETS
from vip_helpers import KEYS, MESH, NOW, VIP, Pair, address

from keel.inspect.tree import File
from keel.mesh import etcd, etcdmsg, etcdpki, etcdstate, vipmsg, vipserve
from keel.mesh.etcdstate import StateError
from keel.mesh.memberlink import LinkError
from keel.mesh.vipnode import VipError
from keel.system import dbgtid, dbpair, dbsecret, dbtls
from keel.system import dbmariadb as mariadb
from keel.system.actions import (
    EnsureDatabaseTls,
    FollowVip,
    Note,
    Refuse,
    Run,
    RunSql,
    WriteFile,
)
from keel.system.database import plan_database, plan_promote
from keel.system.dbpair import PairState
from keel.system.dbstate import Credential, DatabaseState, credential


class TestGtid(unittest.TestCase):
    def test_a_state_is_parsed_by_domain_and_server(self):
        self.assertEqual(dbgtid.parse("0-1-5,0-2-7,1-1-3"),
                         {(0, 1): 5, (0, 2): 7, (1, 1): 3})
        self.assertEqual(dbgtid.parse(""), {})
        with self.assertRaises(ValueError):
            dbgtid.parse("0-1-5,junk")

    def test_nothing_errant_when_the_holder_has_it_all(self):
        self.assertEqual(dbgtid.errant("0-1-150", "0-1-150,0-2-200"), [])
        # the holder applied but never logged it: its slave position
        self.assertEqual(dbgtid.errant("0-1-100", "0-2-7", "0-1-100"), [])

    def test_a_higher_sequence_than_the_holder_knows_is_errant(self):
        found = dbgtid.errant("0-1-152,0-2-10", "0-1-150,0-2-200")
        self.assertEqual(found, ["0-1-152"])
        self.assertEqual(dbgtid.describe(found),
                         "domain 0, server id 1, up to sequence 152")
        # a server the holder never saw at all
        self.assertEqual(dbgtid.errant("0-9-1", "0-1-150"), ["0-9-1"])


def keyed(root: str) -> tuple[str | None, str | None]:
    """The WireGuard key of a test node, which has no key file: by the
    scratch root's name (tests/vip_helpers.py)"""
    for index in range(len(KEYS)):
        if f"/n{index}/" in root:
            return KEYS[index], None
    return None, "no key"


class TestThePair(Pair):
    def setUp(self):
        super().setUp()
        patcher = mock.patch("keel.system.dbpair.wgkeys.public",
                             side_effect=lambda path: keyed(path))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_node_without_a_vip_is_in_no_pair(self):
        self.nodes(vips=(None, None), paired=False)
        self.assertIsNone(dbpair.observe_pair(
            self.all[2].root, self.all[2].node.document()))

    def test_the_record_gives_the_other_member_and_its_address(self):
        self.nodes()
        here = self.all[0]
        found = dbpair.observe_pair(here.root, here.node.document())
        self.assertEqual((found.vip, found.peer_key, found.peer_address),
                         (VIP, KEYS[1], address(1)))
        self.assertIsNone(found.role)
        self.assertFalse(found.claimed)
        # the installation's role stands until a claim
        self.assertEqual(dbpair.role_of(found, "primary"), "primary")
        self.assertEqual(dbpair.primary_host(found, {}), address(1))
        self.assertEqual(dbpair.allowed_hosts(found, {}), [address(1)])
        self.assertEqual(dbpair.allowed_hosts(found, {"replication": {
            "allowed_from": ["fd00::9"]}}), ["fd00::9"])

    def test_without_a_record_the_other_member_is_unknown(self):
        self.nodes(paired=False)
        here = self.all[0]
        found = dbpair.observe_pair(here.root, here.node.document())
        self.assertIsNone(found.peer_key)
        self.assertIsNone(found.peer_address)
        self.assertIsNone(dbpair.primary_host(found, {}))

    def test_the_vip_decides_the_role_once_claimed(self):
        from keel.mesh import vippromote
        self.nodes()
        vippromote.promote(self.all[0], False, self.said[0].append)
        a = dbpair.observe_pair(self.all[0].root, self.all[0].node.document())
        b = dbpair.observe_pair(self.all[1].root, self.all[1].node.document())
        self.assertEqual((a.role, b.role), ("primary", "replica"))
        self.assertEqual(b.holder_address, address(0))
        self.assertEqual(dbpair.primary_host(b, {}), address(0))
        # the planned move: A released, and its own claim is still the
        # newest it knows until B's comes: the other member is the primary
        vippromote.promote(self.all[1], False, self.said[1].append)
        a = dbpair.observe_pair(self.all[0].root, self.all[0].node.document())
        self.assertEqual(a.role, "replica")
        self.assertEqual(a.holder_address, address(1))

    def test_the_bind_addresses_and_the_role_file(self):
        self.assertEqual(dbpair.bind_addresses(["fd00::1", "::1"], [], VIP),
                         ["fd00::1", "::1", VIP])
        self.assertEqual(dbpair.bind_addresses(None, ["fd00::1"], VIP),
                         ["fd00::1", "::1", "127.0.0.1", VIP])
        self.assertEqual(dbpair.role_text("replica", VIP),
                         f"role=replica\nreplicates=database\nvip={VIP}\n")


class TestTheSharedCredential(Pair):
    def test_the_primary_makes_it_and_the_other_member_asks_for_it(self):
        self.nodes()
        a, b = self.all[0], self.all[1]
        self.assertIsNone(dbsecret.read(b.root))
        with self.assertRaisesRegex(VipError, "no replication credential"):
            dbsecret.shared(b, VIP, False, address(0))
        made = dbsecret.shared(a, VIP, True, address(1))
        self.assertEqual(dbsecret.read(a.root), made)
        self.assertEqual(oct(os.stat(os.path.join(
            a.root, dbsecret.SECRET)).st_mode & 0o777), "0o600")
        self.assertEqual(dbsecret.shared(a, VIP, True, None), made)
        self.assertEqual(dbsecret.shared(b, VIP, False, address(0)), made)
        self.assertEqual(dbsecret.read(b.root), made)
        self.assertIn("secret given to", self.text(0))

    def test_only_the_other_member_of_the_pair_is_answered(self):
        self.nodes()
        dbsecret.generate(self.all[0].root)
        # C is a trusted member outside the pair
        with self.assertRaisesRegex(VipError, "did not answer"):
            dbsecret.ask(self.all[2], VIP, address(0))
        self.assertIn("not the other member", self.text(0))
        # a name nobody shares
        answer = vipserve.answer(self.all[0], vipmsg.signed(
            self.all[1].root, vipmsg.SECRET, MESH.hex(), KEYS[1], NOW,
            {"vip": VIP, "name": "root/password"}), KEYS[1])
        self.assertEqual(answer.status, 400)
        # a message that is stale
        answer = vipserve.answer(self.all[0], vipmsg.signed(
            self.all[1].root, vipmsg.SECRET, MESH.hex(), KEYS[1],
            NOW - timedelta(hours=2), {"vip": VIP, "name": dbsecret.NAME}),
            KEYS[1])
        self.assertEqual(answer.status, 403)

    def test_a_node_in_no_pair_knows_nobody_to_ask(self):
        self.nodes()
        with self.assertRaisesRegex(VipError, "knows no other member"):
            dbsecret.shared(self.all[1], VIP, False, None)

    def test_an_answer_that_is_no_credential_is_refused(self):
        self.nodes()
        here = self.all[1]
        here.exchange = lambda host, iface, body: b'{"value": 42}'
        with self.assertRaisesRegex(VipError, "no credential"):
            dbsecret.ask(here, VIP, address(0))
        here.exchange = lambda host, iface, body: b'not json'
        with self.assertRaisesRegex(VipError, "no credential"):
            dbsecret.ask(here, VIP, address(0))

    def test_the_credential_of_a_paired_node_comes_from_the_pair(self):
        self.nodes()
        a = self.all[0]
        pair = dbpair.observe_pair(a.root, a.node.document())
        server = {"role": "primary"}
        found = credential(server, a.root, pair, False, a.node.path)
        self.assertFalse(found.known)
        self.assertIn("not held here yet", found.problem)
        found = credential(server, a.root, pair, True, a.node.path)
        self.assertTrue(found.known)
        self.assertEqual(found.value, dbsecret.read(a.root))
        # a declared file wins
        path = os.path.join(a.root, "repl.secret")
        with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write("typed\n")
        found = credential({"role": "primary", "replication": {
            "secret": {"file": path}}}, a.root, pair, True, a.node.path)
        self.assertEqual(found.value, "typed")


class TestTheDatabaseLeaf(Pair):
    """The leaf the root signs, kind database (keel.system.dbtls)"""

    def member(self, index: int) -> etcd.Etcd:
        here = self.all[index]
        found = etcd.Etcd(here.node, lambda: PKI_NOW, self.said[index].append)
        found.exchange = self.etcd_exchanger(index)
        return found

    def etcd_exchanger(self, index: int):
        from keel.mesh import etcdserve

        def exchange(host: str, iface: str, body: bytes) -> bytes:
            if host in self.down:
                raise LinkError(f"[{host}]:51821 through {iface}: timed out")
            target = next(one for one in self.all
                          if one.overlay()["address"].startswith(host + "/"))
            answer = etcdserve.answer(self.member(self.all.index(target)),
                                      body, KEYS[index])
            if answer.status != 200:
                raise LinkError(f"[{host}]:51821 refused: {answer.body!r}")
            return answer.body
        return exchange

    def test_the_holder_signs_its_own_and_the_other_members_leaf(self):
        self.nodes(mode="cloud_simple")
        a, b = self.member(0), self.member(1)
        etcd.created(a)
        self.assertTrue(etcdstate.holds_root(a.root))
        self.assertIn("cloud simple pair", self.text(0))
        owned = []
        said = dbtls.ensure(a, address(0), VIP, address(1), KEYS[0],
                            owner=lambda d, k: owned.append(k))
        self.assertIn("signed by the mesh's root", said)
        self.assertTrue(dbtls.present(a.root))
        leaf = etcdpki.blocks(etcdstate.read(a.root, dbtls.CERT))[0]
        self.assertEqual(etcdpki.subject(leaf),
                         f"{etcdstate.name(address(0))} mariadb")
        self.assertEqual(etcdpki.addresses(leaf), (address(0), VIP))
        self.assertIn("TLS Web Server Authentication", etcdpki.text(leaf))
        self.assertFalse(etcdpki.is_ca(leaf))
        self.assertEqual(owned, [os.path.join(a.root, dbtls.KEY)])
        # the server reads the root and the certificate as the mysql user
        for relative in (dbtls.CA, dbtls.CERT):
            self.assertEqual(oct(os.stat(os.path.join(
                a.root, relative)).st_mode & 0o777), "0o644")
        # not due again
        self.assertIsNone(dbtls.ensure(a, address(0), VIP, address(1),
                                       KEYS[0], owner=lambda d, k: None))
        # B holds no root and knows no holder: it asks the other member,
        # with the pair's signed record, which binds the VIP SAN
        from keel.mesh import vippair
        record = vippair.read(b.root, VIP)
        with self.assertRaisesRegex(StateError, "needs the pair"):
            dbtls.ensure(b, address(1), VIP, address(0), KEYS[1],
                         owner=lambda d, k: None)
        said = dbtls.ensure(b, address(1), VIP, address(0), KEYS[1],
                            owner=lambda d, k: None, pair=record)
        self.assertIn("signed by the mesh's root", said)
        # the CRL came with it, for the server
        self.assertTrue(os.path.exists(os.path.join(b.root, dbtls.CRL)))
        self.assertIn("ssl_crl = ", dbtls.dropin_lines(b.root))
        self.assertEqual(dbtls.issuer_name(b.root), dbtls.issuer_name(a.root))
        self.assertTrue(dbtls.issuer_name(b.root).startswith("/CN=keel mesh"))
        self.assertEqual(dbtls.peer_subject(address(0)),
                         f"/CN={etcdstate.name(address(0))} mariadb")
        self.assertTrue(dbtls.present(b.root))
        self.assertTrue(dbtls.refresh_crl(b.root) in (True, False))
        self.assertEqual(etcdpki.fingerprint(etcdstate.read(b.root, dbtls.CA)),
                         etcdpki.fingerprint(etcdstate.read(
                             a.root, etcdstate.ROOT_CERT)))
        self.assertIn("database certificate for", self.text(0))
        summary = dbtls.summary(b.root)
        self.assertEqual(summary["addresses"], [address(1), VIP])
        self.assertIn("ssl_cert = ", dbtls.dropin_lines(b.root))
        self.assertIn("ssl-verify-server-cert", dbtls.options_lines(b.root))
        self.assertIn("MASTER_SSL_VERIFY_SERVER_CERT=1",
                      dbtls.master_options(b.root))
        self.assertEqual(dbtls.summary(self.all[2].root), {"present": False})

    def test_the_vip_san_is_bound_to_the_pair_s_signed_record(self):
        """A member outside the pair, or a record not signed by both
        members with keys the holder trusts, gets no certificate naming
        the VIP; its own address alone is signed"""
        from keel.mesh import vippair
        self.nodes()
        a, b, c = self.member(0), self.member(1), self.member(2)
        etcd.created(a)
        record = vippair.read(b.root, VIP)
        csr = etcdpki.request(etcdstate.key(c.root, dbtls.KEY))
        # C, outside the pair, with the pair's genuine record
        with self.assertRaisesRegex(StateError, "did not sign"):
            dbtls._asked(c, csr, address(2), VIP, KEYS[2], address(0),
                         record)
        self.assertIn("not ", self.text(0).split("refused")[-1][:200])
        # B with a record it made up: the VIP's, naming B, unsigned
        forged = vippair.made(record.mesh_id, VIP, (KEYS[1], KEYS[2]))
        csr_b = etcdpki.request(etcdstate.key(b.root, dbtls.KEY))
        with self.assertRaisesRegex(StateError, "did not sign"):
            dbtls._asked(b, csr_b, address(1), VIP, KEYS[1], address(0),
                         forged)
        self.assertIn("not signed by", self.text(0))
        # B with the record of another VIP
        other = vippair.made(record.mesh_id, "fd00:6b65:1::200",
                             (KEYS[0], KEYS[1]))
        with self.assertRaisesRegex(StateError, "did not sign"):
            dbtls._asked(b, csr_b, address(1), VIP, KEYS[1], address(0),
                         other)
        # no VIP asked: no record needed, the address alone
        grant = dbtls._asked(c, csr, address(2), None, KEYS[2], address(0))
        self.assertEqual(etcdpki.addresses(grant.certificate), (address(2),))

    def test_the_holder_signs_only_for_the_senders_own_address(self):
        self.nodes()
        a, c = self.member(0), self.member(2)
        etcd.created(a)
        csr = etcdpki.request(etcdstate.key(c.root, dbtls.KEY))
        # C asks for B's address
        with self.assertRaisesRegex(StateError, "did not sign"):
            dbtls._asked(c, csr, address(1), VIP, KEYS[2], address(0))
        self.assertIn("not the address this node knows", self.text(0))
        # C asks for its own, in another member's name
        with self.assertRaisesRegex(StateError, "did not sign"):
            dbtls._asked(c, csr, address(2), VIP, KEYS[1], address(0))
        # a node that is not the holder refuses to sign
        with self.assertRaisesRegex(StateError, "did not sign"):
            dbtls._asked(c, csr, address(2), VIP, KEYS[2], address(1))
        # nobody to ask
        with self.assertRaisesRegex(StateError, "knows neither"):
            dbtls._asked(c, csr, address(2), VIP, KEYS[2], None)
        # the holder gone
        self.down.add(address(0))
        with self.assertRaisesRegex(StateError, "did not sign"):
            dbtls._asked(c, csr, address(2), VIP, KEYS[2], address(0))

    def test_a_grant_for_another_key_or_name_is_refused(self):
        self.nodes()
        a = self.member(0)
        etcd.created(a)
        other = etcdstate.key(a.root, "var/lib/keel/other.key")
        csr = etcdpki.request(other)
        grant = etcdstate.database_grant(a.root, csr, address(0), VIP,
                                         KEYS[0])
        etcdstate.key(a.root, dbtls.KEY)
        self.assertIn("another key", dbtls._checked(a.root, grant,
                                                    address(0)))
        mine = etcdpki.request(os.path.join(a.root, dbtls.KEY))
        grant = etcdstate.database_grant(a.root, mine, address(1), VIP,
                                         KEYS[0])
        self.assertIn("does not name this node",
                      dbtls._checked(a.root, grant, address(0)))
        with self.assertRaisesRegex(StateError, "only the node"):
            etcdstate.database_grant(self.all[1].root, mine, address(1), VIP)
        self.assertTrue(dbtls.due(a.root, address(0), VIP, PKI_NOW))
        self.assertIsNone(dbtls.expires(a.root))

    def test_the_database_kind_in_the_message_needs_a_request(self):
        self.nodes()
        a = self.member(0)
        etcd.created(a)
        from keel.mesh import etcdserve
        answer = etcdserve.answer(a, etcdmsg.signed(
            self.all[1].root, etcdmsg.ISSUE, MESH.hex(), KEYS[1], PKI_NOW,
            {"kind": "database", "address": address(1),
             "public_key": KEYS[1]}), KEYS[1])
        self.assertEqual(answer.status, 400)
        self.assertIn(b"no request", answer.body)


MACHINE_ID = "0123456789abcdef0123456789abcdef\n"
DOC = {
    "version": 1,
    "appliance": {"name": "core", "vip": VIP},
    "network": {"overlay": {"wireguard": {
        "address": f"{address(0)}/64",
        "peers": [{"public_key": KEYS[1],
                   "allowed_ips": [f"{address(1)}/128"]}]}}},
    "database": {"server": {"engine": "mariadb", "role": "primary",
                            "listen": [address(0), "::1"]}},
}
PAIR = PairState(VIP, KEYS[0], KEYS[1], address(1))
CLAIMED = PairState(VIP, KEYS[0], KEYS[1], address(1), "replica",
                    address(1))


def paired_state(pair: PairState = PAIR, dropin: str | None = None,
                 nonlocal_bind: str = "0", credential_known: bool = True,
                 tls: bool = True, answered: dict | None = None,
                 revoked: str | None = None,
                 issuer: str = "/CN=keel mesh 0001020304050607 etcd root",
                 ) -> DatabaseState:
    return DatabaseState(
        engine="mariadb", live=True, binary="/usr/sbin/mariadbd",
        reading=mariadb_reading(answered or MARIADB_STANDALONE, SOCKETS),
        schemas=File("schemas", "information_schema\nmysql\n"),
        machine_id=File("/etc/machine-id", MACHINE_ID),
        dropin=File(mariadb.DROPIN, dropin) if dropin is not None
        else File(mariadb.DROPIN, problem="not found"),
        credential=Credential(value="pw") if credential_known
        else Credential(problem="not held here yet"),
        revoked=File("record", revoked) if revoked is not None
        else File("record", problem="not found"),
        pair=pair, nonlocal_bind=File("sysctl", nonlocal_bind),
        tls_ready=tls, tls_issuer=issuer,
    )


def only(step, kind) -> list:
    return [one for one in step.actions if isinstance(one, kind)]


class TestThePairPlan(unittest.TestCase):
    def test_the_same_configuration_on_both_nodes_and_the_role_follows(self):
        plan = plan_database(DOC, paired_state(), False, "/spec.yaml")
        fields = [step.field for step in plan]
        self.assertEqual(fields, ["database.server",
                                  "database.server.replication.allowed_from",
                                  "database.server.role"])
        # the certificate first, in the drop-in's step: a certificate that
        # cannot be had skips the drop-in that would name it
        self.assertIsInstance(plan[0].actions[0], EnsureDatabaseTls)
        tls = only(plan[0], EnsureDatabaseTls)[0]
        self.assertEqual((tls.address, tls.vip, tls.peer, tls.spec),
                         (address(0), VIP, address(1), "/spec.yaml"))
        written = only(plan[0], WriteFile)
        self.assertEqual([one.path for one in written],
                         [mariadb.SYSCTL, mariadb.DROPIN])
        self.assertIn("net.ipv6.ip_nonlocal_bind = 1", written[0].content)
        text = written[1].content
        for line in ("log_bin = mariadb-bin", "binlog_format = ROW",
                     "log_slave_updates = ON", "gtid_strict_mode = ON",
                     "rpl_semi_sync_master_enabled = ON",
                     "rpl_semi_sync_slave_enabled = ON",
                     "rpl_semi_sync_master_wait_point = AFTER_SYNC",
                     "rpl_semi_sync_master_timeout = 10000",
                     "rpl_semi_sync_master_wait_no_slave = OFF",
                     "slave_net_timeout = 10",
                     f"bind-address = {address(0)},::1,{VIP}",
                     "ssl_ca = ", "ssl_cert = ", "ssl_key = "):
            self.assertIn(line, text)
        self.assertNotIn("read_only", text)
        # MySQL's, not MariaDB's: 11.8 refuses to start with it (measured)
        self.assertNotIn("wait_for_slave_count", text)
        runs = [one.argv for one in only(plan[0], Run)]
        self.assertIn(("sysctl", "-q", "-w", "net.ipv6.ip_nonlocal_bind=1"),
                      runs)
        self.assertIn(("systemctl", "restart", "mariadb"), runs)
        grants = only(plan[1], RunSql)[0]
        # outside the binary log: a grant logged under the replica's
        # server id would stop it at the primary's next event (ER 1950)
        self.assertTrue(grants.statements.startswith(
            "SET SESSION sql_log_bin = 0;\n"), grants.statements)
        self.assertIn(f"'repl'@'{address(1)}' IDENTIFIED BY 'pw' REQUIRE"
                      f" SUBJECT '/CN={etcdstate.name(address(1))} mariadb'"
                      " AND ISSUER '/CN=keel mesh 0001020304050607 etcd"
                      " root'", grants.statements)
        self.assertIn("certificate /CN=", grants.summary)
        self.assertIn("outside the binary log", grants.summary)
        self.assertEqual(only(plan[2], FollowVip),
                         [FollowVip("/spec.yaml", False)])
        self.assertIn("declared role, primary, stands",
                      only(plan[2], Note)[0].summary)

    def test_an_unchanged_node_restarts_nothing_and_sets_no_sysctl(self):
        first = plan_database(DOC, paired_state(), False, "/s")
        text = only(first[0], WriteFile)[1].content
        plan = plan_database(DOC, paired_state(dropin=text,
                                               nonlocal_bind="1"), False,
                             "/s")
        self.assertEqual(only(plan[0], WriteFile), [])
        self.assertEqual(only(plan[0], Run), [])
        self.assertIn("a paired node", only(plan[0], Note)[0].summary)

    def test_the_role_note_names_the_vip_s_role_once_claimed(self):
        plan = plan_database(DOC, paired_state(CLAIMED), True, "/s")
        self.assertIn("the role is the VIP's: replica",
                      only(plan[2], Note)[0].summary)
        self.assertEqual(only(plan[2], FollowVip)[0].confirmed, True)

    def test_without_a_record_or_a_peer_address_nothing_is_touched(self):
        plan = plan_database(DOC, paired_state(PairState(VIP, KEYS[0])),
                             False, "/s")
        self.assertEqual(len(plan), 1)
        self.assertIn("keel vip pair", only(plan[0], Refuse)[0].summary)
        plan = plan_database(DOC, paired_state(PairState(
            VIP, KEYS[0], KEYS[1], None)), False, "/s")
        self.assertIn("routes no /128", only(plan[0], Refuse)[0].summary)
        plan = plan_database(DOC, paired_state(PairState(
            VIP, KEYS[0], problem="damaged")), False, "/s")
        self.assertIn("damaged", only(plan[0], Refuse)[0].summary)

    def test_no_credential_grants_nothing_but_the_rest_goes_on(self):
        plan = plan_database(DOC, paired_state(credential_known=False),
                             False, "/s")
        self.assertIn("not held here yet", only(plan[1], Refuse)[0].summary)
        self.assertTrue(only(plan[2], FollowVip))

    def test_a_promote_on_a_paired_node_follows_the_vip(self):
        plan = plan_promote(DOC, paired_state(CLAIMED), "/s")
        self.assertEqual(len(plan), 1)
        self.assertTrue(only(plan[0], FollowVip))
        self.assertIn("rejoins as a replica by itself",
                      only(plan[0], Note)[-1].summary)

    def test_no_mesh_identity_binds_no_authorization(self):
        plan = plan_database(DOC, paired_state(issuer=""), False, "/s")
        self.assertIn("root's name is not known",
                      only(plan[1], Refuse)[0].summary)

    def test_the_statements_and_files_of_a_pair(self):
        # both nodes boot read only; follow lifts it on the holder
        self.assertIn("read_only = ON", mariadb.role_dropin_text())
        # a withdrawal is outside the binary log too
        self.assertTrue(mariadb.revoke(["fd00::9"]).text.startswith(
            "SET SESSION sql_log_bin = 0;\n"))
        self.assertIsNone(mariadb.grants([], "pw"))
        self.assertIn("REQUIRE X509", mariadb.grants(["h"], "pw", x509=True)
                      .text)
        with mock.patch.dict(os.environ, {mariadb.SERVICE_ENV: "mariadb-x"}):
            self.assertEqual(mariadb.service(), "mariadb-x")
        self.assertEqual(mariadb.service(), "mariadb")
        found = mariadb.replicate_from("fd00::1", 3306, "pw", "0-1-5",
                                       ", MASTER_SSL=1")
        self.assertIn("MASTER_CONNECT_RETRY=2, MASTER_SSL=1;", found.text)
        self.assertIn("over TLS", found.summary)
        self.assertEqual(mariadb.CLIENT[:4], ("runuser", "-u", "mysql", "--"))

    def test_the_diff_and_inspect_lines_of_a_pair(self):
        from keel.diff import DRIFT, NOT_COMPARED, SAME, compare
        from keel.inspect.database import probe_database
        from keel.inspect.database import Installed
        from keel.inspect.dbengines import ENGINES
        from keel.inspect.report import Inspection
        from helpers_database import answers
        engine = next(one for one in ENGINES if one.name == "mariadb")
        answered = dict(
            MARIADB_STANDALONE,
            variables="log_bin\tON\nport\t3306\nserver_id\t7\nwsrep_on\tOFF\n"
            "read_only\tOFF\n",
            grants=f"{address(1)}\nlocalhost\n",
            semisync="Rpl_semi_sync_master_status\tOFF\n"
            "Rpl_semi_sync_slave_status\tOFF\nRpl_semi_sync_master_clients\t0\n"
            "Rpl_semi_sync_master_yes_tx\t12\nRpl_semi_sync_master_no_tx\t3\n",
            gtid="0-7-15\t\t0-7-15\t0-7-15\n")
        installed = Installed(engine, "/usr/sbin/mariadbd",
                              answers(engine, answered),
                              File("ss -lntH", SOCKETS))
        section, findings = probe_database((installed,), ())
        by_field = {one.field: one for one in findings}
        self.assertTrue(by_field["database.server.semi_sync"].value
                        .startswith("off (0 replica(s)"))
        self.assertIn("binlog_state 0-7-15",
                      by_field["database.server.gtid"].value)
        self.assertNotIn("database.server.replica_lag", by_field)
        self.assertNotIn("semi_sync", section)
        declared = {**DOC, "database": {"server": {
            "engine": "mariadb", "role": "replica", "listen": [address(0)],
            "replication": {"primary": {"host": address(1)}}}}}
        inspection = Inspection("/", "t", {"database": section},
                                tuple(findings), role="primary")
        fields = {one.field: one for one in compare(declared, inspection)
                  .fields}
        # the role is information on a paired node, read_only follows the
        # VIP's role, and the fallback is drift
        self.assertEqual(fields["database.server.role"].status, NOT_COMPARED)
        # the VIP bound beside the declared addresses is never drift
        listen = compare({**declared, "database": {"server": {
            **declared["database"]["server"],
            "listen": [address(0), "::1"]}}}, Inspection(
                "/", "t", {"database": {**section, "server": {
                    **section["server"],
                    "listen": ["::1", address(0), VIP]}}},
                tuple(findings), role="primary")).fields
        by_field = {one.field: one for one in listen}
        self.assertEqual(by_field["database.server.listen"].status, SAME)
        self.assertEqual(sorted(by_field["database.server.listen"].observed),
                         sorted(["::1", address(0)]))
        another = compare({**declared, "database": {"server": {
            **declared["database"]["server"],
            "listen": [address(0), "::1"]}}}, Inspection(
                "/", "t", {"database": {**section, "server": {
                    **section["server"],
                    "listen": ["::1", VIP]}}}, tuple(findings),
                role="primary")).fields
        self.assertEqual({one.field: one.status for one in another}
                         ["database.server.listen"], DRIFT)
        self.assertIn("runtime state", fields["database.server.role"].reason)
        self.assertEqual(fields["database.server.read_only"].status, SAME)
        self.assertEqual(fields["database.server.semi_sync"].status, DRIFT)
        self.assertIn("fell back", fields["database.server.semi_sync"].note)
        # on the replica, semi_sync is not compared; diverged is drift
        inspection = Inspection("/", "t", {"database": section},
                                tuple(findings), role="replica",
                                diverged={"errant": ["0-7-15"]})
        fields = {one.field: one for one in compare(declared, inspection)
                  .fields}
        self.assertEqual(fields["database.server.semi_sync"].status,
                         NOT_COMPARED)
        self.assertEqual(fields["database.server.diverged"].status, DRIFT)
        self.assertIn("0-7-15", fields["database.server.diverged"].note)
        # without a VIP nothing of this appears
        plain = {"database": declared["database"]}
        fields = {one.field for one in compare(
            plain, Inspection("/", "t", {"database": section},
                              tuple(findings))).fields}
        self.assertNotIn("database.server.semi_sync", fields)
        self.assertNotIn("database.server.diverged", fields)

    def test_the_replica_lag_and_an_unconfigured_semi_sync(self):
        from test_inspect_database import MARIADB_REPLICA_STATUS
        reading = mariadb_reading(dict(
            MARIADB_STANDALONE,
            status=MARIADB_REPLICA_STATUS + "        Seconds_Behind_Master: 3\n",
            semisync="", gtid="x\n"), SOCKETS)
        self.assertEqual(reading.lag.value, 3)
        self.assertIn("not configured", reading.semi_sync.problem)
        self.assertIn("no GTID positions", reading.gtid.problem)
        reading = mariadb_reading(dict(
            MARIADB_STANDALONE,
            status=MARIADB_REPLICA_STATUS +
            "        Seconds_Behind_Master: NULL\n"), SOCKETS)
        self.assertIn("not connected", reading.lag.problem)
        reading = mariadb_reading(dict(MARIADB_STANDALONE,
                                       status=MARIADB_REPLICA_STATUS), SOCKETS)
        self.assertIn("names no Seconds_Behind_Master", reading.lag.problem)


if __name__ == "__main__":
    unittest.main()
