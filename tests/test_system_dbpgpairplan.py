# Copyright (c) 2026 KeelLinux maintainers
"""A paired PostgreSQL node (decision 0054): the twin of
tests/test_system_dbpair.py's plan sections — the four files, the
restart and the reload, the pinned peer, the slot and the role, and
the VIP's step"""

import os
import unittest
from dataclasses import replace

from helpers_database import postgresql_reading
from test_inspect_database import PG_STANDALONE, SOCKETS
from vip_helpers import KEYS, VIP, address

from keel.inspect import constants as paths
from keel.inspect.tree import File
from keel.mesh import etcdstate
from keel.system import dbpair, dbpgpairplan, dbpostgres, dbtls
from keel.system.actions import (
    EnsureDatabaseTls,
    FollowVip,
    Note,
    Refuse,
    Run,
    RunSql,
    WriteFile,
)
from keel.system.database import plan_database
from keel.system.dbpair import PairState
from keel.system.dbstate import Credential, DatabaseState

MACHINE_ID = "0123456789abcdef0123456789abcdef\n"
PASSWORD = "a-replication-password"
BINARY = "/usr/lib/postgresql/17/bin/postgres"
PG_DROPIN = "etc/postgresql/17/main/conf.d/99-keel-database.conf"
PG_PAIR = "etc/postgresql/17/main/conf.d/98-keel-pair.conf"
# the hba and ident files are not GUC: conf.d is swept as configuration
# (Debian's postgresql.conf includes it), so they live in the cluster's
# configuration directory, the way Debian keeps pg_hba.conf
PG_HBA = "etc/postgresql/17/main/keel-pg_hba.conf"
PG_IDENT = "etc/postgresql/17/main/keel-pg_ident.conf"
DOC = {
    "version": 1,
    "appliance": {"name": "core", "vip": VIP},
    "network": {"overlay": {"wireguard": {
        "address": f"{address(0)}/64",
        "peers": [{"public_key": KEYS[1],
                   "allowed_ips": [f"{address(1)}/128"]}]}}},
    "database": {"server": {"engine": "postgresql", "role": "primary",
                            "listen": [address(0), "::1"]}},
}
PAIR = PairState(VIP, KEYS[0], KEYS[1], address(1))
CLAIMED = PairState(VIP, KEYS[0], KEYS[1], address(1), "replica",
                    address(1))


def state(pair: PairState = PAIR, dropin: str | None = None,
          pair_dropin: str | None = None, hba: str | None = None,
          ident: str | None = None, nonlocal_bind: str = "0",
          credential_known: bool = True, binary: str = BINARY,
          enabled: str = "enabled") -> DatabaseState:
    return DatabaseState(
        engine="postgresql", live=True, binary=binary,
        reading=postgresql_reading(PG_STANDALONE, SOCKETS),
        schemas=File("schemas", "postgres\n"),
        machine_id=File("/etc/machine-id", MACHINE_ID),
        dropin=_file(PG_DROPIN, dropin),
        hba=_file(PG_HBA, hba),
        pair_dropin=_file(PG_PAIR, pair_dropin),
        ident=_file(PG_IDENT, ident),
        credential=Credential(value=PASSWORD) if credential_known
        else Credential(problem="not held here yet"),
        pair=pair, nonlocal_bind=File("sysctl", nonlocal_bind),
        enabled=enabled,
    )


def _file(path: str, text: str | None) -> File:
    if text is None:
        return File(path, problem="not present")
    return File(path, text)


def wanted_files(doc: dict, observed: DatabaseState) -> tuple[str, ...]:
    """The four files' texts, built the way the planner builds them"""
    server = doc["database"]["server"]
    pair = observed.pair
    overlay = dbpostgres.overlay_addresses(doc)
    allowed = dbpair.allowed_hosts(pair, server) or []
    cns = dbpgpairplan._certificate_names(allowed)
    hba_path = os.path.join(paths.ROOT_DEFAULT, observed.hba.path)
    ident_path = os.path.join(paths.ROOT_DEFAULT, observed.ident.path)
    bind = dbpair.bind_addresses(server.get("listen"), overlay, pair.vip)
    return (
        dbpostgres.dropin_text(bind, "primary", hba_path) + dbtls.dropin_lines(
            paths.ROOT_DEFAULT, "postgresql"),
        dbpostgres.pair_dropin_text(ident_path),
        dbpostgres.hba_text(allowed, PASSWORD, verify=True),
        dbpostgres.ident_text(cns),
    )


def only(step, kind) -> list:
    return [one for one in step.actions if isinstance(one, kind)]


class TestThePairPlan(unittest.TestCase):
    def test_the_four_files_and_the_restart(self):
        plan = plan_database(DOC, state(), False, "/spec.yaml")
        self.assertEqual(
            [step.field for step in plan],
            ["database.server",
             "database.server.replication.allowed_from",
             "database.server.role"])
        # the certificate first, in the drop-in's step: a certificate that
        # cannot be had skips the drop-in that would name it
        self.assertIsInstance(plan[0].actions[0], EnsureDatabaseTls)
        tls = only(plan[0], EnsureDatabaseTls)[0]
        self.assertEqual((tls.address, tls.vip, tls.peer, tls.spec),
                         (address(0), VIP, address(1), "/spec.yaml"))
        written = {one.path: one.content for one in only(plan[0], WriteFile)}
        self.assertEqual(
            sorted(written),
            sorted([dbpostgres.SYSCTL, PG_DROPIN, PG_PAIR, PG_HBA,
                    PG_IDENT]))
        self.assertIn("net.ipv6.ip_nonlocal_bind = 1",
                      written[dbpostgres.SYSCTL])
        dropin = written[PG_DROPIN]
        self.assertIn(f"listen_addresses = '{address(0)},::1,{VIP}'\n",
                      dropin)
        self.assertIn("hba_file = '/etc/postgresql/17/main/"
                      "keel-pg_hba.conf'\n", dropin)
        # both nodes are primary-capable, and the drop-in names the
        # certificate's files, so the server would not start without it;
        # postgresql.conf rejects an unquoted value starting with /, so
        # the paths are quoted the way hba_file is above
        self.assertIn("wal_level = replica\n", dropin)
        self.assertIn("ssl = on\n", dropin)
        self.assertIn("ssl_ca_file = '/etc/postgresql/keel-tls/ca.pem'\n",
                      dropin)
        pair_dropin = written[PG_PAIR]
        self.assertIn("synchronous_standby_names = 'FIRST 1 (keel)'\n",
                      pair_dropin)
        self.assertIn("synchronous_commit = on\n", pair_dropin)
        self.assertIn("wal_log_hints = on\n", pair_dropin)
        self.assertIn("ident_file = '/etc/postgresql/17/main/"
                      "keel-pg_ident.conf'\n", pair_dropin)
        hba = written[PG_HBA]
        # the peer's address comes bare (dbpair.allowed_hosts) and takes
        # the host mask: pg_hba.conf reads a bare token as a hostname,
        # and a host line with no IP mask stops the server at hba load.
        # The method is cert, not scram: pg refuses map= with a password
        # method, and the pair pins the certificate, not a password.
        # clientcert=verify-full is not there: it asks the client host's
        # name of a DNS the mesh has not; the map is the pinning
        self.assertIn("hostssl replication repl " + address(1)
                      + "/128 cert map=keel\n", hba)
        # the role also gets the server's own postgres database, for the
        # reach and seed probes; user data stays unreachable
        self.assertIn("hostssl postgres repl " + address(1)
                      + "/128 scram-sha-256\n", hba)
        ident = written[PG_IDENT]
        self.assertIn('keel "' + etcdstate.name(address(1))
                      + ' postgresql" repl\n', ident)
        runs = [one.argv for one in only(plan[0], Run)]
        self.assertIn(("sysctl", "-q", "-w",
                       "net.ipv6.ip_nonlocal_bind=1"), runs)
        self.assertIn(("systemctl", "restart", dbpostgres.boot_unit()), runs)

    def test_an_unchanged_node_restarts_nothing(self):
        dropin, pair_dropin, hba, ident = wanted_files(DOC, state())
        plan = plan_database(
            DOC, state(dropin=dropin, pair_dropin=pair_dropin, hba=hba,
                       ident=ident, nonlocal_bind="1"), False)
        self.assertEqual(
            [type(one) for one in plan[0].actions],
            [EnsureDatabaseTls, Note])

    def test_a_primary_that_commits_alone_is_not_drift(self):
        """After keel database promote --old-primary-gone the empty
        synchronous_standby_names is follow's runtime state (0054):
        apply neither writes the line back nor restarts the server"""
        dropin, pair_dropin, hba, ident = wanted_files(DOC, state())
        plan = plan_database(
            DOC, state(dropin=dropin,
                       pair_dropin=dbpostgres.alone_text(pair_dropin),
                       hba=hba, ident=ident, nonlocal_bind="1"), False)
        self.assertEqual(
            [type(one) for one in plan[0].actions],
            [EnsureDatabaseTls, Note])

    def test_an_hba_change_alone_reloads(self):
        dropin, pair_dropin, _, ident = wanted_files(DOC, state())
        plan = plan_database(
            DOC, state(dropin=dropin, pair_dropin=pair_dropin,
                       hba="stale\n", ident=ident, nonlocal_bind="1"),
            False)
        runs = [one.argv for one in only(plan[0], Run)]
        self.assertIn(("systemctl", "reload", dbpostgres.boot_unit()), runs)
        self.assertNotIn(("systemctl", "restart", dbpostgres.boot_unit()),
                         runs)
        written = [one.path for one in only(plan[0], WriteFile)]
        self.assertEqual(written, [PG_HBA])

    def test_a_pair_dropin_change_restarts(self):
        dropin, _, hba, ident = wanted_files(DOC, state())
        plan = plan_database(
            DOC, state(dropin=dropin, pair_dropin="stale\n", hba=hba,
                       ident=ident, nonlocal_bind="1"), False)
        runs = [one.argv for one in only(plan[0], Run)]
        self.assertIn(("systemctl", "restart", dbpostgres.boot_unit()), runs)
        self.assertNotIn(("systemctl", "reload", dbpostgres.boot_unit()),
                         runs)

    def test_a_pair_dropin_of_an_older_keel_is_rewritten_and_reloaded(self):
        """0.23.44 adds wal_keep_size, which the server takes on a
        reload: the upgrade never restarts a primary that serves clients
        (0054, amendment of 2026-10-18)"""
        dropin, _, hba, ident = wanted_files(DOC, state())
        ident_path = os.path.join(paths.ROOT_DEFAULT, state().ident.path)
        older = dbpostgres.pair_dropin_text(ident_path, legacy=True)
        self.assertNotIn("wal_keep_size", older)
        plan = plan_database(
            DOC, state(dropin=dropin, pair_dropin=older, hba=hba,
                       ident=ident, nonlocal_bind="1"), False)
        runs = [one.argv for one in only(plan[0], Run)]
        self.assertIn(("systemctl", "reload", dbpostgres.boot_unit()), runs)
        self.assertNotIn(("systemctl", "restart", dbpostgres.boot_unit()),
                         runs)
        written = {one.path: one.content
                   for one in only(plan[0], WriteFile)}
        self.assertEqual(list(written), [PG_PAIR])
        self.assertIn("wal_keep_size = 256MB\n", written[PG_PAIR])
        self.assertIn("synchronous_standby_names = 'FIRST 1", written[PG_PAIR])

    def test_an_older_pair_dropin_that_commits_alone_stays_alone(self):
        dropin, _, hba, ident = wanted_files(DOC, state())
        ident_path = os.path.join(paths.ROOT_DEFAULT, state().ident.path)
        older = dbpostgres.alone_text(
            dbpostgres.pair_dropin_text(ident_path, legacy=True))
        plan = plan_database(
            DOC, state(dropin=dropin, pair_dropin=older, hba=hba,
                       ident=ident, nonlocal_bind="1"), False)
        written = {one.path: one.content
                   for one in only(plan[0], WriteFile)}
        self.assertIn("wal_keep_size = 256MB\n", written[PG_PAIR])
        self.assertIn("synchronous_standby_names = ''", written[PG_PAIR])
        runs = [one.argv for one in only(plan[0], Run)]
        self.assertNotIn(("systemctl", "restart", dbpostgres.boot_unit()),
                         runs)

    def test_a_name_origin_gets_a_line_but_pins_no_certificate(self):
        doc = {
            **DOC,
            "database": {"server": {
                "engine": "postgresql", "role": "primary",
                "replication": {"allowed_from": ["db.example.org"]}}},
        }
        plan = plan_database(doc, state(), False)
        written = {one.path: one.content for one in only(plan[0], WriteFile)}
        self.assertIn("hostssl replication repl db.example.org"
                      " cert map=keel\n",
                      written[PG_HBA])
        self.assertIn("hostssl postgres repl db.example.org"
                      " scram-sha-256\n",
                      written[PG_HBA])
        self.assertNotIn('keel "', written[PG_IDENT])
        notes = "\n".join(one.summary for one in only(plan[0], Note))
        self.assertIn("db.example.org", notes)
        self.assertIn("pins no certificate", notes)

    def test_the_authorizations_send_the_slot_the_role_and_the_grants(self):
        plan = plan_database(DOC, state(), False)
        sent = only(plan[1], RunSql)
        self.assertEqual(len(sent), 3)
        self.assertIn("GRANT EXECUTE ON FUNCTION pg_catalog.pg_ls_dir",
                      sent[2].statements)
        self.assertEqual(sent[0].argv, dbpostgres.CLIENT)
        self.assertIn("pg_create_physical_replication_slot('keel')",
                      sent[0].statements)
        self.assertIn("CREATE ROLE repl", sent[1].statements)
        self.assertIn(PASSWORD.replace("'", "''"), sent[1].statements)

    def test_a_missing_credential_refuses_the_authorizations(self):
        plan = plan_database(DOC, state(credential_known=False), False)
        refused = only(plan[1], Refuse)
        self.assertEqual(len(refused), 1)
        self.assertIn("not held here yet", refused[0].summary)

    def test_the_role_step_follows_the_vip(self):
        plan = plan_database(DOC, state(), False, "/spec.yaml")
        followed = only(plan[2], FollowVip)
        self.assertEqual(len(followed), 1)
        self.assertEqual((followed[0].spec, followed[0].confirmed),
                         ("/spec.yaml", False))
        notes = "\n".join(one.summary for one in only(plan[2], Note))
        self.assertIn("no claim", notes)
        claimed = plan_database(DOC, state(pair=CLAIMED), False)
        notes = "\n".join(one.summary for one in only(claimed[2], Note))
        self.assertIn("replica here", notes)
        self.assertIn(address(1), notes)

    def test_a_disabled_server_is_enabled(self):
        plan = plan_database(DOC, state(enabled="disabled"), False)
        runs = [one.argv for one in only(plan[0], Run)]
        self.assertIn(("systemctl", "enable", dbpostgres.boot_unit()), runs)


class TestTheGates(unittest.TestCase):
    def test_no_pair_record(self):
        plan = plan_database(DOC, state(pair=PairState(VIP, KEYS[0], None,
                                                       None)), False)
        self.assertIn("keel vip pair", only(plan[0], Refuse)[0].summary)

    def test_no_peer_address(self):
        plan = plan_database(
            DOC, state(pair=PairState(VIP, KEYS[0], KEYS[1], None)), False)
        self.assertIn("routes no /128", only(plan[0], Refuse)[0].summary)

    def test_no_overlay_address(self):
        doc = {**DOC, "network": {"overlay": {"wireguard": {}}}}
        plan = plan_database(doc, state(), False)
        self.assertIn("no overlay address",
                      only(plan[0], Refuse)[0].summary)

    def test_no_cluster_installed(self):
        observed = replace(state(), hba=File("", problem="no cluster"))
        plan = plan_database(DOC, observed, False)
        self.assertIn("no PostgreSQL cluster",
                      only(plan[0], Refuse)[0].summary)

    def test_the_common_gate_comes_first(self):
        plan = plan_database(DOC, state(binary=""), False)
        self.assertIn("none is installed here",
                      only(plan[0], Refuse)[0].summary)


if __name__ == "__main__":
    unittest.main()
