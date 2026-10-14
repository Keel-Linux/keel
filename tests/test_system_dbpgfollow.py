# Copyright (c) 2026 KeelLinux maintainers
"""A paired PostgreSQL node follows the VIP (decision 0054): the twin
of tests/test_system_dbfollow.py's table — the holder left alone or
promoted, the unproven claim stopped, the standby left alone or seeded,
and the one rejoin path, a confirmed reseed after a dump

The pair, the VIP's state and the spec are real (tests/vip_helpers.py);
PostgreSQL is a runner that answers as 17 did on the bench, so every
branch of the follow table runs without a server; the real run is
tests/postgres_netns.py.
"""

import json
import os
import subprocess
import unittest
from unittest import mock

from test_system_dbpgpairplan import CLAIMED, DOC, state
from vip_helpers import KEYS, VIP, Pair, address

from keel.mesh import vippromote
from keel.system import dbfollow, dbpair, dbpgfollow, dbpostgres, dbsecret, \
    dbtls
from keel.system.actions import FollowVip, PromoteReplica
from keel.system.database import plan_promote

PRIMARY_SPEC = {"engine": "postgresql", "role": "primary",
                "listen": [address(0), "::1"]}
REPLICA_SPEC = {"engine": "postgresql", "role": "replica",
                "listen": [address(1), "::1"]}
BINARY = "usr/lib/postgresql/17/bin/postgres"
DATADIR = "var/lib/postgresql/17/main"
FOLLOW_DROPIN = "etc/postgresql/17/main/conf.d/" + dbpostgres.FOLLOW_DROPIN_NAME
STANDBY_SIGNAL = DATADIR + "/" + dbpostgres.STANDBY_SIGNAL
SYSTEM_DATABASES = "postgres\ntemplate0\ntemplate1\n"
IDENTIFY_SYSTEM_ANSWER = "72377\t2\t0/4000098\n"


class Server:
    """subprocess.run as one PostgreSQL server answers it: recovery
    state, the walreceiver's conninfo, what it holds, its timeline, and
    what it was sent"""

    def __init__(self, in_recovery: bool = False, receiver: str = "",
                 standby: str = "\n",
                 hba: str = "local\t\t\nhost\t127.0.0.1\t255.255.255.255\n",
                 schemas: str = SYSTEM_DATABASES + "shop\n",
                 timeline: str = "00000002000000000000004A",
                 holder_timeline: str = "2", holder_down: bool = False,
                 positions: str = "t\t0/4000100\t0/4000098\n",
                 dump_fails: bool = False):
        self.row = ("t" if in_recovery else "f") + "\t0\t5432\n"
        self.receiver = receiver
        self.standby = standby
        self.hba = hba
        self.schemas = schemas
        self.timeline = timeline
        self.holder_timeline = holder_timeline
        self.holder_down = holder_down
        self.positions = positions
        self.dump_fails = dump_fails
        self.sent: list[str] = []
        self.argv: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.argv.append(argv)
        stdin = kwargs.get("input")
        if isinstance(stdin, bytes):
            stdin = stdin.decode()
        if stdin:
            self.sent.append(stdin)
        sql = ""
        for flag in ("-c", "--command"):
            if flag in argv:
                sql = argv[argv.index(flag) + 1]
        text = bool(kwargs.get("text"))
        if argv[:2] == ["ss", "-lntH"]:
            out = f"LISTEN 0 80 [{address(1)}]:5432 [::]:*\n"
            return subprocess.CompletedProcess(argv, 0, out, "")
        if "pg_dumpall" in argv:
            if self.dump_fails:
                return subprocess.CompletedProcess(argv, 2, b"", b"no room")
            kwargs["stdout"].write(b"-- dump\n")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if "zstd" in argv[0]:
            for one in argv[1:]:
                if os.path.isfile(one):
                    os.replace(one, one + ".zst")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        basebackup = next((one for one in argv
                           if one.startswith("--pgdata=")), None)
        if basebackup is not None:
            os.makedirs(basebackup.partition("=")[2], exist_ok=True)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        remote = any("passfile=" in one for one in argv)
        out = ""
        code = 0
        err = ""
        if remote:
            if self.holder_down:
                return subprocess.CompletedProcess(
                    argv, 1, "" if text else b"", "no route" if text
                    else b"no route")
            if sql == dbpgfollow.IDENTIFY_SYSTEM:
                out = f"72377\t{self.holder_timeline}\t0/4000098\n"
            else:
                # the seed's probe of the primary: not in recovery,
                # nothing of its own
                out = "f\t0\t100\n"
        elif "pg_last_wal_replay_lsn" in sql:
            out = self.positions
        elif "pg_is_in_recovery()" in sql:
            out = self.row
        elif "conninfo FROM pg_stat_wal_receiver" in sql:
            out = self.receiver
        elif "primary_conninfo" in sql:
            out = self.standby
        elif "pg_hba_file_rules" in sql:
            out = self.hba
        elif "datname FROM pg_database" in sql:
            out = self.schemas
        elif "pg_walfile_name" in sql:
            out = self.timeline + "\n"
        elif "pg_last_wal_replay_lsn" in sql:
            out = self.positions
        elif "status FROM pg_stat_wal_receiver" in sql:
            out = "streaming\n"
        if text:
            return subprocess.CompletedProcess(argv, code, out, err)
        return subprocess.CompletedProcess(argv, code, out.encode(),
                                           err.encode())


class FollowTestCase(Pair):
    def setUp(self):
        super().setUp()
        patcher = mock.patch("keel.system.dbpair.wgkeys.public",
                             side_effect=self.keyed)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("keel.inspect.collect.wgkeys.public",
                             side_effect=self.keyed)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def keyed(path: str):
        for index in range(len(KEYS)):
            if f"/n{index}/" in path:
                return KEYS[index], None
        return None, "no key"

    def pair_nodes(self, claim: int | None = 0,
                   mode: str = "cloud_advanced", etcd: str = "disabled"):
        """A and B paired, their specs declaring the database; A claims
        the VIP, and B's follow sees A as the holder"""
        self.nodes(mode=mode, etcd=etcd)
        layout = dbtls.LAYOUTS["postgresql"]
        for index, server in ((0, PRIMARY_SPEC), (1, REPLICA_SPEC)):
            here = self.all[index]
            doc = here.node.document()
            doc["database"] = {"server": dict(server)}
            here.node.write(doc)
            dbsecret.keep(here.root, "pw")
            binary = os.path.join(here.root, BINARY)
            os.makedirs(os.path.dirname(binary), exist_ok=True)
            with open(binary, "w"):
                pass
            for relative in ("var/tmp", "var/backups/keel",
                             DATADIR,
                             "etc/postgresql/17/main/conf.d"):
                os.makedirs(os.path.join(here.root, relative),
                            exist_ok=True)
            for name in (layout.ca, layout.cert, layout.key, layout.crl):
                target = os.path.join(here.root, name)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w") as fob:
                    fob.write("x")
        if claim is not None:
            vippromote.promote(self.all[claim], False,
                               self.said[claim].append)

    def follow(self, index: int, server: Server, confirmed: bool = False,
               wait: float = 0.0) -> dbfollow.Followed:
        here = self.all[index]
        found = dbfollow.Followed()
        with mock.patch("keel.inspect.constants.ROOT_DEFAULT", here.root), \
                mock.patch("keel.inspect.collect.paths.ROOT_DEFAULT",
                           here.root), \
                mock.patch("keel.system.dbstate.paths.ROOT_DEFAULT",
                           here.root), \
                mock.patch("keel.inspect.collect.subprocess.run", server), \
                mock.patch("keel.system.dbready.ready", return_value=""), \
                mock.patch("keel.system.dbready.enabled",
                           return_value="enabled"), \
                mock.patch("keel.system.dbseed.subprocess.run", server), \
                mock.patch.object(self.all[index].node, "overlay",
                                  wraps=self.all[index].node.overlay):
            dbfollow.follow(here.root, here.node.path, confirmed, found,
                            runner=server, output=self.nets[index].output,
                            wait=wait, sleep=self.sleep)
        return found

    def role_file(self, index: int) -> str:
        try:
            with open(os.path.join(self.all[index].root,
                                   dbpair.ROLE_FILE)) as fob:
                return fob.read()
        except FileNotFoundError:
            return ""

    def ran(self, server: Server, word: str) -> bool:
        return any(word in one for argv in server.argv for one in argv)


class TestThePrimary(FollowTestCase):
    def test_a_writable_server_that_holds_the_vip_is_left_alone(self):
        self.pair_nodes()
        server = Server()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("unchanged (the primary, writable)", found.lines)
        self.assertIn("role=primary", self.role_file(0))
        self.assertFalse(self.ran(server, "pg_basebackup"))
        self.assertFalse(any(one[:2] == ["systemctl", "stop"]
                             for one in server.argv))

    def test_a_standby_holder_is_drained_and_promoted(self):
        self.pair_nodes()
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver)
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("drained and promoted", " ".join(found.lines))
        self.assertTrue(any("pg_promote()" in one for one in server.sent))
        self.assertIn("role=primary", self.role_file(0))

    def test_an_unproven_primary_is_stopped(self):
        """keel#104, the PostgreSQL row: pg cannot be read only while
        it runs, so an unproven claim is enforced by stopping the
        server; a stopped server takes no writes and the stop is
        reversed by the next follow once the VIP is proven"""
        self.pair_nodes(claim=None)
        server = Server()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(["systemctl", "stop", dbpostgres.service()],
                      server.argv)
        self.assertIn("stopped", " ".join(found.lines))
        self.assertNotIn("role=primary", self.role_file(0))

    def test_an_unproven_standby_is_left_to_recover(self):
        """In recovery it refuses writes on its own: the unproven row
        stops nothing, it says so"""
        self.pair_nodes()
        self.nets[0].addresses.clear()
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver)
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("in recovery", " ".join(found.lines))
        self.assertFalse(any(one[:2] == ["systemctl", "stop"]
                             for one in server.argv))
        self.assertNotIn("role=primary", self.role_file(0))


class TestTheReplica(FollowTestCase):
    def test_a_standby_of_the_holder_is_left_alone(self):
        self.pair_nodes()
        receiver = f"user=repl host={address(0)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        found = self.follow(1, Server(in_recovery=True, receiver=receiver))
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(f"unchanged (a standby of [{address(0)}]:5432)",
                      found.lines)
        self.assertIn("role=replica", self.role_file(1))

    def test_a_fresh_server_is_seeded(self):
        """Nothing of its own on disk: seeded from the holder without
        the confirmation, made a standby by the signal and the slot"""
        self.pair_nodes()
        server = Server(schemas=SYSTEM_DATABASES)
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        joined = "\n".join(found.lines)
        self.assertIn(f"seeded from [{address(0)}]:5432", joined)
        self.assertIn("streaming from it over TLS", joined)
        self.assertTrue(self.ran(server, "pg_basebackup"))
        self.assertTrue(os.path.exists(os.path.join(
            self.all[1].root, STANDBY_SIGNAL)))
        with open(os.path.join(self.all[1].root, FOLLOW_DROPIN)) as fob:
            dropin = fob.read()
        self.assertIn(f"host={address(0)}", dropin)
        self.assertIn(f"primary_slot_name = '{dbpostgres.SLOT}'", dropin)
        self.assertIn("role=replica", self.role_file(1))

    def test_an_old_primary_stays_unconnected_and_alerts(self):
        """0054's one rejoin path: it holds data, so it is dumped, the
        divergence is recorded and it is not connected until the
        operator confirms the reseed"""
        self.pair_nodes()
        server = Server(timeline="00000003000000000000004A",
                        holder_timeline="2")
        with mock.patch("keel.monitor.alerting.alert",
                        return_value=True) as alerted:
            found = self.follow(1, server)
        self.assertIn("diverged", found.problem)
        self.assertIn("00000003", found.problem)
        self.assertFalse(self.ran(server, "pg_basebackup"))
        kept = os.listdir(os.path.join(self.all[1].root,
                                       dbpgfollow.BACKUPS))
        self.assertTrue(kept[0].startswith("rejoin-"), kept)
        self.assertTrue(kept[0].endswith(".zst"), kept)
        recorded = dbfollow.diverged(self.all[1].root)
        self.assertEqual(recorded["own_timeline"], "00000003")
        self.assertEqual(recorded["holder_timeline"], "2")
        self.assertEqual(recorded["holder"], address(0))
        self.assertEqual(alerted.call_count, 1)
        self.assertIn("stays read only", alerted.call_args.args[2])
        # a second run alerts no more, and nothing is seeded either
        with mock.patch("keel.monitor.alerting.alert") as alerted:
            found = self.follow(1, server)
        alerted.assert_not_called()
        self.assertIn("diverged", found.problem)
        self.assertEqual(self.ran(server, "pg_basebackup"), False)

    def test_confirmed_the_old_primary_is_reseeded_after_a_dump(self):
        self.pair_nodes()
        server = Server(timeline="00000003000000000000004A",
                        holder_timeline="2")
        found = self.follow(1, server, confirmed=True)
        self.assertIsNone(found.problem, found.lines)
        joined = "\n".join(found.lines)
        self.assertIn("a dump of what this node holds is kept at", joined)
        self.assertIn("confirmed with --destroy-local-database", joined)
        self.assertIn("seeded from", joined)
        self.assertTrue(self.ran(server, "pg_basebackup"))
        self.assertIsNone(dbfollow.diverged(self.all[1].root))

    def test_a_dump_that_cannot_be_kept_stops_the_rejoin(self):
        self.pair_nodes()
        server = Server(dump_fails=True)
        found = self.follow(1, server)
        self.assertIn("not kept", found.problem)
        self.assertFalse(self.ran(server, "pg_basebackup"))

    def test_a_holder_that_does_not_answer_changes_nothing(self):
        self.pair_nodes()
        server = Server(holder_down=True)
        found = self.follow(1, server)
        self.assertIn("did not answer its timeline", found.problem)
        self.assertIn("nothing was changed", found.problem)
        self.assertFalse(self.ran(server, "pg_dumpall"))
        self.assertFalse(self.ran(server, "pg_basebackup"))

    def test_the_seed_and_the_timeline_ask_carry_the_pair_tls(self):
        """The replication protocol's line is the cert method: a copy
        or a timeline ask that presents no certificate is refused by
        the primary (found by the pair's network-namespace test of
        this release)"""
        self.pair_nodes()
        server = Server(timeline="00000003000000000000004A")
        found = self.follow(1, server, confirmed=True)
        self.assertIsNone(found.problem, found.lines)
        asked = "\n".join(one for argv in server.argv for one in argv)
        self.assertIn("sslmode=verify-full", asked)
        self.assertIn("sslcert=", asked)
        timeline = next(" ".join(argv) for argv in server.argv
                        if "IDENTIFY_SYSTEM" in argv)
        self.assertIn("sslmode=verify-full", timeline)
        self.assertIn("replication=database", timeline)

    def test_without_the_certificate_nothing_follows(self):
        self.pair_nodes()
        layout = dbtls.LAYOUTS["postgresql"]
        os.remove(os.path.join(self.all[1].root, layout.key))
        found = self.follow(1, Server(schemas=SYSTEM_DATABASES))
        self.assertIn("certificate is not in place", found.problem)

    def test_a_node_in_no_pair_says_so(self):
        self.nodes(vips=(None, None), paired=False)
        found = self.follow(2, Server())
        self.assertIn("declares no appliance.vip", found.problem)


class TestPromotion(unittest.TestCase):
    """On a pair the VIP decides the role for PostgreSQL too (the
    CONVERGED gate widened with 0054)"""

    def test_the_vip_decides_the_role_for_postgresql_too(self):
        plan = plan_promote(DOC, state(pair=CLAIMED))
        actions = [one for step in plan for one in step.actions]
        followed = [one for one in actions if isinstance(one, FollowVip)]
        self.assertEqual(len(followed), 1)
        self.assertEqual(followed[0].spec, "/etc/keel/instance.yaml")
        self.assertFalse(any(isinstance(one, PromoteReplica)
                             for one in actions))
        self.assertIn("decides the role",
                      "\n".join(one.summary for one in actions
                                if hasattr(one, "summary")))


if __name__ == "__main__":
    unittest.main()
