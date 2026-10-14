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
PAIR_DROPIN = "etc/postgresql/17/main/conf.d/" + dbpostgres.PAIR_DROPIN_NAME
STANDBY_SIGNAL = DATADIR + "/" + dbpostgres.STANDBY_SIGNAL
SYSTEM_DATABASES = "postgres\ntemplate0\ntemplate1\n"
IDENTIFY_SYSTEM_ANSWER = "72377\t2\t0/4000098\n"
# the cluster's own unit: a stop of the umbrella postgresql returns
# before the cluster stops (keel#153)
UNIT = "postgresql@17-main"


class Server:
    """subprocess.run as one PostgreSQL server answers it: recovery
    state, the walreceiver's conninfo, what it holds, its timeline, and
    what it was sent"""

    def __init__(self, in_recovery: bool = False, receiver: str = "",
                 standby: str = "\n",
                 hba: str = "local\t\t\nhost\t127.0.0.1\t255.255.255.255\n",
                 schemas: str = SYSTEM_DATABASES + "shop\n",
                 timeline: str = "2",
                 holder_timeline: str = "2", holder_down: bool = False,
                 positions: str = "t\t0/4000100\t0/4000098\n",
                 dump_fails: bool = False, streaming: str = "",
                 system: str = "72377", holder_system: str = "72377"):
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
        self.streaming = streaming
        self.system = system
        self.holder_system = holder_system
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
        if argv[:2] == ["systemctl", "restart"]:
            # the fence's restart: standby.signal makes the start a
            # recovery
            self.row = "t" + self.row[1:]
            return subprocess.CompletedProcess(argv, 0, b"", b"")
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
                out = (f"{self.holder_system}\t{self.holder_timeline}"
                       "\t0/4000098\n")
            else:
                # the seed's probe of the primary: not in recovery,
                # nothing of its own
                out = "f\t0\t100\n"
        elif "pg_last_wal_replay_lsn" in sql:
            out = self.positions
        elif sql == dbpgfollow.STREAMING_SQL:
            out = self.streaming
        elif sql == dbpgfollow.TIMELINE_SQL:
            out = self.timeline + "\n"
        elif sql == dbpgfollow.SYSTEM_SQL:
            out = self.system + "\n"
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
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(dbpostgres.SERVICE_ENV, None)
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
               wait: float = 0.0, alone: bool = False) -> dbfollow.Followed:
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
                            wait=wait, sleep=self.sleep, alone=alone)
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

    def test_a_promoted_standby_makes_the_pair_s_slot(self):
        """A base backup copies no slot: the new holder makes the
        pair's slot after pg_promote(), or the reseed of the old
        primary never streams (found when the pair's cases (b) to (e)
        were built)"""
        self.pair_nodes()
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver)
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        promoted = next(n for n, one in enumerate(server.sent)
                        if "pg_promote()" in one)
        slot = next(n for n, one in enumerate(server.sent)
                    if "pg_create_physical_replication_slot" in one)
        self.assertGreater(slot, promoted)
        self.assertIn("SET synchronous_commit = local", server.sent[slot])

    def test_the_holder_keeps_the_pair_s_slot_on_each_follow(self):
        self.pair_nodes()
        server = Server()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(any("pg_create_physical_replication_slot" in one
                            for one in server.sent))

    # a standby that follows nobody: what the fence leaves (keel#152)
    FENCED = {"in_recovery": True, "receiver": "", "standby": "\n",
              "positions": "t\t0/3000000\t\n"}

    def record_divergence(self, index: int, own: str, holder: str) -> None:
        dbpgfollow._write(self.all[index].root, dbfollow.DIVERGED,
                          json.dumps({"own_timeline": "1",
                                      "holder_timeline": "1",
                                      "own_system": own,
                                      "holder_system": holder,
                                      "holder": address(1), "dump": ""})
                          + "\n", 0o600)

    def test_a_fenced_fresh_holder_takes_writes(self):
        """keel#152, the setup deadlock: the image's user database made
        both new nodes fenced standbys, and no keel command made the
        VIP's holder writable. A node that never had a role in the pair
        loses nothing of it: it is promoted, with no drain"""
        self.pair_nodes()
        server = Server(**self.FENCED)
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(any("pg_promote()" in one for one in server.sent))
        self.assertIn("never had a role in the pair", " ".join(found.lines))
        self.assertIn("role=primary", self.role_file(0))

    def test_a_fenced_holder_of_another_history_takes_writes(self):
        """the same deadlock after the watch recorded the divergence of
        two clusters that two initdb runs made: the system identifiers
        differ, so the copy never shared a history with the other
        member, and nothing of the pair is lost"""
        self.pair_nodes()
        self.record_divergence(0, own="111", holder="222")
        dbpgfollow._write(self.all[0].root, dbpair.ROLE_FILE,
                          dbpair.role_text("replica", VIP), 0o644)
        server = Server(**self.FENCED)
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(any("pg_promote()" in one for one in server.sent))
        self.assertIn("never shared a history", " ".join(found.lines))
        self.assertIsNone(dbfollow.diverged(self.all[0].root))

    def test_a_fenced_old_primary_that_gets_the_vip_stays_refused(self):
        """case (e)'s fenced old primary shares the pair's history and
        may stand behind the newer primary's writes: a planned promote
        onto it must not lose them"""
        self.pair_nodes()
        self.record_divergence(0, own="72377", holder="72377")
        server = Server(**self.FENCED)
        found = self.follow(0, server)
        self.assertIn("--old-primary-gone", found.problem)
        self.assertFalse(any("pg_promote()" in one for one in server.sent))

    def test_a_fenced_holder_that_had_a_role_stays_refused(self):
        """no divergence record: the holder could not be asked when it
        was fenced, so nothing proves that the copy is not behind"""
        self.pair_nodes()
        dbpgfollow._write(self.all[0].root, dbpair.ROLE_FILE,
                          dbpair.role_text("primary", VIP), 0o644)
        server = Server(**self.FENCED)
        found = self.follow(0, server)
        self.assertIn("--old-primary-gone", found.problem)
        self.assertFalse(any("pg_promote()" in one for one in server.sent))

    def test_the_old_primary_gone_a_fenced_holder_takes_writes(self):
        """after case (e), the newer primary lost: the operator's flag
        says it is gone, so the fenced last node takes writes, alone"""
        self.pair_nodes()
        self.pair_dropin(0, dbpostgres.pair_dropin_text())
        self.record_divergence(0, own="72377", holder="72377")
        server = Server(**self.FENCED, streaming="0\n")
        found = self.follow(0, server, alone=True)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(any("pg_promote()" in one for one in server.sent))
        self.assertIn(dbpgfollow.ALONE_SAID, found.lines)

    def test_the_divergence_record_names_both_system_identifiers(self):
        self.pair_nodes()
        server = Server(timeline="1", holder_timeline="1", system="111",
                        holder_system="222")
        with mock.patch("keel.monitor.alerting.alert", return_value=True):
            self.follow(1, server)
        recorded = dbfollow.diverged(self.all[1].root)
        self.assertEqual(recorded["own_system"], "111")
        self.assertEqual(recorded["holder_system"], "222")

    def test_no_database_section_says_so(self):
        """keel#152, minor: the follow said "no appliance.vip" to a spec
        that declares the VIP and no database.server"""
        self.pair_nodes()
        here = self.all[1]
        doc = here.node.document()
        del doc["database"]
        here.node.write(doc)
        found = self.follow(1, Server())
        self.assertIn("database.server", found.problem)
        self.assertNotIn("appliance.vip", found.problem)

    def pair_dropin(self, index: int, text: str | None = None) -> str:
        path = os.path.join(self.all[index].root, PAIR_DROPIN)
        if text is not None:
            with open(path, "w") as fob:
                fob.write(text)
        with open(path) as fob:
            return fob.read()

    def test_the_old_primary_gone_the_new_primary_commits_alone(self):
        """0054's one exception: keel database promote
        --old-primary-gone says the old primary is gone, so with no
        standby streaming the holder commits alone, reloaded, never
        restarted"""
        self.pair_nodes()
        self.pair_dropin(0, dbpostgres.pair_dropin_text())
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        streaming="0\n")
        found = self.follow(0, server, alone=True)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(dbpgfollow.ALONE_SAID, found.lines)
        text = self.pair_dropin(0)
        self.assertTrue(dbpostgres.commits_alone(text), text)
        self.assertNotIn(dbpostgres.SYNC_LINE, text)
        self.assertTrue(self.ran(server, "SELECT pg_reload_conf()"))
        self.assertFalse(any(one[:2] == ["systemctl", "restart"]
                             for one in server.argv))

    def test_the_operator_s_mark_reaches_the_follow_of_the_claim(self):
        """keel database promote --old-primary-gone marks the statement
        before it moves the VIP, so the follow that the claim starts
        commits alone at once; the mark is used once"""
        self.pair_nodes()
        self.pair_dropin(0, dbpostgres.pair_dropin_text())
        dbpgfollow.mark_alone(self.all[0].root)
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        streaming="0\n")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(dbpgfollow.ALONE_SAID, found.lines)
        self.assertFalse(os.path.exists(os.path.join(
            self.all[0].root, dbpgfollow.ALONE_MARK)))

    def test_without_the_flag_the_new_primary_keeps_waiting(self):
        """A planned promote, or the follow of the VIP: no exception"""
        self.pair_nodes()
        self.pair_dropin(0, dbpostgres.pair_dropin_text())
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        streaming="0\n")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(dbpostgres.SYNC_LINE, self.pair_dropin(0))
        self.assertFalse(self.ran(server, "SELECT pg_reload_conf()"))

    def test_a_standby_that_streams_brings_the_synchronous_line_back(self):
        self.pair_nodes()
        self.pair_dropin(0, dbpostgres.alone_text(
            dbpostgres.pair_dropin_text()))
        server = Server(streaming="1\n")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(dbpgfollow.SYNCHRONOUS_SAID, found.lines)
        self.assertEqual(self.pair_dropin(0), dbpostgres.pair_dropin_text())
        self.assertTrue(self.ran(server, "SELECT pg_reload_conf()"))

    def test_an_unproven_primary_is_stopped(self):
        """keel#104, the PostgreSQL row: pg cannot be read only while
        it runs, so an unproven claim is enforced by stopping the
        server; a stopped server takes no writes and the stop is
        reversed by the next follow once the VIP is proven"""
        self.pair_nodes(claim=None)
        server = Server()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(["systemctl", "stop", UNIT],
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
        root = self.all[1].root
        with open(os.path.join(root, FOLLOW_DROPIN), "w") as fob:
            fob.write("primary_conninfo = 'host=elsewhere'\n")
        server = Server(timeline="3",
                        holder_timeline="2")
        with mock.patch("keel.monitor.alerting.alert",
                        return_value=True) as alerted:
            found = self.follow(1, server)
        self.assertIn("diverged", found.problem)
        self.assertIn("timeline 3 against the holder's 2", found.problem)
        self.assertFalse(self.ran(server, "pg_basebackup"))
        # fenced first: a standby that follows nobody, which refuses
        # every write (found when the pair's cases (b) to (e) were
        # built: the diverged old primary stayed a writable primary)
        self.assertIn("fenced", " ".join(found.lines))
        self.assertTrue(os.path.exists(os.path.join(root, STANDBY_SIGNAL)))
        self.assertFalse(os.path.exists(os.path.join(root, FOLLOW_DROPIN)))
        restart = server.argv.index(["systemctl", "restart",
                                     UNIT])
        dumped = next(n for n, argv in enumerate(server.argv)
                      if "pg_dumpall" in argv)
        self.assertLess(restart, dumped)
        kept = os.listdir(os.path.join(self.all[1].root,
                                       dbpgfollow.BACKUPS))
        self.assertTrue(kept[0].startswith("rejoin-"), kept)
        self.assertTrue(kept[0].endswith(".zst"), kept)
        recorded = dbfollow.diverged(self.all[1].root)
        self.assertEqual(recorded["own_timeline"], "3")
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
        # nor fenced or dumped again: in recovery it took no write, and
        # the dump the record names still holds what it holds
        self.assertEqual(sum("pg_dumpall" in argv for argv in server.argv),
                         1)
        self.assertEqual(server.argv.count(
            ["systemctl", "restart", UNIT]), 1)
        self.assertEqual(len(os.listdir(os.path.join(
            root, dbpgfollow.BACKUPS))), 1)
        self.assertTrue(dbfollow.diverged(root)["dump"].endswith(".zst"))

    def test_a_standby_that_follows_nobody_is_not_fenced_again(self):
        """In recovery it refuses writes already: no restart"""
        self.pair_nodes()
        server = Server(in_recovery=True, timeline="1")
        with mock.patch("keel.monitor.alerting.alert", return_value=True):
            found = self.follow(1, server)
        self.assertIn("timeline 1 against the holder's 2", found.problem)
        self.assertNotIn(["systemctl", "restart", UNIT],
                         server.argv)
        self.assertNotIn("fenced", " ".join(found.lines))

    def test_confirmed_the_old_primary_is_reseeded_after_a_dump(self):
        self.pair_nodes()
        server = Server(timeline="3",
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
        self.assertIn("nothing else was changed", found.problem)
        # the fence comes first all the same: it holds data and is not
        # the holder
        self.assertIn(["systemctl", "restart", UNIT],
                      server.argv)
        self.assertFalse(self.ran(server, "pg_dumpall"))
        self.assertFalse(self.ran(server, "pg_basebackup"))

    def test_the_seed_and_the_timeline_ask_carry_the_pair_tls(self):
        """The replication protocol's line is the cert method: a copy
        or a timeline ask that presents no certificate is refused by
        the primary (found by the pair's network-namespace test of
        this release)"""
        self.pair_nodes()
        server = Server(timeline="3")
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


class TestTheRecord(unittest.TestCase):
    """diff and status read either engine's record: PostgreSQL's has
    timelines, no errant GTID, and said "unknown" before"""

    def test_the_timelines_describe_a_postgresql_divergence(self):
        record = {"own_timeline": "1", "holder_timeline": "2",
                  "holder": "fd00::2"}
        self.assertEqual(dbfollow.described(record),
                         "timeline 1 against the holder's 2")
        self.assertEqual(dbfollow.described({"errant": ["0-7-15"]}),
                         "0-7-15")
        from keel.diff.compare import diverged
        from keel.inspect.report import Inspection
        fields = diverged({"appliance": {"vip": VIP}}, Inspection(
            "/", "t", {}, (), role="replica", diverged=record))
        self.assertIn("timeline 1 against the holder's 2", fields[0].note)


class TestPromotion(unittest.TestCase):
    """On a pair the VIP decides the role for PostgreSQL too (the
    CONVERGED gate widened with 0054)"""

    def test_old_primary_gone_reaches_the_follow(self):
        plan = plan_promote(DOC, state(pair=CLAIMED), alone=True)
        followed = [one for step in plan for one in step.actions
                    if isinstance(one, FollowVip)]
        self.assertTrue(followed[0].alone)
        plain = plan_promote(DOC, state(pair=CLAIMED))
        self.assertFalse(next(one for step in plain for one in step.actions
                              if isinstance(one, FollowVip)).alone)

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
