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
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from test_system_dbpgpairplan import CLAIMED, DOC, state
from vip_helpers import KEYS, VIP, Pair, address

from keel import exits
from keel.mesh import vipnode, vippromote
from keel.mesh import vip as vipstate
from keel.system import dbfollow, dbpair, dbpgcost, dbpgfollow, dbpgpromote, \
    dbpgrewind, dbpostgres, dbsecret, dbtls
from keel.system.actions import FollowVip, PromoteReplica
from keel.system.database import plan_promote

PRIMARY_SPEC = {"engine": "postgresql", "role": "primary",
                "listen": [address(0), "::1"]}
REPLICA_SPEC = {"engine": "postgresql", "role": "replica",
                "listen": [address(1), "::1"]}
BINARY = "usr/lib/postgresql/17/bin/postgres"
REWIND_BINARY = "usr/lib/postgresql/17/bin/pg_rewind"
DATADIR = "var/lib/postgresql/17/main"
FOLLOW_DROPIN = "etc/postgresql/17/main/conf.d/" + dbpostgres.FOLLOW_DROPIN_NAME
PAIR_DROPIN = "etc/postgresql/17/main/conf.d/" + dbpostgres.PAIR_DROPIN_NAME
STANDBY_SIGNAL = DATADIR + "/" + dbpostgres.STANDBY_SIGNAL
SYSTEM_DATABASES = "postgres\ntemplate0\ntemplate1\n"
REAL_RUN = subprocess.run
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
                 system: str = "72377", holder_system: str = "72377",
                 settings: str = "", rewind: str = "refused",
                 grants_fail: bool = False, probe_fails: bool = False,
                 history: str = "", wal_listing: str = "",
                 holder_standby: bool = False, streams: bool = True):
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
        # what the server says of wal_log_hints, data_checksums and
        # full_page_writes (unknown by default: no rewind is tried),
        # and how pg_rewind answers: "ok", "refused" (it fails before
        # the copy) or "halfway" (it fails after the copy began)
        self.settings = settings
        self.rewind = rewind
        self.grants_fail = grants_fail
        self.probe_fails = probe_fails
        self.history = history
        self.wal_listing = wal_listing
        self.holder_standby = holder_standby
        self.streams = streams
        self.sent: list[str] = []
        self.argv: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        if argv[:1] == ["openssl"]:
            # the members' channel signs with openssl: the follow asks
            # the other members (keel#154), and this fake is
            # subprocess.run for the whole process
            return REAL_RUN(argv, **kwargs)
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
        if self.grants_fail and "GRANT EXECUTE" in (stdin or ""):
            return subprocess.CompletedProcess(
                argv, 1, b"", b'ERROR:  role "repl" does not exist')
        if any(one.endswith("/pg_rewind") for one in argv):
            # pg_rewind --progress says "need to copy" when the copy
            # begins: a failure before it changed nothing, a failure
            # after it left the data directory half copied
            if self.rewind == "refused":
                return subprocess.CompletedProcess(
                    argv, 1, b"", b"pg_rewind: error: target server needs"
                    b" to use either data checksums or wal_log_hints")
            if self.rewind == "halfway":
                return subprocess.CompletedProcess(
                    argv, 1, b"", b"pg_rewind: need to copy 51 MB (total"
                    b" source directory size is 70 MB)\npg_rewind: error:"
                    b" could not fetch remote file")
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
            elif sql.startswith("SELECT convert_from"):
                out = self.history
            elif sql == dbpgcost.WAL_SQL:
                out = self.wal_listing
            elif sql.startswith("SELECT length(pg_read_binary_file"):
                out = "262144\n"
            elif self.probe_fails:
                return subprocess.CompletedProcess(
                    argv, 2, b"", b"psql: error: connection refused")
            else:
                # the seed's probe of the primary: not in recovery,
                # nothing of its own
                out = ("t" if self.holder_standby else "f") + "\t0\t100\n"
        elif sql == dbpgrewind.SETTINGS_SQL:
            out = self.settings
        elif sql == dbpgcost.REPLAY_SQL:
            out = "0/3000200\n"
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
            out = "streaming\n" if self.streams else ""
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
                   mode: str = "cloud_advanced", etcd: str = "disabled",
                   had_role: bool = True):
        """A and B paired, their specs declaring the database; A claims
        the VIP, and B's follow sees A as the holder. B had a role in the
        pair before (its role file), as an old primary has: a node with
        none at its first pairing is seeded (TestTheFirstPairing)"""
        self.nodes(mode=mode, etcd=etcd)
        layout = dbtls.LAYOUTS["postgresql"]
        for index, server in ((0, PRIMARY_SPEC), (1, REPLICA_SPEC)):
            here = self.all[index]
            doc = here.node.document()
            doc["database"] = {"server": dict(server)}
            here.node.write(doc)
            dbsecret.keep(here.root, "pw")
            for name in (BINARY, REWIND_BINARY):
                binary = os.path.join(here.root, name)
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
        if had_role:
            dbpgfollow._write(self.all[1].root, dbpair.ROLE_FILE,
                              dbpair.role_text("primary", VIP), 0o644)
        if claim is not None:
            vippromote.promote(self.all[claim], False,
                               self.said[claim].append)

    def follow(self, index: int, server: Server, confirmed: bool = False,
               wait: float = 0.0, alone: bool = False,
               down: str = "") -> dbfollow.Followed:
        here = self.all[index]
        found = dbfollow.Followed()
        with mock.patch("keel.inspect.constants.ROOT_DEFAULT", here.root), \
                mock.patch("keel.inspect.collect.paths.ROOT_DEFAULT",
                           here.root), \
                mock.patch("keel.system.dbstate.paths.ROOT_DEFAULT",
                           here.root), \
                mock.patch("keel.inspect.collect.subprocess.run", server), \
                mock.patch("keel.system.dbready.ready", return_value=down), \
                mock.patch("keel.system.dbready.enabled",
                           return_value="enabled"), \
                mock.patch("keel.system.dbseed.subprocess.run", server), \
                mock.patch.object(self.all[index].node, "overlay",
                                  wraps=self.all[index].node.overlay), \
                mock.patch.object(dbfollow, "_here", return_value=here):
            # _here: this node on the fixture's members' channel, never
            # the real network (keel#154: follow asks the other members)
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

    def test_a_stream_cut_inside_a_record_does_not_hold_the_promotion(self):
        """keel#215: received 0/7EC8000, replayed 0/7EC7A58, both still:
        the last record is not whole, replay never reaches the received
        position, and the follow waited 417 s on a real pair"""
        self.pair_nodes()
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        positions="t\t0/7EC7A58\t0/7EC8000\n")
        with mock.patch.object(dbpgpromote, "STALL_SECONDS", 0.2), \
                mock.patch.object(dbpgpromote, "POLL_SECONDS", 0.05):
            found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        text = " ".join(found.lines)
        self.assertIn("incomplete record", text)
        self.assertIn("1448 bytes", text)
        self.assertIn("drained and promoted", text)
        self.assertTrue(any("pg_promote()" in one for one in server.sent))

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

    def test_a_quiesced_old_primary_that_claims_again_stays_refused(self):
        """A planned promote: A quiesced and released, the other member's
        promote failed, and an operator runs keel vip promote on A. A is
        then a standby that follows nobody, as a follow after a release
        leaves it with no quiesce too (_fence): nothing proves that the
        other member took no write, so A stays refused until the operator
        says the other member is gone. With etcd the other member's
        controller claims by itself (fail_over)"""
        self.pair_nodes()
        root = self.all[0].root
        dbpgfollow._write(root, dbpair.ROLE_FILE,
                          dbpair.role_text("primary", VIP), 0o644)
        self.assertIsNone(dbpgfollow.quiesce(
            root, lambda argv, **kwargs: subprocess.CompletedProcess(
                argv, 0, b"", b"")))
        self.assertTrue(dbpgfollow.is_standby(root))
        server = Server(**self.FENCED)
        found = self.follow(0, server)
        self.assertIn("--old-primary-gone", found.problem)
        self.assertFalse(any("pg_promote()" in one for one in server.sent))
        self.pair_dropin(0, dbpostgres.pair_dropin_text())
        server = Server(**self.FENCED, streaming="0\n")
        found = self.follow(0, server, alone=True)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(any("pg_promote()" in one for one in server.sent))

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

    def gone_by_the_controller(self, index: int, epoch: int) -> None:
        target = os.path.join(self.all[index].root, vipstate.GONE_NOTE)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as fob:
            fob.write(vipstate.gone_text(epoch - 1, epoch))

    def test_the_controller_s_statement_of_this_claim_commits_alone(self):
        """keel#165: the VIP controller claimed because the lease of the
        old primary expired, which states it gone (0054, 2026-10-15)"""
        self.pair_nodes()
        self.pair_dropin(0, dbpostgres.pair_dropin_text())
        self.gone_by_the_controller(
            0, vipnode.current(self.all[0], VIP).epoch)
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        streaming="0\n")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(dbpgfollow.ALONE_SAID, found.lines)
        self.assertTrue(dbpostgres.commits_alone(self.pair_dropin(0)))
        self.assertFalse(os.path.exists(os.path.join(
            self.all[0].root, vipstate.GONE_NOTE)))

    def test_a_statement_for_another_claim_is_stale(self):
        """A statement left from an earlier claim never makes a later
        holder commit alone: it is removed unused"""
        self.pair_nodes()
        self.pair_dropin(0, dbpostgres.pair_dropin_text())
        self.gone_by_the_controller(
            0, vipnode.current(self.all[0], VIP).epoch + 5)
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        streaming="0\n")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertNotIn(dbpgfollow.ALONE_SAID, found.lines)
        self.assertIn(dbpostgres.SYNC_LINE, self.pair_dropin(0))
        self.assertFalse(os.path.exists(os.path.join(
            self.all[0].root, vipstate.GONE_NOTE)))

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
        # it had a role in the pair: its VIP state may have been removed
        dbpgfollow._write(self.all[0].root, dbpair.ROLE_FILE,
                          dbpair.role_text("primary", VIP), 0o644)
        server = Server()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(["systemctl", "stop", UNIT],
                      server.argv)
        self.assertIn("stopped", " ".join(found.lines))

    def test_the_first_primary_is_not_stopped_before_its_first_claim(self):
        """A late join (BR1 9365, keel 0.23.85): the pair record came
        before the primary's first claim, follow stopped its server, and
        the Take the VIP step of keel spec apply then failed on the
        PostgreSQL steps. No node of the pair has claimed and this node
        never had a role in it, so nothing can be taken from another
        holder: the server runs until the first claim"""
        self.pair_nodes(claim=None)
        server = Server()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(any(one[:2] == ["systemctl", "stop"]
                             for one in server.argv), server.argv)
        self.assertIn("first claim", " ".join(found.lines))
        self.assertNotIn("role=primary", self.role_file(0))

    def test_a_first_primary_stopped_before_is_started_again(self):
        # 9365 after 0.23.85: the server is down, nothing claimed yet
        self.pair_nodes(claim=None)
        with mock.patch.object(dbfollow, "observe_database",
                               wraps=dbfollow.observe_database) as observed:
            self.follow(0, Server())
        self.assertTrue(observed.call_args.kwargs["start"])

    def test_an_unproven_standby_is_left_to_recover(self):
        """In recovery it refuses writes on its own: the unproven row
        stops nothing, it says so"""
        self.pair_nodes()
        self.nets[0].addresses.clear()
        # no other member answers: follow asks them first (keel#154)
        self.down.update({address(1), address(2)})
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

    def fence_vip(self, index: int) -> None:
        from dataclasses import replace
        held = vipnode.current(self.all[index], VIP)
        vipstate.write(self.all[index].root, replace(held, fenced=True))

    def test_a_standby_caught_up_with_the_holder_is_unfenced(self):
        """keel#166: the confirmed reseed made this node the holder's
        copy, so the VIP fence of its old loss is cleared once it
        received everything the holder flushed: the next failover is
        automatic again"""
        self.pair_nodes()
        self.fence_vip(1)
        receiver = f"user=repl host={address(0)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        positions="t\t0/4000098\t0/4000098\n")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(vipnode.current(self.all[1], VIP).fenced)
        self.assertIn(dbpgfollow.UNFENCED_SAID, found.lines)

    def test_a_standby_behind_the_holder_stays_fenced(self):
        self.pair_nodes()
        self.fence_vip(1)
        receiver = f"user=repl host={address(0)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        positions="t\t0/4000000\t0/4000000\n")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(vipnode.current(self.all[1], VIP).fenced)
        self.assertNotIn(dbpgfollow.UNFENCED_SAID, found.lines)

    def test_a_rewound_standby_that_replayed_the_holder_s_position_is_unfenced(
            self):
        """After a rewind the walreceiver starts at the start of its
        segment, and an idle holder sends nothing more, so the received
        position stays below what the node replayed from its own WAL.
        What the node replayed is on the node (0054, amendment of
        2026-10-18)"""
        self.pair_nodes()
        self.fence_vip(1)
        receiver = f"user=repl host={address(0)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        positions="t\t0/4000100\t0/4000000\n")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(vipnode.current(self.all[1], VIP).fenced)
        self.assertIn(dbpgfollow.UNFENCED_SAID, found.lines)

    def test_a_holder_that_does_not_answer_keeps_the_fence(self):
        self.pair_nodes()
        self.fence_vip(1)
        receiver = f"user=repl host={address(0)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        server = Server(in_recovery=True, receiver=receiver,
                        holder_down=True)
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(vipnode.current(self.all[1], VIP).fenced)

    def test_a_reseed_that_streams_clears_the_fence(self):
        self.pair_nodes()
        self.fence_vip(1)
        server = Server(schemas=SYSTEM_DATABASES,
                        positions="t\t0/4000098\t0/4000098\n")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(vipnode.current(self.all[1], VIP).fenced)

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


class TestTheFirstPairing(FollowTestCase):
    """The standby of a cloud mode at its first pairing holds the
    databases of its own first boot: Odoo wrote to the local cluster
    before the role was known, and both nodes came from one image, so
    the system identifiers are the same (BR1 9360 and BR2 9361, keel
    0.23.84). pg_rewind could not run, and follow refused the node as a
    diverged old primary; the primary's synchronous commit then waited
    for a standby that never came. A node that never had a role in the
    pair (no role file) loses nothing of the pair: it is dumped and
    seeded from the holder, as a MariaDB replica is (keel 0.23.84)"""

    FIRST_BOOT = {"timeline": "1", "holder_timeline": "1",
                  "system": "7705069944881121780",
                  "holder_system": "7705069944881121780"}

    def test_a_first_pairing_is_dumped_and_seeded(self):
        self.pair_nodes(mode="cloud_simple", had_role=False)
        server = Server(**self.FIRST_BOOT)
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        joined = "\n".join(found.lines)
        self.assertIn("first pairing", joined)
        self.assertIn("seeded from", joined)
        self.assertTrue(self.ran(server, "pg_basebackup"))
        kept = os.listdir(os.path.join(self.all[1].root,
                                       dbpgfollow.BACKUPS))
        self.assertTrue(any(one.startswith("first-boot-schemas-")
                            for one in kept), kept)
        dump = next(os.path.join(self.all[1].root, dbpgfollow.BACKUPS, one)
                    for one in kept if one.startswith("first-boot"))
        self.assertEqual(os.stat(dump).st_mode & 0o777, 0o600)
        self.assertIn(dump, joined)
        dumped = next(n for n, argv in enumerate(server.argv)
                      if "pg_dumpall" in argv)
        seeded = next(n for n, argv in enumerate(server.argv)
                      if "pg_basebackup" in " ".join(argv))
        self.assertLess(dumped, seeded)
        self.assertIsNone(dbfollow.diverged(self.all[1].root))

    def test_a_node_refused_before_is_seeded_once_it_runs_0_23_86(self):
        # 9361: the divergence record of 0.23.84 stands, and no role file
        self.pair_nodes(mode="cloud_simple", had_role=False)
        dbpgfollow._write(self.all[1].root, dbfollow.DIVERGED, json.dumps({
            "own_timeline": "1", "holder_timeline": "1",
            "own_system": "7705069944881121780",
            "holder_system": "7705069944881121780",
            "holder": address(0), "dump": ""}) + "\n", 0o600)
        server = Server(in_recovery=True, **self.FIRST_BOOT)
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(self.ran(server, "pg_basebackup"))

    def test_a_node_that_had_a_role_in_the_pair_stays_refused(self):
        for role in ("primary", "replica"):
            with self.subTest(role=role):
                self.pair_nodes(mode="cloud_simple", had_role=False)
                dbpgfollow._write(self.all[1].root, dbpair.ROLE_FILE,
                                  dbpair.role_text(role, VIP), 0o644)
                server = Server(**self.FIRST_BOOT)
                with mock.patch("keel.monitor.alerting.alert",
                                return_value=True):
                    found = self.follow(1, server)
                self.assertIn("diverged", found.problem)
                self.assertFalse(self.ran(server, "pg_basebackup"))

    def test_a_simple_installation_stays_refused(self):
        self.pair_nodes(mode="cloud_simple", had_role=False)
        here = self.all[1]
        doc = here.node.document()
        doc["installation"]["mode"] = "simple"
        here.node.write(doc)
        server = Server(**self.FIRST_BOOT)
        with mock.patch("keel.monitor.alerting.alert", return_value=True):
            found = self.follow(1, server)
        self.assertIsNotNone(found.problem)
        self.assertFalse(self.ran(server, "pg_basebackup"))

    def test_a_dump_that_cannot_be_kept_seeds_nothing(self):
        self.pair_nodes(mode="cloud_simple", had_role=False)
        server = Server(dump_fails=True, **self.FIRST_BOOT)
        found = self.follow(1, server)
        self.assertIn("not kept", found.problem)
        self.assertFalse(self.ran(server, "pg_basebackup"))


class TestThePromoteOfAFencedStandby(FollowTestCase):
    """keel vip promote on a standby that follows nobody (BR1 9368 and
    BR2 9369, keel 0.23.84): the replica was promoted, and at once the
    old primary claimed the VIP back before it rejoined. It then held
    the VIP as a fenced standby that takes no writes, the other node was
    a standby too, and no server of the pair took writes. The promote
    refuses there: follow would leave the holder refused (above)"""

    FENCED = TestThePrimary.FENCED

    def promote(self, index: int, server: Server, gone: bool = False,
                alone: bool = False) -> tuple[int, list[str]]:
        here = self.all[index]
        said: list[str] = []
        with mock.patch("keel.inspect.constants.ROOT_DEFAULT", here.root), \
                mock.patch("keel.inspect.collect.paths.ROOT_DEFAULT",
                           here.root), \
                mock.patch("keel.system.dbstate.paths.ROOT_DEFAULT",
                           here.root), \
                mock.patch("keel.inspect.collect.subprocess.run", server), \
                mock.patch("keel.system.dbready.ready", return_value=""), \
                mock.patch("keel.system.dbready.enabled",
                           return_value="enabled"):
            code = vippromote.promote(here, gone, said.append, alone=alone)
        return code, said

    def old_primary(self) -> None:
        """A was the primary; B holds the VIP now"""
        self.pair_nodes(claim=1)
        dbpgfollow._write(self.all[0].root, dbpair.ROLE_FILE,
                          dbpair.role_text("primary", VIP), 0o644)

    def newest_holder(self) -> str:
        held = vipstate.read(self.all[0].root, VIP)
        return f"{held.claim.holder} {held.claim.epoch}" if held and held.claim else ""

    def test_a_fenced_old_primary_is_refused_the_vip(self):
        self.old_primary()
        before = self.newest_holder()
        code, said = self.promote(0, Server(**self.FENCED))
        self.assertEqual(code, exits.MESH_REFUSED, said)
        text = " ".join(said)
        self.assertIn("follows nobody", text)
        self.assertIn("--old-primary-gone", text)
        self.assertEqual(self.newest_holder(), before)

    def test_the_operator_s_old_primary_gone_lets_it_promote(self):
        self.old_primary()
        code, said = self.promote(0, Server(**self.FENCED), gone=True,
                                  alone=True)
        self.assertNotIn("follows nobody", " ".join(said))

    def test_a_fenced_node_that_never_had_a_role_may_promote(self):
        # keel#152: follow makes such a holder writable, nothing is lost
        self.pair_nodes(claim=1)
        code, said = self.promote(0, Server(**self.FENCED))
        self.assertNotIn("follows nobody", " ".join(said))

    def test_a_standby_that_follows_the_holder_may_promote(self):
        self.old_primary()
        receiver = f"user=repl host={address(1)} port=5432 " \
                   "password=******** sslmode=verify-full\n"
        code, said = self.promote(0, Server(in_recovery=True,
                                            receiver=receiver))
        self.assertNotIn("follows nobody", " ".join(said))

    def test_the_guard_says_nothing_without_a_postgresql_server(self):
        self.assertIsNone(dbpgfollow.promote_refusal("/", {}, False))
        self.assertIsNone(dbpgfollow.promote_refusal(
            "/", {"database": {"server": {"engine": "mariadb"}}}, False))
        doc = {"database": {"server": {"engine": "postgresql"}}}
        with mock.patch("keel.system.dbstate.observe_database",
                        side_effect=OSError(5, "I/O error")):
            self.assertIsNone(dbpgfollow.promote_refusal("/", doc, False))


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



class TestWithoutEtcd(FollowTestCase):
    """keel#154: in a pair without etcd nothing ran keel vip check, so a
    returned old primary never learned the newer claim, and each watch
    started its server for its follow to stop again"""

    def returned_old_primary(self) -> None:
        """A claimed and carried the VIP; B took it with
        --old-primary-gone while A was away; A is back, its VIP gone
        from wg0 by the reboot, its own claim the newest it knows"""
        self.pair_nodes(claim=0)
        # A's follow recorded its role while it was the primary
        dbpgfollow._write(self.all[0].root, dbpair.ROLE_FILE,
                          dbpair.role_text("primary", VIP), 0o644)
        self.down.add(address(0))
        vippromote.promote(self.all[1], True, self.said[1].append)
        self.down.discard(address(0))
        self.nets[0].addresses.remove(f"{VIP}/128")
        self.assertTrue(self.carried(1))

    def follow_learning(self, index: int, server: Server, **kwargs):
        here = self.all[index]
        with mock.patch.object(dbfollow, "_here", return_value=here) as made:
            found = self.follow(index, server, **kwargs)
        return found, made

    def test_a_returned_old_primary_learns_the_newer_claim(self):
        self.returned_old_primary()
        server = Server()
        with mock.patch("keel.monitor.alerting.alert", return_value=True):
            found, _ = self.follow_learning(0, server)
        said = " ".join(found.lines)
        self.assertIn("took epoch 2", said)
        self.assertIn("fenced", said)
        self.assertNotIn(["systemctl", "stop", UNIT], server.argv)
        self.assertNotIn("is not proven", said)

    def test_an_unproven_primary_s_server_is_not_started(self):
        """the other member does not answer: the claim stays unproven,
        and the follow does not start a server that it then stops"""
        self.returned_old_primary()
        # no other member answers: B and the third node, which B told
        self.down.update({address(1), address(2)})
        started = []
        real = dbfollow.observe_database

        def observe(*args, **kwargs):
            started.append(kwargs.get("start"))
            return real(*args, **kwargs)

        with mock.patch.object(dbfollow, "observe_database", observe):
            found, _ = self.follow_learning(0, Server())
        self.assertEqual(started, [False])
        self.assertIn("is not proven", " ".join(found.lines))

    def test_a_stopped_unproven_primary_stays_stopped(self):
        import dataclasses
        self.returned_old_primary()
        # no other member answers: B and the third node, which B told
        self.down.update({address(1), address(2)})
        real = dbfollow.observe_database

        def observe(*args, **kwargs):
            return dataclasses.replace(real(*args, **kwargs),
                                       down=f"{UNIT} is inactive")

        server = Server()
        with mock.patch.object(dbfollow, "observe_database", observe):
            found, _ = self.follow_learning(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("stays stopped", " ".join(found.lines))
        self.assertFalse(any(one[:1] == ["systemctl"]
                             for one in server.argv))

    def test_a_holder_back_with_no_newer_claim_carries_the_vip_again(self):
        """keel vip check without etcd: a peer answered and none knows a
        newer claim, so the holder carries the VIP again"""
        self.pair_nodes(claim=0)
        self.nets[0].addresses.remove(f"{VIP}/128")
        found, _ = self.follow_learning(0, Server())
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(self.carried(0))
        self.assertIn("unchanged (the primary, writable)", found.lines)

    def test_a_holder_that_carries_the_vip_asks_nobody(self):
        self.pair_nodes(claim=0)
        found, made = self.follow_learning(0, Server())
        self.assertIsNone(found.problem, found.lines)
        made.assert_not_called()

    def test_with_etcd_the_controller_tells_and_follow_asks_nobody(self):
        self.returned_old_primary()
        with mock.patch.object(vippromote, "with_etcd", return_value=True):
            found, _ = self.follow_learning(0, Server())
        self.assertNotIn("took epoch 2", " ".join(found.lines))

class TestTheFileFlip(FollowTestCase):
    """0050's amendment, point 5: the folders flip with the database
    role for PostgreSQL too, and pause when the follow records nothing
    (the holder did not answer: record_role stays False, the role file
    is left as it was)"""

    def test_the_primary_flip_flips_the_folders(self):
        self.pair_nodes()
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            found = self.follow(0, Server())
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(flipped.call_count, 1)
        self.assertEqual(flipped.call_args.args[3], "primary")

    def test_a_failed_follow_pauses_the_folders(self):
        self.pair_nodes()
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            found = self.follow(1, Server(holder_down=True))
        self.assertIsNotNone(found.problem)
        self.assertIsNone(flipped.call_args.args[3])


class TestQuiesce(unittest.TestCase):
    """The PostgreSQL quiesce for a planned promote: CHECKPOINT, then
    standby.signal and a restart, so the new primary replays the
    shutdown checkpoint and the old primary does not diverge"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        for relative in (DATADIR, "etc/postgresql/17/main/conf.d"):
            os.makedirs(os.path.join(self.root, relative), exist_ok=True)

    def _runner(self, checkpoint_rc=0, restart_rc=0,
                checkpoint_timeout=False, restart_timeout=False):
        """A runner that records what it was asked to do"""
        calls = []

        def run(argv, **kwargs):
            argv = list(argv)
            calls.append(argv)
            timeout = kwargs.get("timeout")
            if any("psql" in a for a in argv) and "CHECKPOINT" in str(argv):
                if checkpoint_timeout:
                    raise subprocess.TimeoutExpired(argv, timeout)
                return subprocess.CompletedProcess(
                    argv, checkpoint_rc, b"", b"" if checkpoint_rc == 0
                    else b"ERROR: permission denied")
            if argv[:2] == ["systemctl", "restart"]:
                if restart_timeout:
                    raise subprocess.TimeoutExpired(argv, timeout)
                return subprocess.CompletedProcess(
                    argv, restart_rc, b"", b"" if restart_rc == 0
                    else b"Job failed")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        return run, calls

    def test_quiesce_fences_the_cluster(self):
        runner, calls = self._runner()
        problem = dbpgfollow.quiesce(self.root, runner)
        self.assertIsNone(problem)
        # CHECKPOINT must run first
        self.assertTrue(any("CHECKPOINT" in str(c) for c in calls),
                        calls)
        # then systemctl restart
        self.assertTrue(any(c[:2] == ["systemctl", "restart"]
                            for c in calls), calls)
        # standby.signal must exist
        signal = os.path.join(self.root, STANDBY_SIGNAL)
        self.assertTrue(os.path.exists(signal))

    def test_quiesce_returns_none_without_a_cluster(self):
        empty = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, empty)

        def must_not_be_called(argv, **kwargs):
            raise AssertionError(f"runner called with {argv}")
        problem = dbpgfollow.quiesce(empty, must_not_be_called)
        self.assertIsNotNone(problem)
        self.assertIn("no PostgreSQL cluster", problem)

    def test_checkpoint_timeout_stops_early(self):
        runner, calls = self._runner(checkpoint_timeout=True)
        problem = dbpgfollow.quiesce(self.root, runner)
        self.assertIsNotNone(problem)
        self.assertIn("CHECKPOINT did not finish", problem)
        # no restart attempted
        self.assertFalse(any(c[:2] == ["systemctl", "restart"]
                             for c in calls), calls)
        # standby.signal must NOT exist
        signal = os.path.join(self.root, STANDBY_SIGNAL)
        self.assertFalse(os.path.exists(signal))

    def test_checkpoint_failure_stops_early(self):
        runner, calls = self._runner(checkpoint_rc=1)
        problem = dbpgfollow.quiesce(self.root, runner)
        self.assertIsNotNone(problem)
        self.assertIn("CHECKPOINT failed", problem)
        # no restart attempted
        self.assertFalse(any(c[:2] == ["systemctl", "restart"]
                             for c in calls), calls)

    def test_restart_timeout_reports_the_job_runs(self):
        """Killing the systemctl client does not cancel the systemd job,
        so the restart runs anyway, but the caller should not claim
        the server is a standby"""
        runner, _ = self._runner(restart_timeout=True)
        problem = dbpgfollow.quiesce(self.root, runner)
        self.assertIsNotNone(problem)
        self.assertIn("the systemd job runs", problem)

    def test_restart_failure_is_reported(self):
        runner, _ = self._runner(restart_rc=1)
        problem = dbpgfollow.quiesce(self.root, runner)
        self.assertIsNotNone(problem)
        self.assertIn("restart failed", problem)

    def signal_file(self):
        return os.path.join(self.root, STANDBY_SIGNAL)

    def test_a_standby_is_not_quiesced_again(self):
        open(self.signal_file(), "w").close()
        runner, calls = self._runner()
        self.assertIsNone(dbpgfollow.quiesce(self.root, runner))
        self.assertEqual(calls, [])
        self.assertTrue(dbpgfollow.is_standby(self.root))

    def test_is_standby_without_a_cluster(self):
        empty = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, empty)
        self.assertFalse(dbpgfollow.is_standby(empty))

    def test_unquiesce_removes_the_signal_and_restarts(self):
        open(self.signal_file(), "w").close()
        runner, calls = self._runner()
        self.assertIsNone(dbpgfollow.unquiesce(self.root, runner))
        self.assertFalse(os.path.exists(self.signal_file()))
        self.assertTrue(any(c[:2] == ["systemctl", "restart"] for c in calls))

    def test_unquiesce_with_no_signal_does_nothing(self):
        runner, calls = self._runner()
        self.assertIsNone(dbpgfollow.unquiesce(self.root, runner))
        self.assertEqual(calls, [])

    def test_unquiesce_reports_the_failures(self):
        for kwargs, said in (({"restart_rc": 1}, "restart failed"),
                             ({"restart_timeout": True}, "timed out")):
            with self.subTest(said=said):
                open(self.signal_file(), "w").close()
                runner, _ = self._runner(**kwargs)
                self.assertIn(said, dbpgfollow.unquiesce(self.root, runner))

    def test_unquiesce_without_systemctl(self):
        open(self.signal_file(), "w").close()

        def run(argv, **kwargs):
            raise OSError("no systemctl")
        self.assertIn("cannot run systemctl",
                      dbpgfollow.unquiesce(self.root, run))

    def test_unquiesce_cannot_remove_the_signal(self):
        with mock.patch("os.remove", side_effect=PermissionError("no")):
            self.assertIn("could not be removed",
                          dbpgfollow.unquiesce(self.root))

    def test_checkpoint_runs_before_standby_signal(self):
        """CHECKPOINT must finish before standby.signal is written:
        a slow CHECKPOINT leaves the server untouched"""
        order = []

        def run(argv, **kwargs):
            argv = list(argv)
            if "CHECKPOINT" in str(argv):
                order.append("checkpoint")
                signal = os.path.join(self.root, STANDBY_SIGNAL)
                self.assertFalse(os.path.exists(signal),
                                 "standby.signal before CHECKPOINT")
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[:2] == ["systemctl", "restart"]:
                order.append("restart")
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        problem = dbpgfollow.quiesce(self.root, run)
        self.assertIsNone(problem)
        self.assertEqual(order, ["checkpoint", "restart"])


if __name__ == "__main__":
    unittest.main()
