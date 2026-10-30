# Copyright (c) 2026 KeelLinux maintainers
"""keel database follow and keel database watch (decisions 0020, 0031,
0049), against a server replaced at the subprocess boundary

The pair, the VIP's state and the spec are real (tests/vip_helpers.py);
MariaDB is a runner that answers as 11.8 did on the bench, so every
branch of the follow table runs without a server; the real run is
tests/test_mariadb_netns.py.
"""

import json
import os
import subprocess
import unittest
from unittest import mock

from test_inspect_database import MARIADB_REPLICA_STATUS
from vip_helpers import KEYS, VIP, Pair, address

from keel.mesh import vippromote
from keel.system import dbfollow, dbpair, dbsecret, dbtls, dbwatch
from keel.system import dbmariadb as mariadb

PRIMARY_SPEC = {"engine": "mariadb", "role": "primary",
                "listen": [address(0), "::1"]}
REPLICA_SPEC = {"engine": "mariadb", "role": "replica",
                "listen": [address(1), "::1"]}


REAL_RUN = subprocess.run


class Server:
    """subprocess.run as one MariaDB server answers it: a status, GTID
    positions, what it holds, and what it was sent"""

    def __init__(self, replicating_from: str | None = None,
                 read_only: str = "OFF", schemas: str = "shop\n",
                 binlog_state: str = "0-1-10", binlog_pos: str = "0-1-10",
                 holder_state: str = "0-1-10,0-2-20", holder_pos: str = "",
                 sql_running: str = "Yes", holder_down: bool = False,
                 bypass: str = "'root'@'localhost'\n'admin'@'localhost'\n",
                 dump_fails: bool = False, slave_pos: str = "",
                 log_bin: str = "1", clients: tuple = ()):
        self.log_bin = log_bin
        # the semi-synchronous replicas each status read finds, in turn;
        # one when the turns are used up
        self.clients = list(clients)
        self.replicating_from = replicating_from
        self.read_only = read_only
        self.schemas = schemas
        self.binlog_state, self.binlog_pos = binlog_state, binlog_pos
        self.holder_state, self.holder_pos = holder_state, holder_pos
        self.sql_running = sql_running
        self.holder_down = holder_down
        self.bypass = bypass
        self.dump_fails = dump_fails
        self.slave_pos = slave_pos
        self.sent: list[str] = []
        self.argv: list[list[str]] = []
        # what was asked or sent, in order
        self.events: list[str] = []

    def status(self) -> str:
        if not self.replicating_from:
            return ""
        return (MARIADB_REPLICA_STATUS.replace("2001:db8:1::10",
                                               self.replicating_from)
                .replace("Slave_SQL_Running: Yes",
                         f"Slave_SQL_Running: {self.sql_running}")
                + "        Seconds_Behind_Master: 1\n"
                + "         Master_Log_File: b.000002\n"
                + "     Read_Master_Log_Pos: 10\n"
                + "   Relay_Master_Log_File: b.000002\n"
                + "     Exec_Master_Log_Pos: 10\n"
                + "          Last_SQL_Error: \n")

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        if argv[:1] == ["openssl"]:
            # the members' channel signs with openssl: follow asks the
            # other members (keel#154), and this fake is subprocess.run
            # for the whole process
            return REAL_RUN(argv, **kwargs)
        self.argv.append(argv)
        stdin = kwargs.get("input")
        if isinstance(stdin, bytes):
            stdin = stdin.decode()
        if stdin:
            self.sent.append(stdin)
        self.events.append(stdin or argv[-1])
        if argv[0] == "mariadb-dump":
            if self.dump_fails:
                return subprocess.CompletedProcess(argv, 2, b"", b"no room")
            kwargs["stdout"].write(b"-- dump\n-- SET GLOBAL gtid_slave_pos="
                                   b"'0-1-10';\n")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[0] == "zstd":
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        remote = any(one.startswith("--defaults-extra-file") for one in argv)
        asked = argv[-1] if "--execute" in argv else ""
        out = ""
        if remote:
            if self.holder_down:
                return subprocess.CompletedProcess(
                    argv, 1, "" if kwargs.get("text") else b"",
                    "ERROR 2002 cannot connect" if kwargs.get("text")
                    else b"ERROR 2002 cannot connect")
            if "gtid_binlog_state, @@gtid_slave_pos" in asked:
                out = f"{self.holder_state}\t{self.holder_pos}\n"
            elif "USER_PRIVILEGES" in asked:
                out = "SELECT\nREPLICATION SLAVE\nSHOW VIEW\nEVENT\nTRIGGER\n"
            elif "mysql.user" in asked:
                out = "root\tlocalhost\tN\n"
            else:
                out = "keel:account\n"
        elif "SHOW REPLICA STATUS" in asked:
            out = self.status()
        elif asked == "SELECT @@log_bin":
            out = f"{self.log_bin}\n"
        elif "gtid_binlog_state, @@gtid_slave_pos" in asked:
            out = f"{self.binlog_state}\t{self.slave_pos}\n"
        elif "gtid_binlog_state, @@gtid_binlog_pos" in asked:
            out = f"{self.binlog_state}\t{self.binlog_pos}\n"
        elif "SCHEMATA" in asked:
            out = "information_schema\nmysql\n" + self.schemas
        elif "READ_ONLY ADMIN" in asked:
            out = self.bypass
        elif "mysql.user" in asked:
            out = "root\tlocalhost\nadmin\tlocalhost\n"
        elif "Rpl_semi_sync" in asked:
            # the turns are follow's wait (keel#242), not inspect's read
            waits = "yes_tx" not in asked
            clients = self.clients.pop(0) if waits and self.clients else 1
            out = (f"Rpl_semi_sync_master_status\t"
                   f"{'ON' if clients else 'OFF'}\n"
                   f"Rpl_semi_sync_master_clients\t{clients}\n")
        elif "Variable_name IN" in asked:
            out = (f"log_bin\tON\nport\t3306\nserver_id\t1\nwsrep_on\tOFF\n"
                   f"read_only\t{self.read_only}\n")
        elif "SHOW REPLICA HOSTS" in asked:
            out = ""
        elif "Repl_slave_priv" in asked:
            out = f"localhost\n{address(1)}\n"
        elif "@@gtid_binlog_pos, @@gtid_slave_pos" in asked:
            out = f"{self.binlog_pos}\t\t{self.binlog_pos}\t{self.binlog_state}\n"
        elif argv[:2] == ["ss", "-lntH"]:
            out = f"LISTEN 0 80 [{address(1)}]:3306 [::]:*\n"
        if kwargs.get("text"):
            return subprocess.CompletedProcess(argv, 0, out, "")
        return subprocess.CompletedProcess(argv, 0, out.encode(), b"")


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
        for index, server in ((0, PRIMARY_SPEC), (1, REPLICA_SPEC)):
            here = self.all[index]
            doc = here.node.document()
            doc["database"] = {"server": dict(server)}
            here.node.write(doc)
            dbsecret.keep(here.root, "pw")
            binary = os.path.join(here.root, "usr/sbin/mariadbd")
            os.makedirs(os.path.dirname(binary), exist_ok=True)
            with open(binary, "w"):
                pass
            for relative in ("var/tmp", "var/lib/mysql"):
                os.makedirs(os.path.join(here.root, relative), exist_ok=True)
            for name in (dbtls.CA, dbtls.CERT, dbtls.KEY, dbtls.CRL):
                target = os.path.join(here.root, name)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w") as fob:
                    fob.write("x")
        if claim is not None:
            vippromote.promote(self.all[claim], False,
                               self.said[claim].append)

    def follow(self, index: int, server: Server, confirmed: bool = False,
               live: bool = True, wait: float = 0.0,
               nothing_without_vip: bool = False) -> dbfollow.Followed:
        here = self.all[index]
        found = dbfollow.Followed()
        found.nothing_without_vip = nothing_without_vip
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
                mock.patch("keel.system.dbreadonly.subprocess.run", server), \
                mock.patch.object(self.all[index].node, "overlay",
                                  wraps=self.all[index].node.overlay), \
                mock.patch.object(dbfollow, "_here", return_value=here):
            # _here: this node on the fixture's members' channel, never
            # the real network (keel#154: follow asks the other members)
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


class TestThePrimary(FollowTestCase):
    def test_a_writable_server_that_holds_the_vip_is_left_alone(self):
        self.pair_nodes()
        found = self.follow(0, Server())
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("unchanged (the primary, writable)", found.lines)
        self.assertIn("primary", self.role_file(0))
        # the drop-in keeps the server read only at its next boot too:
        # a crashed old primary takes no write before follow runs
        with open(os.path.join(self.all[0].root, mariadb.ROLE_DROPIN)) as f:
            self.assertIn("read_only = ON", f.read())

    def test_a_read_only_holder_is_made_writable(self):
        self.pair_nodes()
        server = Server(read_only="ON")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("SET GLOBAL read_only = OFF;\n", server.sent)
        self.assertEqual(server.argv[-1][:4], ["runuser", "-u", "mysql", "--"])

    def test_a_restarted_holder_takes_no_write_before_its_replica_is_back(
            self):
        # keel#242: the primary's server killed and started again while it
        # holds the VIP. Writable before the replica reconnects, it
        # acknowledged a commit with no copy (wait_no_slave OFF)
        self.pair_nodes()
        server = Server(read_only="ON", clients=(0, 0, 0, 1))
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        semi = [i for i, one in enumerate(server.events)
                if one == dbfollow.SEMI_SYNC_QUESTION[-1]]
        off = server.events.index("SET GLOBAL read_only = OFF;\n")
        # four reads, the last one found the replica back, and only then
        # read_only went off
        self.assertEqual(len(semi), 4, server.events)
        self.assertGreater(off, semi[-1])
        self.assertNotIn(dbfollow.NO_REPLICA.format(
            wait=dbfollow.REPLICA_WAIT), found.lines)

    def test_a_holder_whose_replica_stays_away_takes_writes_after_the_wait(
            self):
        self.pair_nodes()
        turns = int(dbfollow.REPLICA_WAIT / dbfollow.REPLICA_POLL) + 1
        server = Server(read_only="ON", clients=(0,) * turns)
        started = self.monotonic()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("SET GLOBAL read_only = OFF;\n", server.sent)
        self.assertIn(dbfollow.NO_REPLICA.format(wait=dbfollow.REPLICA_WAIT),
                      found.lines)
        self.assertGreaterEqual(self.monotonic() - started,
                                dbfollow.REPLICA_WAIT)

    def test_a_holder_that_lost_the_vip_while_it_waited_stays_read_only(self):
        self.pair_nodes()
        turns = int(dbfollow.REPLICA_WAIT / dbfollow.REPLICA_POLL) + 1
        server = Server(read_only="ON", clients=(0,) * turns)
        with mock.patch.object(dbfollow, "_proven",
                               side_effect=[True, False, False]):
            found = self.follow(0, server)
        self.assertNotIn("SET GLOBAL read_only = OFF;\n", server.sent)
        self.assertTrue(any("not proven" in one for one in found.lines),
                        found.lines)

    def test_a_replica_that_takes_the_vip_is_drained_and_promoted(self):
        self.pair_nodes()
        server = Server(replicating_from=address(1), read_only="ON")
        with open(os.path.join(self.all[0].root, "x"), "w"):
            pass
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("drained and promoted", " ".join(found.lines))
        self.assertIn("STOP SLAVE IO_THREAD", [one[-1] for one in
                                               server.argv])
        # writable once drained, the primary forgotten after
        sent = "".join(server.sent)
        self.assertLess(sent.index("read_only = OFF"),
                        sent.index("RESET SLAVE ALL"))

    def test_the_privilege_goes_back_to_what_the_replica_took_it_from(self):
        self.pair_nodes()
        record = os.path.join(self.all[0].root, dbfollow.dbreadonly.RECORD)
        os.makedirs(os.path.dirname(record), exist_ok=True)
        with open(record, "w") as fob:
            fob.write("root\tlocalhost\nadmin\tlocalhost\n")
        server = Server()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(any("GRANT READ_ONLY ADMIN ON *.* TO"
                            " 'root'@'localhost'" in one
                            for one in server.sent))
        self.assertFalse(os.path.exists(record))


class TestTheReplica(FollowTestCase):
    def test_a_server_with_no_binary_log_is_not_seeded_yet(self):
        # keel#202: the follow that the VIP's promotion starts on the
        # replica runs before keel spec apply writes the pair's
        # configuration. A copy loaded then cannot carry the binary log
        # history of the primary, which the old primary needs to rejoin.
        # The apply seeds it after the restart that turns the log on.
        self.pair_nodes()
        server = Server(schemas="", log_bin="0")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        joined = "\n".join(found.lines)
        self.assertIn("binary log", joined)
        self.assertNotIn("seeded from", joined)
        self.assertFalse(any(one[0] == "mariadb-dump" for one in server.argv))
        self.assertFalse(any("CHANGE MASTER" in one for one in server.sent))

    def test_a_fresh_server_is_made_read_only_locked_and_seeded(self):
        self.pair_nodes()
        server = Server(schemas="")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        joined = "\n".join(found.lines)
        self.assertIn("set read_only ON", joined)
        self.assertIn(f"seeded from [{address(0)}]:3306", joined)
        self.assertTrue(any("REVOKE READ_ONLY ADMIN ON *.* FROM"
                            " 'root'@'localhost'" in one
                            for one in server.sent))
        change = next(one for one in server.sent if "CHANGE MASTER" in one)
        self.assertIn(f"MASTER_HOST='{address(0)}'", change)
        self.assertIn("MASTER_SSL=1", change)
        self.assertIn("MASTER_SSL_VERIFY_SERVER_CERT=1", change)
        self.assertIn("role=replica", self.role_file(1))
        with open(os.path.join(self.all[1].root, mariadb.ROLE_DROPIN)) as f:
            self.assertIn("read_only = ON", f.read())
        dump = next(one for one in server.argv if one[0] == "mariadb-dump")
        self.assertTrue(any(one.startswith("--defaults-extra-file")
                            for one in dump))

    def test_a_replica_of_the_holder_is_left_alone(self):
        self.pair_nodes()
        found = self.follow(1, Server(replicating_from=address(0),
                                      read_only="ON"))
        self.assertIsNone(found.problem, found.lines)
        self.assertIn(f"unchanged (a replica of [{address(0)}]:3306)",
                      found.lines)

    def test_an_old_primary_with_nothing_errant_rejoins_by_gtid(self):
        self.pair_nodes()
        server = Server(read_only="OFF", binlog_state="0-2-20",
                        binlog_pos="0-2-20", holder_state="0-1-5,0-2-20")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        joined = "\n".join(found.lines)
        self.assertIn("a dump of what this node holds is kept at", joined)
        self.assertIn("rejoined: no errant GTID", joined)
        change = next(one for one in server.sent if "CHANGE MASTER" in one)
        self.assertIn("SET GLOBAL gtid_slave_pos = '0-2-20';", change)
        self.assertIn(f"MASTER_HOST='{address(0)}'", change)
        kept = os.listdir(os.path.join(self.all[1].root, dbfollow.BACKUPS))
        self.assertTrue(kept[0].startswith("rejoin-"), kept)
        self.assertIsNone(dbfollow.diverged(self.all[1].root))

    def test_an_old_primary_with_errant_gtids_stays_read_only_and_alerts(
            self):
        self.pair_nodes()
        server = Server(binlog_state="0-2-25", binlog_pos="0-2-25",
                        holder_state="0-1-5,0-2-20")
        with mock.patch("keel.monitor.alerting.alert",
                        return_value=True) as alerted:
            found = self.follow(1, server)
        self.assertIn("diverged", found.problem)
        self.assertIn("domain 0, server id 2, up to sequence 25",
                      found.problem)
        self.assertFalse(any("CHANGE MASTER" in one for one in server.sent))
        self.assertTrue(any("read_only = ON" in one for one in server.sent))
        recorded = dbfollow.diverged(self.all[1].root)
        self.assertEqual(recorded["errant"], ["0-2-25"])
        self.assertEqual(recorded["holder"], address(0))
        self.assertEqual(alerted.call_count, 1)
        self.assertIn("stays read only", alerted.call_args.args[2])
        # a second run alerts no more, and the status and inspect see it
        with mock.patch("keel.monitor.alerting.alert") as alerted:
            self.follow(1, server)
        alerted.assert_not_called()
        from keel.inspect import collect
        # the second run refreshed the record's "at" (it is when the
        # divergence was last seen, keel#129): what stays stable is what
        # the record says, not when it last said it
        seen = collect.divergence(collect.Tree(self.all[1].root))
        self.assertEqual({key: seen[key] for key in ("errant", "holder")},
                         {key: recorded[key] for key in ("errant", "holder")})

    def test_confirmed_the_errant_node_is_reseeded_after_a_dump(self):
        self.pair_nodes()
        server = Server(binlog_state="0-2-25", holder_state="0-2-20")
        found = self.follow(1, server, confirmed=True)
        self.assertIsNone(found.problem, found.lines)
        joined = "\n".join(found.lines)
        self.assertIn("errant GTID(s) discarded", joined)
        self.assertIn("seeded from", joined)
        self.assertTrue(any("DROP DATABASE IF EXISTS `shop`" in one
                            for one in server.sent))

    def test_a_dump_that_cannot_be_kept_stops_the_rejoin(self):
        self.pair_nodes()
        server = Server(dump_fails=True)
        found = self.follow(1, server)
        self.assertIn("not kept", found.problem)
        self.assertFalse(any("CHANGE MASTER" in one for one in server.sent))

    def test_a_holder_that_does_not_answer_changes_nothing(self):
        self.pair_nodes()
        found = self.follow(1, Server(holder_down=True))
        self.assertIn("did not answer its GTID state", found.problem)

    def test_a_stopped_sql_thread_waits_for_the_operator(self):
        self.pair_nodes()
        found = self.follow(1, Server(replicating_from=address(0),
                                      sql_running="No"))
        self.assertIn("SQL thread stopped", found.problem)

    def test_without_the_certificate_or_the_credential_nothing_follows(self):
        self.pair_nodes()
        os.remove(os.path.join(self.all[1].root, dbtls.KEY))
        found = self.follow(1, Server(schemas=""))
        self.assertIn("certificate is not in place", found.problem)

    def test_a_node_with_no_vip_that_asks_for_it_has_nothing_to_follow(self):
        """keel#211: the command and the unit are not a failure there; a
        spec apply that declares a role still refuses (above)"""
        self.nodes(vips=(None, None), paired=False)
        found = self.follow(2, Server(), nothing_without_vip=True)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(any("nothing to follow" in line
                            for line in found.lines), found.lines)

    def test_a_node_in_no_pair_or_with_no_claim_says_so(self):
        self.nodes(vips=(None, None), paired=False)
        found = self.follow(2, Server())
        self.assertIn("declares no appliance.vip", found.problem)
        self.pair_nodes(claim=None)
        # no claim on a paired node: the declared primary is not proven,
        # so it stays read only until a claim is (keel#104)
        server = Server()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("SET GLOBAL read_only = ON;\n", server.sent)
        self.assertIn("holds no claim", "\n".join(found.lines))
        self.assertNotIn("role=primary", self.role_file(0))

    def test_followed_is_the_effects_face_of_follow(self):
        self.pair_nodes()
        here = self.all[0]
        with mock.patch.object(dbfollow, "follow") as inner:
            self.assertIsNone(dbfollow.followed(here.root, here.node.path))
        inner.assert_called_once()


class TestTheFenceOfACaughtUpReplica(FollowTestCase):
    """keel#192: the VIP fence of a replica that rejoined or was reseeded
    is cleared once it applied everything the holder logged, as keel#166
    does for PostgreSQL; before, a MariaDB pair failed over once only"""

    def fence_vip(self, index: int) -> None:
        from dataclasses import replace

        from keel.mesh import vip as vipstate
        from keel.mesh import vipnode
        held = vipnode.current(self.all[index], VIP)
        vipstate.write(self.all[index].root, replace(held, fenced=True))

    def fenced(self, index: int) -> bool:
        from keel.mesh import vipnode
        return vipnode.current(self.all[index], VIP).fenced

    def test_a_replica_caught_up_with_the_holder_is_unfenced(self):
        self.pair_nodes()
        self.fence_vip(1)
        # reseeded: the dump's position is the slave position, the
        # holder's older GTIDs of another server id are not in the binlog
        server = Server(replicating_from=address(0), read_only="ON",
                        binlog_state="0-2-3", slave_pos="0-1-30",
                        holder_state="0-2-7,0-1-30")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(self.fenced(1))
        self.assertIn(dbfollow.UNFENCED_SAID, found.lines)

    def test_a_replica_behind_the_holder_stays_fenced(self):
        self.pair_nodes()
        self.fence_vip(1)
        server = Server(replicating_from=address(0), read_only="ON",
                        binlog_state="0-2-3", slave_pos="0-1-29",
                        holder_state="0-2-7,0-1-30")
        found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(self.fenced(1))
        self.assertNotIn(dbfollow.UNFENCED_SAID, found.lines)

    def test_a_holder_that_does_not_answer_keeps_the_fence(self):
        self.pair_nodes()
        self.fence_vip(1)
        server = Server(replicating_from=address(0), read_only="ON",
                        slave_pos="0-1-30", holder_down=True)
        found = self.follow(1, server)
        self.assertTrue(self.fenced(1))

    def test_a_replica_whose_sql_thread_stopped_stays_fenced(self):
        self.pair_nodes()
        self.fence_vip(1)
        server = Server(replicating_from=address(0), read_only="ON",
                        sql_running="No", slave_pos="0-1-30",
                        holder_state="0-1-30")
        self.follow(1, server)
        self.assertTrue(self.fenced(1))

    def test_the_watch_follows_a_fenced_replica_of_either_engine(self):
        from keel.inspect.dbreading import Reading, Value
        root = self.enterContext(__import__("tempfile").TemporaryDirectory())
        os.makedirs(os.path.join(root, "var/lib/keel"))
        with open(os.path.join(root, dbpair.ROLE_FILE), "w") as fob:
            fob.write(dbpair.role_text("replica", VIP))
        fenced = dbpair.PairState(VIP, KEYS[1], KEYS[0], address(0),
                                  "replica", address(0), fenced=True)
        replicates = Reading(role=Value("replica"), read_only=Value(True),
                             primary=Value({"host": address(0),
                                            "port": 3306}))
        maria = {"database": {"server": {"engine": "mariadb"}}}
        self.assertTrue(dbwatch.needs_follow(root, fenced, replicates,
                                             maria))


class TestTheOldPrimaryAtBoot(FollowTestCase):
    """keel#104: a stale claim of its own never makes a server writable.
    The node is read only from its first second (the role's drop-in),
    and read_only goes off only once the VIP is on wg0, which keel puts
    there only after a proof: a peer's answer and no newer claim (keel
    vip check), the node's own fresh claim (keel vip promote), or, with
    etcd, a renewal of its lease the majority confirmed"""

    def booted(self, index: int) -> None:
        """The node crashed and booted: wg0 lost every address"""
        self.nets[index].addresses.clear()

    def no_write_taken(self, server: Server) -> None:
        self.assertFalse(any("read_only = OFF" in one for one in server.sent),
                         server.sent)

    def test_crashed_another_promoted_it_stays_read_only_then_follows(self):
        # the tester's mesh: a cloud simple pair, no etcd
        self.pair_nodes(mode="cloud_simple")
        a, b = self.all[0], self.all[1]
        # A crashes; B is promoted at a newer epoch with A gone
        self.down.add(address(0))
        said: list[str] = []
        self.assertEqual(vippromote.promote(b, True, said.append), 0, said)
        self.assertTrue(self.carried(1))
        # A boots: its file still says it holds epoch 1, unfenced
        self.down.discard(address(0))
        self.booted(0)
        # no other member answers yet: follow asks them first without
        # etcd (keel#154), and an answer with no newer claim proves it
        self.down.update({address(1), address(2)})
        self.assertEqual(dbpair.observe_pair(a.root, a.node.document()).role,
                         dbpair.PRIMARY)
        server = Server(read_only="ON")
        found = self.follow(0, server, wait=3.0)
        self.assertIsNone(found.problem, found.lines)
        self.no_write_taken(server)
        joined = "\n".join(found.lines)
        self.assertIn("not proven", joined)
        self.assertNotIn("role=primary", self.role_file(0))
        # READ_ONLY ADMIN taken too: root writes nothing either
        self.assertTrue(any("REVOKE READ_ONLY ADMIN" in one
                            for one in server.sent), server.sent)
        # it waited for a proof, polling, and none came
        self.assertGreaterEqual(self.monotonic(), 1003.0)
        # keel vip check learns epoch 2: A is fenced, then a replica of B
        self.down.clear()
        vippromote.check(a, lambda line: None)
        self.assertFalse(self.carried(0))
        server = Server(read_only="ON", binlog_state="0-1-10",
                        binlog_pos="0-1-10", holder_state="0-1-10,0-2-20")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.no_write_taken(server)
        joined = "\n".join(found.lines)
        self.assertIn(f"rejoined: no errant GTID, replicating from"
                      f" [{address(1)}]:3306", joined)
        self.assertIn("role=replica", self.role_file(0))

    def test_without_etcd_follow_learns_the_newer_claim_by_itself(self):
        """keel#154: without etcd nothing ran keel vip check, so the old
        primary never learned the newer claim. Follow asks the other
        members first and rejoins in the same run"""
        self.pair_nodes(mode="cloud_simple")
        self.down.add(address(0))
        self.assertEqual(vippromote.promote(self.all[1], True,
                                            lambda line: None), 0)
        self.down.discard(address(0))
        self.booted(0)
        server = Server(read_only="ON", binlog_state="0-1-10",
                        binlog_pos="0-1-10", holder_state="0-1-10,0-2-20")
        found = self.follow(0, server, wait=3.0)
        self.assertIsNone(found.problem, found.lines)
        self.no_write_taken(server)
        joined = "\n".join(found.lines)
        self.assertIn("took epoch 2", joined)
        self.assertNotIn("not proven", joined)
        self.assertIn("role=replica", self.role_file(0))

    def test_a_server_found_writable_without_a_proof_is_made_read_only(self):
        self.pair_nodes(mode="cloud_simple")
        self.booted(0)
        # no other member answers yet: follow asks them first without
        # etcd (keel#154), and an answer with no newer claim proves it
        self.down.update({address(1), address(2)})
        server = Server(read_only="OFF")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("SET GLOBAL read_only = ON;\n", server.sent)
        self.no_write_taken(server)

    def test_the_holder_proven_again_after_its_boot_takes_writes(self):
        self.pair_nodes(mode="cloud_simple")
        self.booted(0)
        # no other member answers yet: follow asks them first without
        # etcd (keel#154), and an answer with no newer claim proves it
        self.down.update({address(1), address(2)})
        server = Server(read_only="ON")
        self.follow(0, server)
        self.no_write_taken(server)
        # nobody promoted: a peer answers, none knows a newer claim, and
        # keel vip check carries the VIP again
        self.down.clear()
        vippromote.check(self.all[0], lambda line: None)
        self.assertTrue(self.carried(0))
        server = Server(read_only="ON")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("SET GLOBAL read_only = OFF;\n", server.sent)
        self.assertIn("primary", self.role_file(0))

    def test_no_peer_answers_at_boot_it_stays_read_only(self):
        self.pair_nodes(mode="cloud_simple")
        self.booted(0)
        self.down.update({address(1), address(2)})
        vippromote.check(self.all[0], lambda line: None)
        server = Server(read_only="ON")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.no_write_taken(server)

    def test_a_proof_that_comes_while_follow_waits_is_taken(self):
        """keel vip promote records its claim, then carries the VIP: the
        follow its record started waits for the address"""
        self.pair_nodes(mode="cloud_simple")
        self.booted(0)
        net = self.nets[0]
        polls: list[str] = []
        real = net.output

        def output(argv):
            polls.append(argv[0])
            if len(polls) == 2:
                net.addresses.append(f"{VIP}/128")
            return real(argv)
        net.output = output
        server = Server(read_only="ON")
        found = self.follow(0, server, wait=5.0)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("SET GLOBAL read_only = OFF;\n", server.sent)

    def test_with_etcd_unreachable_at_boot_it_stays_read_only(self):
        from keel.mesh import etcdstate, vipetcd
        from keel.mesh.etcdstate import Cluster, Member
        from vip_helpers import KEYS as keys
        self.pair_nodes(claim=None, etcd="enabled")
        cluster = Cluster("new", tuple(Member(keys[i], address(i))
                                       for i in range(3)),
                          bytes(range(16)).hex())
        for one in self.all:
            etcdstate.save_cluster(one.root, cluster)
        a = self.all[0]
        controller = vipetcd.Controller(
            vipetcd.Ops(a), lambda: self.kv, __import__("threading").Event(),
            self.said[0].append, self.monotonic, lambda *args: None)
        with mock.patch.object(vippromote, "carried_soon",
                               return_value=True):
            vippromote.promote(a, False, self.said[0].append)
        self.assertIsNotNone(vipstate_read(a).lease)
        # A boots and etcd answers nothing: no renewal, nothing carried
        self.booted(0)
        self.kv.refuse = "all"
        for _ in range(3):
            self.sleep(vipetcd.RENEW)
            controller.holding()
        self.assertFalse(self.carried(0))
        server = Server(read_only="ON")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.no_write_taken(server)
        self.assertIn("not proven", "\n".join(found.lines))
        # etcd back, the lease renewed by the majority: proven
        self.kv.refuse = None
        self.sleep(vipetcd.RENEW)
        controller.holding()
        self.sleep(vipetcd.RENEW)
        controller.holding()
        self.assertTrue(self.carried(0))
        server = Server(read_only="ON")
        found = self.follow(0, server)
        self.assertIn("SET GLOBAL read_only = OFF;\n", server.sent)


class TestTheHolderInDoubt(FollowTestCase):
    """keel#195: a holder whose lease has no renewal the majority
    confirmed for vipetcd.DOUBT s may be cut off; a write that waits for
    the replica there returns OK when the dump thread to it ends, before
    the release. So follow fences the server while the mark is there,
    and the watch does not lift it"""

    def mark(self, index: int, on: bool = True) -> None:
        from keel.mesh import vip as vipstate
        vipstate.mark_unconfirmed(self.all[index].root, VIP, on)

    def test_a_writable_holder_in_doubt_is_fenced(self):
        self.pair_nodes()
        self.mark(0)
        server = Server()
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("SET GLOBAL read_only = ON;\n", server.sent)
        self.assertNotIn("SET GLOBAL read_only = OFF;\n", server.sent)
        self.assertIn("keel#195", " ".join(found.lines))

    def test_a_read_only_holder_in_doubt_stays_read_only(self):
        self.pair_nodes()
        self.mark(0)
        server = Server(read_only="ON")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertNotIn("SET GLOBAL read_only = OFF;\n", server.sent)

    def test_once_confirmed_the_holder_is_writable_again(self):
        self.pair_nodes()
        self.mark(0)
        self.mark(0, False)
        server = Server(read_only="ON")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertIn("SET GLOBAL read_only = OFF;\n", server.sent)

    def test_the_watch_follows_a_writable_holder_in_doubt_only(self):
        from keel.inspect.dbreading import Reading, Value
        from keel.mesh import vip as vipstate
        root = self.enterContext(__import__("tempfile").TemporaryDirectory())
        os.makedirs(os.path.join(root, "var/lib/keel"))
        with open(os.path.join(root, dbpair.ROLE_FILE), "w") as fob:
            fob.write(dbpair.role_text("primary", VIP))
        holder = dbpair.PairState(VIP, KEYS[0], KEYS[1], address(1),
                                  "primary", address(0))
        doc = {"database": {"server": {"engine": "mariadb"}}}
        writable = Reading(role=Value("primary"), read_only=Value(False))
        fenced = Reading(role=Value("primary"), read_only=Value(True))
        vipstate.mark_unconfirmed(root, VIP, True)
        self.assertTrue(dbwatch.needs_follow(root, holder, writable, doc))
        self.assertFalse(dbwatch.needs_follow(root, holder, fenced, doc))


class TestNoClaimAndNoAddress(FollowTestCase):
    """The security review of keel#104: no claim is no proof, a VIP gone
    from wg0 is followed again, and two runs never interleave"""

    def test_a_primary_whose_vip_state_file_was_removed_stays_read_only(
            self):
        self.pair_nodes(mode="cloud_simple")
        a = self.all[0]
        from keel.mesh import vip as vipstate
        # docs tell the operator to remove a damaged file; the pair
        # record stays, and the address is still on wg0
        os.remove(os.path.join(a.root, vipstate.file_of(VIP)))
        self.assertTrue(self.carried(0))
        pair = dbpair.observe_pair(a.root, a.node.document())
        self.assertFalse(pair.claimed)
        self.assertIsNotNone(pair.peer_key)
        server = Server(read_only="ON")
        found = self.follow(0, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(any("read_only = OFF" in one for one in server.sent))
        self.assertNotIn("role=primary", self.role_file(0))
        # and watch follows a server that is writable with no claim
        from keel.inspect.dbreading import Reading, Value
        writable = Reading(role=Value("standalone"), read_only=Value(False))
        read_only = Reading(role=Value("standalone"), read_only=Value(True))
        doc = a.node.document()
        self.assertTrue(dbwatch.needs_follow(a.root, pair, writable, doc,
                                             self.nets[0].output))
        self.assertFalse(dbwatch.needs_follow(a.root, pair, read_only, doc,
                                              self.nets[0].output))
        self.assertFalse(dbwatch.needs_follow(
            a.root, dbpair.PairState(VIP, KEYS[0]), writable, doc,
            self.nets[0].output))

    def test_watch_follows_a_writable_primary_whose_vip_left_wg0(self):
        from keel.inspect.dbreading import Reading, Value
        self.pair_nodes()
        a = self.all[0]
        self.follow(0, Server(read_only="ON"))
        self.assertIn("primary", self.role_file(0))
        pair = dbpair.observe_pair(a.root, a.node.document())
        doc = a.node.document()
        writable = Reading(role=Value("standalone"), read_only=Value(False))
        self.assertFalse(dbwatch.needs_follow(a.root, pair, writable, doc,
                                              self.nets[0].output))
        # the kernel ended the address (valid_lft): follow again, and
        # follow makes it read only
        self.nets[0].addresses.clear()
        self.assertTrue(dbwatch.needs_follow(a.root, pair, writable, doc,
                                             self.nets[0].output))
        # no other member answers yet: follow asks them first without
        # etcd (keel#154), and an answer with no newer claim proves it
        self.down.update({address(1), address(2)})
        server = Server(read_only="OFF")
        self.follow(0, server)
        self.assertIn("SET GLOBAL read_only = ON;\n", server.sent)

    def test_follow_runs_under_its_lock(self):
        import fcntl
        self.pair_nodes()
        taken: list[int] = []
        real = fcntl.flock

        def flock(fd, how):
            taken.append(how)
            return real(fd, how)
        with mock.patch.object(dbfollow.dbreadonly.fcntl, "flock",
                               side_effect=flock):
            self.follow(0, Server())
        self.assertEqual(taken, [fcntl.LOCK_EX])
        self.assertTrue(os.path.exists(os.path.join(
            self.all[0].root, dbfollow.FOLLOW_LOCK)))


def vipstate_read(here):
    from keel.mesh import vip as vipstate
    return vipstate.read(here.root, VIP)


class TestWatch(FollowTestCase):
    def test_the_fallback_and_the_recovery_are_alerted_once_each(self):
        self.pair_nodes()
        here = self.all[0]
        answers = {"status": "ON"}

        def server(argv, **kwargs):
            asked = argv[-1] if "--execute" in argv else ""
            out = ""
            if "Rpl_semi_sync" in asked:
                out = f"Rpl_semi_sync_master_status\t{answers['status']}\n"
            elif "Variable_name IN" in asked:
                out = ("log_bin\tON\nport\t3306\nserver_id\t1\nwsrep_on\tOFF\n"
                       "read_only\tOFF\n")
            elif "Repl_slave_priv" in asked:
                out = f"{address(1)}\n"
            return subprocess.CompletedProcess(argv, 0, out, "")
        said: list[str] = []
        with mock.patch("keel.inspect.collect.paths.ROOT_DEFAULT",
                        here.root), \
                mock.patch("keel.inspect.collect.subprocess.run", server), \
                mock.patch("keel.system.dbwatch.certificate",
                           return_value=True), \
                mock.patch("keel.system.dbwatch.needs_follow",
                           return_value=False), \
                mock.patch("keel.monitor.alerting.alert") as alerted:
            dbwatch.watch(here.root, here.node.path, said.append,
                          said.append)
            alerted.assert_not_called()
            answers["status"] = "OFF"
            dbwatch.watch(here.root, here.node.path, said.append,
                          said.append)
            self.assertEqual(alerted.call_count, 1)
            self.assertIn("fell back", alerted.call_args.args[2])
            dbwatch.watch(here.root, here.node.path, said.append,
                          said.append)
            self.assertEqual(alerted.call_count, 1)
            answers["status"] = "ON"
            dbwatch.watch(here.root, here.node.path, said.append,
                          said.append)
            self.assertEqual(alerted.call_count, 2)
            self.assertIn("is back", alerted.call_args.args[2])
            self.assertEqual(alerted.call_args.args[5], "recovery")
        with open(os.path.join(here.root, dbwatch.STATE)) as fob:
            self.assertEqual(json.load(fob)["semi_sync"], "on")
        self.assertTrue(any("semi-synchronous on" in one for one in said))
        # off at the pair's first watch is alerted at once, and the
        # recovery never before an off was seen
        os.remove(os.path.join(here.root, dbwatch.STATE))
        answers["status"] = "OFF"
        with mock.patch("keel.inspect.collect.paths.ROOT_DEFAULT",
                        here.root), \
                mock.patch("keel.inspect.collect.subprocess.run", server), \
                mock.patch("keel.system.dbwatch.certificate",
                           return_value=True), \
                mock.patch("keel.system.dbwatch.needs_follow",
                           return_value=False), \
                mock.patch("keel.monitor.alerting.alert") as alerted:
            dbwatch.watch(here.root, here.node.path, said.append,
                          said.append)
            self.assertEqual(alerted.call_count, 1)
            self.assertIn("fell back", alerted.call_args.args[2])

    def test_a_pending_file_flip_is_followed_again(self):
        self.pair_nodes()
        here = self.all[0]
        with mock.patch("keel.system.dbwatch.certificate",
                        return_value=True), \
                mock.patch("keel.system.dbwatch.semi_sync",
                           return_value=None), \
                mock.patch("keel.system.filesync.flip_pending",
                           return_value=True), \
                mock.patch("keel.system.filesync_watch.watch_counts"), \
                mock.patch.object(dbfollow, "follow") as followed:
            code = dbwatch.watch(here.root, here.node.path, lambda x: None,
                                 lambda x: None)
        followed.assert_called_once()
        self.assertEqual(code, 0)

    def test_nothing_is_followed_when_nothing_is_pending(self):
        self.pair_nodes()
        here = self.all[0]
        with mock.patch("keel.system.dbwatch.certificate",
                        return_value=True), \
                mock.patch("keel.system.dbwatch.semi_sync",
                           return_value=None), \
                mock.patch("keel.system.filesync.flip_pending",
                           return_value=False), \
                mock.patch("keel.system.filesync_watch.watch_counts"), \
                mock.patch.object(dbfollow, "follow") as followed:
            dbwatch.watch(here.root, here.node.path, lambda x: None,
                          lambda x: None)
        followed.assert_not_called()

    def test_the_file_replication_alert_goes_through_the_channels(self):
        self.pair_nodes()
        here = self.all[0]

        def watch_counts(root, doc, out, deliver):
            self.assertTrue(deliver("title", "text", "filesync-counts",
                                    "critical"))

        with mock.patch("keel.system.dbwatch.certificate",
                        return_value=True), \
                mock.patch("keel.system.dbwatch.semi_sync",
                           return_value=None), \
                mock.patch("keel.system.filesync_watch.watch_counts",
                           watch_counts), \
                mock.patch("keel.monitor.alerting.alert",
                           return_value=True) as alerted:
            dbwatch.watch(here.root, here.node.path, lambda x: None,
                          lambda x: None)
        self.assertEqual(alerted.call_args.args[2:],
                         ("title", "text", "filesync-counts", "critical"))

    def test_a_node_in_no_pair_has_nothing_to_watch(self):
        self.nodes(vips=(None, None), paired=False)
        said: list[str] = []
        here = self.all[2]
        self.assertEqual(dbwatch.watch(here.root, here.node.path, said.append,
                                       said.append), 0)
        self.assertIn("nothing to watch", said[0])

    def test_needs_follow_when_the_server_disagrees_with_the_vip(self):
        from keel.inspect.dbreading import Reading, Value
        pair = dbpair.PairState(VIP, KEYS[1], KEYS[0], address(0), "replica",
                                address(0))
        root = self.enterContext(__import__("tempfile").TemporaryDirectory())
        standalone = Reading(role=Value("standalone"), read_only=Value(False))
        self.assertTrue(dbwatch.needs_follow(root, pair, standalone, {}))
        os.makedirs(os.path.join(root, "var/lib/keel"))
        with open(os.path.join(root, dbpair.ROLE_FILE), "w") as fob:
            fob.write(dbpair.role_text("replica", VIP))
        self.assertTrue(dbwatch.needs_follow(root, pair, standalone, {}))
        replica = Reading(role=Value("replica"), read_only=Value(True))
        self.assertFalse(dbwatch.needs_follow(root, pair, replica, {}))
        primary = dbpair.PairState(VIP, KEYS[0], KEYS[1], address(1),
                                   "primary", address(0))
        with open(os.path.join(root, dbpair.ROLE_FILE), "w") as fob:
            fob.write(dbpair.role_text("primary", VIP))
        self.assertTrue(dbwatch.needs_follow(root, primary, replica, {}))
        self.assertFalse(dbwatch.needs_follow(root, primary, standalone, {}))
        self.assertFalse(dbwatch.needs_follow(
            root, dbpair.PairState(VIP, KEYS[0]), standalone, {}))

    def test_needs_follow_on_a_stopped_server_that_carries_the_vip(self):
        """keel#168: the holder's server was stopped while the VIP was
        off wg0, and stayed stopped after the VIP came back: the watch
        followed only a server that answered"""
        from keel.inspect.dbreading import Reading, Value
        root = self.enterContext(__import__("tempfile").TemporaryDirectory())
        os.makedirs(os.path.join(root, "var/lib/keel"))
        with open(os.path.join(root, dbpair.ROLE_FILE), "w") as fob:
            fob.write(dbpair.role_text("primary", VIP))
        primary = dbpair.PairState(VIP, KEYS[0], KEYS[1], address(1),
                                   "primary", address(0))
        stopped = Reading(role=Value(problem="no socket"))
        writable = Reading(role=Value("primary"), read_only=Value(False))
        doc = {"network": {"overlay": {"wireguard": {}}}}

        def carried(argv):
            return f"5: wg0    inet6 {VIP}/128 scope global\n"
        self.assertTrue(dbwatch.needs_follow(root, primary, stopped, doc,
                                             output=carried))
        self.assertFalse(dbwatch.needs_follow(root, primary, writable, doc,
                                              output=carried))

    def test_needs_follow_on_a_fenced_postgresql_standby(self):
        """keel#166: a fenced replica that streams is followed again, so
        follow clears the fence once it caught up; one that follows
        nobody is not"""
        from keel.inspect.dbreading import Reading, Value
        root = self.enterContext(__import__("tempfile").TemporaryDirectory())
        os.makedirs(os.path.join(root, "var/lib/keel"))
        with open(os.path.join(root, dbpair.ROLE_FILE), "w") as fob:
            fob.write(dbpair.role_text("replica", VIP))
        fenced = dbpair.PairState(VIP, KEYS[1], KEYS[0], address(0),
                                  "replica", address(0), fenced=True)
        streams = Reading(role=Value("replica"), read_only=Value(True),
                          primary=Value({"host": address(0), "port": 5432}))
        nobody = Reading(role=Value("replica"), read_only=Value(True))
        pg = {"database": {"server": {"engine": "postgresql"}}}
        maria = {"database": {"server": {"engine": "mariadb"}}}
        self.assertTrue(dbwatch.needs_follow(root, fenced, streams, pg))
        self.assertFalse(dbwatch.needs_follow(root, fenced, nobody, pg))
        # a MariaDB replica too since keel#192
        self.assertTrue(dbwatch.needs_follow(root, fenced, streams, maria))


class TestStatus(FollowTestCase):
    def test_one_screen_for_the_operator(self):
        from keel.system import dbstatus
        self.pair_nodes()
        here = self.all[1]
        server = Server(replicating_from=address(0), read_only="ON")
        with mock.patch("keel.inspect.collect.paths.ROOT_DEFAULT",
                        here.root), \
                mock.patch("keel.inspect.collect.subprocess.run", server), \
                mock.patch("keel.system.dbstatus.vip_lines",
                           return_value=["vip: faked"]):
            lines = dbstatus.lines(here.root, here.node.path)
        joined = "\n".join(lines)
        self.assertIn(f"pair: VIP {VIP}; role here replica", joined)
        self.assertIn(f"the primary's address: {address(0)}", joined)
        self.assertIn(f"replicating from: [{address(0)}]:3306", joined)
        self.assertIn("semi-synchronous: master ON", joined)
        self.assertIn("certificate: not a certificate", joined)
        self.assertIn("vip: faked", joined)
        self.nodes(vips=(None, None), paired=False)
        with mock.patch("keel.system.dbstatus.vip_lines", return_value=[]):
            lines = dbstatus.lines(self.all[2].root, self.all[2].node.path)
        self.assertIn("pair: none", lines[0])


class TestTheFileFlip(FollowTestCase):
    """0050's amendment, point 5: the file folders flip with the
    database role, in the same operation. A core appliance replicates
    no file: the flip is a no-op and the role file keeps
    replicates=database"""

    def test_a_spec_without_the_overlay_warns_and_follows(self):
        self.pair_nodes()
        text = "overlays.syncthing: not declared"
        with mock.patch("keel.system.filesync.undeclared_problem",
                        return_value=text), \
                mock.patch("keel.system.dbfollow.alerting.alert") as alert:
            found = self.follow(0, Server())
        self.assertIsNone(found.problem, found.lines)
        self.assertTrue(any("WARNING: file replication is off" in line
                            and text in line for line in found.lines))
        self.assertIn("primary", self.role_file(0))
        self.assertEqual(alert.call_count, 1)

    def test_the_alert_is_sent_once_while_the_spec_stays_undeclared(self):
        self.pair_nodes()
        with mock.patch("keel.system.filesync.undeclared_problem",
                        return_value="x"), \
                mock.patch("keel.system.dbfollow.alerting.alert") as alert:
            self.follow(0, Server())
            self.follow(0, Server())
        self.assertEqual(alert.call_count, 1)

    def test_the_primary_flip_flips_the_folders(self):
        self.pair_nodes()
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            found = self.follow(0, Server())
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(flipped.call_count, 1)
        self.assertEqual(flipped.call_args.args[3], "primary")
        self.assertIn("replicates=database\n", self.role_file(0))

    def test_a_replica_flip_flips_the_folders(self):
        self.pair_nodes()
        server = Server(replicating_from=address(0), read_only="ON")
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            found = self.follow(1, server)
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(flipped.call_args.args[3], "replica")

    def test_an_in_doubt_holder_pauses_the_folders(self):
        from keel.mesh import vip as vipstate
        self.pair_nodes()
        vipstate.mark_unconfirmed(self.all[0].root, VIP, True)
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            found = self.follow(0, Server())
        self.assertIsNone(found.problem, found.lines)
        self.assertIsNone(flipped.call_args.args[3])
        self.assertEqual(self.role_file(0), "")

    def paused_once(self, flipped, found):
        """Every exit that proved no role pauses the folders, once"""
        self.assertEqual(flipped.call_count, 1)
        self.assertIsNone(flipped.call_args.args[3])

    def test_a_holder_that_does_not_answer_pauses_the_folders(self):
        self.pair_nodes()
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            found = self.follow(1, Server(holder_down=True))
        self.assertIsNotNone(found.problem)
        self.paused_once(flipped, found)

    def test_the_certificate_missing_pauses_the_folders(self):
        self.pair_nodes()
        os.remove(os.path.join(self.all[1].root, dbtls.KEY))
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            found = self.follow(1, Server(schemas=""))
        self.assertIsNotNone(found.problem)
        self.paused_once(flipped, found)

    def test_a_node_in_no_pair_pauses_the_folders(self):
        self.nodes(vips=(None, None), paired=False)
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            found = self.follow(2, Server())
        self.assertIsNotNone(found.problem)
        self.paused_once(flipped, found)
        self.assertIsNone(flipped.call_args.args[2])

    def test_a_node_without_a_vip_that_asks_nothing_pauses_them_too(self):
        self.nodes(vips=(None, None), paired=False)
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            self.follow(2, Server(), nothing_without_vip=True)
        self.paused_once(flipped, None)

    def test_a_server_that_is_not_answering_pauses_the_folders(self):
        import dataclasses
        self.pair_nodes()
        real = dbfollow.observe_database

        def down(*args, **kwargs):
            return dataclasses.replace(real(*args, **kwargs),
                                       down="connection refused")

        with mock.patch("keel.system.filesync.follow_flip") as flipped, \
                mock.patch.object(dbfollow, "observe_database", down):
            found = self.follow(0, Server())
        self.assertIn("not answering", found.problem)
        self.paused_once(flipped, found)

    def test_a_pair_with_a_problem_pauses_the_folders(self):
        import dataclasses
        self.pair_nodes()
        real = dbfollow.observe_database

        def broken(*args, **kwargs):
            state = real(*args, **kwargs)
            return dataclasses.replace(state, pair=dataclasses.replace(
                state.pair, problem="the pair record is damaged"))

        with mock.patch("keel.system.filesync.follow_flip") as flipped, \
                mock.patch.object(dbfollow, "observe_database", broken):
            found = self.follow(0, Server())
        self.assertIn("damaged", found.problem)
        self.paused_once(flipped, found)

    def test_a_server_that_cannot_be_asked_pauses_the_folders(self):
        import dataclasses
        self.pair_nodes()
        real = dbfollow.observe_database

        def mute(*args, **kwargs):
            state = real(*args, **kwargs)
            role = dataclasses.replace(state.reading.role, value=None,
                                       problem="timed out")
            return dataclasses.replace(
                state, reading=dataclasses.replace(state.reading, role=role))

        with mock.patch("keel.system.filesync.follow_flip") as flipped, \
                mock.patch.object(dbfollow, "observe_database", mute):
            found = self.follow(0, Server())
        self.assertIn("could not be asked", found.problem)
        self.paused_once(flipped, found)

    def test_a_flip_that_raises_leaves_the_follow_result_alone(self):
        self.pair_nodes()
        with mock.patch("keel.system.filesync.follow_flip",
                        side_effect=RuntimeError("boom")) as flipped:
            with self.assertRaises(RuntimeError):
                self.follow(0, Server())
        flipped.assert_called_once()


if __name__ == "__main__":
    unittest.main()
