# Copyright (c) 2026 KeelLinux maintainers
"""keel database status on a PostgreSQL pair (keel#155, item 1)

The status said "server: no MariaDB server installed here" on a
PostgreSQL pair, and nothing of the standby, the slot, the synchronous
commit or the timeline. The pair, the VIP's state and the spec are real
(tests/vip_helpers.py); the server is a runner that answers as
PostgreSQL 17 answers the questions of inspect and of the status.
"""

import os
import subprocess
import unittest
from unittest import mock

from test_system_dbfollow import FollowTestCase
from vip_helpers import VIP, address

from keel.system import dbpgstatus, dbstatus

REAL_RUN = subprocess.run


class PgServer:
    """subprocess.run as one PostgreSQL server answers it"""

    def __init__(self, recovery: bool, status: str | None,
                 status_error: str = ""):
        self.recovery = recovery
        self.status = status
        self.status_error = status_error

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        if argv[:1] == ["openssl"]:
            return REAL_RUN(argv, **kwargs)
        out, code, err = "", 0, ""
        if "--command" in argv and argv[-1] == dbpgstatus.STATUS_SQL:
            if self.status is None:
                code, err = 2, self.status_error
            else:
                out = self.status
        elif "-c" in argv:
            sql = argv[-1]
            if "pg_is_in_recovery()" in sql:
                out = ("t\t0\t5432\n" if self.recovery else "f\t1\t5432\n")
            elif "pg_stat_wal_receiver" in sql and self.recovery:
                out = (f"user=keel host={address(0)} port=5432"
                       " password=******** sslmode=verify-full\n")
            elif "pg_hba_file_rules" in sql:
                out = f"hostssl\t{address(1)}\t\n"
        elif argv[:2] == ["ss", "-lntH"]:
            out = "LISTEN 0 200 [::1]:5432 [::]:*\n"
        if kwargs.get("text"):
            return subprocess.CompletedProcess(argv, code, out, err)
        return subprocess.CompletedProcess(argv, code, out.encode(),
                                           err.encode())


PRIMARY_STATUS = (
    "state\tfalse\t3\ton\tFIRST 1 (keel)\t\n"
    f"standby\tkeel\t{address(1)}\tstreaming\tsync\t00:00:00.001234\n"
    "slot\tkeel\tactive\t0/3000148\treserved\t\n"
    "slot\tpg_receivewal_service\tinactive\t0/1000000\treserved\t\n"
)
REPLICA_STATUS = (
    "state\ttrue\t3\ton\t\t00:00:01.5\n"
    f"receiver\tstreaming\t{address(0)}\t5432\t3\t\n"
)


class TestPostgreSQLStatus(FollowTestCase):
    def pg_pair(self):
        """the pair of FollowTestCase, both nodes a PostgreSQL server"""
        self.pair_nodes()
        for index, role in ((0, "primary"), (1, "replica")):
            here = self.all[index]
            doc = here.node.document()
            doc["database"] = {"server": {
                "engine": "postgresql", "role": role,
                "listen": [address(index), "::1"]}}
            here.node.write(doc)
            os.remove(os.path.join(here.root, "usr/sbin/mariadbd"))
            binary = os.path.join(here.root,
                                  "usr/lib/postgresql/17/bin/postgres")
            os.makedirs(os.path.dirname(binary), exist_ok=True)
            with open(binary, "w"):
                pass

    def status(self, index: int, server: PgServer) -> str:
        here = self.all[index]
        with mock.patch("keel.inspect.collect.paths.ROOT_DEFAULT",
                        here.root), \
                mock.patch("keel.inspect.collect.subprocess.run", server), \
                mock.patch("keel.system.dbpgstatus.subprocess.run", server), \
                mock.patch("keel.system.dbstatus.vip_lines",
                           return_value=["vip: faked"]):
            return "\n".join(dbstatus.lines(here.root, here.node.path))

    def test_the_primary_shows_its_standby_slot_commit_and_timeline(self):
        self.pg_pair()
        joined = self.status(0, PgServer(False, PRIMARY_STATUS))
        self.assertNotIn("MariaDB", joined)
        self.assertIn(f"pair: VIP {VIP}; role here primary", joined)
        # keel#155, item 2: the primary is this node on the holder
        self.assertIn(f"  the primary's address: {address(0)}", joined)
        self.assertIn("server: primary", joined)
        self.assertIn("  timeline: 3", joined)
        self.assertIn("  synchronous commit: on, synchronous_standby_names"
                      " 'FIRST 1 (keel)'", joined)
        self.assertIn(f"  standby: keel from [{address(1)}], streaming,"
                      " sync, replay lag 00:00:00.001234", joined)
        self.assertIn("  slot: keel, active, restart_lsn 0/3000148,"
                      " wal_status reserved", joined)
        self.assertIn("  slot: pg_receivewal_service, inactive,"
                      " restart_lsn 0/1000000, wal_status reserved", joined)
        self.assertIn("  certificate: ", joined)
        self.assertIn("vip: faked", joined)

    def test_the_standby_shows_what_it_receives_and_its_lag(self):
        self.pg_pair()
        joined = self.status(1, PgServer(True, REPLICA_STATUS))
        self.assertIn("server: replica", joined)
        self.assertIn("  timeline: 3", joined)
        self.assertIn(f"  receiving from: [{address(0)}]:5432, streaming,"
                      " timeline 3", joined)
        self.assertIn("  replay lag: 00:00:01.5", joined)
        self.assertIn("  standby: none streams from here", joined)

    def test_a_primary_with_no_standby_and_no_slot_says_so(self):
        self.pg_pair()
        joined = self.status(0, PgServer(False, "state\tfalse\t3\ton\t\t\n"))
        self.assertIn("  standby: none streams from here", joined)
        self.assertIn("  slot: none", joined)
        self.assertIn("synchronous_standby_names ''", joined)
        self.assertIn("  receiving from: nobody", joined)

    def test_a_status_that_cannot_be_read_says_why(self):
        self.pg_pair()
        joined = self.status(0, PgServer(False, None,
                                         "psql: error: connection refused"))
        self.assertIn("server: primary", joined)
        self.assertIn("  status: not readable (psql: error: connection"
                      " refused)", joined)

    def test_a_client_that_cannot_start_says_why(self):
        def missing(argv, **kwargs):
            raise OSError("no such file: runuser")
        lines = dbpgstatus.status_lines(missing)
        self.assertEqual(lines, ["  status: not readable (no such file:"
                                 " runuser)"])


if __name__ == "__main__":
    unittest.main()
