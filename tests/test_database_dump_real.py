# Copyright (c) 2026 KeelLinux maintainers
"""keel database dump's commands on real servers (docs/replication.md)

A server of this machine in a temporary directory, with a row. The
command is the one keel runs, and only the way to reach this private
server is added. The file must hold the row, and the MariaDB file its
GTID position, after the real pack.

Runs where the server and zstd are installed: in the jobs "mariadb /
trixie" and "postgres / trixie" as root, or on a developer's machine as
any user. Skips elsewhere.
"""

import glob
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from keel.system import dbdump

MARIADBD = "/usr/sbin/mariadbd"
AS_ROOT = os.geteuid() == 0
LIMIT = 1024 * 1024 * 1024
ROW = "row-of-the-real-dump"
WAIT_S = 60


def wait_for(check) -> None:
    deadline = time.monotonic() + WAIT_S
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.2)
    raise AssertionError("the server did not start")


def unpacked(path: str) -> str:
    return subprocess.run(["zstd", "-dc", path], capture_output=True,
                          check=True, text=True).stdout


class Common(unittest.TestCase):
    def setUp(self):
        if not shutil.which("zstd"):
            self.skipTest("zstd is not installed")
        self.base = tempfile.mkdtemp(dir="/tmp")
        os.chmod(self.base, 0o755)
        self.addCleanup(shutil.rmtree, self.base, True)
        self.backups = os.path.join(self.base, "backups")
        os.makedirs(self.backups, mode=0o700)

    def as_user(self, user: str, argv: list[str]) -> list[str]:
        return ["runuser", "-u", user, "--"] + argv if AS_ROOT else argv

    def taken(self, engine: str) -> str:
        path = dbdump.take(engine, self.backups, LIMIT, time.time())
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        return path


@unittest.skipUnless(os.path.exists(MARIADBD) and shutil.which("mariadb-dump"),
                     "mariadbd is not installed")
class TestMariaDB(Common):
    def test_the_dump_holds_the_row_and_the_gtid_position(self):
        data = os.path.join(self.base, "data")
        socket = os.path.join(self.base, "s.sock")
        os.makedirs(data)
        user = ["--user=mysql"] if AS_ROOT else []
        if AS_ROOT:
            shutil.chown(data, "mysql", "mysql")
            shutil.chown(self.base, "mysql", "mysql")
        subprocess.run(
            ["mariadb-install-db", "--no-defaults", f"--datadir={data}",
             "--skip-test-db", "--auth-root-authentication-method=normal"]
            + user, check=True, capture_output=True)
        server = subprocess.Popen(
            [MARIADBD, "--no-defaults", f"--datadir={data}",
             f"--socket={socket}", "--skip-networking", "--log-bin=b",
             "--server-id=7"] + user,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(server.wait)
        self.addCleanup(server.terminate)
        client = ["mariadb", "--no-defaults", f"--socket={socket}", "-uroot"]
        wait_for(lambda: subprocess.run(
            client + ["-e", "SELECT 1"], capture_output=True).returncode == 0)
        subprocess.run(client, input=(
            "CREATE DATABASE keeltest; CREATE TABLE keeltest.t"
            f" (a VARCHAR(40)) ENGINE=InnoDB; INSERT INTO keeltest.t VALUES"
            f" ('{ROW}');"), text=True, check=True)
        argv = list(dbdump.COMMANDS["mariadb"])
        argv[1:1] = ["--no-defaults", f"--socket={socket}", "-uroot"]
        with mock.patch.dict(dbdump.COMMANDS, {"mariadb": tuple(argv)}):
            text = unpacked(self.taken("mariadb"))
        self.assertIn(ROW, text)
        self.assertRegex(text, r"-- SET GLOBAL gtid_slave_pos='0-7-\d+'")


@unittest.skipUnless(glob.glob("/usr/lib/postgresql/*/bin/initdb"),
                     "postgresql is not installed")
class TestPostgreSQL(Common):
    def test_the_dump_holds_the_row(self):
        bin_dir = os.path.dirname(glob.glob(
            "/usr/lib/postgresql/*/bin/initdb")[0])
        user = "postgres" if AS_ROOT else None
        data = os.path.join(self.base, "data")
        if AS_ROOT:
            shutil.chown(self.base, "postgres", "postgres")

        def tool(name: str, *args: str) -> list[str]:
            argv = [os.path.join(bin_dir, name), *args]
            return self.as_user(user, argv) if user else argv
        subprocess.run(tool("initdb", "-D", data, "-A", "peer"), check=True,
                       capture_output=True)
        subprocess.run(tool(
            "pg_ctl", "-D", data, "-w", "-l",
            os.path.join(self.base, "log"), "-o",
            f"-c listen_addresses='' -c unix_socket_directories={self.base}",
            "start"), check=True, capture_output=True)
        self.addCleanup(subprocess.run, tool("pg_ctl", "-D", data, "-m",
                                             "immediate", "stop"),
                        capture_output=True)
        subprocess.run(tool("psql", "-h", self.base, "-d", "postgres", "-c",
                            f"CREATE TABLE t AS SELECT '{ROW}'::text AS a"),
                       check=True, capture_output=True)
        argv = tool("pg_dumpall", "-h", self.base)
        with mock.patch.dict(dbdump.COMMANDS, {"postgresql": tuple(argv)}):
            text = unpacked(self.taken("postgresql"))
        self.assertIn(ROW, text)
