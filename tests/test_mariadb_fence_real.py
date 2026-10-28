# Copyright (c) 2026 KeelLinux maintainers
"""The fence of a MariaDB primary that lost the VIP, on real servers
(keel#186)

Two mariadbd of the machine, semi-synchronous as keel's drop-in makes
them (AFTER_SYNC), the replica stopped with SIGSTOP as a cut stops it. A
write on the primary waits for the replica's ACK. Before keel#186, the
fence of the old primary was `SET GLOBAL read_only = ON` alone: it waits
for the backup lock behind the waiting write, and the write returned OK
when the semi-synchronous timeout ended, a write the new primary never
got. The fence now kills the client connections while read_only waits,
so the waiting write gets an error and no OK.

Runs where mariadbd is installed: in the job "mariadb / trixie" as root
(KEEL_MARIADB_NETNS), or on a developer's machine as any user. Skips
elsewhere.
"""

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from keel.mesh.vip import RELEASE_AFTER
from keel.system import dbmariadb, dbreadonly

MARIADBD = "/usr/sbin/mariadbd"
INSTALL_DB = shutil.which("mariadb-install-db")
# long, so a test that passes cannot be the timeout's doing
TEST_TIMEOUT_MS = 60000
# what the fence may take with the write waiting, far under the timeout
FENCE_BOUND_S = 10.0
AS_ROOT = os.geteuid() == 0


def bare(argv) -> list[str]:
    """As root the clients run as the mysql user, as on a machine;
    as another user they run as that user, root by the options file"""
    argv = list(argv)
    prefix = list(dbmariadb.AS_MYSQL)
    if not AS_ROOT and argv[:len(prefix)] == prefix:
        return argv[len(prefix):]
    return argv


def run(argv, **kwargs):
    return subprocess.run(bare(argv), **kwargs)


def popen(argv, **kwargs):
    return subprocess.Popen(bare(argv), **kwargs)


class BlackHole:
    """A TCP relay to the primary that can stop moving bytes while it
    keeps both sockets open, as a cut does to a connection: the peer
    never reads and never closes"""

    def __init__(self, port: int):
        self.cut = threading.Event()
        self.socks: list[socket.socket] = []
        self.server = socket.create_server(("127.0.0.1", 0))
        self.port = self.server.getsockname()[1]
        self.target = port
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self) -> None:
        while True:
            try:
                near, _ = self.server.accept()
            except OSError:
                return
            far = socket.create_connection(("127.0.0.1", self.target))
            self.socks += [near, far]
            for a, b in ((near, far), (far, near)):
                threading.Thread(target=self.pipe, args=(a, b),
                                 daemon=True).start()

    def pipe(self, a: socket.socket, b: socket.socket) -> None:
        try:
            while True:
                data = a.recv(65536)
                while self.cut.is_set():
                    time.sleep(0.05)
                if not data:
                    break
                b.sendall(data)
        except OSError:
            pass
        while self.cut.is_set():
            time.sleep(0.05)

    def close(self) -> None:
        self.cut.clear()
        for one in [self.server] + self.socks:
            try:
                one.close()
            except OSError:
                pass


def available() -> str:
    if not (os.path.exists(MARIADBD) and INSTALL_DB):
        return "mariadbd is not installed here"
    if AS_ROOT and not os.environ.get("KEEL_MARIADB_NETNS"):
        return "as root, only in the job mariadb / trixie"
    return ""


class TestTheQuestions(unittest.TestCase):
    def test_the_questions_name_the_setting_exactly(self):
        """the setting is left out of the kills and looked for by its
        statement, spelled out in both questions (no SQL is built)"""
        for question in (dbreadonly.CLIENTS_QUESTION,
                         dbreadonly.FENCE_SHOWN):
            self.assertIn(f"'{dbreadonly.FENCE}'", question[-1])


class TestTheTimeout(unittest.TestCase):
    def test_the_semi_sync_timeout_outlasts_the_vip_release(self):
        """keel#186, cause 1: a write that waits for the ACK on a cut
        primary must not return OK before that primary drops the VIP
        and its fence runs: the release (RELEASE_AFTER) plus the follow
        that keel-database-follow.path starts, with room"""
        self.assertGreaterEqual(dbmariadb.SEMI_SYNC_TIMEOUT_MS / 1000,
                                2 * RELEASE_AFTER)
        self.assertIn(f"rpl_semi_sync_master_timeout = "
                      f"{dbmariadb.SEMI_SYNC_TIMEOUT_MS}",
                      dbmariadb.PAIR_LINES.format(
                          binlog="b", timeout=dbmariadb.SEMI_SYNC_TIMEOUT_MS))


@unittest.skipIf(available(), available())
class TestTheFence(unittest.TestCase):
    def setUp(self):
        # a short path: a unix socket path has at most 107 bytes
        self.dir = tempfile.mkdtemp(prefix="kf", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.dir, True)
        if AS_ROOT:
            shutil.chown(self.dir, "mysql", "mysql")
        self.procs: dict[str, subprocess.Popen] = {}
        self.addCleanup(self.stop_all)
        self.start("p", 1)
        self.start("r", 2)
        self.home = os.path.join(self.dir, "client")
        os.makedirs(self.home)
        os.chmod(self.home, 0o755)
        with open(os.path.join(self.home, "my.cnf"), "w") as fob:
            fob.write(f"[client]\nsocket={self.sock('p')}\n"
                      + ("" if AS_ROOT else "user=root\n"))
        os.chmod(os.path.join(self.home, "my.cnf"), 0o644)
        env = mock.patch.dict(os.environ, {"MYSQL_HOME": self.home})
        env.start()
        self.addCleanup(env.stop)
        self.pair()

    def sock(self, name: str) -> str:
        return os.path.join(self.dir, f"{name}.sock")

    def start(self, name: str, server_id: int) -> None:
        data = os.path.join(self.dir, name)
        user = ["--user=mysql"] if AS_ROOT else []
        subprocess.run([INSTALL_DB, "--no-defaults", f"--datadir={data}",
                        "--auth-root-authentication-method="
                        + ("socket" if AS_ROOT else "normal"), *user],
                       check=True, capture_output=True)
        self.procs[name] = subprocess.Popen([
            MARIADBD, "--no-defaults", f"--datadir={data}",
            f"--socket={self.sock(name)}", "--skip-networking=0",
            f"--port={23300 + server_id}", "--bind-address=127.0.0.1",
            f"--server-id={server_id}", f"--log-bin={data}/bin",
            "--binlog-format=ROW", "--gtid-strict-mode=ON",
            "--log-slave-updates", "--rpl-semi-sync-master-enabled=ON",
            "--rpl-semi-sync-slave-enabled=ON",
            "--rpl-semi-sync-master-wait-point=AFTER_SYNC",
            "--rpl-semi-sync-master-wait-no-slave=OFF",
            f"--rpl-semi-sync-master-timeout={TEST_TIMEOUT_MS}",
            f"--pid-file={data}.pid", f"--log-error={data}.err", *user],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 60
        while not os.path.exists(self.sock(name)):
            if time.monotonic() > deadline:
                self.fail(f"mariadbd {name} did not start")
            time.sleep(0.2)

    def stop_all(self) -> None:
        for hole in getattr(self, "holes", []):
            hole.close()
        for proc in self.procs.values():
            try:
                os.kill(proc.pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            proc.terminate()
            try:
                proc.wait(30)
            except subprocess.TimeoutExpired:
                proc.kill()

    def sql(self, name: str, text: str, check: bool = True) -> str:
        done = subprocess.run(
            ["mariadb", "--no-defaults", f"--socket={self.sock(name)}",
             "-uroot", "--batch", "--skip-column-names", "-e", text],
            capture_output=True, text=True, check=False)
        if check and done.returncode != 0:
            self.fail(f"{text}: {done.stderr}")
        return done.stdout

    def pair(self) -> None:
        self.sql("p", "CREATE USER repl@'%' IDENTIFIED BY 'x';"
                 " GRANT REPLICATION SLAVE ON *.* TO repl@'%';"
                 " CREATE USER repl@localhost IDENTIFIED BY 'x';"
                 " GRANT REPLICATION SLAVE ON *.* TO repl@localhost;"
                 " CREATE USER app@localhost IDENTIFIED BY 'a';"
                 " CREATE DATABASE shop; CREATE TABLE shop.t"
                 " (id INT PRIMARY KEY);"
                 " GRANT ALL ON shop.* TO app@localhost")
        self.sql("r", "CHANGE MASTER TO MASTER_HOST='127.0.0.1',"
                 " MASTER_PORT=23301, MASTER_USER='repl',"
                 " MASTER_PASSWORD='x', MASTER_CONNECT_RETRY=1,"
                 " MASTER_USE_GTID=slave_pos; START SLAVE")
        deadline = time.monotonic() + 30
        while "ON" not in self.sql(
                "p", "SHOW STATUS LIKE 'Rpl_semi_sync_master_status'"):
            if time.monotonic() > deadline:
                self.fail("semi-sync did not start")
            time.sleep(0.5)
        self.sql("p", "INSERT INTO shop.t VALUES (1)")

    def write(self, value: int, said: dict) -> None:
        done = subprocess.run(
            ["mariadb", "--no-defaults", f"--socket={self.sock('p')}",
             "-uapp", "-pa", "-e", f"INSERT INTO shop.t VALUES ({value})"],
            capture_output=True, text=True, check=False)
        said["rc"], said["at"] = done.returncode, time.monotonic()

    def waiting(self) -> bool:
        return "Waiting for semi-sync ACK" in self.sql(
            "p", "SELECT STATE FROM information_schema.PROCESSLIST")

    def test_a_write_waiting_for_the_ack_gets_no_ok_after_the_fence(self):
        os.kill(self.procs["r"].pid, signal.SIGSTOP)
        said: dict = {}
        writer = threading.Thread(target=self.write, args=(2, said))
        writer.start()
        deadline = time.monotonic() + 10
        while not self.waiting():
            self.assertLess(time.monotonic(), deadline, "no write waits")
            time.sleep(0.1)
        began = time.monotonic()
        problem = dbreadonly.fence(run, popen)
        took = time.monotonic() - began
        writer.join(30)
        self.assertIsNone(problem)
        self.assertLess(took, FENCE_BOUND_S)
        # the write ended, and its client was not told the row is stored
        self.assertFalse(writer.is_alive())
        self.assertIn("rc", said)
        self.assertNotEqual(said["rc"], 0, said)
        self.assertEqual(self.sql("p", "SELECT @@global.read_only").strip(),
                         "1")
        # a new write is refused, it does not wait
        later: dict = {}
        self.write(3, later)
        self.assertNotEqual(later["rc"], 0)

    def test_a_fenced_node_keeps_no_dump_thread_to_a_cut_replica(self):
        """keel#193: a dump thread to a cut replica stays, and when that
        replica connects again with the same server id, MariaDB 11.8.6
        ends the old thread and takes no connection after it. A fenced
        node serves no replica, so the fence ends that thread too; ended
        by a KILL, it ends cleanly"""
        hole = BlackHole(23301)
        self.holes = [hole]
        self.sql("r", f"STOP SLAVE; CHANGE MASTER TO MASTER_PORT={hole.port},"
                 " MASTER_HEARTBEAT_PERIOD=5; START SLAVE")
        deadline = time.monotonic() + 30
        while "1" not in self.sql(
                "p", "SHOW STATUS LIKE 'Rpl_semi_sync_master_clients'"):
            self.assertLess(time.monotonic(), deadline, "no replica")
            time.sleep(0.5)
        # the cut, then the other node promoted: it stops replicating, and
        # the primary never hears of it
        hole.cut.set()
        self.sql("r", "STOP SLAVE; RESET SLAVE ALL; SET GLOBAL read_only = 0")
        self.assertIn("Binlog Dump", self.sql(
            "p", "SELECT COMMAND FROM information_schema.PROCESSLIST"))
        self.assertIsNone(dbreadonly.fence(run, popen))
        self.assertNotIn("Binlog Dump", self.sql(
            "p", "SELECT COMMAND FROM information_schema.PROCESSLIST"))
        # later the other node replicates from this one, server id 2 again
        self.sql("p", "SET GLOBAL read_only = 0")
        self.sql("r", "SET GLOBAL read_only = 1;"
                 " SET GLOBAL gtid_slave_pos = @@gtid_binlog_pos;"
                 " CHANGE MASTER TO MASTER_HOST='127.0.0.1',"
                 " MASTER_PORT=23301, MASTER_USER='repl',"
                 " MASTER_PASSWORD='x', MASTER_CONNECT_RETRY=1,"
                 " MASTER_USE_GTID=slave_pos; START SLAVE")
        time.sleep(4)
        done = subprocess.run(
            ["mariadb", "--no-defaults", f"--socket={self.sock('p')}",
             "-uroot", "--batch", "--skip-column-names", "-e", "SELECT 1"],
            capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(done.stdout.strip(), "1", done.stderr)

    @unittest.skipUnless(AS_ROOT, "the clients run as the mysql user")
    def test_the_fence_as_follow_runs_it(self):
        """No seam: the runner and Popen as keel database follow has
        them, the clients as the mysql user"""
        os.kill(self.procs["r"].pid, signal.SIGSTOP)
        said: dict = {}
        writer = threading.Thread(target=self.write, args=(4, said))
        writer.start()
        deadline = time.monotonic() + 10
        while not self.waiting():
            self.assertLess(time.monotonic(), deadline, "no write waits")
            time.sleep(0.1)
        self.assertIsNone(dbreadonly.fence())
        writer.join(30)
        self.assertFalse(writer.is_alive())
        self.assertNotEqual(said.get("rc", 0), 0, said)
        self.assertEqual(self.sql("p", "SELECT @@global.read_only").strip(),
                         "1")

    def test_with_nothing_waiting_the_fence_is_read_only_at_once(self):
        began = time.monotonic()
        self.assertIsNone(dbreadonly.fence(run, popen))
        self.assertLess(time.monotonic() - began, FENCE_BOUND_S)
        self.assertEqual(self.sql("p", "SELECT @@global.read_only").strip(),
                         "1")


if __name__ == "__main__":
    unittest.main()
