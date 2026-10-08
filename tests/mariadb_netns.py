# Copyright (c) 2026 KeelLinux maintainers
"""A MariaDB pair on the mesh, three nodes in three namespaces

Run as root in a network namespace of its own by
tests/test_mariadb_netns.py (tests/wgtools.py says how); never run by
hand on a machine. The nodes, the links of decision 0050's design case
(250 ms ±25 ms with 2 % loss, measured first), etcd, the members'
channel, the VIP's units and the agents are tests/vip_netns.py's: this
module drives them with a MariaDB server per node, each as a systemd
unit of its own in the node's namespace (`mariadb-keel-<node>`), reading
the node's scratch root's `etc/mysql/mariadb.conf.d/` as the real one
reads /etc/mysql/mariadb.conf.d/, so the drop-in keel writes under that
root is the server's. keel runs in each node's agent with
KEEL_LIVE_ROOT naming the node's root (the live system of that node),
MYSQL_HOME naming the options file with that node's socket, and
KEEL_MARIADB_SERVICE naming its unit: the three seams the PR body names.
Each agent also stands for keel-database-follow.path (keel database
follow when the VIP's state changes) and keel-database-watch.timer
(keel database watch every 10 s here, 30 on a machine).

A and B are the pair (A primary, B replica, by their specs); C writes to
the VIP as the application. The alerts go to a webhook this namespace
serves. Then:

- **(a)** A and B applied: B seeded over TLS (`Master_SSL_Allowed: Yes`,
  the replication account `REQUIRE X509`); a row written at the VIP is
  read on B, the lag measured from the write;
- **(b)** a commit at the VIP costs about one round trip; B's leg cut
  (100 % loss): the next commit returns after about 10 s, A's
  semi-synchronous status reads off, `keel diff` reports drift, the
  alert reaches the webhook, writes go on; healed, on again;
- **(c)** `keel database promote` on B: the longest gap in C's writes
  is the downtime, every row C wrote before is on B;
- **(d)** B, the primary, cut off with C idle: the VIP fails over to A
  (keel#81's times), the database follows, C's writes resume; healed, B
  turns read only and rejoins A by itself, no errant GTID. Then A, the
  primary, cut off with C writing through: healed, A comes back
  diverged, read only, the errant GTIDs reported and alerted; confirmed,
  it is reseeded and follows;
- **(e)** the replica refuses an INSERT as root by the socket and as the
  application at its own address, 1290.


The result is one JSON line, `RESULT {...}`.
"""

import json
import os
import subprocess
import sys
import threading
import time

ROOT_PREFIX = "keel-vip-"
WEBHOOK_PORT = 8099
# the time between two watch runs in an agent (30 s on a machine)
WATCH_EVERY = 10.0
APP_USER, APP_PASSWORD, APP_DB = "app", "app-pw-1", "shop"


# --- the agent's side: a node's keel, with its seams -------------------

def node_name(root: str) -> str:
    """A, B or C, from the scratch root's name"""
    base = os.path.basename(root.rstrip("/"))
    return base[len(ROOT_PREFIX):].split("-")[0]


def socket_of(root: str) -> str:
    return os.path.join(root, "run/mysqld/mysqld.sock")


def service_of(root: str) -> str:
    return f"mariadb-keel-{node_name(root)}"


def client_home(root: str) -> str:
    """MYSQL_HOME: an options file with this node's socket, which the
    clients read after /etc/mysql/my.cnf and before the command line"""
    home = os.path.join(root, "etc/mysql-client")
    os.makedirs(home, exist_ok=True)
    os.chmod(home, 0o755)
    path = os.path.join(home, "my.cnf")
    with open(path, "w") as fob:
        fob.write(f"[client]\nsocket={socket_of(root)}\n")
    os.chmod(path, 0o644)
    return home


def seams(root: str) -> None:
    os.environ["KEEL_LIVE_ROOT"] = root
    os.environ["MYSQL_HOME"] = client_home(root)
    os.environ["KEEL_MARIADB_SERVICE"] = service_of(root)


VIP_COMMAND = None


def agent_main(root: str, path: str) -> None:
    global VIP_COMMAND
    seams(root)
    import vip_netns
    VIP_COMMAND = vip_netns.command
    vip_netns.command = database_command
    FOLLOWER.start(root, path)
    vip_netns.agent(root, path)


class Follower:
    """What keel-database-follow.path and keel-database-watch.timer do
    on a machine: follow when the VIP's state changes, watch regularly"""

    def __init__(self):
        self.thread = None
        self.stop = threading.Event()
        self.log: list[str] = []
        self.runs = 0

    def start(self, root: str, path: str) -> None:
        self.root, self.path = root, path
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stamp(self) -> float:
        found = 0.0
        directory = os.path.join(self.root, "var/lib/keel/vip")
        try:
            for name in os.listdir(directory):
                found = max(found, os.stat(os.path.join(directory,
                                                        name)).st_mtime)
        except OSError:
            pass
        return found

    def run(self) -> None:
        last = self.stamp()
        watched = time.monotonic()
        while not self.stop.wait(0.5):
            now = self.stamp()
            if now != last and now:
                last = now
                self.follow("the VIP's state changed")
            if time.monotonic() - watched >= WATCH_EVERY:
                watched = time.monotonic()
                self.watch()

    def follow(self, why: str) -> dict:
        from keel.system import dbfollow
        with LOCK:
            found = dbfollow.Followed()
            dbfollow.follow(self.root, self.path, False, found)
            self.runs += 1
            self.log.append(f"{time.time():.3f} follow ({why}):"
                            f" {found.problem or 'ok'}: {found.lines}")
            print(self.log[-1], file=sys.stderr, flush=True)
            return {"problem": found.problem, "lines": found.lines}

    def watch(self) -> None:
        import argparse
        from keel.system import dbwatch
        said: list[str] = []
        with LOCK:
            code = dbwatch.watch(self.root, self.path, said.append,
                                 said.append)
        self.log.append(f"{time.time():.3f} watch: {code}: {said}")
        print(self.log[-1], file=sys.stderr, flush=True)


FOLLOWER = Follower()
LOCK = threading.RLock()


def sql(statement: str, user: str | None = None,
        host: str | None = None, password: str | None = None,
        database: str | None = None, timeout: float = 60) -> dict:
    """One statement through the client: as root by the socket, or as
    `user` at `host`; what it answered and how long it took"""
    argv = ["mariadb", "--batch", "--skip-column-names",
            f"--connect-timeout={int(timeout)}"]
    if host:
        argv += ["-h", host, "-u", user or "root", "--skip-ssl-verify-server-cert"]
    if password:
        argv.append(f"--password={password}")
    if database:
        argv.append(database)
    argv += ["--execute", statement]
    started = time.monotonic()
    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"code": -1, "out": "", "err": "timed out",
                "took_s": round(time.monotonic() - started, 3)}
    return {"code": done.returncode, "out": done.stdout.strip(),
            "err": done.stderr.strip()[-300:],
            "took_s": round(time.monotonic() - started, 3)}


def database_command(here, words: list[str]) -> dict | None:
    """The driver's commands to a node's agent, the database ones first,
    the VIP's after (tests/vip_netns.py)"""
    import vip_netns
    from keel import system
    from keel.system.actions import Plan
    from keel.system.database import plan_database
    root, path = here.root, here.node.path
    if words[:1] == ["apply"]:
        confirmed = "destroy" in words
        with LOCK:
            doc = here.node.document()
            state = system.observe(root, doc, start=True, spec=path)
            plan = Plan(tuple(plan_database(doc, state.database, confirmed,
                                            path)))
            outcome = system.execute(plan, system.Effects(root), False,
                                     "apply --system-only")
        return {"lines": outcome.lines, "failed": outcome.failed,
                "changed": outcome.changed}
    if words[:1] == ["follow"]:
        return FOLLOWER.follow("asked")
    if words[:1] == ["watch"]:
        FOLLOWER.watch()
        return {"log": FOLLOWER.log[-1:]}
    if words[:1] == ["sql"]:
        return sql(" ".join(words[1:]))
    if words[:1] == ["sql-as-root-tcp"]:
        return sql(" ".join(words[1:]), "root", "::1")
    if words[:1] == ["repl-probe"]:
        # a connection to the other member as the replication account
        # with the certificate and key given: the database leaf is
        # taken, an etcd member's leaf of the same root refused
        from keel.system import dbsecret, dbtls
        cert, key, host = words[1], words[2], words[3]
        done = subprocess.run(
            ["mariadb", "--batch", "--skip-column-names",
             "--connect-timeout=30", "-h", host, "-u", "repl",
             f"--password={dbsecret.read(root)}",
             f"--ssl-ca={os.path.join(root, dbtls.CA)}",
             f"--ssl-cert={os.path.join(root, cert)}",
             f"--ssl-key={os.path.join(root, key)}",
             "--ssl-verify-server-cert", "--execute",
             "SELECT CURRENT_USER()"], capture_output=True, text=True,
            check=False, timeout=60)
        return {"code": done.returncode, "out": done.stdout.strip(),
                "err": done.stderr.strip()[-200:]}
    if words[:1] == ["restart"]:
        # the server restarted, and read_only read at once
        started = time.monotonic()
        subprocess.run(["systemctl", "restart", service_of(root)],
                       capture_output=True, check=False, timeout=120)
        first = sql("SELECT @@read_only")
        return {"restart_s": round(time.monotonic() - started, 2),
                "read_only": first.get("out"), "err": first.get("err")}
    if words[:1] == ["rstatus"]:
        # with its column names: --skip-column-names would leave the
        # vertical output's values nameless
        done = subprocess.run(["mariadb", "--batch", "--execute",
                               "SHOW REPLICA STATUS\\G"], capture_output=True,
                              text=True, check=False, timeout=60)
        values = {}
        for line in done.stdout.splitlines():
            key, sep, value = line.partition(":")
            if sep and not key.startswith("*"):
                values[key.strip()] = value.strip()
        return {"code": done.returncode, "status": values,
                "err": done.stderr.strip()[-200:]}
    if words[:1] == ["dbstatus"]:
        from keel.system import dbstatus
        return {"lines": dbstatus.lines(root, path)}
    if words[:1] == ["diff"]:
        import contextlib
        import io
        from keel import cli
        out = io.StringIO()
        with LOCK, contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(out):
            code = cli.main(["diff", "--spec", path, "--root", root])
        return {"code": code, "out": out.getvalue().splitlines()}
    if words[:1] == ["dbpromote"]:
        import contextlib
        import io
        from keel import cli
        out = io.StringIO()
        started = time.monotonic()
        with LOCK, contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(out):
            code = cli.main(["database", "promote", "--spec", path, "--root",
                             root] + (["--old-primary-gone"]
                                      if "gone" in words else []))
        return {"code": code, "out": out.getvalue().splitlines(),
                "took_s": round(time.monotonic() - started, 2)}
    if words[:1] == ["followlog"]:
        return {"log": FOLLOWER.log[-20:], "runs": FOLLOWER.runs}
    if words[:1] == ["role-file"]:
        try:
            with open(os.path.join(root, "var/lib/keel/role")) as fob:
                return {"text": fob.read()}
        except OSError as e:
            return {"text": "", "error": str(e)}
    return VIP_COMMAND(here, words)


# --- the driver's side: the servers, the writer, the scenario ---------

def driver_main() -> None:
    import vip_netns
    vip_netns.spec_of = spec_of
    vip_netns.__file__ = os.path.abspath(__file__)
    vip_netns.main(play=scenario)


def spec_of(root: str, index: int, pairs) -> str:
    """vip_netns.spec_of, with the database section on the pair"""
    import yaml
    import vip_netns
    peers = [{"public_key": pairs[other][1],
              "endpoint": f"[{vip_netns.UPLINK.format(n=other + 1)}::2]:51820",
              "allowed_ips": [f"{vip_netns.OVERLAY.format(n=other + 1)}/128"],
              "persistent_keepalive": 25}
             for other in range(len(vip_netns.NAMES)) if other != index]
    own = vip_netns.OVERLAY.format(n=index + 1)
    doc = {"version": 1,
           "appliance": {"name": "core"},
           "installation": {"mode": "cloud_advanced"},
           "overlays": {"etcd": "enabled"},
           "network": {"overlay": {"wireguard": {
               "address": f"{own}/64",
               "listen_port": 51820,
               "private_key": {"file": "/etc/wireguard/wg0.key"},
               "peers": peers}}}}
    if index < 2:
        doc["appliance"]["vip"] = vip_netns.VIP
        doc["database"] = {"server": {
            "engine": "mariadb", "role": "primary" if index == 0
            else "replica", "listen": [own, "::1"]}}
    path = os.path.join(root, "instance.yaml")
    with open(path, "w") as fob:
        yaml.safe_dump(doc, fob, sort_keys=False)
    return path


def sh(*argv: str, pid: int | None = None, check: bool = True,
       env: dict | None = None) -> str:
    prefix = ["nsenter", "-t", str(pid), "-n"] if pid else []
    done = subprocess.run(prefix + list(argv), capture_output=True,
                          text=True, check=False, env=env)
    if check and done.returncode:
        raise RuntimeError(f"{' '.join(argv)}: {done.stderr.strip()[-500:]}")
    return done.stdout


def server(index: int, pid: int, root: str) -> str:
    """A MariaDB server for the node: its data directory made, its unit
    in the node's namespace started; the unit's name"""
    import vip_netns
    name = vip_netns.NAMES[index]
    unit = f"mariadb-keel-{name}"
    # the mysql user traverses the scratch root
    os.chmod(root, 0o755)
    for relative in ("var/lib/mysql", "run/mysqld", "var/tmp",
                     "etc/mysql/mariadb.conf.d", "var/lib/keel",
                     "var/backups", "etc/keel"):
        os.makedirs(os.path.join(root, relative), exist_ok=True)
    for relative in ("var/lib/mysql", "run/mysqld"):
        sh("chown", "mysql:mysql", os.path.join(root, relative))
    # the manifests of the format under the root: keel diff and keel
    # database promote read the spec as on a machine, where
    # appliance.name names an installed appliance (tests/manifest_helpers)
    import manifest_helpers
    for kind in manifest_helpers.KINDS:
        for entry in sorted(os.listdir(os.path.join(manifest_helpers.FIXTURES,
                                                    kind))):
            name = entry[:-len(".yaml")]
            manifest_helpers.put(root, kind, name,
                                 manifest_helpers.fixture(kind, name))
    # and the units and hooks the manifests name, as the fixture root has
    for name in manifest_helpers.UNITS:
        manifest_helpers.unit(root, name)
    for name in manifest_helpers.HOOKS:
        manifest_helpers.hook(root, name)
    # the spec where inspect reads the emitted one on a machine
    os.makedirs(os.path.join(root, "etc/keel"), exist_ok=True)
    emitted = os.path.join(root, "etc/keel/instance.yaml")
    if not os.path.exists(emitted):
        os.symlink(os.path.join(root, "instance.yaml"), emitted)
    # the server binary under the node's root, where keel looks for it
    os.makedirs(os.path.join(root, "usr/sbin"), exist_ok=True)
    binary = os.path.join(root, "usr/sbin/mariadbd")
    if not os.path.exists(binary):
        os.symlink("/usr/sbin/mariadbd", binary)
    sh("chmod", "1777", os.path.join(root, "var/tmp"))
    my = os.path.join(root, "etc/mysql/my.cnf")
    with open(my, "w") as fob:
        fob.write(f"""[client]
socket={socket_of(root)}
[mysqld]
user=mysql
datadir={root}/var/lib/mysql
socket={socket_of(root)}
pid-file={root}/run/mysqld/mysqld.pid
port=3306
bind-address=::1
log_error={root}/mariadb.log
tmpdir={root}/var/tmp
!includedir {root}/etc/mysql/mariadb.conf.d/
""")
    os.chmod(my, 0o644)
    sh("mariadb-install-db", f"--datadir={root}/var/lib/mysql",
       "--user=mysql", "--auth-root-authentication-method=socket",
       "--skip-test-db", env={**os.environ,
                              "TMPDIR": os.path.join(root, "var/tmp")})
    with open(f"/run/systemd/system/{unit}.service", "w") as fob:
        fob.write(f"""[Unit]
Description=MariaDB of the test node {name}
[Service]
Type=notify
User=mysql
Group=mysql
ExecStart=/usr/sbin/mariadbd --defaults-file={my}
NetworkNamespacePath=/proc/{pid}/ns/net
KillSignal=SIGTERM
TimeoutStopSec=60
""")
    sh("systemctl", "daemon-reload")
    sh("systemctl", "start", unit)
    UNITS.append(unit)
    return unit


UNITS: list[str] = []
HOOKS: dict = {"alerts": []}


def webhook_server() -> threading.Thread:
    """This namespace, the internet, takes the pair's alerts"""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import socketserver

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            try:
                HOOKS["alerts"].append({"t": time.time(),
                                        **json.loads(body.decode())})
            except ValueError:
                HOOKS["alerts"].append({"t": time.time(), "raw": body[:200]
                                        .decode(errors="replace")})
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    class Server(socketserver.ThreadingMixIn, HTTPServer):
        address_family = __import__("socket").AF_INET6
        allow_reuse_address = True

    found = Server(("::", WEBHOOK_PORT), Handler)
    thread = threading.Thread(target=found.serve_forever, daemon=True)
    thread.start()
    return thread


def monitor_settings(root: str, name: str, gateway: str) -> None:
    """/etc/keel/monitor.json of the node: a webhook at this namespace"""
    from keel.monitor import channelfile
    path = os.path.join(root, channelfile.PATH.lstrip("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
              "w") as fob:
        json.dump({"written_by": channelfile.WRITTEN_BY, "host": name,
                   "address": "", "details": False,
                   "webhook": {"url": f"http://[{gateway}]:{WEBHOOK_PORT}"
                               "/alert"}}, fob)


class Writer:
    """C, the application: one INSERT at the VIP after another, each
    timed; the gaps between successes are what a client saw"""

    def __init__(self, pid: int, vip: str):
        self.pid, self.vip = pid, vip
        self.stop = threading.Event()
        self.pause = threading.Event()
        self.results: list[dict] = []
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        n = 0
        while not self.stop.is_set():
            if self.pause.is_set():
                time.sleep(0.2)
                continue
            n += 1
            at = time.time()
            done = subprocess.run(
                ["nsenter", "-t", str(self.pid), "-n", "mariadb", "--batch",
                 "--connect-timeout=15", "-h", self.vip, "-u", APP_USER,
                 f"--password={APP_PASSWORD}", "--skip-ssl-verify-server-cert",
                 APP_DB, "--execute",
                 f"INSERT INTO t (v, at) VALUES ('w{n}', {at:.3f})"],
                capture_output=True, text=True, check=False, timeout=40)
            self.results.append({"n": n, "t": at, "ok": done.returncode == 0,
                                 "took_s": round(time.time() - at, 3),
                                 "err": done.stderr.strip()[-120:]})

    def successes(self, since: float = 0, until: float = 1e12) -> list[dict]:
        return [one for one in self.results
                if one["ok"] and since <= one["t"] + one["took_s"] <= until]

    def gap(self, start: float, end: float) -> float | None:
        """The longest stretch without a write acknowledged in
        [start, end]"""
        times = sorted(one["t"] + one["took_s"]
                       for one in self.successes(start, end))
        if not times:
            return None
        edges = [start] + times + [end]
        return round(max(b - a for a, b in zip(edges, edges[1:])), 3)

    def rows(self) -> int:
        return len([one for one in self.results if one["ok"]])


def count_rows(pid_root: str, agent, name: str) -> int | None:
    found = agent(name, f"sql SELECT COUNT(*) FROM {APP_DB}.t")
    try:
        return int(found["out"])
    except (KeyError, ValueError):
        return None


def status_value(agent, name: str, variable: str) -> str:
    found = agent(name, f"sql SHOW GLOBAL STATUS LIKE '{variable}'")
    return (found.get("out") or "").split("\t")[-1]


def replica_status(agent, name: str) -> dict:
    return agent(name, "rstatus").get("status") or {}


def scenario(report: dict, pids: list[int], pairs, roots: list[str],
             samples: list[dict]) -> None:
    """The scenario, its traceback kept in the report when it fails"""
    try:
        play(report, pids, pairs, roots, samples)
    except Exception:  # noqa: BLE001 - the report says where it ended
        import traceback
        report["trace"] = traceback.format_exc()[-3000:]
        raise


def play(report: dict, pids: list[int], pairs, roots: list[str],
         samples: list[dict]) -> None:
    import vip_netns
    from vip_netns import (
        OVERLAY, UPLINK, VIP, agent_send, heal, partition, pinger,
        wait_until,
    )
    a_pid, b_pid, c_pid = pids
    webhook_server()
    for index in (0, 1):
        monitor_settings(roots[index], vip_netns.NAMES[index],
                         f"{UPLINK.format(n=index + 1)}::1")
    # the servers, one per node
    for index in range(len(vip_netns.NAMES) - 1):
        server(index, pids[index], roots[index])
    # the application's data on A, before it is a primary: what a first
    # boot leaves
    for statement in (
            f"CREATE DATABASE {APP_DB}",
            f"CREATE TABLE {APP_DB}.t (id INT AUTO_INCREMENT PRIMARY KEY,"
            " v VARCHAR(64), at DOUBLE)",
            f"CREATE USER '{APP_USER}'@'%' IDENTIFIED BY '{APP_PASSWORD}'",
            f"GRANT ALL ON {APP_DB}.* TO '{APP_USER}'@'%'",
            f"INSERT INTO {APP_DB}.t (v, at) VALUES ('seed', {time.time():.3f})"):
        found = agent_send("A", f"sql {statement}")
        if found.get("code"):
            report["setup_error"] = found
            return
    # the pair, the VIP on A first (what the installer does); C pings it
    report["a_promote"] = agent_send("A", "promote")
    pinger(c_pid, os.path.join(roots[2], "ping.log"))
    report["a_apply"] = agent_send("A", "apply", 600)
    report["b_apply"] = agent_send("B", "apply", 900)
    report["b_follow_log"] = agent_send("B", "followlog")

    # (a) replication over TLS, a write at the VIP read on B. The I/O
    # thread's first connection to A is a TLS handshake and a
    # registration over 250 ms: waited for until it streams, up to a
    # minute (Slave_IO_Running says Yes while it still connects)
    report["b_connected_s"] = wait_until(
        lambda: replica_status(agent_send, "B").get("Slave_IO_State", "")
        .startswith("Waiting for master to send event"), 60, 1)
    report["b_status_a"] = replica_status(agent_send, "B")
    report["a_rows_a"] = count_rows(None, agent_send, "A")
    report["b_rows_a"] = count_rows(None, agent_send, "B")
    before = report["b_rows_a"]
    written = time.time()
    writer = Writer(c_pid, VIP)
    one = subprocess.run(
        ["nsenter", "-t", str(c_pid), "-n", "mariadb", "--batch",
         "-h", VIP, "-u", APP_USER, f"--password={APP_PASSWORD}",
         "--skip-ssl-verify-server-cert", APP_DB, "--execute",
         "INSERT INTO t (v, at) VALUES ('probe', 0)"],
        capture_output=True, text=True, check=False, timeout=60)
    report["a_write"] = {"code": one.returncode, "err": one.stderr[-200:],
                         "took_s": round(time.time() - written, 3)}
    seen = wait_until(lambda: count_rows(None, agent_send, "B") ==
                      (before or 0) + 1, 60, 0.05)
    report["a_lag_s"] = None if seen is None else round(
        time.time() - written, 3)
    report["a_grants"] = agent_send(
        "A", "sql SELECT Host, ssl_type, x509_subject, x509_issuer FROM"
        " mysql.user WHERE User='repl'")
    report["a_semisync"] = status_value(agent_send, "A",
                                        "Rpl_semi_sync_master_status")
    report["a_dbstatus"] = agent_send("A", "dbstatus")
    report["a_diff"] = agent_send("A", "diff")
    report["b_diff"] = agent_send("B", "diff")
    report["b_role_file"] = agent_send("B", "role-file")

    # (b) semi-synchronous: a commit's cost, then B cut
    costs = []
    for _ in range(3):
        found = agent_send("C", f"sql-as-root-tcp SELECT 1")
        costs.append(found.get("took_s"))
    report["b_commit_costs_s"] = [
        agent_send("A", f"sql INSERT INTO {APP_DB}.t (v, at) VALUES"
                   f" ('cost', {time.time():.3f})").get("took_s")
        for _ in range(3)]
    agent_send("A", "watch")
    vip_netns.leg("to2", "100%")
    sh("tc", "qdisc", "replace", "dev", "uplink", "root", "netem", "loss",
       "100%", pid=b_pid)
    cut_at = time.time()
    slow = agent_send("A", f"sql INSERT INTO {APP_DB}.t (v, at) VALUES"
                      f" ('fallback', {time.time():.3f})", 120)
    report["b_fallback_commit_s"] = slow.get("took_s")
    report["b_semisync_after"] = status_value(agent_send, "A",
                                              "Rpl_semi_sync_master_status")
    report["b_fast_after"] = agent_send(
        "A", f"sql INSERT INTO {APP_DB}.t (v, at) VALUES ('after',"
        f" {time.time():.3f})").get("took_s")
    report["b_diff_a"] = agent_send("A", "diff")
    agent_send("A", "watch")
    report["b_alert_s"] = wait_until(
        lambda: any("asynchronous" in str(one.get("text")) for one in
                    HOOKS["alerts"]), 30)
    report["b_alerts"] = [one.get("text", "")[:120] for one in HOOKS["alerts"]]
    heal(pids, 1)
    healed_at = time.time()
    report["b_back_s"] = wait_until(
        lambda: status_value(agent_send, "A", "Rpl_semi_sync_master_status")
        == "ON", 120, 1)
    agent_send("A", "watch")
    report["b_recovery_alert"] = any(
        "is back" in str(one.get("text")) for one in HOOKS["alerts"])
    report["b_cut_to_heal_s"] = round(healed_at - cut_at, 1)

    # (c) planned promote on B, C writing
    writer.start()
    time.sleep(8)
    moved_at = time.time()
    report["c_promote"] = agent_send("B", "dbpromote", 600)
    report["c_b_writable_s"] = wait_until(
        lambda: agent_send("B", "sql SELECT @@read_only").get("out") == "0",
        120, 0.5)
    time.sleep(15)
    report["c_downtime_s"] = writer.gap(moved_at - 1, time.time())
    report["c_a_rejoined_s"] = wait_until(
        lambda: replica_status(agent_send, "A").get("Master_Host") ==
        OVERLAY.format(n=2) and replica_status(agent_send, "A").get(
            "Slave_SQL_Running") == "Yes", 120, 1)
    writer.pause.set()
    time.sleep(6)
    report["c_rows_c"] = writer.rows()
    report["c_b_rows"] = count_rows(None, agent_send, "B")
    report["c_a_rows"] = count_rows(None, agent_send, "A")
    report["c_a_status"] = replica_status(agent_send, "A")
    report["c_a_role_file"] = agent_send("A", "role-file")
    report["c_a_followlog"] = agent_send("A", "followlog")

    # (d) the primary B cut off, C idle: failover, then rejoin by itself
    cut_at = partition(report, "d", pids, roots, samples, 1, 0,
                       os.path.join(roots[2], "ping.log"), {
                           n: pairs[i][1] for i, n in
                           enumerate(vip_netns.NAMES)})
    report["d_a_writable_s"] = wait_until(
        lambda: agent_send("A", "sql SELECT @@read_only").get("out") == "0",
        120, 0.5)
    writer.pause.clear()
    resumed = wait_until(lambda: writer.successes(cut_at), 120, 0.5)
    report["d_writes_resume_s"] = None if resumed is None else round(
        writer.successes(cut_at)[0]["t"] + writer.successes(cut_at)[0]
        ["took_s"] - cut_at, 2)
    writer.pause.set()
    time.sleep(3)
    healed_at = heal(pids, 1)
    report["d_b_rejoined_s"] = wait_until(
        lambda: replica_status(agent_send, "B").get("Master_Host") ==
        OVERLAY.format(n=1) and replica_status(agent_send, "B").get(
            "Slave_SQL_Running") == "Yes", 240, 1)
    report["d_b_read_only"] = agent_send("B", "sql SELECT @@read_only")
    report["d_b_dbstatus"] = agent_send("B", "dbstatus")
    report["d_b_followlog"] = agent_send("B", "followlog")
    report["d_rows"] = {"c": writer.rows(),
                        "a": count_rows(None, agent_send, "A"),
                        "b": count_rows(None, agent_send, "B")}

    # (d), second run: A the primary, cut off with C writing through
    writer.pause.clear()
    time.sleep(6)
    alerts_before = len(HOOKS["alerts"])
    cut_at = partition(report, "d2", pids, roots, samples, 0, 1,
                       os.path.join(roots[2], "ping.log"), {
                           n: pairs[i][1] for i, n in
                           enumerate(vip_netns.NAMES)})
    report["d2_b_writable_s"] = wait_until(
        lambda: agent_send("B", "sql SELECT @@read_only").get("out") == "0",
        120, 0.5)
    time.sleep(12)
    writer.pause.set()
    time.sleep(3)
    heal(pids, 0)
    report["d2_a_diverged_s"] = wait_until(
        lambda: "diverged" in "\n".join(agent_send("A", "dbstatus").get(
            "lines") or []), 240, 2)
    report["d2_a_dbstatus"] = agent_send("A", "dbstatus")
    report["d2_a_read_only"] = agent_send("A", "sql SELECT @@read_only")
    report["d2_a_diff"] = agent_send("A", "diff")
    report["d2_alert_s"] = wait_until(
        lambda: any("diverged" in str(one.get("text")) for one in
                    HOOKS["alerts"][alerts_before:]), 30)
    report["d2_a_followlog"] = agent_send("A", "followlog")
    report["d2_a_errant_write"] = agent_send(
        "A", f"sql SELECT COUNT(*) FROM {APP_DB}.t")
    report["d2_b_rows"] = count_rows(None, agent_send, "B")
    # confirmed: reseeded from B, a replica again
    report["d2_a_reseed"] = agent_send("A", "apply destroy", 600)
    report["d2_a_rejoined_s"] = wait_until(
        lambda: replica_status(agent_send, "A").get("Master_Host") ==
        OVERLAY.format(n=2) and replica_status(agent_send, "A").get(
            "Slave_SQL_Running") == "Yes", 120, 1)
    report["d2_rows_after"] = {"a": count_rows(None, agent_send, "A"),
                               "b": count_rows(None, agent_send, "B")}

    # (e) the replica, A, refuses writes
    report["e_root_socket"] = agent_send(
        "A", f"sql INSERT INTO {APP_DB}.t (v, at) VALUES ('root', 0)")
    found = subprocess.run(
        ["nsenter", "-t", str(c_pid), "-n", "mariadb", "--batch",
         "-h", OVERLAY.format(n=1), "-u", APP_USER,
         f"--password={APP_PASSWORD}", "--skip-ssl-verify-server-cert",
         APP_DB, "--execute", "INSERT INTO t (v, at) VALUES ('app', 0)"],
        capture_output=True, text=True, check=False, timeout=60)
    report["e_app_at_replica"] = {"code": found.returncode,
                                  "err": found.stderr.strip()[-200:]}
    report["e_a_bypass"] = agent_send(
        "A", "sql SELECT GRANTEE FROM information_schema.USER_PRIVILEGES"
        " WHERE PRIVILEGE_TYPE = 'READ_ONLY ADMIN'")
    writer.stop.set()
    report["writes"] = {"total": len(writer.results), "ok": writer.rows(),
                        "failed_tail": [one for one in writer.results
                                        if not one["ok"]][-5:]}
    report["alerts"] = [one.get("text", "")[:160] for one in HOOKS["alerts"]]
    for process in vip_netns.AGENTS.values():
        try:
            process.stdin.write("quit\n")
            process.stdin.close()
        except OSError:
            pass


def main() -> None:
    try:
        driver_main()
    finally:
        for unit in UNITS:
            subprocess.run(["systemctl", "stop", unit], capture_output=True,
                           check=False)
            try:
                os.remove(f"/run/systemd/system/{unit}.service")
            except OSError:
                pass


if __name__ == "__main__":
    if sys.argv[1:2] == ["agent"]:
        agent_main(sys.argv[2], sys.argv[3])
    elif sys.argv[1:2] == ["lead"]:
        import vip_netns
        vip_netns.move_leader(sys.argv[2])
    else:
        main()
