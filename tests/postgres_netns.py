# Copyright (c) 2026 KeelLinux maintainers
"""A PostgreSQL pair on the mesh, three nodes in three namespaces

Run as root in a network namespace of its own by
tests/test_postgres_netns.py (tests/wgtools.py says how); never run by
hand on a machine. The nodes, the links of decision 0050's design case
(250 ms +-25 ms with 2 % loss, measured first), etcd, the members'
channel, the VIP's units and the agents are tests/vip_netns.py's: this
module drives them with a PostgreSQL server per node, each a systemd
unit of its own in the node's namespace (`postgresql-keel-<node>`),
with its cluster's configuration under the node's scratch root's
`etc/postgresql/<version>/main/`, so the drop-ins keel writes under
that root are the server's. keel runs in each node's agent with
KEEL_LIVE_ROOT naming the node's root (the live system of that node),
PGHOST naming the directory of that node's socket, which runuser keeps
for the clients (keel.system.dbpostgres), and KEEL_POSTGRES_SERVICE
naming its unit: the three seams the PR body names. Each agent also
stands for keel-database-follow.path (keel database follow when the
VIP's state changes) and keel-database-watch.timer (keel database
watch every 10 s here, 30 on a machine).

A and B are the pair (A primary, B replica, by their specs); C is the
client at the VIP. This module runs case (a) of docs/replication.md,
the PostgreSQL wording: A and B applied, B seeded over TLS with
pg_basebackup (the walreceiver of application_name `keel` streams with
sslmode=verify-full, the pair's slot on A), a write on the primary
through its loopback (::1: on a pair the socket listens on the overlay
and the VIP for the replication, and the application stays loopback,
the way the appliance manifest has it) read on B, the synchronous
commit cost measured (a commit is acknowledged once the standby
received and flushed it: about one round trip), the replica refusing
writes while it is in recovery, and `keel diff` clean on both. Cases
(b) to (e), the fallback, the planned promote, the failover and
rejoin, the diverged old primary and the replica's refusals, are the
follow-up pull request's, with the rest of this harness.

The result is one JSON line, `RESULT {...}`.
"""

import glob
import json
import os
import shutil
import subprocess
import sys
import threading
import time

ROOT_PREFIX = "keel-vip-"
WEBHOOK_PORT = 8099
# the time between two watch runs in an agent (30 s on a machine)
WATCH_EVERY = 10.0
APP_USER, APP_PASSWORD, APP_DB = "app", "app-pw-1", "shop"
PORT = 5432


def binary_dir() -> str:
    """The installed server's bin directory, as Debian versions it"""
    found = sorted(glob.glob("/usr/lib/postgresql/*/bin"))
    if not found:
        raise RuntimeError("no PostgreSQL server under /usr/lib/postgresql")
    return found[-1]


# --- the agent's side: a node's keel, with its seams -------------------

def node_name(root: str) -> str:
    """A, B or C, from the scratch root's name"""
    base = os.path.basename(root.rstrip("/"))
    return base[len(ROOT_PREFIX):].split("-")[0]


def socket_dir(root: str) -> str:
    return os.path.join(root, "run/postgresql")


def service_of(root: str) -> str:
    return f"postgresql-keel-{node_name(root)}"


def seams(root: str) -> None:
    os.environ["KEEL_LIVE_ROOT"] = root
    os.environ["PGHOST"] = socket_dir(root)
    os.environ["KEEL_POSTGRES_SERVICE"] = service_of(root)


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
        from keel.system import dbwatch
        said: list[str] = []
        with LOCK:
            code = dbwatch.watch(self.root, self.path, said.append,
                                 said.append)
        self.log.append(f"{time.time():.3f} watch: {code}: {said}")
        print(self.log[-1], file=sys.stderr, flush=True)


FOLLOWER = Follower()
LOCK = threading.RLock()


def sql(statement: str, database: str | None = None,
        timeout: float = 60) -> dict:
    """One statement through the socket as the postgres OS user (the
    way keel.system.dbpostgres' CLIENT does); what it answered and how
    long it took. PGHOST, set by seams(), names the node's socket"""
    argv = ["runuser", "-u", "postgres", "--", "psql", "--no-psqlrc",
            "--tuples-only"]
    if database:
        argv += ["--dbname", database]
    argv += ["--command", statement]
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


def app_sql(statement: str, timeout: float = 60) -> dict:
    """One statement as the application, over the loopback the way a
    co-located application reaches the server on a pair: the password
    by the environment, never the argument vector"""
    # connect_timeout is a conninfo parameter, not a psql flag (the way
    # MariaDB's --connect-timeout is a flag)
    argv = ["psql", "--no-psqlrc", "--tuples-only",
            f"host=::1 port={PORT} user={APP_USER} dbname={APP_DB} "
            f"connect_timeout={int(timeout)}",
            "--command", statement]
    started = time.monotonic()
    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              check=False, timeout=timeout,
                              env={**os.environ,
                                   "PGPASSWORD": APP_PASSWORD})
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
    if words[:1] == ["sql-db"]:
        return sql(" ".join(words[2:]), words[1])
    if words[:1] == ["sql-app"]:
        return app_sql(" ".join(words[1:]))
    if words[:1] == ["wstatus"]:
        # what the server is and where its walreceiver stands: in
        # recovery, the status, and the conninfo (the password of which
        # the server never shows)
        recovery = sql("SELECT pg_is_in_recovery()")
        status = sql("SELECT status FROM pg_stat_wal_receiver")
        conninfo = sql("SELECT conninfo FROM pg_stat_wal_receiver")
        return {"recovery_code": recovery.get("code"),
                "in_recovery": recovery.get("out"),
                "status": status.get("out"),
                "conninfo": conninfo.get("out"),
                "err": recovery.get("err") or status.get("err")}
    if words[:1] == ["repl-probe"]:
        # pg_basebackup of the other member as the replication role, the
        # certificate and key given and the password by a pgpass file:
        # the physical replication protocol the standby itself speaks,
        # so the pair's hba line (database replication, the cert method
        # and the keel map) is exactly what accepts or refuses — the
        # database leaf is taken, an etcd member's leaf of the same root
        # refused
        from keel.system import dbsecret, dbpostgres, dbtls
        cert, key, host = words[1], words[2], words[3]
        lay = dbtls.LAYOUTS["postgresql"]
        password = str(dbsecret.read(root)).replace("\\", "\\\\") \
            .replace(":", "\\:")
        pgpass = os.path.join(root, "var/tmp/probe.pgpass")
        # any host, the replication pseudo-database, the pair's role;
        # the two characters a pgpass field escapes (keel.system.dbpgseed)
        with open(os.open(pgpass, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                          0o600), "w") as fob:
            # codeql[py/clear-text-storage-sensitive-data] the 0600 pgpass of the node's scratch root, the twin of what keel.system.dbpgseed writes
            fob.write(f"*:{PORT}:replication:"
                      f"{dbpostgres.REPLICATION_USER}:{password}\n")
        os.chmod(pgpass, 0o600)
        target = os.path.join(root, "var/tmp/probe-basebackup")
        shutil.rmtree(target, ignore_errors=True)
        done = subprocess.run(
            ["pg_basebackup", "--verbose", "--checkpoint=fast",
             "-X", "none", "--pgdata", target,
             "--dbname",
             f"host={host} port={PORT} user={dbpostgres.REPLICATION_USER}"
             f" connect_timeout=30 sslmode=verify-full"
             f" sslrootcert={os.path.join(root, lay.ca)}"
             f" sslcert={os.path.join(root, cert)}"
             f" sslkey={os.path.join(root, key)}"],
            capture_output=True, text=True, check=False, timeout=120,
            env=dict(os.environ, PGPASSFILE=pgpass))
        shutil.rmtree(target, ignore_errors=True)
        return {"code": done.returncode,
                "out": (done.stdout + done.stderr).strip()[-300:],
                "err": done.stderr.strip()[-300:]}
    if words[:1] == ["restart"]:
        # the server restarted (the unit's ExecStartPost holds the start
        # until pg_isready answers), and its recovery state read as soon
        # as it answers again
        started = time.monotonic()
        subprocess.run(["systemctl", "restart", service_of(root)],
                       capture_output=True, check=False, timeout=120)
        recovery = ""
        for _ in range(60):
            found = sql("SELECT pg_is_in_recovery()")
            if not found.get("code"):
                recovery = found.get("out")
                break
            time.sleep(1)
        return {"restart_s": round(time.monotonic() - started, 2),
                "in_recovery": recovery}
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
    if words[:1] == ["followlog"]:
        return {"log": FOLLOWER.log[-20:], "runs": FOLLOWER.runs}
    if words[:1] == ["role-file"]:
        try:
            with open(os.path.join(root, "var/lib/keel/role")) as fob:
                return {"text": fob.read()}
        except OSError as e:
            return {"text": "", "error": str(e)}
    return VIP_COMMAND(here, words)


def follow_when_etcd_answers(ask, upto_s: float = 120) -> dict:
    """A's boot follow, asked again while its etcd is too new to answer.

    A's etcd is seconds old at boot and the link is the poor one: a
    single run can fail with "etcd did not answer" (keel#94). The
    failure is at the observation, before anything was changed, so the
    run is safe to repeat; bounded"""
    deadline = time.monotonic() + upto_s
    tries = 0
    while True:
        tries += 1
        found = ask("A", "follow", 180)
        found["tries"] = tries
        if found["problem"] is None or "did not answer" not in \
                found["problem"] or time.monotonic() >= deadline:
            return found
        time.sleep(3)


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
            "engine": "postgresql", "role": "primary" if index == 0
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
    """A PostgreSQL server for the node: its cluster made under the
    node's root (a fresh initdb), its unit in the node's namespace
    started; the unit's name"""
    import vip_netns
    name = vip_netns.NAMES[index]
    unit = f"postgresql-keel-{name}"
    bindir = binary_dir()
    version = os.path.basename(os.path.dirname(bindir))
    conf = os.path.join(root, f"etc/postgresql/{version}/main")
    datadir = os.path.join(root, f"var/lib/postgresql/{version}/main")
    # the postgres user traverses the scratch root
    os.chmod(root, 0o755)
    for relative in (f"var/lib/postgresql/{version}", "run/postgresql",
                     "var/tmp", "var/backups/keel", "var/lib/keel",
                     "etc/keel", "etc/postgresql/keel-tls"):
        os.makedirs(os.path.join(root, relative), exist_ok=True)
    os.makedirs(os.path.join(conf, "conf.d"), exist_ok=True)
    sh("chown", "postgres:postgres",
       os.path.join(root, f"var/lib/postgresql/{version}"))
    sh("chown", "postgres:postgres", os.path.join(root, "run/postgresql"))
    sh("chmod", "2775", os.path.join(root, "run/postgresql"))
    sh("chmod", "1777", os.path.join(root, "var/tmp"))
    # the manifests of the format under the root: keel diff reads the
    # spec as on a machine, where appliance.name names an installed
    # appliance (tests/manifest_helpers)
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
    # the server binaries under the node's root, where keel looks for
    # them (keel.inspect.dbengines' installed check)
    os.makedirs(os.path.join(root, "usr/lib/postgresql", version, "bin"),
                exist_ok=True)
    for tool in ("postgres", "pg_ctl"):
        target = os.path.join(root, "usr/lib/postgresql", version, "bin",
                              tool)
        if not os.path.exists(target):
            os.symlink(os.path.join(bindir, tool), target)
    # initdb has no /usr/bin wrapper the way psql has: the absolute
    # path of the versioned server directory
    sh("runuser", "-u", "postgres", "--", os.path.join(bindir, "initdb"),
       "-D", datadir,
       "-E", "UTF8", "--auth-local=peer", "--auth-host=scram-sha-256",
       "--no-sync",
       env={**os.environ, "TMPDIR": os.path.join(root, "var/tmp")})
    # the cluster's configuration, under the root the way Debian's
    # layout has it: the data directory, the port, the loopback and the
    # socket of this node, and conf.d, where keel's drop-ins land. The
    # hba is initdb's until an apply points hba_file at keel's file
    with open(os.path.join(conf, "postgresql.conf"), "w") as fob:
        fob.write(f"""data_directory = '{datadir}'
port = {PORT}
listen_addresses = '::1,127.0.0.1'
unix_socket_directories = '{socket_dir(root)}'
include_dir = 'conf.d'
""")
    os.chmod(os.path.join(conf, "postgresql.conf"), 0o644)
    with open(f"/run/systemd/system/{unit}.service", "w") as fob:
        fob.write(f"""[Unit]
Description=PostgreSQL of the test node {name}
[Service]
Type=simple
User=postgres
Group=postgres
ExecStart={bindir}/postgres -D {datadir} -c config_file={conf}/postgresql.conf
# the readiness production's Type=notify gives: apply runs its SQL the
# moment a restart returns, so the restart must not return first
ExecStartPost=/bin/sh -c 'for i in $(seq 1 300); do {bindir}/pg_isready -q -h {socket_dir(root)} -p {PORT} && exit 0; sleep 0.2; done; exit 1'
NetworkNamespacePath=/proc/{pid}/ns/net
KillSignal=SIGINT
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


def count_rows(agent, name: str) -> int | None:
    found = agent(name, f"sql SELECT COUNT(*) FROM {APP_DB}.t")
    try:
        return int(found["out"])
    except (KeyError, ValueError):
        return None


def apply_with_cert_ask_retry(name: str, upto_s: float = 300) -> dict:
    """`keel apply` on a paired database node, retrying while the only
    failure is the certificate ask over the members' channel (keel#131):
    that ask is one message, which can die on the lossy link ("did not
    sign the database certificate"), and a failed apply changed nothing
    past the certificate step, so running it again is safe"""
    from vip_netns import agent_send
    deadline = time.monotonic() + upto_s
    tries = 0
    while True:
        tries += 1
        said = agent_send(name, "apply", 900)
        if not said.get("failed") or time.monotonic() >= deadline or not \
                any("did not sign the database certificate" in line
                    for line in said.get("lines") or []):
            said["tries"] = tries
            return said
        time.sleep(3)


def write_on(pid: int, value: str) -> tuple[subprocess.CompletedProcess,
                                            float, float]:
    """One application INSERT on the primary through its loopback, as a
    co-located application does on a pair; the attempt, its start and
    its acknowledgement (a synchronous commit: once the standby flushed
    it)"""
    started = time.time()
    one = subprocess.run(
        ["nsenter", "-t", str(pid), "-n", "psql", "--no-psqlrc",
         "--tuples-only",
         f"host=::1 port={PORT} user={APP_USER} dbname={APP_DB} "
         f"connect_timeout=30",
         "--command", f"INSERT INTO t (v, at) VALUES ('{value}',"
         f" {started:.3f})"],
        capture_output=True, text=True, check=False, timeout=60,
        env={**os.environ, "PGPASSWORD": APP_PASSWORD})
    return one, started, time.time()


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
    from vip_netns import OVERLAY, UPLINK, agent_send, wait_until
    a_pid = pids[0]
    webhook_server()
    for index in (0, 1):
        monitor_settings(roots[index], vip_netns.NAMES[index],
                         f"{UPLINK.format(n=index + 1)}::1")
    for index in range(len(vip_netns.NAMES) - 1):
        server(index, pids[index], roots[index])
    # the VIP on A first (what the installer does): A takes the
    # application's data once it holds the VIP and follow confirmed it
    report["a_promote"] = agent_send("A", "promote")
    report["a_follow_after_promote"] = agent_send("A", "follow", 180)
    # the application's data on A: what a first boot leaves (the table
    # in the shop database, the application user, one seed row)
    for statement, database in (
            (f"CREATE DATABASE {APP_DB}", None),
            (f"CREATE USER {APP_USER} WITH PASSWORD '{APP_PASSWORD}'", None),
            (f"GRANT ALL ON DATABASE {APP_DB} TO {APP_USER}", None),
            (f"GRANT USAGE ON SCHEMA public TO {APP_USER}", APP_DB),
            (f"CREATE TABLE t (id SERIAL PRIMARY KEY, v TEXT,"
             " at DOUBLE PRECISION)", APP_DB),
            (f"GRANT ALL ON TABLE t TO {APP_USER}", APP_DB),
            # PostgreSQL, unlike MariaDB's twin of this setup, keeps the
            # serial's sequence a separate object: INSERT takes the
            # table grant, the id column's default nextval does not
            (f"GRANT ALL ON SEQUENCE t_id_seq TO {APP_USER}", APP_DB),
            (f"INSERT INTO t (v, at) VALUES ('seed', {time.time():.3f})",
             APP_DB)):
        found = agent_send("A", "sql-db " + (database or "postgres") + " "
                           + statement) if database else \
            agent_send("A", f"sql {statement}")
        if found.get("code"):
            report["setup_error"] = found
            return
    # then apply on each, as its first boot would
    report["a_apply"] = apply_with_cert_ask_retry("A", 600)
    report["b_apply"] = apply_with_cert_ask_retry("B", 900)
    report["b_follow_log"] = agent_send("B", "followlog")

    # (a) the standby streams from the primary over TLS, a write on the
    # primary read on it. The walreceiver's first connection is a TLS
    # handshake and a registration over 250 ms: waited for until it
    # streams (B's apply already waited for the seed's streaming; this
    # reads the steady state)
    report["b_connected_s"] = wait_until(
        lambda: agent_send("B", "wstatus").get("status") == "streaming",
        60, 1)
    report["b_status_a"] = agent_send("B", "wstatus")
    report["a_rows_a"] = count_rows(agent_send, "A")
    report["b_rows_a"] = count_rows(agent_send, "B")
    before = report["b_rows_a"] or 0
    lags = []
    for n in range(3):
        one, started, acked = write_on(a_pid, f"probe{n}")
        seen = wait_until(lambda: count_rows(agent_send, "B") ==
                          before + n + 1, 60, 0.05)
        lags.append({"write_ok": one.returncode == 0,
                     "write_s": round(acked - started, 3),
                     "lag_s": None if seen is None else round(
                         time.time() - acked, 3),
                     "err": one.stderr.strip()[-200:]})
    report["a_writes"] = lags
    report["a_write"] = {"code": 0 if all(one["write_ok"] for one in lags)
                         else 1}
    report["a_lag_s"] = max((one["lag_s"] for one in lags
                             if one["lag_s"] is not None), default=None)
    # the pair's synchronous commit: the primary acknowledges a commit
    # once the standby of application_name keel received and flushed it
    report["a_sync"] = agent_send("A", "sql SHOW synchronous_standby_names")
    report["a_slot"] = agent_send(
        "A", "sql SELECT slot_name, active FROM pg_replication_slots")
    report["a_commit_costs_s"] = [
        agent_send("A", f"sql-app INSERT INTO t (v, at) VALUES"
                   f" ('cost', {time.time():.3f})").get("took_s")
        for _ in range(3)]
    report["a_dbstatus"] = agent_send("A", "dbstatus")
    report["a_diff"] = agent_send("A", "diff")
    report["b_diff"] = agent_send("B", "diff")
    report["b_role_file"] = agent_send("B", "role-file")
    report["b_in_recovery"] = agent_send("B", "sql SELECT pg_is_in_recovery()")
    # a standby refuses writes while it is in recovery: no account, no
    # privilege, a property of the role (0054)
    report["b_refused"] = agent_send(
        "B", "sql-app INSERT INTO t (v, at) VALUES ('nope', 0)")
    # the replication account takes the other member's database leaf
    # alone: B's etcd member certificate, of the same root, is refused
    report["a_repl_database_leaf"] = agent_send(
        "B", "repl-probe etc/postgresql/keel-tls/server.pem"
        " etc/postgresql/keel-tls/server.key " + OVERLAY.format(n=1))
    report["a_repl_etcd_leaf"] = agent_send(
        "B", "repl-probe var/lib/keel/etcd/member.crt"
        " var/lib/keel/etcd/member.key " + OVERLAY.format(n=1))
    # the primary restarted: PostgreSQL has no read-only boot (a
    # standby's refusal is recovery, and a primary serves at once), so
    # the check is the opposite of MariaDB's: writable again, the
    # standby streaming again after
    report["a_restart"] = agent_send("A", "restart", 180)
    report["a_follow_after_restart"] = agent_send("A", "follow", 180)
    report["a_writable_after_restart"] = agent_send(
        "A", "sql-app INSERT INTO t (v, at) VALUES"
        f" ('after-restart', {time.time():.3f})")
    report["b_streaming_after_restart_s"] = wait_until(
        lambda: agent_send("B", "wstatus").get("status") == "streaming",
        120, 1)
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
    else:
        main()
