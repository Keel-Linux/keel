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
writes while it is in recovery, and `keel diff` clean on both. Then
cases (b) to (e), the PostgreSQL wording of docs/replication.md's:

- (b) the replica cut off: the primary keeps the VIP, a commit on it
  waits (no timeout, no fallback: 0054), the primary's watch alerts,
  and after the heal the commit is acknowledged and the end alerted;
- (c) the primary cut off and killed while the application writes:
  B's VIP controller claims once the lease of A's claim expired, and
  B commits alone with no operator (keel#165), the downtime, and no
  acknowledged row lost;
- (e) the old primary back from its crash: never acknowledging a write,
  fenced as a standby that follows nobody, dumped (the dump holds its
  own unacknowledged rows), the divergence recorded and alerted once;
- (d) the old primary's rejoin, the one path 0054 has: the confirmed
  reseed, after which it streams from B and B's commits finish again.

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
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEBHOOK_PORT = 8099
# the time between two watch runs in an agent (30 s on a machine)
WATCH_EVERY = 10.0
APP_USER, APP_PASSWORD, APP_DB = "app", "app-pw-1", "shop"
PORT = 5432
# how long the application's client waits for one write: a commit that
# waits for an away standby has no end of its own (0054), so the
# client is killed then, never cancelled — a cancelled wait answers
# success with a warning that the commit is only local
HANG_S = 30
T0 = time.time()


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

    def run(self) -> None:
        """keel-database-follow.path is PathChanged=/var/lib/keel/vip:
        systemd's inotify mask, so an open for writing that writes
        nothing starts follow as on a machine (keel#164; the mtime that
        this loop read before missed it)"""
        from pathwatch import PathChanged
        directory = os.path.join(self.root, "var/lib/keel/vip")
        os.makedirs(directory, mode=0o700, exist_ok=True)
        watch = PathChanged(directory)
        watched = time.monotonic()
        while not self.stop.is_set():
            if watch.events(0.5):
                self.follow("the VIP's state changed")
            if time.monotonic() - watched >= WATCH_EVERY:
                watched = time.monotonic()
                self.watch()
        watch.close()

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
        # IDENTIFY_SYSTEM on a physical replication connection as the
        # replication role, the certificate and key given and the
        # password by a pgpass file: the connection matches the pair's
        # hba line (the replication keyword, the cert method and the
        # keel map) exactly — the database leaf is taken, an etcd
        # member's leaf of the same root refused. replication=true (the
        # walreceiver's dialect), not =database: a logical connection
        # asks for the postgres database and the scram probe line under
        # it, and a password prompt would read the agent's own command
        # pipe. The ask is one handshake, not a copy of the data
        # directory: what a copy proved would be the link's patience,
        # not the authorization
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
        try:
            done = subprocess.run(
                ["psql", "--no-psqlrc", "--tuples-only",
                 f"host={host} port={PORT}"
                 f" user={dbpostgres.REPLICATION_USER}"
                 f" dbname=postgres connect_timeout=30"
                 f" sslmode=verify-full"
                 f" sslrootcert={os.path.join(root, lay.ca)}"
                 f" sslcert={os.path.join(root, cert)}"
                 f" sslkey={os.path.join(root, key)}"
                 " replication=true",
                 "--command", "IDENTIFY_SYSTEM"],
                capture_output=True, text=True, check=False, timeout=120,
                env=dict(os.environ, PGPASSFILE=pgpass))
        except subprocess.TimeoutExpired:
            return {"code": -1, "out": "IDENTIFY_SYSTEM timed out",
                    "err": "IDENTIFY_SYSTEM timed out"}
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
    if words[:1] == ["dbpromote"]:
        import contextlib
        import io
        from keel import cli
        out = io.StringIO()
        started = time.monotonic()
        # not under LOCK: on a machine keel-database-follow.path runs
        # follow while the promote goes on (when the claim is written),
        # and follow's own lock orders the two runs (keel#118)
        with contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(out):
            code = cli.main(["database", "promote", "--spec", path, "--root",
                             root] + (["--old-primary-gone"]
                                      if "gone" in words else []))
        return {"code": code, "out": out.getvalue().splitlines(),
                "took_s": round(time.monotonic() - started, 2)}
    if words[:1] == ["followlog"]:
        return {"log": FOLLOWER.log[-20:], "runs": FOLLOWER.runs,
                "follows": [one for one in FOLLOWER.log if " follow (" in one]}
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
    for tool in ("postgres", "pg_ctl", "pg_rewind"):
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
       # pg_rewind copies the WAL segments of the new primary in full,
       # 16 MB each by default: at 50 kB/s on the design case's link
       # that is 5 minutes for one, and a node has three to copy. The
       # test is about what keel decides, not about that cost, which the
       # release test on real nodes measures (0054, amendment of
       # 2026-10-18)
       "--wal-segsize=1",
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
# keel's drop-in for postgresql@.service, as the package installs it
# (keel#156): the start as a primary only on the proven holder
ExecStartPre=+/usr/bin/env PYTHONPATH={REPO} KEEL_POSTGRES_SERVICE={unit} {sys.executable} -m keel database guard --root {root} --spec {root}/instance.yaml
ExecStart={bindir}/postgres -D {datadir} -c config_file={conf}/postgresql.conf
# the readiness production's Type=notify gives: apply runs its SQL the
# moment a restart returns, so the restart must not return first
ExecStartPost=/bin/sh -c 'for i in $(seq 1 300); do {bindir}/pg_isready -q -h {socket_dir(root)} -p {PORT} && exit 0; sleep 0.2; done; exit 1'
NetworkNamespacePath=/proc/{pid}/ns/net
KillSignal=SIGINT
TimeoutStopSec=60
""")
    # the unit's name is this node's, host-global, the way the
    # product's is: a generation whose driver was killed (a pytest
    # timeout) leaves it active against the old root, and a start
    # against an active unit is a no-op that leaves this generation
    # with no server of its own (found by this test's run on the
    # lossy link, where a hang let the runner's kill leak the unit
    # into the next generation)
    subprocess.run(["systemctl", "stop", unit], capture_output=True,
                   check=False)
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
    # the application's database, the table in its public schema: a
    # qualified "shop.t" would name a schema, not the database
    found = agent(name, f"sql-db {APP_DB} SELECT COUNT(*) FROM t")
    try:
        return int(found["out"])
    except (KeyError, ValueError):
        return None


def apply_with_cert_ask_retry(name: str, upto_s: float = 300,
                              destroy: bool = False) -> dict:
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
        started = time.monotonic()
        said = agent_send(name, "apply destroy" if destroy else "apply",
                          900)
        said["took_s"] = round(time.monotonic() - started, 2)
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
            # as the keel-lnpp check database had it: repl may not
            # connect, and the reseed of case (d) must still work
            # (keel#183)
            (f"REVOKE CONNECT ON DATABASE {APP_DB} FROM PUBLIC", None),
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
    mark(report, "setup")
    # then apply on each, as its first boot would
    report["a_apply"] = apply_with_cert_ask_retry("A", 600)
    mark(report, "a_apply")
    report["b_apply"] = apply_with_cert_ask_retry("B", 900)
    mark(report, "b_apply")
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
    mark(report, "case_a")
    # a steady pair starts no follow by keel-database-follow.path
    # (keel#164: with etcd, every 1 to 2 s until the start limit)
    before = {name: agent_send(name, "followlog").get("runs")
              for name in ("A", "B")}
    time.sleep(20)
    report["a_quiet_follow_runs"] = {
        name: (agent_send(name, "followlog").get("runs") or 0)
        - (before[name] or 0) for name in ("A", "B")}
    replica_cut(report, pids, roots)
    mark(report, "case_b")
    crashed(report, pids, roots)
    report["alerts"] = [one.get("text", "")[:160] for one in HOOKS["alerts"]]
    for process in vip_netns.AGENTS.values():
        try:
            process.stdin.write("quit\n")
            process.stdin.close()
        except OSError:
            pass


def mark(report: dict, phase: str) -> None:
    """When a phase ended, in seconds from the driver's start: the CI
    job's budget is read from these"""
    report.setdefault("phase_s", {})[phase] = round(time.time() - T0, 1)


def pg_ask(root: str, statement: str, database: str | None = None,
           timeout: float = 10) -> str:
    """One question to a node's server by its socket, from the driver,
    so the node's agent stays free for the command in flight; the
    answer, or "down" """
    argv = ["runuser", "-u", "postgres", "--", "psql", "--no-psqlrc",
            "--tuples-only", "--no-align", "--field-separator=\t",
            "--host", socket_dir(root), "--port", str(PORT)]
    if database:
        argv += ["--dbname", database]
    try:
        done = subprocess.run(argv + ["--command", statement],
                              capture_output=True, text=True, check=False,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        return "timed out"
    return done.stdout.strip() if done.returncode == 0 else "down"


def sync_standbys(root: str) -> str:
    return pg_ask(root, "SELECT count(*) FROM pg_stat_replication WHERE"
                  " application_name = 'keel' AND sync_state = 'sync'")


def app_write(pid: int, value: str, timeout: float = HANG_S) -> dict:
    """One INSERT by the application on a node, through its loopback
    (on a pair the application is co-located: 0054); acknowledged only
    by its own answer"""
    started = time.time()
    try:
        one = subprocess.run(
            ["nsenter", "-t", str(pid), "-n", "psql", "--no-psqlrc",
             "--tuples-only",
             f"host=::1 port={PORT} user={APP_USER} dbname={APP_DB}"
             " connect_timeout=2",
             "--command", f"INSERT INTO t (v, at) VALUES ('{value}',"
             f" {started:.3f})"],
            capture_output=True, text=True, check=False, timeout=timeout,
            env={**os.environ, "PGPASSWORD": APP_PASSWORD})
        # a cancelled wait for the standby answers success with this
        # warning: the commit is local only, and nobody may count on it
        ok = one.returncode == 0 and "committed locally" not in one.stderr
        err = one.stderr.strip()[-80:]
    except subprocess.TimeoutExpired:
        ok, err = False, f"no answer within {timeout:.0f} s"
    return {"t": round(started, 3), "end": round(time.time(), 3), "ok": ok,
            "err": err}


def alerted(name: str, title: str, since: int) -> list[dict]:
    """The alerts of node `name` with this title, from index `since`"""
    return [one for one in HOOKS["alerts"][since:]
            if str(one.get("text", "")).startswith(f"[{name}] {title}")]


def replica_cut(report: dict, pids: list[int], roots: list[str]) -> None:
    """(b): the replica B cut off, both ways. A keeps the VIP (its lease
    is renewed through C, the majority); with etcd nothing is fenced,
    since B holds no lease. A commit on A waits for B, with no timeout
    and no fallback to asynchronous (0054): A's watch alerts, and once
    the link heals the commit is acknowledged, the end alerted"""
    import vip_netns
    from keel.system import dbwatch
    from vip_netns import wait_until
    a_root, b_root = roots[0], roots[1]
    report["b_sync_before_s"] = wait_until(
        lambda: sync_standbys(a_root) == "1", 120, 1)
    since = len(HOOKS["alerts"])
    vip_netns.leg("to2", "100%")
    sh("tc", "qdisc", "replace", "dev", "uplink", "root", "netem", "loss",
       "100%", pid=pids[1])
    cut_at = time.time()
    pending: dict = {}
    writing = threading.Thread(target=lambda: pending.update(
        app_write(pids[0], "cut-1", 600)), daemon=True)
    writing.start()
    report["b_waits_alerted_s"] = wait_until(
        lambda: alerted("A", dbwatch.SYNC_WAITS, since), 120, 0.5)
    report["b_pending_at_alert"] = writing.is_alive()
    report["b_a_holds_vip"] = vip_netns.holds(pids[0])
    # cut for 40 s in all, the alert's 10 s and a watch run past it
    time.sleep(max(0.0, cut_at + 40 - time.time()))
    report["b_pending_at_heal"] = writing.is_alive()
    healed_at = vip_netns.heal(pids, 1)
    writing.join(600)
    report["b_cut_write"] = pending
    report["b_cut_s"] = round(healed_at - cut_at, 2)
    report["b_ack_after_heal_s"] = round(pending["end"] - healed_at, 2) \
        if pending.get("ok") else None
    report["b_sync_after_heal_s"] = wait_until(
        lambda: sync_standbys(a_root) == "1", 180, 1)
    report["b_back_alerted_s"] = wait_until(
        lambda: alerted("A", dbwatch.SYNC_BACK, since), 120, 0.5)
    report["b_row_on_b"] = pg_ask(
        b_root, "SELECT count(*) FROM t WHERE v = 'cut-1'", APP_DB)
    report["b_alerts"] = [one.get("text", "")[:200]
                          for one in HOOKS["alerts"][since:]]


class Writer:
    """The application writes every 0.1 s on the node that carries the
    VIP, through that node's loopback, a new connection each time (the
    real-node test's writer, co-located the way 0054 has it)"""

    def __init__(self, pids: list[int]):
        self.pids = pids
        self.done: list[dict] = []
        self.halt = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.halt.set()
        self.thread.join()

    def run(self) -> None:
        import vip_netns
        n = 0
        while not self.halt.is_set():
            n += 1
            index = 0 if vip_netns.holds(self.pids[0]) else 1
            one = app_write(self.pids[index], f"crash-{n}")
            self.done.append({"n": n, "node": vip_netns.NAMES[index], **one})
            self.halt.wait(0.1)


class NewPrimary:
    """When B carries the VIP, and when its server ends recovery,
    sampled every 0.2 s from the driver"""

    def __init__(self, pid: int, root: str):
        self.pid, self.root = pid, root
        self.carried_at = self.promoted_at = None
        self.halt = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.halt.set()
        self.thread.join()

    def run(self) -> None:
        import vip_netns
        while not self.halt.is_set():
            now = time.time()
            if self.carried_at is None and vip_netns.holds(self.pid):
                self.carried_at = now
            if self.promoted_at is None and \
                    pg_ask(self.root, "SELECT pg_is_in_recovery()") == "f":
                self.promoted_at = now
            self.halt.wait(0.2)


def downtime(writer: Writer, watched: NewPrimary, cut_at: float,
             promote_at: float, promoted_at: float,
             reseeded_at: float | None) -> dict:
    """The unplanned write downtime and where it went"""
    ok = [one for one in writer.done if one["ok"]]
    before = [one["end"] for one in ok if one["end"] <= cut_at]
    after = [one["end"] for one in ok if one["t"] > cut_at]
    errors: dict[str, int] = {}
    for one in writer.done:
        if not one["ok"] and one["t"] > cut_at:
            key = f"{one['node']}: {one['err'][:40]}"
            errors[key] = errors.get(key, 0) + 1

    def since(at):
        return None if at is None else round(at - cut_at, 2)
    first_after = min(after) if after else None
    return {"last_ok_before_s": since(max(before)) if before else None,
            "first_ok_after_s": since(first_after),
            "downtime_s": None if not before or first_after is None
            else round(first_after - max(before), 2),
            "promote_started_s": since(promote_at),
            "promote_took_s": round(promoted_at - promote_at, 2),
            "carried_s": since(watched.carried_at),
            "promoted_s": since(watched.promoted_at),
            "reseeded_s": since(reseeded_at),
            "first_ok_after_reseed_s": None if reseeded_at is None
            or first_after is None else round(first_after - reseeded_at, 2),
            "errors_after_cut": errors, "writes": len(writer.done),
            "acked": len(ok)}


def held_values(root: str, like: str) -> set[str] | None:
    found = pg_ask(root, f"SELECT v FROM t WHERE v LIKE '{like}'", APP_DB,
                   30)
    if found in ("down", "timed out"):
        return None
    return set(found.split())


def dumps_of(root: str) -> list[str]:
    from keel.system import dbpgfollow
    directory = os.path.join(root, dbpgfollow.BACKUPS)
    try:
        return sorted(os.path.join(directory, one)
                      for one in os.listdir(directory))
    except OSError:
        return []


def dump_holds(path: str, values: list[str]) -> list[str]:
    """Which of `values` the compressed dump holds"""
    try:
        done = subprocess.run(["zstd", "-dc", path], capture_output=True,
                              check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return []
    text = done.stdout.decode(errors="replace")
    return [one for one in values if f"\t{one}\t" in text]


class BootWrites:
    """The application on A, while A is back from its crash: one write
    every 2 s, its client killed after 10 s; none may be acknowledged
    (the new primary is B, and A has no standby to acknowledge it)"""

    def __init__(self, pid: int):
        self.pid = pid
        self.done: list[dict] = []
        self.halt = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.halt.set()
        self.thread.join()

    def run(self) -> None:
        n = 0
        while not self.halt.is_set():
            n += 1
            self.done.append(app_write(self.pid, f"boot-{n}", 10))
            self.halt.wait(2)


def stuck_facts(root: str) -> dict:
    """What a rewind that never ended leaves to read: the processes, the
    unit's journal and the state directory of the node"""
    return {
        "ps": sh("sh", "-c", "ps -eo pid,ppid,etimes,stat,args | grep -E"
                 " 'pg_rewind|postgres|systemctl|runuser|keel' | grep -v"
                 " grep | cut -c1-240", check=False),
        "journal": sh("journalctl", "-u", service_of(root), "-o", "cat",
                      "--no-pager", "-n", "40", check=False),
        "state": sh("sh", "-c", f"ls -la {root}/var/lib/keel/database;"
                    f" ls {root}/var/backups/keel/postgresql", check=False),
        "pgdata": sh("sh", "-c", f"ls {root}/var/lib/postgresql/*/main |"
                     " head -40; cat "
                     f"{root}/var/lib/postgresql/*/main/postmaster.pid"
                     " 2>&1 | head -2", check=False)}


def crashed(report: dict, pids: list[int], roots: list[str]) -> None:
    """(c), (e), (d): the primary A cut off while the application
    writes, then killed; B promoted by itself once A's lease expired; A back
    from its crash, fenced and dumped, then rewound against B with
    pg_rewind and streaming from it, with no reseed (0054, amendment of
    2026-10-18). The reseed itself is the seed of case (a)"""
    import vip_netns
    from keel.system import dbfollow, dbpgfollow, dbwatch
    from vip_netns import OVERLAY, agent_send, wait_until
    a_pid, a_root, b_root = pids[0], roots[0], roots[1]
    report["c_sync_before_s"] = wait_until(
        lambda: sync_standbys(a_root) == "1", 180, 1)
    since = len(HOOKS["alerts"])
    writer = Writer(pids[:2])
    watched = NewPrimary(pids[1], b_root)
    writer.start()
    watched.start()
    report["c_first_ack_s"] = wait_until(
        lambda: any(one["ok"] for one in writer.done), 60, 0.2)
    time.sleep(3)
    # (c) A cut off first, so the write in flight on it waits for B and
    # is in A's WAL unacknowledged (what makes A diverge), then killed
    # with its VIP helper, the twin of MariaDB's crash
    vip_netns.leg("to1", "100%")
    sh("tc", "qdisc", "replace", "dev", "uplink", "root", "netem", "loss",
       "100%", pid=a_pid)
    cut_at = time.time()
    time.sleep(2)
    killed_at = time.time()
    sh("systemctl", "kill", "--signal=SIGKILL", service_of(a_root),
       check=False)
    sh("systemctl", "stop", f"keel-vip-test-{vip_netns.NAMES[0]}",
       check=False)
    # no operator: B's VIP controller claims once the lease of A's
    # claim expired, and that states A gone (keel#165, the 0054
    # amendment of 2026-10-15), so B commits alone with no promote
    promote_at = killed_at
    report["c_automatic_s"] = wait_until(
        lambda: watched.promoted_at is not None, 120, 0.2)
    promoted_at = watched.promoted_at or time.time()
    # the controller runs in a unit of its own, which the helper starts
    from keel.mesh import vipbridge
    report["c_b_vip_log"] = [line for line in sh(
        "journalctl", "-u", vipbridge.unit_name(b_root), "-u",
        f"keel-vip-test-{vip_netns.NAMES[1]}", "-o", "cat", "--no-pager",
        check=False).splitlines() if "claimed at epoch" in line]
    mark(report, "case_c_promoted")
    # the follow makes the slot just after the promotion: waited for
    wait_until(lambda: pg_ask(b_root, "SELECT slot_name FROM"
                              " pg_replication_slots"), 30, 0.5)
    report["c_b_slot"] = pg_ask(b_root, "SELECT slot_name FROM"
                                " pg_replication_slots")
    # the expired lease said the old primary is gone: the new primary
    # commits alone (0054, amendment of 2026-10-15), reloaded, and its
    # watch alerts at each run while it does
    # the follow reloads the empty line just after the promotion: waited
    # for, since no command returns after it now (keel#165)
    report["c_b_alone_s"] = wait_until(
        lambda: pg_ask(b_root, "SHOW synchronous_standby_names") == "",
        30, 0.5)
    report["c_b_sync_names"] = pg_ask(b_root,
                                      "SHOW synchronous_standby_names")
    report["c_b_alone_alerted_s"] = wait_until(
        lambda: len(alerted("B", dbwatch.SYNC_ALONE, since)) >= 2,
        3 * WATCH_EVERY + 10, 0.5)
    report["c_b_waits_alerts"] = len(alerted("B", dbwatch.SYNC_WAITS,
                                             since))
    # (e) A boots: the link back, its server started from its crash (a
    # primary, writable, with no standby to acknowledge it), and what
    # keel-database-follow.service does at boot, before its VIP helper
    # told it of B's newer claim
    vip_netns.heal(pids, 0)
    sh("systemctl", "reset-failed", service_of(a_root), check=False)
    # keel database guard refuses the start: A's own claim is not proven
    # (keel#156), so its server never takes a write as a primary
    started = subprocess.run(["systemctl", "start", service_of(a_root)],
                             capture_output=True, text=True, check=False)
    report["e_boot_start"] = {
        "code": started.returncode,
        "guard": [line for line in sh(
            "journalctl", "-u", service_of(a_root), "-o", "cat",
            "--no-pager", check=False).splitlines()
            if "keel database guard" in line][-3:]}
    boot = BootWrites(a_pid)
    boot.start()
    try:
        report["e_follow_at_boot"] = follow_when_etcd_answers(agent_send)
        # A's VIP helper starts again: its lease is gone, so it is fenced
        # and takes B's claim; follow fences A's server, dumps it, stops
        # it, rewinds it against B and starts it as B's standby (0054,
        # amendment of 2026-10-18)
        vip_netns.tended(0, a_pid, a_root,
                         os.path.join(a_root, "instance.yaml"))
        report["e_fenced_s"] = wait_until(
            lambda: dumps_of(a_root), 240, 1)
        mark(report, "case_e_fenced")
        report["e_rewound_s"] = wait_until(
            lambda: pg_ask(a_root, "SELECT status FROM"
                           " pg_stat_wal_receiver", timeout=5)
            == "streaming" and dbfollow.diverged(a_root) is None,
            600, 1)
        rewound_at = time.time()
        if report["e_rewound_s"] is None:
            report["e_stuck"] = stuck_facts(a_root)
        mark(report, "case_e_rewound")
    finally:
        boot.stop()
    report["e_boot_writes"] = boot.done
    report["e_record"] = dbfollow.diverged(a_root)
    report["e_in_recovery"] = pg_ask(a_root, "SELECT pg_is_in_recovery()")
    report["e_receivers"] = pg_ask(
        a_root, "SELECT count(*) FROM pg_stat_wal_receiver")
    report["e_refused"] = agent_send(
        "A", "sql-app INSERT INTO t (v, at) VALUES ('fenced', 0)")
    # the writes on A that waited for B when A was cut off: committed in
    # A's WAL, never acknowledged; a write after the kill was refused
    # and is nowhere
    unacked = [f"crash-{one['n']}" for one in writer.done
               if one["node"] == "A" and not one["ok"]
               and cut_at - 1 <= one["t"] < killed_at]
    report["e_a_unacked"] = unacked
    dumps = dumps_of(a_root)
    report["e_dumps"] = [os.path.basename(one) for one in dumps]
    # the dump was taken before the rewind: it holds A's own writes
    report["e_dump_holds"] = dump_holds(dumps[-1], unacked) if dumps else []
    report["e_diff"] = agent_send("A", "diff")
    report["e_dbstatus"] = agent_send("A", "dbstatus")
    # two watch runs later: still one dump, no divergence, no alert
    time.sleep(2 * WATCH_EVERY + 5)
    report["e_dumps_later"] = [os.path.basename(one)
                               for one in dumps_of(a_root)]
    report["e_alerts"] = [one.get("text", "")[:200] for one in
                          alerted("A", dbpgfollow.DIVERGED_TITLE, since)]
    report["e_follow_log"] = agent_send("A", "followlog")
    report["d_streaming_s"] = wait_until(
        lambda: agent_send("A", "wstatus").get("status") == "streaming",
        120, 1)
    report["d_status"] = agent_send("A", "wstatus")
    report["d_b_sync_s"] = wait_until(
        lambda: sync_standbys(b_root) == "1", 120, 1)
    report["d_b_sync_names"] = pg_ask(b_root,
                                      "SHOW synchronous_standby_names")
    # the writer's next write on B is acknowledged: the downtime's end
    report["d_first_ack_s"] = wait_until(
        lambda: any(one["ok"] and one["t"] > rewound_at
                    for one in writer.done), 120, 0.2)
    time.sleep(3)
    writer.stop()
    watched.stop()
    report["c_downtime"] = downtime(writer, watched, cut_at, promote_at,
                                    promoted_at, rewound_at)
    report["d_rewound_s"] = round(rewound_at - cut_at, 2)
    acked = {f"crash-{one['n']}" for one in writer.done if one["ok"]}
    on_b = held_values(b_root, "crash-%")
    report["c_acked_missing"] = sorted(acked - (on_b or set()))[:20] \
        if on_b is not None else ["B did not answer"]
    report["d_rows_equal_s"] = wait_until(
        lambda: pg_ask(a_root, "SELECT count(*) FROM t", APP_DB) ==
        pg_ask(b_root, "SELECT count(*) FROM t", APP_DB), 60, 0.5)
    report["d_rows_a"] = pg_ask(a_root, "SELECT count(*) FROM t", APP_DB)
    report["d_rows_b"] = pg_ask(b_root, "SELECT count(*) FROM t", APP_DB)
    # A is B's copy now: of its own unacknowledged rows it holds those
    # B holds (one B received before the cut), and no other
    report["d_a_holds_unacked"] = sorted(
        (held_values(a_root, "crash-%") or set()) & set(unacked))
    report["d_b_holds_unacked"] = sorted((on_b or set()) & set(unacked))
    report["d_record_after"] = dbfollow.diverged(a_root)
    # the VIP fence of A's loss is cleared once A is B's copy and caught
    # up, within a watch run, so a next failover is automatic (keel#166)
    from keel.mesh import vip as vipstate
    report["d_a_unfenced_s"] = wait_until(
        lambda: not (vipstate.read(a_root, vip_netns.VIP) or
                     vipstate.Held(vip_netns.VIP)).fenced,
        3 * WATCH_EVERY + 10, 1)
    report["d_back_alerted_s"] = wait_until(
        lambda: alerted("B", dbwatch.SYNC_BACK, since), 60, 0.5)
    report["d_a_status_line"] = OVERLAY.format(n=2) in str(
        report["d_status"].get("conninfo"))
    report["c_writes"] = writer.done[-60:]


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
