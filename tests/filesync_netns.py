# Copyright (c) 2026 KeelLinux maintainers
"""File replication with syncthing, two nodes of a pair in namespaces

Run as root in a network namespace of its own by tests/test_filesync_netns.py
(tests/wgtools.py says how); never run by hand on a machine. This
namespace is the internet: it routes between two children, A and B, each
a network namespace of its own joined to it by a veth. A and
B are the pair of handbook decision 0050: their specs declare the same
`appliance.vip` and the blog appliance's `state.replicate`, and the
syncthing overlay is enabled. No etcd: the `device` message works with
and without it (0050's amendment, point 3). Both run the members'
channel (its root helper, and the listener as a process of its own with
every capability dropped, as tests/mesh_netns.py runs it), the real
syncthing from the Keel archive, and keel's flip
(keel.system.filesync.follow_flip) as `keel database follow` calls it.

The link between A and B is tuned to each of decision 0050's profiles in
turn, measured before each scenario, and per profile the scenario is:

1. B flips replica first: its ask of A's device ID fails, said, and the
   folders render without a peer; A flips primary and asks B (B's
   identity was made at its flip): the peer device fills in; B flips
   again and asks A back. The identity exchange rides the members'
   channel alone;
2. syncthing starts on both with keel's rendered config.xml: every file
   of A's content and media folders reaches B, except the excluded
   cache, and B's counters read clean;
3. the flip a `keel database promote` does: A replica, B primary; a
   write on B reaches A;
4. the lossy profile adds the one-writer rule's case: a local write on
   the replica is counted (receiveOnlyChangedFiles), and when that node
   is promoted its change crosses, and the old content is kept on the
   other side, as a version or as syncthing's conflict copy.

The fifth profile is the partition: both legs at 100% loss while the
primary writes, then healed: the checksums converge and the counters
read clean. The result is one JSON line, `RESULT {...}`.
"""

import hashlib
import json
import os
import pwd
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import etcd_netns
from etcd_netns import measured, sh, tune
from manifest_helpers import (HOOKS, UNITS, app_fixture, hook, overlay,
                              put, unit)

from keel.mesh import (identity, memberd, signing, sync, trust, vipnode,
                       vippromote)
from keel.mesh.node import Node
from keel.network import wireguard
from keel.system import filesync, filesync_api, filesync_io

MESH = "6b65656c2066696c6573796e63210001"
UPLINK = "2001:db8:f5d:{n}"
OVERLAY = "fd00:6b65:f5d::{n}"
VIP = "fd00:6b65:f5d::ffff:100"
NAMES = ("A", "B")
CONTENT = "/var/www/blog/content"
MEDIA = "/var/www/blog/media"
CACHE = "/var/www/blog/content/cache"
PATHS = (CONTENT, MEDIA)
# decision 0050's profiles, as both legs of the link see them: the
# delay is one way, so a leg holds half the round trip
PROFILES = {
    "ideal": ["2.5ms", "0.25ms", "0%"],
    "regional": ["50ms", "5ms", "0%"],
    "design": ["125ms", "12.5ms", "0%"],
    "lossy": ["125ms", "12.5ms", "2%"],
}
LIMITS = {"ideal": (30, 30), "regional": (60, 60),
          "design": (180, 120), "lossy": (300, 180)}
PIDS: list[int] = []
CHILDREN: list[subprocess.Popen] = []
AGENTS: dict[str, subprocess.Popen] = {}
ROOTS: list[str] = []
# the listener holds no capability, so as root without CAP_DAC_READ_SEARCH
# it cannot traverse a home directory the checkout may be in: it imports
# a copy of keel (tests/mesh_netns.py)
RUN_BASE = "/run/keel-filesync-test"
# /run is mounted noexec: the helper's copy of wg is under /var/lib
TOOLS = "/var/lib/keel-filesync-test/bin"
LISTENER_HOME = os.environ.get("KEEL_FILESYNC_LISTENER_HOME") or ""
# syncthing's copy of the content a concurrent change replaced: this
# node's alone, as the versions are
CONFLICT = ".sync-conflict-"
SEED = [f"post-{n:02d}.txt" for n in range(1, 13)] + \
       [f"media-{n:02d}.txt" for n in range(1, 5)]


def child(index: int) -> int:
    """A namespace joined to this one by a veth on its own /64"""
    found = subprocess.Popen(["unshare", "-n", "sleep", "3600"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    CHILDREN.append(found)
    n = index + 1
    net = UPLINK.format(n=n)
    sh("ip", "link", "add", f"to{n}", "type", "veth", "peer", "name",
       "uplink")
    sh("ip", "link", "set", "uplink", "netns", str(found.pid))
    sh("ip", "-6", "address", "add", f"{net}::1/64", "dev", f"to{n}",
       "nodad")
    sh("ip", "link", "set", f"to{n}", "up")
    for argv in (("ip", "link", "set", "lo", "up"),
                 ("ip", "-6", "address", "add", f"{net}::2/64", "dev",
                  "uplink", "nodad"),
                 ("ip", "link", "set", "uplink", "up"),
                 ("ip", "-6", "route", "add", "default", "via", f"{net}::1",
                  "dev", "uplink")):
        sh(*argv, pid=found.pid)
    tune(found.pid)
    return found.pid


def spec_of(root: str, index: int, pairs) -> str:
    """The node's spec: its overlay, the other node a peer, the pair's
    VIP, and the syncthing overlay enabled"""
    import yaml
    others = [{"public_key": pairs[other][1],
               "endpoint": f"[{UPLINK.format(n=other + 1)}::2]:51820",
               "allowed_ips": [f"{OVERLAY.format(n=other + 1)}/128"],
               "persistent_keepalive": 25}
              for other in range(len(NAMES)) if other != index]
    doc = {"version": 1,
           "appliance": {"name": "blog", "vip": VIP},
           "installation": {"mode": "cloud_simple"},
           "overlays": {"syncthing": "enabled"},
           "network": {"overlay": {"wireguard": {
               "address": f"{OVERLAY.format(n=index + 1)}/64",
               "listen_port": 51820,
               "private_key": {"file": "/etc/wireguard/wg0.key"},
               "peers": others}}}}
    path = os.path.join(root, "instance.yaml")
    with open(path, "w") as fob:
        yaml.safe_dump(doc, fob, sort_keys=False)
    return path


def overlay_up(pid: int, root: str, index: int, pairs, path: str) -> None:
    """wg0 from the file keel renders, where keel keeps it"""
    os.makedirs(os.path.join(root, "etc/wireguard"), exist_ok=True)
    key = os.path.join(root, "etc/wireguard/wg0.key")
    with open(os.open(key, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        fob.write(pairs[index][0] + "\n")
    # the key is under the node's root, where keel reads it (keel's
    # rendering, with the key's path under the scratch root for wg)
    overlay = {**Node(root, path).overlay(), "private_key": {"file": key}}
    conf = os.path.join(root, "etc/wireguard/wg0.conf")
    with open(os.open(conf, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        fob.write(wireguard.render(overlay))
    sh("wg-quick", "up", conf, pid=pid)


def mesh_state(roots: list[str], pairs) -> None:
    """The identity, each node's signing key, and each trusting the
    other as a root: what a join leaves (tests/vip_netns.py)"""
    signs = []
    for root in roots:
        identity.adopt(root, bytes.fromhex(MESH))
        signs.append(signing.ensure(root))
    for index, root in enumerate(roots):
        store = trust.Store()
        for other in range(len(NAMES)):
            if other != index:
                store.members[pairs[other][1]] = trust.Member(
                    signs[other], True)
        trust.save(root, store)


def keys() -> list[tuple[str, str]]:
    found = []
    for _ in NAMES:
        private = sh("wg", "genkey").strip()
        public = subprocess.run(["wg", "pubkey"], input=private + "\n",
                                capture_output=True, text=True,
                                check=True).stdout.strip()
        found.append((private, public))
    return found


def manifests(root: str) -> None:
    """The format's fixtures under the root, as `keel system apply` finds
    them on a machine: every overlay and appliance, the blog carrying
    the syncthing overlay, with the unit files and the hook it names"""
    from manifest_helpers import FIXTURES, KINDS, fixture
    for kind in KINDS:
        for entry in sorted(os.listdir(os.path.join(FIXTURES, kind))):
            name = entry[:-len(".yaml")]
            put(root, kind, name, fixture(kind, name))
    text = app_fixture("appliances", "blog").replace(
        "overlays:\n  mariadb:",
        "overlays:\n  syncthing:"
        " {simple: enabled, cloud_simple: enabled,"
        " cloud_advanced: enabled}\n  mariadb:")
    put(root, "overlays", "mariadb", app_fixture("overlays", "mariadb"))
    put(root, "appliances", "blog", text)
    put(root, "overlays", "syncthing", overlay(
        filesync.OVERLAY,
        "processes:\n"
        "  - name: syncthing\n"
        "    unit: syncthing.service\n"
        "    listen: [{port: 22000, protocol: tcp, expose: mesh}]\n"))
    # the units and first-boot hooks the manifests name, and the blog's
    for name in (*UNITS, "syncthing", "mariadb", "blog", "blog-cron",
                 "blog-mailer"):
        unit(root, name)
    for name in (*HOOKS, "40blog"):
        hook(root, name)


def bound(pid: int, root: str) -> None:
    """The replicated paths of this node's scratch tree, with the
    .stignore and the .stfolder markers a `keel system apply` writes.
    The paths the manifest declares are the node's own through a chroot
    of syncthing (the CI container allows no mount, bind mounts
    included): syncthing is a static binary, so its copy in the root is
    all the chroot holds besides the tree"""
    base = os.path.join(root, "var/www/blog")
    os.makedirs(os.path.join(base, "content/cache"), exist_ok=True)
    os.makedirs(os.path.join(base, "media"), exist_ok=True)
    with open(os.path.join(base, "content/.stignore"), "w") as fob:
        fob.write(filesync.stignore((CACHE,), CONTENT))
    for folder in ("content", "media"):
        with open(os.path.join(base, folder, ".stfolder"), "w") as fob:
            fob.write("")
    shutil.copy(shutil.which("syncthing"), os.path.join(root, "syncthing"))
    os.chmod(os.path.join(root, "syncthing"), 0o755)


def seed(root: str) -> None:
    """A primary's files: twelve posts, four media files, and one file
    in the excluded cache"""
    for name in SEED:
        folder = "content" if name.startswith("post-") else "media"
        path = os.path.join(root, "var/www/blog", folder, name)
        with open(path, "w") as fob:
            fob.write(f"{name}\n")
    with open(os.path.join(root, "var/www/blog/content/cache/tracker.txt"),
              "w") as fob:
        fob.write("not replicated\n")


def tree_hash(root: str, folder: str) -> str:
    """The checksums of every replicated file under a path, as a digest:
    syncthing's own markers and versions are this node's alone, and the
    excluded cache is on the primary only (its crossing is asserted
    apart)"""
    base = os.path.join(root, "var/www/blog", folder)
    found = hashlib.sha256()
    for where, dirs, names in os.walk(base):
        dirs[:] = sorted(d for d in dirs
                         if d not in (".stversions", "cache"))
        for name in sorted(names):
            if name in (".stignore", ".stfolder") or CONFLICT in name:
                continue
            path = os.path.join(where, name)
            rel = os.path.relpath(path, base)
            found.update(rel.encode() + b"\0")
            with open(path, "rb") as fob:
                found.update(fob.read() + b"\0")
    return found.hexdigest()


def in_sync() -> bool:
    return tree_hash(ROOTS[0], "content") == \
        tree_hash(ROOTS[1], "content") and \
        tree_hash(ROOTS[0], "media") == tree_hash(ROOTS[1], "media")


def wait_until(test, seconds: float, step: float = 0.5) -> float | None:
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        if test():
            return round(time.monotonic() - started, 2)
        time.sleep(step)
    return None


def agent_send(name: str, line: str, timeout: float = 300) -> dict:
    """One command to a node's agent, and its JSON answer"""
    process = AGENTS[name]
    process.stdin.write(line + "\n")
    process.stdin.flush()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        wait = max(0.0, deadline - time.monotonic())
        ready, _, _ = select.select([process.stdout], [], [], wait)
        if not ready:
            break
        said = process.stdout.readline()
        if not said:
            break
        if said.startswith("ANSWER "):
            return json.loads(said[len("ANSWER "):])
    return {"error": f"no answer to {line!r}"}


def clear_node(name: str, with_files: bool) -> dict:
    """A node stopped and un-rendered, its replica's files and versions
    wiped, ready for the next profile"""
    said = agent_send(name, "stop-sync")
    said.update(agent_send(name, "clear-render"))
    if with_files:
        root = ROOTS[NAMES.index(name)]
        for folder in ("content", "media"):
            base = os.path.join(root, "var/www/blog", folder)
            for where, dirs, names in os.walk(base):
                for one in names:
                    if one not in (".stignore", ".stfolder"):
                        os.remove(os.path.join(where, one))
                if ".stversions" in dirs:
                    shutil.rmtree(os.path.join(where, ".stversions"))
    return said


def flip(name: str, role: str) -> dict:
    return agent_send(name, f"flip {role}")


def scenario(report: dict, name: str, profile: list[str], extra: bool,
             sync_s: float, flip_s: float) -> dict:
    """One profile's run: the identity exchange, the first sync, the
    promote's flip, and on the lossy link the one-writer rule's case"""
    found = {"legs": profile}
    # etcd_netns.leg reads its legs from LEG: set them to this profile's
    etcd_netns.LEG = list(profile)
    for n in (1, 2):
        etcd_netns.leg(f"to{n}")
    etcd_netns.PINGS = 100
    found["link"] = measured(PIDS[1], OVERLAY.format(n=1))
    # the identity exchange over the members' channel alone: B first,
    # its ask refused (A holds no identity yet), then A, then B again
    found["b_first"] = flip("B", "replica")
    found["a"] = flip("A", "primary")
    found["b"] = flip("B", "replica")
    found["devices"] = agent_send("A", "devices")
    for node in NAMES:
        agent_send(node, "start-sync")
    found["sync_s"] = wait_until(in_sync, sync_s)
    found["hashes"] = {folder: tree_hash(ROOTS[0], folder)
                       for folder in ("content", "media")}
    found["b_cache"] = os.path.exists(os.path.join(
        ROOTS[1], "var/www/blog/content/cache/tracker.txt"))
    found["b_counts"] = agent_send("B", "counts", 60)
    # the flip a `keel database promote` does: A replica, B primary
    found["a_back"] = flip("A", "replica")
    found["b_primary"] = flip("B", "primary")
    # a name of its own per profile: A keeps the files of the last one
    with open(os.path.join(ROOTS[1], f"var/www/blog/content/new-{name}.txt"),
              "w") as fob:
        fob.write("written on the new primary\n")
    found["flip_sync_s"] = wait_until(in_sync, flip_s)
    if not extra:
        report[name] = found
        return found
    # the one-writer rule's case, on the lossy link only: A is primary
    # again; a local write on the replica B is counted, and when B is
    # promoted that change crosses, and A keeps the old content as a
    # version
    found["a_primary"] = flip("A", "primary")
    found["b_replica"] = flip("B", "replica")
    wait_until(in_sync, flip_s)
    with open(os.path.join(ROOTS[1], "var/www/blog/content/post-01.txt"),
              "a") as fob:
        fob.write("a local line on the replica\n")
    found["replica_edit_seen_s"] = wait_until(
        lambda: (agent_send("B", "counts", 60) or {}).get(
            "counts", {}).get(CONTENT, {}).get(
            "receiveOnlyChangedFiles", 0) > 0, 60)
    found["b_promoted"] = flip("B", "primary")
    found["a_replica"] = flip("A", "replica")
    found["promote_sync_s"] = wait_until(in_sync, flip_s)
    # the old content is kept: as a version, or, when the replica's edit
    # and A's file were concurrent changes to syncthing, as its conflict
    # copy of the content the incoming change replaced
    base = os.path.join(ROOTS[0], "var/www/blog/content")
    versions = os.path.join(base, ".stversions")
    found["a_versions"] = sorted(
        (os.listdir(versions) if os.path.isdir(versions) else []) +
        [one for one in os.listdir(base) if CONFLICT in one])
    report[name] = found
    return found


def cut_primary(report: dict, sync_s: float) -> None:
    """The cut primary (0050's amendment, point 5), not a clean
    failover: both legs at 100% loss, the primary A is in doubt and
    pauses its folders. A write it takes while paused does not cross
    when the link heals, because a paused folder sends nothing; proving
    the role again sends it"""
    found = {}
    target = os.path.join(ROOTS[1], "var/www/blog/content",
                          "written-while-paused.txt")
    for n in (1, 2):
        etcd_netns.leg(f"to{n}", "100%")
    found["paused"] = flip("A", "none")
    with open(os.path.join(ROOTS[0], "var/www/blog/content",
                           "written-while-paused.txt"), "w") as fob:
        fob.write("written while the primary was paused\n")
    for n in (1, 2):
        etcd_netns.leg(f"to{n}")
    time.sleep(20)
    found["reached_while_paused"] = os.path.exists(target)
    found["a_counts"] = agent_send("A", "counts", 60)
    found["proven_again"] = flip("A", "primary")
    found["resume_sync_s"] = wait_until(lambda: os.path.exists(target),
                                        sync_s)
    report["cut_primary"] = found


def partition(report: dict, sync_s: float) -> None:
    """The fifth profile: both legs at 100% loss while the primary
    writes, then healed; the checksums converge, the counters clean"""
    found = {}
    for n in (1, 2):
        etcd_netns.leg(f"to{n}", "100%")
    cut_at = time.monotonic()
    for name in ("during-partition-1.txt", "during-partition-2.txt"):
        with open(os.path.join(ROOTS[0], "var/www/blog/content", name),
                  "w") as fob:
            fob.write(f"{name}\n")
    time.sleep(15)
    for n in (1, 2):
        etcd_netns.leg(f"to{n}")
    found["cut_s"] = round(time.monotonic() - cut_at, 2)
    found["heal_sync_s"] = wait_until(in_sync, sync_s)
    found["a_counts"] = agent_send("A", "counts", 60)
    found["b_counts"] = agent_send("B", "counts", 60)
    report["partition"] = found


class Spawned:
    """`keel mesh members-listen` as its own process, with no capability"""

    def __init__(self, path: str):
        with open(os.path.join(LISTENER_HOME, "listener.log"), "a") as log:
            self.process = subprocess.Popen(
                ["setpriv", "--no-new-privs", "--bounding-set", "-all",
                 "--inh-caps", "-all", "--ambient-caps", "-all",
                 sys.executable, "-m", "keel", "mesh", "members-listen",
                 path], stdout=log, stderr=log, cwd=LISTENER_HOME,
                env={**os.environ, "PYTHONPATH": LISTENER_HOME})

    def trusted(self, pid: int, uid: int) -> bool:
        return pid == self.process.pid

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(10)


def utc() -> datetime:
    return datetime.now(timezone.utc)


def listens_on(port: int) -> bool:
    done = subprocess.run(["ss", "-Hltn", "sport", f"= :{port}"],
                          capture_output=True, text=True, check=False)
    return bool(done.stdout.strip())


def listening(here: vipnode.Here) -> bool:
    return listens_on(51821)


def _text(root: str, path: str) -> str | None:
    try:
        with open(os.path.join(root, path)) as fob:
            return fob.read()
    except OSError:
        return None


def agent(root: str, path: str) -> None:
    """In a node's namespaces: the members' channel, syncthing as the
    flip leaves it, and the driver's commands on standard input"""
    def log(line: str) -> None:
        print(f"{time.time():.3f} {line}", file=sys.stderr, flush=True)

    node = Node(root, path)
    here = vipnode.Here(node, utc, log)
    doc = node.document()
    # the members' channel runs through wg0, to the other node's overlay
    # address (what dbpair gives keel), not to its endpoint
    peer_address = next(
        one["allowed_ips"][0].split("/")[0]
        for one in doc["network"]["overlay"]["wireguard"]["peers"])
    peer = SimpleNamespace(vip=VIP, peer_address=peer_address)
    stop, served = threading.Event(), threading.Event()
    members = threading.Thread(target=memberd.serve, args=(
        sync.Syncer(node, utc, log), served),
        kwargs={"start": Spawned}, daemon=True)
    members.start()
    syncthing: list[subprocess.Popen] = []

    def restart_sync() -> None:
        for one in syncthing:
            one.terminate()
        for one in syncthing:
            one.wait(10)
        syncthing.clear()
        user = pwd.getpwnam("syncthing")
        with open(os.path.join(root, "syncthing.log"), "ab") as out:
            syncthing.append(subprocess.Popen(
                ["chroot", f"--userspec={user.pw_uid}:{user.pw_gid}", root,
                 "/syncthing", "serve", "--home", "/" + filesync.HOME,
                 "--no-upgrade"], stdout=out, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                # no monitor process (STMONITORED): it opens /dev/null,
                # which the chroot does not hold
                env={**os.environ, "STMONITORED": "1"}))

    def record() -> str | None:
        return _text(root, filesync.RECORD)

    for line in sys.stdin:
        try:
            found = command(line.split(), root, doc, peer, here,
                            restart_sync, record, syncthing)
        except Exception as e:  # noqa: BLE001 - the driver reads why
            import traceback
            found = {"error": repr(e),
                     "trace": traceback.format_exc()[-1500:]}
        if found is None:
            break
        print("ANSWER " + json.dumps(found), flush=True)
    stop.set()
    served.set()
    for one in syncthing:
        one.terminate()


def unit_runner(restart_sync, syncthing):
    """subprocess.run, with the systemctl calls answered for a syncthing
    the test started itself"""
    def run(argv, **kwargs):
        if argv[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(
                argv, 0 if syncthing else 3, "", "")
        if argv[:2] == ["systemctl", "restart"]:
            restart_sync()
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:1] == ["systemctl"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.run(argv, **kwargs)
    return run


def command(words: list[str], root: str, doc: dict, peer, here,
            restart_sync, record, syncthing) -> dict | None:
    """One of the driver's commands; None to quit"""
    if words[:1] == ["ready"]:
        return {"members": wait_until(lambda: listening(here), 60)}
    if words[:1] == ["flip"]:
        role = words[1] if words[1] != "none" else None
        said: list[str] = []
        found = SimpleNamespace(say=said.append, fail=said.append)
        before = record()
        # no systemd in the namespace: a running syncthing counts as an
        # active unit, so the flip sets the folders through the API, as
        # it does on a node, and a restart is the test's own
        filesync.follow_flip(root, doc, peer, role, found,
                             unit_runner(restart_sync, syncthing),
                             here=here)
        after = record()
        changed = before != after and after is not None
        return {"said": said, "rendered": changed}
    if words[:1] == ["start-sync"]:
        if not syncthing:
            restart_sync()
        # back only once it listens: a node started first would dial a
        # peer that does not listen yet, and syncthing dials again only
        # after its reconnection interval (20 s)
        return {"started": wait_until(lambda: listens_on(22000), 60)
                is not None}
    if words[:1] == ["stop-sync"]:
        for one in syncthing:
            one.terminate()
        for one in syncthing:
            one.wait(10)
        syncthing.clear()
        return {"stopped": True}
    if words[:1] == ["clear-render"]:
        for name in (filesync.RECORD, filesync.CONFIG, filesync_io.STATE_FILE,
                     filesync_io.PENDING, filesync_io.WATCH_STATE):
            try:
                os.remove(os.path.join(root, name))
            except OSError:
                pass
        # the identities and the index, so each profile starts as a new
        # install does: no device ID on either node (B's first ask is
        # refused), and a wiped replica pulls every file anew (a deletion
        # syncthing still holds in its index would otherwise read as a
        # local change of a receive-only folder)
        for name in (filesync.DEVICE_FILE, filesync.PEER_FILE):
            try:
                os.remove(os.path.join(root, name))
            except OSError:
                pass
        shutil.rmtree(os.path.join(root, filesync.HOME), ignore_errors=True)
        return {"cleared": True}
    if words[:1] == ["counts"]:
        return {"counts": filesync_api.counts(root, PATHS)}
    if words[:1] == ["pair"]:
        said = []
        return {"code": vippromote.pair(here, words[1], said.append),
                "said": said}
    if words[:1] == ["devices"]:
        return {"device": filesync.device_id(root),
                "peer": ( _text(root, filesync.PEER_FILE) or "").strip()}
    return None


def driver() -> None:
    """The two nodes, the agents and the scenarios, then the RESULT line"""
    global LISTENER_HOME
    os.makedirs(RUN_BASE, mode=0o755, exist_ok=True)
    LISTENER_HOME = tempfile.mkdtemp(prefix="listener-", dir=RUN_BASE)
    sh("ip", "link", "set", "lo", "up")
    with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as fob:
        fob.write("1\n")
    shutil.copytree(os.path.dirname(os.path.dirname(os.path.abspath(
        memberd.__file__))), os.path.join(LISTENER_HOME, "keel"))
    # the listener's dynamic user reads the copy of keel it runs
    for where, dirs, files in os.walk(LISTENER_HOME):
        os.chmod(where, 0o755)
        for name in files:
            os.chmod(os.path.join(where, name), 0o644)
    os.environ["KEEL_FILESYNC_LISTENER_HOME"] = LISTENER_HOME
    # wg, where the helper, root without CAP_DAC_OVERRIDE, can reach it
    os.makedirs(TOOLS, mode=0o755, exist_ok=True)
    found = shutil.which("wg")
    if found:
        shutil.copy(found, os.path.join(TOOLS, "wg"))
    PIDS.extend(child(index) for index in range(len(NAMES)))
    ROOTS.extend(tempfile.mkdtemp(prefix=f"keel-filesync-{name}-")
                 for name in NAMES)
    # mkdtemp makes a root 0700; syncthing runs as its own user and must
    # reach its home under the root, as it reaches /var/lib on a node
    for root in ROOTS:
        os.chmod(root, 0o755)
    pairs = keys()
    specs = [spec_of(ROOTS[i], i, pairs) for i in range(len(NAMES))]
    for index, pid in enumerate(PIDS):
        overlay_up(pid, ROOTS[index], index, pairs, specs[index])
        manifests(ROOTS[index])
        bound(pid, ROOTS[index])
        seed(ROOTS[index])
        # syncthing runs as its own user and writes the replicated paths:
        # on a node the application's directories allow it, and here the
        # scratch tree is the syncthing user's
        sh("chown", "-R", "syncthing:syncthing",
           os.path.join(ROOTS[index], "var/www/blog"))
    mesh_state(ROOTS, pairs)
    done = subprocess.run(["syncthing", "--version"], capture_output=True,
                          text=True, check=False)
    report = {"syncthing": (done.stdout or done.stderr).split()[:2],
              "mesh": MESH}
    for index, pid in enumerate(PIDS):
        AGENTS[NAMES[index]] = subprocess.Popen(
            ["nsenter", "-t", str(pid), "-n", sys.executable,
             __file__, "agent", ROOTS[index], specs[index]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=open(os.path.join(ROOTS[index], "agent.log"), "w"),
            text=True, env=os.environ.copy())
    for name in NAMES:
        report.setdefault("agents", {})[name] = agent_send(name, "ready",
                                                           120)
    # the operator's `keel vip pair`, on A, with B's overlay address:
    # the pair record the device message needs (it rides on the pair)
    # on a cold tunnel the first handshake can outlast the ask: warm it,
    # and ask again where it timed out
    subprocess.run(["nsenter", "-t", str(PIDS[0]), "-n", "ping", "-6", "-I",
                    "wg0", "-c", "5", "-i", "0.5", "-W", "3",
                    OVERLAY.format(n=2)], capture_output=True, check=False,
                   timeout=60)
    for _ in range(5):
        report["paired"] = agent_send("A", f"pair {OVERLAY.format(n=2)}")
        if report["paired"].get("code") == 0:
            break
        time.sleep(3)
    try:
        for name, profile in PROFILES.items():
            clear_node("B", with_files=True)
            clear_node("A", with_files=False)
            sync_s, flip_s = LIMITS[name]
            scenario(report, name, profile, name == "lossy",
                     sync_s, flip_s)
        # the partition, from a clean lossy sync
        clear_node("B", with_files=True)
        clear_node("A", with_files=False)
        for n in (1, 2):
            etcd_netns.leg(f"to{n}")
        # the exchange as a scenario makes it: B, A, then B again
        flip("B", "replica")
        flip("A", "primary")
        flip("B", "replica")
        for node in NAMES:
            agent_send(node, "start-sync")
        report["partition_baseline_s"] = wait_until(in_sync, 300)
        partition(report, 300)
        cut_primary(report, 300)
    except Exception as e:  # noqa: BLE001 - the report says how it ended
        report["error"] = repr(e)
    finally:
        for process in AGENTS.values():
            try:
                process.stdin.write("quit\n")
                process.stdin.close()
            except OSError:
                pass
    print("RESULT " + json.dumps(report), flush=True)


def main() -> None:
    """The driver, and whatever it started stopped and removed after"""
    keep = os.environ.get("FILESYNC_KEEP")
    try:
        driver()
    finally:
        subprocess.run(["pkill", "-f", "syncthing serve"], check=False,
                       capture_output=True)
        for process in list(AGENTS.values()) + CHILDREN:
            process.kill()
        for process in AGENTS.values():
            process.wait(30)
        for root in ([] if keep else ROOTS) + \
                ([] if keep else [LISTENER_HOME, TOOLS]):
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["agent"]:
        agent(sys.argv[2], sys.argv[3])
    else:
        main()
