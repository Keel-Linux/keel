# Copyright (c) 2026 KeelLinux maintainers
"""Three nodes in three network namespaces, joined with keel mesh

Run as root in a network namespace of its own by tests/test_mesh_netns.py
(tests/wgtools.py says how); never run by hand on a machine. This
namespace is the inviter A. Two children, B and C, are network
namespaces of their own (`unshare -n`), each joined to A by a veth on
its own /64. Then, with the real wg-quick, the real TLS listener and
client, the real flows and the real confirmation logic of 0018:

1. A is in the mesh: its overlay up, and `keel mesh invite` through
   keel.cli prints the line;
2. A's listener serves the invite (keel.mesh.inviting.serve_invite) and
   B joins with the token (keel.mesh.joining), both windows confirmed
   by the mesh session over the overlay; B pings A over the overlay;
3. a second invite is made with nothing listening: C's join gets no
   TCP answer, applies its side and prints `keel mesh accept`, which A
   runs (keel.mesh.inviting.accept); both windows are confirmed over
   the overlay, and C pings A;
4. the second token used again, from a fresh scratch root on C: the
   port gives no answer, so the join falls back again, and A refuses
   its line: the invite is spent.

Two things are not keel's own here. apply: a live apply arms systemd
timers on the host, which no namespace isolates, so apply writes keel's
rendered wg-quick file under the node's scratch root, runs `wg-quick up`
on it in the node's namespace, and records the change as apply does
(keel.network.marker); everything that confirms a window is the real
keel.network.confirm with the real `ip` probes. And the listener's
unit: the root side starts `keel mesh listen` as a process of its own
under `setpriv` with every capability dropped and no new privileges,
where keel-mesh-listen@ adds a dynamic user and systemd's sandbox; the
bridge checks it is that process (SO_PEERCRED), and the listener, which
refuses to run with any capability, reports its CapEff.

With MESH_NETEM set (`250ms 25ms 2%`, say) every veth, both ends,
delays by the first, with the second as jitter, and loses the third:
a poor network.

The result is one JSON line on standard output, `RESULT {...}`.
"""

import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

from keel import cli
from keel.mesh import inviting, joining
from keel.mesh.node import Node
from keel.mesh.token import parse
from keel.network import marker, wireguard

PREFIX = "fd00:6b65:e2e"
OVERLAY_A = f"{PREFIX}::1"
LINKS = {"B": "2001:db8:e2e:1", "C": "2001:db8:e2e:2"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Recorder:
    """systemctl, systemd-run and nft: nothing of the host is touched"""

    def __init__(self):
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)


def sh(*argv: str, pid: int | None = None) -> str:
    prefix = ["nsenter", "-t", str(pid), "-n"] if pid else []
    done = subprocess.run(prefix + list(argv), capture_output=True,
                          text=True, check=False)
    if done.returncode:
        raise RuntimeError(f"{' '.join(argv)}: {done.stderr.strip()}")
    return done.stdout


def netns_apply(doc: dict, root: str, window: int) -> int:
    """apply's overlay step, in this namespace, under the node's root"""
    overlay = doc["network"]["overlay"]["wireguard"]
    iface = wireguard.interface(overlay)
    relative = wireguard.conf_path(iface)
    conf = os.path.join(root, relative)
    os.makedirs(os.path.dirname(conf), exist_ok=True)
    # the key is under the scratch root, where keel made it
    key = os.path.join(root, wireguard.key_path(overlay).lstrip("/"))
    with open(os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
              "w") as fob:
        fob.write(wireguard.render({**overlay, "private_key": {"file": key}}))
    subprocess.run(["wg-quick", "down", conf], capture_output=True,
                   check=False)
    up = subprocess.run(["wg-quick", "up", conf], capture_output=True,
                        text=True, check=False)
    if up.returncode:
        print(up.stderr, file=sys.stderr)
        return 16
    marker.save(root, "", marker.Target(relative, marker.OVERLAY, True))
    marker.write(root, marker.Pending(
        iface=iface, path=relative, window=window,
        addresses=tuple(one.split("/")[0]
                        for one in wireguard.addresses(overlay)),
        kind=marker.OVERLAY, absent=True).up(marker.boot_id(),
                                              marker.process_clock()))
    return 0


def scratch(spec: str) -> tuple[str, str]:
    root = tempfile.mkdtemp(prefix="keel-mesh-")
    path = os.path.join(root, "instance.yaml")
    with open(path, "w") as fob:
        fob.write(spec.format(root=root))
    return root, path


def node(root: str, path: str) -> Node:
    return Node(root, path, apply=netns_apply, run=Recorder())


def ping(address: str) -> bool:
    """One answer of five is enough: the link may lose packets"""
    return subprocess.run(["ping", "-6", "-c", "5", "-i", "0.3", "-W", "3",
                           address], capture_output=True,
                          check=False).returncode == 0


def joiner(token_text: str, endpoint: str) -> None:
    """In B's or C's namespace: join, then ping A over the overlay"""
    root, path = scratch("version: 1\n")
    out, err = [], []

    def said(line):
        out.append(line)
        print(line, flush=True)
    found = joining.Joiner(node(root, path), parse(token_text, utcnow()),
                           utcnow, said, err.append)
    code = joining.run(found, endpoint)
    last = marker.last(root)
    print("RESULT " + json.dumps({
        "code": code, "out": out, "err": err, "ping": ping(OVERLAY_A),
        "outcome": last.outcome if last else None}), flush=True)


CHILDREN: list[subprocess.Popen] = []
CAPABILITIES: list[str] = []
NETEM = os.environ.get("MESH_NETEM", "").split()


# The listener holds no capability, so as root without
# CAP_DAC_READ_SEARCH it cannot traverse a home directory the checkout
# may be in (a CI runner's): it imports a copy of keel kept beside the
# nodes' scratch roots, and logs where the driver can read it.
LISTENER_HOME = tempfile.mkdtemp(prefix="keel-mesh-listener-")
LISTENER_LOG = os.path.join(LISTENER_HOME, "listener.log")
shutil.copytree(os.path.dirname(os.path.dirname(os.path.abspath(
    inviting.__file__))), os.path.join(LISTENER_HOME, "keel"))


class Spawned:
    """`keel mesh listen` as its own process, with no capability"""

    def __init__(self, invite_id: str, path: str, seconds: int):
        with open(LISTENER_LOG, "a") as log:
            self.process = subprocess.Popen(
                ["setpriv", "--no-new-privs", "--bounding-set", "-all",
                 "--inh-caps", "-all", "--ambient-caps", "-all",
                 sys.executable, "-m", "keel", "mesh", "listen", path],
                stdout=log, stderr=log, cwd=LISTENER_HOME,
                env={**os.environ, "PYTHONPATH": LISTENER_HOME})

    def trusted(self, pid: int, uid: int) -> bool:
        with open(f"/proc/{pid}/status") as fob:
            CAPABILITIES.extend(one.split()[1] for one in fob
                                if one.startswith("CapEff:"))
        return pid == self.process.pid

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(10)


def shaped(device: str, pid: int | None = None) -> None:
    if NETEM:
        delay, jitter, loss = NETEM
        sh("tc", "qdisc", "add", "dev", device, "root", "netem", "delay",
           delay, jitter, "loss", loss, pid=pid)


def listening(host: str, port: int) -> None:
    """Wait until the listener's port takes a connection"""
    for _ in range(300):
        try:
            socket.create_connection((host, port), 1).close()
            return
        except OSError:
            time.sleep(0.1)
    with open(LISTENER_LOG) as fob:
        said = fob.read()[-2000:]
    raise RuntimeError(f"nothing listens on [{host}]:{port}; the"
                       f" listener said: {said}")


def link(name: str) -> int:
    """A child namespace, and a veth from here to it on its own /64"""
    child = subprocess.Popen(["unshare", "-n", "sleep", "600"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    CHILDREN.append(child)
    net = LINKS[name]
    sh("ip", "link", "add", f"to{name}", "type", "veth", "peer", "name",
       "uplink")
    sh("ip", "link", "set", "uplink", "netns", str(child.pid))
    sh("ip", "-6", "address", "add", f"{net}::1/64", "dev", f"to{name}",
       "nodad")
    sh("ip", "link", "set", f"to{name}", "up")
    for argv in (("ip", "link", "set", "lo", "up"),
                 ("ip", "-6", "address", "add", f"{net}::2/64", "dev",
                  "uplink", "nodad"),
                 ("ip", "link", "set", "uplink", "up")):
        sh(*argv, pid=child.pid)
    shaped(f"to{name}")
    shaped("uplink", child.pid)
    return child.pid


def invite(root: str, path: str, name: str, port: int) -> str:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(["mesh", "invite", "--root", root, "--spec", path,
                         "--endpoint", f"{LINKS[name]}::1", "--port",
                         str(port)])
    if code:
        raise RuntimeError(err.getvalue())
    return out.getvalue().split()[-1]


def run_joiner(pid: int, token_text: str, name: str) -> subprocess.Popen:
    return subprocess.Popen(
        ["nsenter", "-t", str(pid), "-n", sys.executable, __file__, "join",
         token_text, f"{LINKS[name]}::2"], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True)


def result(process: subprocess.Popen) -> dict:
    out, err = process.communicate(timeout=300)
    for line in out.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[len("RESULT "):])
    raise RuntimeError(f"no result: {out}\n{err}")


def accept_line(process: subprocess.Popen) -> str:
    """The line a joiner that fell back prints, as an operator reads it"""
    for text in process.stdout:
        if text.startswith("keel mesh accept "):
            return text.split()[-1]
    return ""


def inviter() -> None:
    sh("ip", "link", "set", "lo", "up")
    pids = {name: link(name) for name in LINKS}
    root, path = scratch("version: 1\nnetwork:\n  overlay:\n    wireguard:\n"
                         f"      address: {OVERLAY_A}/64\n")
    key = os.path.join(root, "etc/wireguard/wg0.key")
    os.makedirs(os.path.dirname(key))
    with open(os.open(key, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fob:
        subprocess.run(["wg", "genkey"], stdout=fob, check=True)
    a = node(root, path)
    netns_apply(a.document(), root, 120)
    marker.clear(root)
    journal = []
    report = {}

    # 1-2. the root helper and its unprivileged listener, and B joins
    first = invite(root, path, "B", 51900)
    a_side = inviting.Inviter(a, utcnow, journal.append, journal.append,
                              run=Recorder(), output=lambda argv: None,
                              start=Spawned)
    codes = []
    thread = threading.Thread(target=lambda: codes.append(
        inviting.serve_invite(a_side, parse(first, utcnow()).invite_id)))
    thread.start()
    listening(f"{LINKS['B']}::1", 51900)
    report["b"] = result(run_joiner(pids["B"], first, "B"))
    thread.join(120)
    report["serve"] = codes
    report["a_after_b"] = marker.last(root).outcome

    # 3. nothing listens on the second invite's port: the fallback
    second = invite(root, path, "C", 51901)
    accepting = inviting.Inviter(a, utcnow, journal.append, journal.append,
                                 run=Recorder(), output=lambda argv: None,
                                 start=Spawned)
    process = run_joiner(pids["C"], second, "C")
    report["accept"] = inviting.accept(accepting, accept_line(process))
    rest, err = process.communicate(timeout=300)
    report["c"] = next(
        (json.loads(one[len("RESULT "):]) for one in rest.splitlines()
         if one.startswith("RESULT ")), {"err": err})
    report["a_after_c"] = marker.last(root).outcome

    # 4. the second token again: A refuses the line, the join is stopped
    process = run_joiner(pids["C"], second, "C")
    refused = []
    again = inviting.Inviter(a, utcnow, refused.append, refused.append,
                             run=Recorder(), output=lambda argv: None,
                             start=Spawned)
    report["again"] = [inviting.accept(again, accept_line(process)),
                       refused]
    process.kill()
    process.wait()
    report["peers"] = [peer.get("persistent_keepalive")
                       for peer in a.overlay()["peers"]]
    report["invites_left"] = os.listdir(os.path.join(
        root, "var/lib/keel/mesh/invites"))
    report["journal"] = journal
    report["tokens"] = [first, second]
    report["capabilities"] = CAPABILITIES
    report["netem"] = NETEM
    print("RESULT " + json.dumps(report), flush=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["join"]:
        joiner(sys.argv[2], sys.argv[3])
    else:
        try:
            inviter()
        finally:
            for one in CHILDREN:
                one.kill()
