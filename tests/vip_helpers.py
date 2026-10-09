# Copyright (c) 2026 KeelLinux maintainers
"""What the VIP tests share: a pair and a third node in one process

`Pair.nodes(n)` makes nodes of one mesh, each a keel.mesh.vipnode.Here
on a keel.mesh.node.Node of a scratch root with the format's manifests
(tests/manifest_helpers.py), a real signing key, the mesh's identity and
every other node trusted as a root with its signing key bound, as
tests/etcd_helpers.py makes them. The first two declare the same
`appliance.vip`. `ip` and `wg` are `FakeNet`, wg0's addresses and each
peer's allowed-ips; the members' channel is in process, a node's
`exchange` handing the message to the receiver's vipserve.answer, named
by the sender's key; etcd is `FakeKv`: keys, revisions, leases.
"""

import base64
import os
import shutil
import tempfile
import unittest
from unittest import mock

from etcd_helpers import KEYS, MESH, NOW, KeyedNode, address
from manifest_helpers import build_root

from keel.mesh import identity, signing, trust, vippair, vipserve
from keel.mesh.etcdclient import EtcdError, Value
from keel.mesh.memberlink import LinkError
from keel.mesh.vipnode import Here

VIP = "fd00:6b65:1::ffff:100"


def spec(index: int, count: int, vip: str | None,
         mode: str = "cloud_advanced", etcd: str = "disabled") -> str:
    peers = "".join(
        f"      - public_key: {KEYS[other]}\n"
        f"        allowed_ips: [{address(other)}/128]\n"
        for other in range(count) if other != index)
    vip_line = f"  vip: {vip}\n" if vip else ""
    return f"""\
version: 1
appliance:
  name: core
{vip_line}installation:
  mode: {mode}
overlays:
  installer: enabled
  wireguard: enabled
  etcd: {etcd}
  crowdsec: disabled
network:
  overlay:
    wireguard:
      address: {address(index)}/64
      peers:
{peers}"""


class FakeNet:
    """wg0 as `ip` and `wg` see it; `down` answers nothing, `fail` maps
    a command's first words to the error it fails with"""

    def __init__(self, peers: dict[str, list[str]]):
        self.addresses: list[str] = []
        # each address's valid_lft as `ip addr replace` set it, None for
        # forever
        self.lifetimes: dict[str, int | None] = {}
        self.routes = {key: list(nets) for key, nets in peers.items()}
        self.down = False
        self.fail: dict[tuple[str, ...], str] = {}
        self.calls: list[tuple[str, ...]] = []

    def failing(self, argv: tuple[str, ...]) -> str | None:
        for words, why in self.fail.items():
            if argv[:len(words)] == words:
                return why
        return None

    def run(self, argv: tuple[str, ...]) -> str | None:
        self.calls.append(argv)
        why = self.failing(argv)
        if why:
            return why
        if argv[:3] == ("ip", "-6", "addr") and argv[3] == "replace":
            if argv[4] not in self.addresses:
                self.addresses.append(argv[4])
            self.lifetimes[argv[4]] = int(argv[argv.index("valid_lft") + 1]) \
                if "valid_lft" in argv else None
            return None
        if argv[:3] == ("ip", "-6", "addr") and argv[3] == "del":
            if argv[4] not in self.addresses:
                return "ip exited 2: RTNETLINK answers: Cannot assign"
            self.addresses.remove(argv[4])
            return None
        if argv[:2] == ("wg", "set"):
            key, nets = argv[4], argv[6].split(",")
            for other in self.routes:
                self.routes[other] = [one for one in self.routes[other]
                                      if one not in nets]
            self.routes[key] = nets
            return None
        return f"{argv[0]}: not faked"

    def lifetime(self, address: str) -> str:
        found = self.lifetimes.get(address)
        return "forever" if found is None else f"{found}sec"

    def output(self, argv: tuple[str, ...]) -> str | None:
        if self.down or self.failing(argv):
            return None
        if argv[:4] == ("ip", "-6", "-o", "addr"):
            return "".join(f"5: wg0    inet6 {one} scope global deprecated"
                           f" \\       valid_lft {self.lifetime(one)}"
                           " preferred_lft 0sec\n"
                           for one in self.addresses)
        if argv[:2] == ("wg", "show") and argv[3] == "allowed-ips":
            return "".join(f"{key}\t{' '.join(nets) or '(none)'}\n"
                           for key, nets in self.routes.items())
        return ""


class FakeKv:
    """etcd's keys, revisions and leases, as keel.mesh.etcdclient asks
    them, on the test's clock: a lease not renewed for its TTL expires,
    and its keys go with it; `refuse` makes a call fail ("all": every
    call, "connect": the connection)"""

    def __init__(self, clock=lambda: 0.0):
        self.clock = clock
        self.kvs: dict[str, tuple[bytes, int, str | None]] = {}
        self.leases: dict[str, float] = {}
        self.revision = 1
        self.next_lease = 7000
        self.refuse: str | None = None
        self.timeout = 10
        self.calls: list[str] = []

    def __call__(self):
        if self.refuse == "connect":
            raise EtcdError("no member answered")
        return self

    def check(self, call: str) -> None:
        self.calls.append(call)
        if self.refuse in (call, "all"):
            raise EtcdError(f"{call}: etcdserver: request timed out")
        self.reap()

    def reap(self) -> None:
        for lease, until in list(self.leases.items()):
            if until <= self.clock():
                self.expire(lease)

    def grant(self, ttl: int) -> str:
        self.check("grant")
        self.next_lease += 1
        self.leases[str(self.next_lease)] = self.clock() + ttl
        return str(self.next_lease)

    def keepalive(self, lease: str) -> int:
        self.check("keepalive")
        if lease not in self.leases:
            return 0
        self.leases[lease] = self.clock() + 20
        return 20

    def time_to_live(self, lease: str) -> int:
        """As etcd says it: whole seconds, rounded down, so a lease in
        its last second says 0 and a renewal still keeps it (keel#126);
        -1 once it is gone"""
        self.check("time_to_live")
        if lease not in self.leases:
            return -1
        return int(self.leases[lease] - self.clock())

    def revoke(self, lease: str) -> None:
        self.check("revoke")
        self.expire(lease)

    def expire(self, lease: str) -> None:
        self.leases.pop(lease, None)
        for key in [k for k, v in self.kvs.items() if v[2] == lease]:
            del self.kvs[key]
            self.revision += 1

    def put(self, key: str, value: bytes, lease: str | None = None) -> None:
        """What any member may write, without a transaction"""
        self.revision += 1
        self.kvs[key] = (value, self.revision, lease)

    def delete(self, key: str) -> None:
        self.kvs.pop(key, None)
        self.revision += 1

    def prefix(self, key: str) -> list[Value]:
        self.check("prefix")
        return [Value(k, v[0], v[1], v[2])
                for k, v in sorted(self.kvs.items()) if k.startswith(key)]

    def swap(self, compare, puts, deletes=()) -> bool:
        self.check("swap")
        for one in compare:
            key = base64.b64decode(one["key"]).decode()
            if one["target"] == "MOD":
                now = self.kvs[key][1] if key in self.kvs else 0
                if now != int(one["mod_revision"]):
                    return False
            elif key in self.kvs:
                return False
        self.revision += 1
        for key, value, lease in puts:
            self.kvs[key] = (value, self.revision, lease)
        for key in deletes:
            self.kvs.pop(key, None)
        return True


class Pair(unittest.TestCase):
    """Nodes of one mesh; `nodes(n)` makes them, the first two a pair"""

    def setUp(self):
        self.parent = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.parent)
        patcher = mock.patch("keel.manifest.machine.ROOT_UID", os.getuid())
        patcher.start()
        self.addCleanup(patcher.stop)
        # keel vip tend sets no-new-privs on its own process: never on
        # the test runner's, whose later tests may need sudo
        patcher = mock.patch("keel.mesh.vipbridge.no_new_privileges",
                             return_value=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.all: list[Here] = []
        self.nets: list[FakeNet] = []
        self.said: dict[int, list[str]] = {}
        self.down: set[str] = set()
        self.ticks = [1000.0]
        self.kv = FakeKv(self.monotonic)

    def monotonic(self) -> float:
        return self.ticks[0]

    def sleep(self, seconds: float) -> None:
        self.ticks[0] += seconds

    def nodes(self, count: int = 3, vips: tuple = (VIP, VIP),
              mode: str = "cloud_advanced", etcd: str = "disabled",
              paired: bool = True) -> list[Here]:
        made = []
        for index in range(count):
            root = build_root(os.path.join(self.parent, f"n{index}"))
            path = os.path.join(root, "instance.yaml")
            with open(path, "w") as fob:
                fob.write(spec(index, count,
                               vips[index] if index < len(vips) else None,
                               mode, etcd))
            net = FakeNet({KEYS[other]: [f"{address(other)}/128"]
                           for other in range(count) if other != index})
            node = KeyedNode(root, path, run=net.run, output=net.output)
            node.key = KEYS[index]
            identity.adopt(root, MESH)
            signing.ensure(root)
            self.said[index] = []
            self.nets.append(net)
            made.append(Here(node, lambda: NOW, self.said[index].append,
                             exchange=self.exchanger(index),
                             client=self.kv, monotonic=self.monotonic,
                             sleep=self.sleep))
        for one in made:
            store = trust.load(one.root)
            for other in made:
                if other is not one:
                    trust.make_roots(store, (other.node.key,))
                    trust.bind_root(store, other.node.key,
                                    signing.public(other.root))
            trust.save(one.root, store)
        self.all = made
        if paired and count >= 2 and vips[:2] == (VIP, VIP):
            self.pair_up(0, 1)
        return made

    def pair_up(self, first: int, second: int, vip: str = VIP) -> None:
        """The pair record `keel vip pair` leaves on both members"""
        record = vippair.made(MESH.hex(), vip, (KEYS[first], KEYS[second]))
        for index in (first, second):
            record = vippair.sign(self.all[index].root, record, KEYS[index])
        for index in (first, second):
            vippair.write(self.all[index].root, record)

    def exchanger(self, index: int):
        def exchange(host: str, iface: str, body: bytes) -> bytes:
            if host in self.down:
                raise LinkError(f"[{host}]:51821 through {iface}: timed out")
            target = next(one for one in self.all
                          if one.overlay()["address"].startswith(host + "/"))
            found = vipserve.answer(target, body, KEYS[index])
            if found.status != 200:
                raise LinkError(f"[{host}]:51821 refused: {found.body!r}")
            return found.body
        return exchange

    def text(self, index: int) -> str:
        return "\n".join(self.said[index])

    def carried(self, index: int) -> bool:
        return f"{VIP}/128" in self.nets[index].addresses

    def routed(self, index: int) -> str | None:
        return next((key for key, nets in self.nets[index].routes.items()
                     if f"{VIP}/128" in nets), None)


__all__ = ["KEYS", "MESH", "NOW", "VIP", "FakeKv", "FakeNet", "Pair",
           "address", "spec"]
