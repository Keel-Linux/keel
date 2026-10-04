# Copyright (c) 2026 KeelLinux maintainers
"""What the etcd flow tests share: members of one mesh in one process

`Mesh` makes members, each a real keel.mesh.node.Node on a scratch root
that holds the manifests of the format (tests/manifest_helpers.py), so
its spec is validated as on a machine, with apply replaced by one that
records the documents it is given; a real signing key, the mesh's
identity, and every other member trusted as a root with its signing key
bound, as an adopted mesh's members are. The members' channel is in
process: a member's `exchange` hands the signed message to the
receiver's keel.mesh.etcdserve.answer, named by the sender's key as the
root side names it. etcd itself is `FakeEtcd`: the member list, and the
calls made of it.
"""

import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from manifest_helpers import build_root

from keel.mesh import etcdserve, identity, signing, trust
from keel.mesh.etcd import Etcd
from keel.mesh.etcdclient import EtcdError
from keel.mesh.etcdclient import Member as EtcdMember
from keel.mesh.memberlink import LinkError
from keel.mesh.node import Node

MESH = bytes(range(16))
NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)
KEYS = ("nb9/izIukqWXM7gnBpe7hki4jKZZChWOW1wEfONn82E=",
        "FHKH10gOWeK2bXHZPg8y+oPTprv556bwrmmRkbyEPgg=",
        "9vm/AzCVQQsWt1cU2eyjom4cABkNuodiHL8nDjKohEE=",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "HyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4=")
PREFIX = "fd00:6b65:1::"


def address(index: int) -> str:
    return f"{PREFIX}{index + 1}"


def spec(index: int, count: int, mode: str = "cloud_advanced",
         etcd: str = "disabled") -> str:
    peers = "".join(
        f"      - public_key: {KEYS[other]}\n"
        f"        allowed_ips: [{address(other)}/128]\n"
        for other in range(count) if other != index)
    return f"""\
version: 1
appliance:
  name: core
installation:
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


class Recorded:
    """apply: the documents given, and the code it answers"""

    def __init__(self, code: int = 0):
        self.code = code
        self.documents: list[dict] = []

    def __call__(self, doc: dict, root: str, window: int) -> int:
        self.documents.append(doc)
        print("apply: done")
        return self.code


class KeyedNode(Node):
    key: str = ""

    def public_key(self):
        return self.key, ""


class FakeEtcd:
    """The member list, and what was asked; `refuse` maps a call to the
    error etcd answers it with"""

    def __init__(self, members=()):
        self.members_ = list(members)
        self.calls: list[tuple] = []
        self.refuse: dict[str, str] = {}
        self.healthy: dict[str, tuple[bool, str]] = {}
        self.leaders: dict[str, str] = {}
        self.next_id = 100

    def __call__(self):
        if "connect" in self.refuse:
            raise EtcdError(self.refuse["connect"])
        return self

    def check(self, call: str, *args):
        self.calls.append((call, *args))
        if call in self.refuse:
            raise EtcdError(self.refuse[call])

    def members(self):
        self.check("members")
        return list(self.members_)

    def add_learner(self, url):
        self.check("add_learner", url)
        self.next_id += 1
        found = EtcdMember(str(self.next_id), "", (url,), (), True)
        self.members_.append(found)
        return found

    def promote(self, member_id):
        self.check("promote", member_id)

    def remove(self, member_id):
        self.check("remove", member_id)
        self.members_ = [one for one in self.members_ if one.id != member_id]

    def health(self, url):
        return self.healthy.get(url, (True, ""))

    def status(self, url):
        self.check("status", url)
        from keel.mesh.etcdclient import Status
        return Status("x", self.leaders.get(url, ""), 2, False)


def voter(index: int, name: bool = True) -> EtcdMember:
    at = address(index)
    return EtcdMember(str(index + 1), f"keel-{at.replace(':', '-')}"
                      if name else "", (f"https://[{at}]:2380",),
                      (f"https://[{at}]:2379",) if name else (), False)


class Mesh(unittest.TestCase):
    """Members of one mesh; `members(n)` makes them"""

    def setUp(self):
        self.parent = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.parent)
        patcher = mock.patch("keel.manifest.machine.ROOT_UID", os.getuid())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.all: list[Etcd] = []
        self.said: dict[int, list[str]] = {}
        self.down: set[str] = set()
        self.clock = lambda: NOW

    def members(self, count: int, modes: tuple[str, ...] = (),
                etcd: FakeEtcd | None = None) -> list[Etcd]:
        made = []
        for index in range(count):
            root = build_root(os.path.join(self.parent, f"n{index}"))
            path = os.path.join(root, "instance.yaml")
            mode = modes[index] if index < len(modes) else "cloud_advanced"
            with open(path, "w") as fob:
                fob.write(spec(index, count, mode))
            node = KeyedNode(root, path, apply=Recorded())
            node.key = KEYS[index]
            identity.adopt(root, MESH)
            signing.ensure(root)
            self.said[index] = []
            made.append(Etcd(node, self.clock, self.said[index].append,
                             client=etcd or FakeEtcd(),
                             exchange=self.exchanger(index),
                             sleep=lambda seconds: None))
        for one in made:
            store = trust.load(one.root)
            for other in made:
                if other is not one:
                    trust.make_roots(store, (other.node.key,))
                    trust.bind_root(store, other.node.key,
                                    signing.public(other.root))
            trust.save(one.root, store)
        self.all = made
        return made

    def exchanger(self, index: int):
        def exchange(host: str, iface: str, body: bytes) -> bytes:
            if host in self.down:
                raise LinkError(f"[{host}]:51821 through {iface}: timed out")
            target = next(one for one in self.all
                          if one.node.overlay()["address"].startswith(
                              host + "/"))
            found = etcdserve.answer(target, body, KEYS[index])
            if found.status != 200:
                raise LinkError(f"[{host}]:51821 refused: {found.body!r}")
            return found.body
        return exchange

    def applied(self, member: Etcd) -> list[dict]:
        return member.node.apply.documents

    def text(self, index: int) -> str:
        return "\n".join(self.said[index])
