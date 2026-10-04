# Copyright (c) 2026 KeelLinux maintainers
"""What the tests of sync, adopt, remove and the members' service share

This node is JOINER at fd00:6b65:1::3, a real Node on a scratch root
(tests/mesh_wire.py: apply arms the window's marker, the real
keel.network.confirm decides), with a real signing key; INVITER at ::1
is its one peer and its trust root, whose signing key lives in a scratch
root of its own (`INVITER_ROOT`), so its evidence is really signed. The
members' channel is `Network`: rosters by address, what was told and
touched, the latest handshakes.
"""

import atexit
import shutil
import tempfile
import unittest
from datetime import timedelta
from unittest import mock

import yaml
from mesh_helpers import INVITER, JOINER, MESH, NOW, OTHER, Clock
from mesh_wire import node

from keel.mesh import identity, signing, sync, trust
from keel.mesh.memberlink import LinkError
from keel.mesh.members import Roster
from keel.mesh.protocol import Peer

FOURTH = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
SPLIT = bytes(16)
SPEC = f"""\
version: 1
network:
  overlay:
    wireguard:
      address: fd00:6b65:1::3/64
      peers:
      - public_key: {INVITER}
        endpoint: '[2001:db8:1::10]:51820'
        allowed_ips: [fd00:6b65:1::1/128]
"""
INVITER_ROOT = tempfile.mkdtemp(prefix="keel-inviter-")
atexit.register(shutil.rmtree, INVITER_ROOT, True)
INVITER_SIGNER = signing.ensure(INVITER_ROOT)
# OTHER's signing key: any, nothing it signs is checked here
OTHER_SIGNER = FOURTH


def evidence(key: str = OTHER, address: str = "fd00:6b65:1::7",
             endpoint: str | None = "[2001:db8:3::30]:51820",
             root: str = INVITER_ROOT, mesh: bytes = MESH,
             sign_key: str = OTHER_SIGNER):
    """The admission of `key`, signed by the inviter (or `root`)"""
    return trust.admit(root, mesh, "0123456789abcdef", key, sign_key,
                       address, endpoint, NOW)


def admitted(key: str = OTHER, **changed) -> Peer:
    found = evidence(key, **changed)
    return Peer(found.public_key, found.endpoint, found.address, found)


def inviter_roster(*entries: Peer, identity_of: bytes | None = MESH,
                   removed=()) -> Roster:
    return Roster(identity_of, INVITER, INVITER_SIGNER, "fd00:6b65:1::1",
                  (Peer(JOINER, None, "fd00:6b65:1::3"),) + entries,
                  tuple(removed))


class Network:
    """The members as this node reaches them over the overlay"""

    def __init__(self, rosters=None, handshakes=None):
        self.rosters = dict(rosters or {})
        self.told, self.touched = [], []
        self.down: set[str] = set()
        # key -> seconds since the epoch of its last handshake
        self.handshakes = dict(handshakes or {})

    def fetch(self, host, iface):
        if host in self.down or host not in self.rosters:
            raise LinkError(f"[{host}]:51821 through {iface}: timed out")
        return self.rosters[host]

    def tell(self, host, iface, roster):
        if host in self.down:
            raise LinkError(f"[{host}]:51821 through {iface}: timed out")
        self.told.append((host, roster))

    def touch(self, host, iface):
        self.touched.append(host)

    def output(self, argv):
        if argv[-1] == "latest-handshakes":
            return "".join(f"{key}\t{at}\n"
                           for key, at in self.handshakes.items())
        return None


class Case(unittest.TestCase):
    """This node in MESH, trusting INVITER as its root"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.node = node(self.root, SPEC)
        self.net = Network({"fd00:6b65:1::1": inviter_roster(admitted())},
                           handshakes={OTHER: int(NOW.timestamp())})
        self.node.output = self.net.output
        self.clock = Clock()
        self.err, self.slept = [], []
        self.syncer = sync.Syncer(
            self.node, self.clock, self.err.append, fetch=self.net.fetch,
            tell=self.net.tell, touch=self.net.touch, sleep=self.later)
        keys = mock.patch("keel.mesh.node.wgkeys.public",
                          return_value=(JOINER, None))
        keys.start()
        self.addCleanup(keys.stop)
        identity.adopt(self.root, MESH)
        self.signer = signing.ensure(self.root)
        self.trusting(INVITER, INVITER_SIGNER)

    def trusting(self, key: str, sign_key: str | None) -> None:
        store = trust.load(self.root)
        trust.make_roots(store, (key,))
        if sign_key:
            trust.bind_root(store, key, sign_key)
        trust.save(self.root, store)

    def later(self, seconds):
        self.slept.append(seconds)
        self.clock.now += timedelta(seconds=seconds)

    def peers(self):
        with open(self.node.path) as fob:
            doc = yaml.safe_load(fob)
        return doc["network"]["overlay"]["wireguard"]["peers"]

    def said(self):
        return "\n".join(self.err)
