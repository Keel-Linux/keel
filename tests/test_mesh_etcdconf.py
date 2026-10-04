# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.etcdconf: etcd's environment file and systemd drop-in,
rendered from the cluster; pure"""

import unittest

from keel.mesh import etcdconf
from keel.mesh.etcdstate import Cluster, Member

MESH = "ab" * 16
THREE = Cluster("new", (Member("k1", "fd00::1"), Member("k2", "fd00::2"),
                        Member("k3", "fd00::3")), MESH)


def parsed(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines()
                if line and not line.startswith("#"))


class TestEnvironment(unittest.TestCase):
    def test_a_member_of_a_new_cluster(self):
        found = parsed(etcdconf.environment("fd00::2", THREE))
        self.assertEqual(found["ETCD_NAME"], "keel-fd00--2")
        self.assertEqual(found["ETCD_LISTEN_PEER_URLS"],
                         "https://[fd00::2]:2380")
        self.assertEqual(found["ETCD_LISTEN_CLIENT_URLS"],
                         "https://[fd00::2]:2379,https://[::1]:2379")
        self.assertEqual(found["ETCD_ADVERTISE_CLIENT_URLS"],
                         "https://[fd00::2]:2379")
        self.assertEqual(found["ETCD_INITIAL_ADVERTISE_PEER_URLS"],
                         "https://[fd00::2]:2380")
        self.assertEqual(found["ETCD_INITIAL_CLUSTER"], ",".join(
            f"keel-fd00--{n}=https://[fd00::{n}]:2380" for n in (1, 2, 3)))
        self.assertEqual(found["ETCD_INITIAL_CLUSTER_STATE"], "new")
        self.assertEqual(found["ETCD_INITIAL_CLUSTER_TOKEN"], MESH)
        self.assertEqual(found["ETCD_HEARTBEAT_INTERVAL"], "300")
        self.assertEqual(found["ETCD_ELECTION_TIMEOUT"], "5000")
        for one in ("ETCD_CLIENT_CERT_AUTH", "ETCD_PEER_CLIENT_CERT_AUTH"):
            self.assertEqual(found[one], "true")
        self.assertEqual(found["ETCD_TLS_MIN_VERSION"], "TLS1.3")
        self.assertEqual(found["ETCD_CERT_FILE"], "/etc/etcd/keel/member.crt")
        self.assertEqual(found["ETCD_PEER_KEY_FILE"],
                         "/etc/etcd/keel/member.key")
        self.assertEqual(found["ETCD_TRUSTED_CA_FILE"],
                         "/etc/etcd/keel/ca.crt")
        self.assertEqual(found["ETCD_DATA_DIR"], "/var/lib/etcd/default")
        # never a wildcard address
        self.assertNotIn("[::]", etcdconf.environment("fd00::2", THREE))
        self.assertNotIn("0.0.0.0", etcdconf.environment("fd00::2", THREE))

    def test_a_learner_joins_an_existing_cluster(self):
        found = parsed(etcdconf.environment("fd00::4", Cluster(
            "existing", THREE.members + (Member("k4", "fd00::4"),), MESH)))
        self.assertEqual(found["ETCD_INITIAL_CLUSTER_STATE"], "existing")
        self.assertIn("keel-fd00--4=https://[fd00::4]:2380",
                      found["ETCD_INITIAL_CLUSTER"])

    def test_the_header_says_who_writes_it(self):
        self.assertTrue(etcdconf.environment("fd00::2", THREE).startswith(
            etcdconf.HEADER))


class TestDropIn(unittest.TestCase):
    def test_after_the_overlay_and_sandboxed(self):
        found = etcdconf.drop_in("wg7")
        self.assertIn("After=wg-quick@wg7.service", found)
        self.assertIn("Restart=on-failure", found)
        self.assertIn("TimeoutStartSec=infinity", found)
        for one in ("NoNewPrivileges=yes", "ProtectSystem=strict",
                    "ReadWritePaths=/var/lib/etcd", "CapabilityBoundingSet=",
                    "PrivateDevices=yes", "ProtectHome=yes",
                    "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
                    "SystemCallFilter=@system-service",
                    "MemoryDenyWriteExecute=yes"):
            self.assertIn(one + "\n", found)
        self.assertTrue(found.startswith(etcdconf.HEADER))


if __name__ == "__main__":
    unittest.main()
