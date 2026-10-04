# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.etcdpki: the mesh's etcd CA, with the real openssl"""

import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from keel.mesh import etcdpki
from keel.mesh.etcdpki import PkiError


class Case(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def key(self, name: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w") as fob:
            fob.write(etcdpki.new_key())
        return path


class TestRootAndChain(Case):
    def test_a_root_an_intermediate_two_deep_and_a_leaf(self):
        root_key = self.key("root.key")
        root = etcdpki.root(root_key, "ab" * 16)
        self.assertTrue(etcdpki.is_ca(root))
        b_key = self.key("b.key")
        b = etcdpki.issue(etcdpki.CA, root_key, root,
                          etcdpki.request(b_key), "keel-b")
        c_key = self.key("c.key")
        # an intermediate issued by an intermediate: any member invites
        c = etcdpki.issue(etcdpki.CA, b_key, b, etcdpki.request(c_key),
                          "keel-c")
        m_key = self.key("m.key")
        leaf = etcdpki.issue(etcdpki.MEMBER, c_key, c,
                             etcdpki.request(m_key), "keel-m",
                             ("fd00::3", "::1"), days=365)
        self.assertTrue(etcdpki.is_ca(c))
        self.assertFalse(etcdpki.is_ca(leaf))
        self.assertTrue(etcdpki.verified(leaf, [c, b], root))
        self.assertFalse(etcdpki.verified(leaf, [c], root))
        other = etcdpki.root(self.key("other.key"), "cd" * 16)
        self.assertFalse(etcdpki.verified(leaf, [c, b], other))
        self.assertEqual(etcdpki.subject(leaf), "keel-m")
        self.assertEqual(etcdpki.addresses(leaf), ("fd00::3", "::1"))
        left = etcdpki.not_after(leaf) - datetime.now(timezone.utc)
        self.assertTrue(timedelta(days=364) < left <= timedelta(days=366))

    def test_the_csr_gives_only_its_key(self):
        """The issuer sets the subject and every extension: a request
        asking for CA:TRUE or another name gets none of it"""
        root_key = self.key("root.key")
        root = etcdpki.root(root_key, "ab" * 16)
        asked = self.key("asked.key")
        conf = os.path.join(self.dir, "req.cnf")
        with open(conf, "w") as fob:
            fob.write("[req]\ndistinguished_name=dn\nreq_extensions=x\n"
                      "[dn]\n[x]\nbasicConstraints=critical,CA:TRUE\n"
                      "subjectAltName=IP:10.0.0.1\n")
        csr = subprocess.run(
            ["openssl", "req", "-new", "-key", asked, "-subj", "/CN=evil",
             "-config", conf], capture_output=True, text=True,
            check=True).stdout
        leaf = etcdpki.issue(etcdpki.CLIENT, root_key, root, csr,
                             "keel-client")
        self.assertFalse(etcdpki.is_ca(leaf))
        self.assertEqual(etcdpki.subject(leaf), "keel-client")
        self.assertEqual(etcdpki.addresses(leaf), ())
        self.assertEqual(etcdpki.public(leaf), etcdpki.request_key(csr))
        self.assertEqual(etcdpki.request_key(csr),
                         etcdpki.key_public(asked))

    def test_a_request_that_is_not_one(self):
        with self.assertRaises(PkiError):
            etcdpki.request_key("-----BEGIN CERTIFICATE REQUEST-----\n"
                                "AAAA\n-----END CERTIFICATE REQUEST-----\n")
        with self.assertRaises(PkiError):
            etcdpki.request_key("nothing")

    def test_garbage_is_no_certificate(self):
        self.assertFalse(etcdpki.verified("x", [], "y"))
        with self.assertRaises(PkiError):
            etcdpki.not_after("x")
        with self.assertRaises(PkiError):
            etcdpki.public("x")
        self.assertFalse(etcdpki.is_ca("x"))
        self.assertEqual(etcdpki.addresses("x"), ())
        with self.assertRaises(PkiError):
            etcdpki.subject("x")

    def test_fingerprint_is_the_der_sha256(self):
        root = etcdpki.root(self.key("root.key"), "ab" * 16)
        der = subprocess.run(["openssl", "x509", "-outform", "DER"],
                             input=root.encode(), capture_output=True,
                             check=True).stdout
        import hashlib
        self.assertEqual(etcdpki.fingerprint(root),
                         hashlib.sha256(der).hexdigest())

    def test_no_fingerprint_for_what_is_no_certificate(self):
        with self.assertRaises(PkiError):
            etcdpki.fingerprint("x")
        with mock.patch("keel.mesh.etcdpki.subprocess.run",
                        side_effect=OSError("not found")), \
                self.assertRaises(PkiError):
            etcdpki.fingerprint("x")

    def test_pem_blocks_split(self):
        root = etcdpki.root(self.key("root.key"), "ab" * 16)
        self.assertEqual(etcdpki.blocks(root + root), [root, root])
        self.assertEqual(etcdpki.blocks("none"), [])


class TestOpensslFailing(Case):
    def test_missing_or_failing(self):
        with mock.patch("keel.mesh.etcdpki.subprocess.run",
                        side_effect=OSError("not found")), \
                self.assertRaises(PkiError):
            etcdpki.new_key()
        failed = subprocess.CompletedProcess([], 1, "", "bad")
        with mock.patch("keel.mesh.etcdpki.subprocess.run",
                        return_value=failed), self.assertRaises(PkiError):
            etcdpki.new_key()
        with mock.patch("keel.mesh.etcdpki.subprocess.run",
                        return_value=failed), self.assertRaises(PkiError):
            etcdpki.root(self.key("k"), "ab" * 16)
        empty = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch("keel.mesh.etcdpki.subprocess.run",
                        return_value=empty), self.assertRaises(PkiError):
            etcdpki.new_key()


if __name__ == "__main__":
    unittest.main()
