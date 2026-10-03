# Copyright (c) 2026 KeelLinux maintainers
"""keel.mesh.signing: this node's Ed25519 key, with the real openssl"""

import base64
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from keel.mesh import signing


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)


class TestKey(Case):
    def test_made_once_root_s_alone(self):
        public = signing.ensure(self.root)
        self.assertEqual(len(base64.b64decode(public)), 32)
        self.assertEqual(signing.ensure(self.root), public)
        mode = os.stat(os.path.join(self.root, signing.KEY)).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o600)

    def test_no_key_yet(self):
        with self.assertRaises(signing.SigningError):
            signing.public(self.root)

    def test_a_file_that_is_no_key(self):
        os.makedirs(os.path.join(self.root, "var/lib/keel/mesh"))
        with open(os.path.join(self.root, signing.KEY), "w") as fob:
            fob.write("nope\n")
        with self.assertRaises(signing.SigningError):
            signing.public(self.root)
        with self.assertRaises(signing.SigningError):
            signing.sign(self.root, b"x")

    def test_openssl_failing_or_missing(self):
        failed = subprocess.CompletedProcess([], 1, b"", b"no")
        with mock.patch("keel.mesh.signing.subprocess.run",
                        return_value=failed), \
                self.assertRaises(signing.SigningError):
            signing.ensure(self.root)
        with mock.patch("keel.mesh.signing.subprocess.run",
                        side_effect=OSError("not found")), \
                self.assertRaises(signing.SigningError):
            signing.ensure(self.root)
        self.assertFalse(os.path.exists(os.path.join(self.root,
                                                     signing.KEY)))


class TestSignatures(Case):
    def test_signed_and_verified(self):
        public = signing.ensure(self.root)
        signature = signing.sign(self.root, b"message")
        self.assertTrue(signing.verified(public, b"message", signature))
        self.assertFalse(signing.verified(public, b"messagf", signature))

    def test_another_key_or_garbage_is_no_signature(self):
        public = signing.ensure(self.root)
        signature = signing.sign(self.root, b"message")
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other)
        self.assertFalse(signing.verified(signing.ensure(other), b"message",
                                          signature))
        for key, sig in ((public, "!!"), (public, "AAAA"), ("x", signature)):
            self.assertFalse(signing.verified(key, b"message", sig))
        with mock.patch("keel.mesh.signing.subprocess.run",
                        side_effect=OSError("not found")):
            self.assertFalse(signing.verified(public, b"message",
                                              signature))


if __name__ == "__main__":
    unittest.main()
