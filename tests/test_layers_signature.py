# Copyright (c) 2026 KeelLinux maintainers
"""Verifying a clear signed pointer against a keyring, with a real verifier

Every test here signs with a real key and verifies with gpgv, because the
two traps this code exists to avoid are properties of that program and of
nothing else: gpgv writes the plain text of a document whose signature it
refused, and it reads a binary keyring only.
"""

import os
import shutil
import tempfile
import unittest
from os.path import join
from unittest import mock

from channel_helpers import channel_body, keys, tools_missing

from keel.layers import signature
from keel.layers.constants import VERIFIER  # noqa: F401
from keel.layers.errors import SignatureError

MISSING = tools_missing()


@unittest.skipIf(MISSING, f"{MISSING} is not installed")
class SignatureTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.keys = keys()
        self.body = channel_body()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def signed(self, text: str | None = None, fpr: str | None = None) -> str:
        path = join(self.tmpdir, "stable")
        with open(path, "w") as fob:
            fob.write(self.keys.clearsign(text or self.body, fpr))
        return path

    def verify(self, path, keyring=None, signers=()):
        return signature.verify(
            path, keyring or self.keys.keyring, signers
        )

    def failing(self, path, keyring=None, signers=()) -> SignatureError:
        with self.assertRaises(SignatureError) as raised:
            self.verify(path, keyring, signers)
        return raised.exception


class TestGoodSignature(SignatureTestCase):
    def test_the_verified_text_is_the_body_that_was_signed(self):
        found = self.verify(self.signed())
        self.assertEqual(found.text, self.body)

    def test_the_signing_key_is_reported_by_fingerprint(self):
        found = self.verify(self.signed())
        self.assertIn(self.keys.channel, found.fingerprints)

    def test_an_armored_keyring_is_accepted_although_gpgv_refuses_one(self):
        found = self.verify(
            self.signed(), keyring=self.keys.keyring_armored
        )
        self.assertEqual(found.text, self.body)

    def test_a_signer_allowlist_that_names_the_key_passes(self):
        found = self.verify(self.signed(), signers=(self.keys.channel,))
        self.assertEqual(found.text, self.body)

    def test_a_lowercase_fingerprint_in_the_allowlist_passes(self):
        found = self.verify(
            self.signed(), signers=(self.keys.channel.lower(),)
        )
        self.assertEqual(found.text, self.body)

    def test_nothing_is_left_behind_in_the_temporary_directory(self):
        before = set(os.listdir(self.tmpdir))
        self.verify(self.signed(), keyring=self.keys.keyring_armored)
        self.assertEqual(set(os.listdir(self.tmpdir)) - before, {"stable"})


class TestRefusals(SignatureTestCase):
    def test_a_body_changed_after_signing_is_refused(self):
        path = self.signed()
        with open(path, encoding="utf-8") as fob:
            text = fob.read()
        with open(path, "w", encoding="utf-8") as fob:
            fob.write(text.replace("rev 1", "rev 2"))
        problem = self.failing(path)
        self.assertIn("signature does not verify", str(problem))

    def test_the_text_of_a_refused_document_is_never_returned(self):
        """gpgv writes the plain text even when it refuses the signature"""
        path = self.signed(fpr=self.keys.other)
        problem = self.failing(path)
        self.assertNotIn("release 2026-09-28", str(problem))

    def test_a_signature_by_a_key_that_is_not_in_the_keyring_is_refused(self):
        problem = self.failing(self.signed(fpr=self.keys.other))
        self.assertIn("signature does not verify", str(problem))

    def test_a_key_in_the_keyring_but_not_in_the_allowlist_is_refused(self):
        path = self.signed(fpr=self.keys.other)
        problem = self.failing(
            path, keyring=self.keys.both, signers=(self.keys.channel,)
        )
        self.assertIn(self.keys.other, str(problem))
        self.assertIn("not the key that may move a channel", str(problem))

    def test_a_document_with_no_signature_is_refused(self):
        path = join(self.tmpdir, "stable")
        with open(path, "w") as fob:
            fob.write(self.body)
        self.assertIn("signature does not verify", str(self.failing(path)))

    def test_a_pointer_that_is_not_there_is_refused(self):
        problem = self.failing(join(self.tmpdir, "absent"))
        self.assertIn("absent", str(problem))

    def test_a_keyring_that_is_not_there_is_refused(self):
        problem = self.failing(
            self.signed(), keyring=join(self.tmpdir, "absent.gpg")
        )
        self.assertIn("absent.gpg", str(problem))

    def test_a_keyring_that_cannot_be_read_is_refused(self):
        if os.geteuid() == 0:
            self.skipTest("root reads a file with mode 0")
        keyring = join(self.tmpdir, "keyring.asc")
        shutil.copy(self.keys.keyring_armored, keyring)
        path = self.signed()
        os.chmod(keyring, 0)
        try:
            problem = self.failing(path, keyring=keyring)
        finally:
            os.chmod(keyring, 0o644)
        self.assertIn("keyring.asc", str(problem))

    def test_an_empty_armored_keyring_is_refused_before_gpgv_runs(self):
        keyring = join(self.tmpdir, "empty.asc")
        with open(keyring, "w") as fob:
            fob.write("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n=A\n")
        problem = self.failing(self.signed(), keyring=keyring)
        self.assertIn("no OpenPGP key", str(problem))

    def test_a_verifier_that_is_not_installed_is_refused(self):
        path = self.signed()
        with mock.patch.object(
            signature.subprocess, "run", side_effect=OSError("no gpgv")
        ):
            problem = self.failing(path)
        self.assertIn("no gpgv", str(problem))

    def test_a_verifier_that_exits_well_without_a_validsig_is_refused(self):
        """GOODSIG but no VALIDSIG: no fingerprint to hold anyone to"""
        path = self.signed()
        completed = mock.Mock(returncode=0, stderr="",
                              stdout="[GNUPG:] GOODSIG DEADBEEF x\n")
        with mock.patch.object(
            signature.subprocess, "run", return_value=completed
        ):
            with open(join(self.tmpdir, "plain"), "w"):
                problem = self.failing(path)
        self.assertIn("said nothing about a valid signature", str(problem))


@unittest.skipIf(MISSING, f"{MISSING} is not installed")
class TestRetiredKeys(SignatureTestCase):
    """A revoked or an expired key is a refusal, whatever the exit status

    gpgv exits 0 for both and still prints VALIDSIG; GOODSIG is the only
    line it withholds. Measured on gpgv 2.4.7, and the reason revocation
    is the one answer to the theft of an online key.
    """

    def written(self, text: str) -> str:
        path = join(self.tmpdir, "stable")
        with open(path, "w") as fob:
            fob.write(text)
        return path

    def test_a_key_revoked_in_the_keyring_given_is_refused(self):
        problem = self.failing(
            self.written(self.keys.sign_revoked(self.body)),
            keyring=self.keys.keyring_revoked,
        )
        self.assertIn("revoked or expired", str(problem))

    def test_a_revoked_key_is_refused_even_when_it_is_the_pinned_signer(self):
        problem = self.failing(
            self.written(self.keys.sign_revoked(self.body)),
            keyring=self.keys.keyring_revoked,
            signers=(self.keys.revoked,),
        )
        self.assertIn("revoked or expired", str(problem))

    def test_the_text_of_a_revoked_signature_is_never_returned(self):
        problem = self.failing(
            self.written(self.keys.sign_revoked(self.body)),
            keyring=self.keys.keyring_revoked,
        )
        self.assertNotIn("release 2026-09-28", str(problem))

    def test_an_expired_key_is_refused(self):
        problem = self.failing(
            self.written(self.keys.expired_signature),
            keyring=self.keys.keyring_expired,
        )
        self.assertIn("revoked or expired", str(problem))

    def test_a_revoked_signing_subkey_under_a_live_primary_is_refused(self):
        """The shape apt/keys/keel-archive-keyring.asc already has

        VALIDSIG's last field is the primary fingerprint, so pinning the
        primary as the accepted signer matches a signature made by a
        subkey of it that has since been revoked. The retirement refusal
        is what stops one, not the allowlist.
        """
        problem = self.failing(
            self.written(self.keys.subkey_signature),
            keyring=self.keys.keyring_subkey,
            signers=(self.keys.subkey_primary,),
        )
        self.assertIn("revoked or expired", str(problem))

    def test_a_verifier_that_prints_validsig_without_goodsig_is_refused(self):
        """The general form, in case a future gpgv drops a line we name"""
        path = self.signed()
        status = (
            "[GNUPG:] VALIDSIG " + "A" * 40 + " 2026-09-28 1790566273 0 4 0"
            " 22 10 01 " + "A" * 40 + "\n"
        )
        completed = mock.Mock(returncode=0, stdout=status, stderr="")
        with mock.patch.object(
            signature.subprocess, "run", return_value=completed
        ):
            problem = self.failing(path)
        self.assertIn("did not call the signature good", str(problem))


@unittest.skipIf(MISSING, f"{MISSING} is not installed")
class TestWeakDigest(SignatureTestCase):
    def test_a_sha1_signature_is_refused(self):
        path = join(self.tmpdir, "stable")
        with open(path, "w") as fob:
            fob.write(self.keys.clearsign(self.body, digest="SHA1"))
        problem = self.failing(path)
        self.assertIn("signature does not verify", str(problem))

    def test_the_verifier_is_asked_to_treat_sha1_as_weak(self):
        self.assertIn("--weak-digest", signature.VERIFIER)
        self.assertIn("SHA1", signature.VERIFIER)


@unittest.skipIf(MISSING, f"{MISSING} is not installed")
class TestDearmor(unittest.TestCase):
    def test_an_armored_keyring_dearmors_to_the_binary_one(self):
        with open(keys().keyring_armored, "rb") as fob:
            armored = fob.read()
        with open(keys().keyring, "rb") as fob:
            binary = fob.read()
        self.assertEqual(signature.dearmor(armored), binary)

    def test_a_binary_keyring_is_returned_as_it_is(self):
        with open(keys().keyring, "rb") as fob:
            binary = fob.read()
        self.assertEqual(signature.dearmor(binary), binary)

    def test_two_blocks_dearmor_to_both_keys(self):
        with open(keys().keyring_armored, "rb") as fob:
            armored = fob.read()
        with open(keys().keyring, "rb") as fob:
            binary = fob.read()
        self.assertEqual(signature.dearmor(armored * 2), binary * 2)

    def test_armor_that_is_not_base64_is_a_signature_error(self):
        armored = (
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
            b"not base64 at all!!\n=AAAA\n"
            b"-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        with self.assertRaises(SignatureError) as raised:
            signature.dearmor(armored)
        self.assertIn("cannot be decoded", str(raised.exception))
