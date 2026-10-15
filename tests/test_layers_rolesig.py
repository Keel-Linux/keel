# Copyright (c) 2026 KeelLinux maintainers
"""Signatures of the image artifacts, by main or by images (decision 0055)

The release MANIFEST and a layer `.hash` file carry 1 signature by the
main key and 1 by the images key, in 1 file, while every verifier moves to
the images key. A verifier that has only one of the 2 keys must accept the
file: gpgv exits 2 for it, because it cannot check the other signature, so
the verdict comes from the status lines of each signature. Real keys and a
real gpgv, as in test_layers_signature.
"""

import contextlib
import hashlib
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from os.path import join

from channel_helpers import keys, tools_missing
from layers_helpers import build_tree, hash_text, write

from keel import exits
from keel.cli import main
from keel.layers import release_manifest, signature, verify, verify_layers
from keel.layers.errors import SignatureError

MISSING = tools_missing()


def detach_sign(home: str, path: str, *fprs: str) -> str:
    """One armored detached signature file with a signature by each key"""
    users = []
    for fpr in fprs:
        users += ["--local-user", fpr]
    subprocess.run(
        ["gpg", "--batch", "--quiet", "--homedir", home, "--passphrase", "",
         "--pinentry-mode", "loopback", *users, "--yes", "--armor",
         "--output", path + ".asc", "--detach-sign", path],
        capture_output=True, text=True, check=True,
    )
    return path + ".asc"


def clearsign_many(home: str, text: str, *fprs: str) -> str:
    """A clear signed text with a signature by each key"""
    users = []
    for fpr in fprs:
        users += ["--local-user", fpr]
    done = subprocess.run(
        ["gpg", "--batch", "--quiet", "--homedir", home, "--passphrase", "",
         "--pinentry-mode", "loopback", *users, "--clearsign"],
        input=text, capture_output=True, text=True, check=True,
    )
    return done.stdout


@unittest.skipIf(MISSING, f"{MISSING} is not installed")
class RoleTestCase(unittest.TestCase):
    """main is the channel test key and images is the other test key"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.keys = keys()
        self.main = self.keys.channel
        self.images = self.keys.other
        self.main_ring = self.keys.keyring
        self.images_ring = self.keys.export(
            join(self.tmpdir, "images.gpg"), self.images
        )
        self.images_armored = self.keys.export(
            join(self.tmpdir, "images.asc"), self.images, armored=True
        )

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def write(self, name: str, data: str) -> str:
        path = join(self.tmpdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fob:
            fob.write(data)
        return path


class TestDetachedByAny(RoleTestCase):
    def signed(self, *fprs: str) -> str:
        path = self.write("file", "payload\n")
        detach_sign(self.keys.home, path, *fprs)
        return path

    def verify(self, path, keyrings):
        with open(path + ".asc", "rb") as fob:
            sig = fob.read()
        with open(path, "rb") as fob:
            data = fob.read()
        return signature.verify_by_any(path, data, keyrings, detached=sig)

    def test_both_signatures_and_the_main_keyring_alone_is_good(self):
        found = self.verify(self.signed(self.main, self.images),
                            (self.main_ring,))
        self.assertEqual(found.fingerprints, (self.main,))

    def test_both_signatures_and_the_images_keyring_alone_is_good(self):
        found = self.verify(self.signed(self.main, self.images),
                            (self.images_ring,))
        self.assertEqual(found.fingerprints, (self.images,))

    def test_both_keyrings_name_both_keys(self):
        found = self.verify(self.signed(self.main, self.images),
                            (self.main_ring, self.images_armored))
        self.assertEqual(set(found.fingerprints), {self.main, self.images})

    def test_main_alone_is_good_with_both_keyrings(self):
        found = self.verify(self.signed(self.main),
                            (self.main_ring, self.images_ring))
        self.assertEqual(found.fingerprints, (self.main,))

    def test_a_key_in_no_keyring_is_refused(self):
        with self.assertRaises(SignatureError) as raised:
            self.verify(self.signed(self.images), (self.main_ring,))
        self.assertIn("no good signature", str(raised.exception))

    def test_a_changed_file_is_refused_even_by_a_key_that_is_known(self):
        path = self.signed(self.main, self.images)
        with open(path, "a", encoding="utf-8") as fob:
            fob.write("changed\n")
        for rings in ((self.main_ring,), (self.images_ring,)):
            with self.assertRaises(SignatureError) as raised:
                self.verify(path, rings)
            self.assertIn("BADSIG", str(raised.exception))

    def test_a_revoked_key_gives_no_good_signature(self):
        path = self.write("file", "payload\n")
        subprocess.run(
            ["gpg", "--batch", "--quiet", "--homedir",
             self.keys.home_stolen, "--yes", "--armor", "--local-user",
             self.keys.revoked, "--output", path + ".asc", "--detach-sign",
             path],
            capture_output=True, text=True, check=True,
        )
        with self.assertRaises(SignatureError) as raised:
            self.verify(path, (self.keys.keyring_revoked,))
        self.assertIn("revoked or expired", str(raised.exception))

    def test_a_keyring_that_is_not_there_is_skipped(self):
        found = self.verify(
            self.signed(self.main, self.images),
            (join(self.tmpdir, "absent.gpg"), self.images_ring),
        )
        self.assertEqual(found.fingerprints, (self.images,))

    def test_a_refusal_names_the_keyrings_that_were_skipped(self):
        with self.assertRaises(SignatureError) as raised:
            self.verify(self.signed(self.images),
                        (join(self.tmpdir, "absent.gpg"), self.main_ring))
        self.assertIn("skipped", str(raised.exception))
        self.assertIn("absent.gpg", str(raised.exception))

    def test_no_keyring_that_can_be_read_is_refused(self):
        with self.assertRaises(SignatureError) as raised:
            self.verify(self.signed(self.main),
                        (join(self.tmpdir, "absent.gpg"),))
        self.assertIn("no keyring", str(raised.exception))
        self.assertIn("absent.gpg", str(raised.exception))

    def test_a_verifier_that_cannot_run_is_refused(self):
        path = self.signed(self.main)
        old = os.environ.get("PATH", "")
        os.environ["PATH"] = self.tmpdir
        try:
            with self.assertRaises(SignatureError) as raised:
                self.verify(path, (self.main_ring,))
        finally:
            os.environ["PATH"] = old
        self.assertIn("cannot run gpgv", str(raised.exception))


class TestClearByAny(RoleTestCase):
    def test_the_text_is_what_was_signed_with_one_keyring(self):
        text = "a1b2  core.tar.zst\n"
        data = clearsign_many(self.keys.home, text, self.main, self.images)
        for ring, fpr in ((self.main_ring, self.main),
                          (self.images_ring, self.images)):
            found = signature.verify_by_any("x.hash", data.encode(), (ring,))
            self.assertEqual(found.text, text)
            self.assertEqual(found.fingerprints, (fpr,))


class TestReleaseManifest(RoleTestCase):
    """keel verify --release-manifest on a staged or published release"""

    def release(self, *fprs: str) -> str:
        image = self.write("rel/images/t.tar.zst", "template\n")
        index = self.write("rel/pve/aplinfo.dat", "Package: keel-core\n")
        lines = []
        for path, rel in ((image, "images/t.tar.zst"),
                          (index, "pve/aplinfo.dat")):
            with open(path, "rb") as fob:
                data = fob.read()
            lines.append(
                f"{len(data)} {hashlib.sha256(data).hexdigest()} {rel}"
            )
        lines.append(f"5 {'0' * 64} images/absent.tar.zst")
        manifest = self.write(
            "rel/MANIFEST",
            "release 2026-10-11\nrevision 1\nsigned yes subkey X\n\n"
            "# size sha256 path\n" + "\n".join(lines) + "\n",
        )
        detach_sign(self.keys.home, manifest, *fprs)
        return manifest

    def check(self, manifest, keyrings):
        return release_manifest.verify(manifest, keyrings)

    def test_each_keyring_alone_accepts_a_manifest_both_keys_signed(self):
        manifest = self.release(self.main, self.images)
        for ring, fpr in ((self.main_ring, self.main),
                          (self.images_ring, self.images)):
            report = self.check(manifest, (ring,))
            self.assertEqual(report.code, exits.OK, report.lines())
            self.assertIn(fpr, report.lines()[0])
            self.assertIn("images/t.tar.zst: ok", report.lines())
            self.assertIn("pve/aplinfo.dat: ok", report.lines())
            self.assertIn("images/absent.tar.zst: not present, not checked",
                          report.lines())

    def test_a_file_that_differs_from_the_manifest_is_a_mismatch(self):
        manifest = self.release(self.main, self.images)
        self.write("rel/pve/aplinfo.dat", "Package: keel-evil\n")
        report = self.check(manifest, (self.images_ring,))
        self.assertEqual(report.code, exits.LAYER_MISMATCH)
        self.assertTrue(
            any(line.startswith("pve/aplinfo.dat: mismatch")
                for line in report.lines()),
            report.lines(),
        )

    def test_a_changed_manifest_is_unverified_and_nothing_is_read(self):
        manifest = self.release(self.main, self.images)
        with open(manifest, "a", encoding="utf-8") as fob:
            fob.write(f"1 {'0' * 64} pve/aplinfo.dat\n")
        report = self.check(manifest, (self.main_ring,))
        self.assertEqual(report.code, exits.SIGNATURE_UNVERIFIED)
        self.assertEqual(len(report.lines()), 1)
        self.assertIn("BADSIG", report.lines()[0])

    def test_a_manifest_with_no_signature_file_is_unverified(self):
        manifest = self.release(self.main)
        os.remove(manifest + ".asc")
        report = self.check(manifest, (self.main_ring,))
        self.assertEqual(report.code, exits.SIGNATURE_UNVERIFIED)
        self.assertIn("MANIFEST.asc", report.lines()[0])

    def test_a_manifest_that_cannot_be_read_is_invalid(self):
        report = self.check(join(self.tmpdir, "nothing", "MANIFEST"),
                            (self.main_ring,))
        self.assertEqual(report.code, exits.MANIFEST_INVALID)

    def test_a_path_that_leaves_the_release_is_refused(self):
        manifest = self.write(
            "rel/MANIFEST",
            f"release x\n\n1 {'0' * 64} ../outside\n"
            f"1 {'0' * 64} /etc/passwd\n1 {'0' * 64} a b\n",
        )
        detach_sign(self.keys.home, manifest, self.main)
        report = self.check(manifest, (self.main_ring,))
        self.assertEqual(report.code, exits.MANIFEST_INVALID)
        self.assertIn("../outside: path leaves the release", report.lines())
        self.assertIn("/etc/passwd: path leaves the release",
                      report.lines())
        self.assertIn("line 5: not '<size> <sha256> <path>'",
                      report.lines())

    def test_a_file_that_cannot_be_read_is_a_mismatch(self):
        manifest = self.release(self.main)
        os.remove(join(self.tmpdir, "rel/images/t.tar.zst"))
        os.mkdir(join(self.tmpdir, "rel/images/t.tar.zst"))
        report = self.check(manifest, (self.main_ring,))
        self.assertEqual(report.code, exits.LAYER_MISMATCH)

    def test_a_size_mismatch_is_named(self):
        manifest = self.release(self.main)
        self.write("rel/images/t.tar.zst", "template, longer\n")
        report = self.check(manifest, (self.main_ring,))
        line = [x for x in report.lines() if x.startswith("images/t")][0]
        self.assertIn("size", line)
        self.assertIn("sha256", line)


class TestSignedHashFile(RoleTestCase):
    """keel verify checks a signed .hash file against main and images"""

    def setUp(self):
        super().setUp()
        self.root = join(self.tmpdir, "layers")
        self.fields = build_tree(self.root)
        self.hash = join(self.root, "lamp.tar.zst.hash")

    def signed_hash(self, digest: str, *fprs: str) -> None:
        text = hash_text("lamp", digest)
        write(self.hash, clearsign_many(self.keys.home, text, *fprs))

    def result(self, keyrings):
        report = verify_layers(self.root, keyrings=keyrings)
        return next(r for r in report.results if r.name == "lamp")

    def test_a_hash_file_both_keys_signed_is_ok_with_each_keyring(self):
        self.signed_hash(self.fields["lamp"]["sha256"], self.main,
                         self.images)
        for ring, fpr in ((self.main_ring, self.main),
                          (self.images_ring, self.images)):
            found = self.result((ring,))
            self.assertEqual(found.status, verify.STATUS_OK, found.line())
            self.assertEqual(found.code, exits.OK)
            self.assertEqual(found.details, (f"hash file signed by {fpr}",))

    def test_a_hash_file_by_an_unknown_key_is_unverified(self):
        self.signed_hash(self.fields["lamp"]["sha256"], self.images)
        found = self.result((self.main_ring,))
        self.assertEqual(found.status, verify.STATUS_UNVERIFIED)
        self.assertIn("no good signature", found.line())

    def test_a_changed_hash_file_is_a_mismatch(self):
        self.signed_hash(self.fields["lamp"]["sha256"], self.main)
        with open(self.hash, encoding="utf-8") as fob:
            text = fob.read()
        write(self.hash, text.replace("lamp.tar.zst", "lamb.tar.zst", 1))
        found = self.result((self.main_ring,))
        self.assertEqual(found.status, verify.STATUS_MISMATCH)
        self.assertIn("BADSIG", found.line())

    def test_the_digest_is_read_from_the_signed_text(self):
        """Text outside the signature cannot change the digest"""
        self.signed_hash("f" * 64, self.main)
        with open(self.hash, encoding="utf-8") as fob:
            text = fob.read()
        real = self.fields["lamp"]["sha256"]
        write(self.hash, f"{real}  lamp.tar.zst\n" + text)
        found = self.result((self.main_ring,))
        self.assertEqual(found.status, verify.STATUS_MISMATCH)
        self.assertIn(f"hash file sha256 {'f' * 64}", found.line())

    def test_without_keyrings_a_signature_is_still_only_reported(self):
        self.signed_hash(self.fields["lamp"]["sha256"], self.main)
        found = self.result(())
        self.assertEqual(found.details, (verify.SIGNATURE_PRESENT,))


class TestVerifyCommand(RoleTestCase):
    """The two checks through `keel verify`, as an operator runs them"""

    release = TestReleaseManifest.release

    def cli(self, *argv: str, env: dict | None = None):
        out, err = io.StringIO(), io.StringIO()
        old = dict(os.environ)
        os.environ.update(env or {})
        try:
            with contextlib.redirect_stdout(out), \
                    contextlib.redirect_stderr(err):
                code = main(["verify", *argv])
        finally:
            os.environ.clear()
            os.environ.update(old)
        return code, out.getvalue(), err.getvalue()

    def test_release_manifest_with_each_keyring_alone(self):
        manifest = self.release(self.main, self.images)
        for ring, fpr in ((self.main_ring, self.main),
                          (self.images_ring, self.images)):
            code, out, _ = self.cli("--release-manifest", manifest,
                                    "--keyring", ring)
            self.assertEqual(code, exits.OK, out)
            self.assertIn(f"signed by {fpr}", out.splitlines()[0])
            self.assertIn("pve/aplinfo.dat: ok", out.splitlines())

    def test_release_manifest_refused_is_exit_8(self):
        manifest = self.release(self.images)
        code, out, _ = self.cli("--release-manifest", manifest,
                                "--keyring", self.main_ring)
        self.assertEqual(code, exits.SIGNATURE_UNVERIFIED)
        self.assertIn("no good signature", out)

    def test_the_keyrings_come_from_the_environment_by_default(self):
        manifest = self.release(self.main, self.images)
        absent = join(self.tmpdir, "absent.gpg")
        code, out, _ = self.cli(
            "--release-manifest", manifest,
            env={"KEEL_IMAGE_KEYRINGS": f"{absent}:{self.images_ring}"},
        )
        self.assertEqual(code, exits.OK, out)
        self.assertIn(f"signed by {self.images}", out)

    def test_layers_with_a_signed_hash_file(self):
        root = join(self.tmpdir, "layers")
        fields = build_tree(root)
        text = hash_text("lamp", fields["lamp"]["sha256"])
        write(join(root, "lamp.tar.zst.hash"),
              clearsign_many(self.keys.home, text, self.main, self.images))
        code, out, _ = self.cli("--layers-dir", root,
                                "--keyring", self.images_ring)
        self.assertEqual(code, exits.NOT_IMPLEMENTED, out)
        self.assertIn(f"lamp: ok: hash file signed by {self.images}",
                      out.splitlines())


if __name__ == "__main__":
    unittest.main()
