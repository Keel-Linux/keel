# Copyright (c) 2026 KeelLinux maintainers
"""A root tree holding the manifests of the format, for the manifest tests

tests/fixtures/manifest/ holds the overlay and appliance manifests of
docs/manifest-v1.md in the handbook, "Worked example: Keel Core" and
"Worked example: Keel Web", byte for byte. build_root() lays them out
where a machine has them, /usr/share/keel/{overlays,appliances}/, under
a temporary root, with the unit files and first boot hooks they name, so
the checks a machine gets (rules 5 and 12) have something to find. The
hooks are made here with mode 0755 rather than committed, because the
mode a checkout gives a file depends on the umask; the owner check is
pointed at the user running the tests, since nothing here runs as root.
"""

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from os.path import abspath, dirname, join
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel.cli import main  # noqa: E402

FIXTURES = join(dirname(abspath(__file__)), "fixtures", "manifest")
UNIT_DIR = "usr/lib/systemd/system"
HOOK_DIR = "usr/lib/inithooks/firstboot.d"
UNITS = (
    "ssh", "webmin", "shellinabox", "postfix", "etcd", "crowdsec",
    "crowdsec-firewall-bouncer", "nginx", "anubis",
)
HOOKS = ("00declarative", "10keel-system", "75keel-role", "80keel-cloud")
KINDS = ("overlays", "appliances")


def fixture(kind: str, name: str) -> str:
    """The text of one manifest of the format"""
    with open(join(FIXTURES, kind, f"{name}.yaml")) as fob:
        return fob.read()


def manifest_path(root: str, kind: str, name: str) -> str:
    return join(root, "usr", "share", "keel", kind, f"{name}.yaml")


def put(root: str, kind: str, name: str, text: str) -> str:
    """Install one manifest under the root, replacing any there"""
    path = manifest_path(root, kind, name)
    os.makedirs(dirname(path), exist_ok=True)
    with open(path, "w") as fob:
        fob.write(text)
    return path


def unit(root: str, name: str) -> None:
    path = join(root, UNIT_DIR, f"{name}.service")
    os.makedirs(dirname(path), exist_ok=True)
    with open(path, "w") as fob:
        fob.write("[Service]\nExecStart=/bin/true\n")


def hook(root: str, name: str, mode: int = 0o755) -> str:
    path = join(root, HOOK_DIR, name)
    os.makedirs(dirname(path), exist_ok=True)
    with open(path, "w") as fob:
        fob.write("#!/bin/sh\n")
    os.chmod(path, mode)
    return path


def build_root(parent: str) -> str:
    """A root with every manifest of the format, its units and its hooks"""
    root = join(parent, "root")
    for kind in KINDS:
        for entry in sorted(os.listdir(join(FIXTURES, kind))):
            put(root, kind, entry[:-len(".yaml")],
                fixture(kind, entry[:-len(".yaml")]))
    for name in UNITS:
        unit(root, name)
    for name in HOOKS:
        hook(root, name)
    return root


def app_fixture(kind: str, name: str) -> str:
    """The text of the application fixtures, which are not the format's"""
    with open(join(FIXTURES, "app", kind, f"{name}.yaml")) as fob:
        return fob.read()


def install_app(root: str) -> None:
    """Add the blog application and its mariadb overlay to a root"""
    put(root, "overlays", "mariadb", app_fixture("overlays", "mariadb"))
    put(root, "appliances", "blog", app_fixture("appliances", "blog"))
    for name in ("mariadb", "blog", "blog-cron", "blog-mailer"):
        unit(root, name)
    hook(root, "40blog")


def overlay(name: str, body: str = "") -> str:
    """A minimal overlay manifest with BODY appended"""
    return (f"manifest_version: 1\nkind: overlay\nname: {name}\n"
            f"title: {name}\nsummary: A test overlay\n{body}")


def appliance(name: str, base: str, body: str = "") -> str:
    """A minimal appliance manifest with BODY appended"""
    return (f"manifest_version: 1\nkind: appliance\nname: {name}\n"
            f"title: {name}\nsummary: A test appliance\nbase: {base}\n{body}")


class ManifestCase(unittest.TestCase):
    """A fresh root per test, and the CLI run in process against it"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir)
        self.root = build_root(self.tmpdir)
        patcher = mock.patch("keel.manifest.machine.ROOT_UID", os.getuid())
        patcher.start()
        self.addCleanup(patcher.stop)

    def path(self, kind: str, name: str) -> str:
        return manifest_path(self.root, kind, name)

    def put(self, kind: str, name: str, text: str) -> str:
        return put(self.root, kind, name, text)

    def edit(self, kind: str, name: str, *pairs: str) -> str:
        """Install a fixture with each OLD, NEW pair of text replaced

        Always from the fixture, so a second edit of the same file undoes
        the first: a test that needs two changes passes both pairs.
        """
        text = fixture(kind, name)
        for old, new in zip(pairs[::2], pairs[1::2]):
            self.assertIn(old, text)
            text = text.replace(old, new)
        return self.put(kind, name, text)

    def cli(self, *argv: str, root: str = "") -> tuple[int, str, str]:
        """Run keel in process with --root; (code, stdout, stderr)"""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv) + ["--root", root or self.root])
        return code, out.getvalue(), err.getvalue()

    def refused(self, target: str, *messages: str) -> str:
        """validate TARGET exits 3 and prints every message on stderr"""
        code, _, err = self.cli("manifest", "validate", target)
        self.assertEqual(code, 3, err)
        for message in messages:
            self.assertIn(message, err)
        return err
