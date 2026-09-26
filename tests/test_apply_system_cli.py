# Copyright (c) 2026 KeelLinux maintainers
"""keel spec apply --system end to end, and the round trip through inspect

useradd and usermod are replaced at the subprocess boundary by a fake
that edits the scratch tree's passwd and group files the way the real
commands would under --root, so the suite needs no root. Everything else
(directories, keys files, modes, the timezone files, the locale file) is
written for real under a temporary root and read back by keel inspect.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from argparse import Namespace
from os.path import abspath, dirname, join
from unittest import mock

import yaml

from helpers import spec

from keel import commands, exits
from keel.cli import main
from keel.system import effects

FIXTURES = join(dirname(abspath(__file__)), "fixtures", "inspect")
TURNKEY = join(FIXTURES, "turnkey")
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterialOnly admin@blog"
AS_ROOT = mock.patch("os.geteuid", return_value=0)
AS_USER = mock.patch("os.geteuid", return_value=1000)

SPEC = (
    "version: 1\n"
    "instance:\n"
    "  hostname: blog\n"
    "  fqdn: blog.example.org\n"
    "users:\n"
    "  root:\n"
    "    authorized_keys:\n"
    f"      - {KEY}\n"
    "  admin:\n"
    "    shell: /bin/bash\n"
    "    groups: [sudo]\n"
    "    authorized_keys:\n"
    f"      - {KEY}\n"
    "locale:\n"
    "  timezone: Europe/Lisbon\n"
    "  lang: en_US.UTF-8\n"
)


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def fake_shadow_tools(argv, **kwargs):
    """useradd and usermod under --root, as far as passwd and group go"""
    if argv[0] not in ("useradd", "usermod"):
        return subprocess.CompletedProcess(argv, 1, "", "not here\n")
    options = dict(zip(argv, argv[1:]))
    root = options["--root"]
    name = argv[-1]
    if argv[0] == "useradd":
        home = "/root" if name == "root" else f"/home/{name}"
        with open(join(root, "etc", "passwd"), "a") as fob:
            shell = options.get("--shell", "/bin/sh")
            fob.write(f"{name}:x:{os.getuid()}:{os.getgid()}::{home}:{shell}\n")
        os.makedirs(join(root, home.strip("/")), exist_ok=True)
    for group in options.get("--groups", "").split(","):
        if group:
            with open(join(root, "etc", "group"), "a") as fob:
                fob.write(f"{group}:x:27:{name}\n")
    return subprocess.CompletedProcess(argv, 0, "", "")


class ApplySystemTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.conf = join(self.tmpdir, "inithooks.conf")
        self.root = join(self.tmpdir, "scratch")
        os.makedirs(join(self.root, "etc"))
        for name in ("passwd", "group"):
            with open(join(self.root, "etc", name), "w") as fob:
                fob.write("")
        self.spec = join(self.tmpdir, "instance.yaml")
        self.write_spec(SPEC)

    def write_spec(self, text: str) -> None:
        with open(self.spec, "w") as fob:
            fob.write(text)

    def apply(self, *extra: str) -> tuple[int, str, str]:
        with mock.patch.object(effects.subprocess, "run",
                               side_effect=fake_shadow_tools):
            return run_cli("spec", "apply", "--spec", self.spec, "--conf",
                           self.conf, "--system", "--root", self.root, *extra)

    def read(self, relative: str) -> str:
        with open(join(self.root, relative)) as fob:
            return fob.read()


class TestApplySystem(ApplySystemTestCase):
    def test_converges_a_scratch_tree_then_changes_nothing_on_rerun(self):
        code, out, err = self.apply()
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertIn(f"{self.spec} applied to {self.conf}", out)
        self.assertIn("users.admin: create user admin (useradd --root", out)
        self.assertIn("--shell /bin/bash --groups sudo admin): done", out)
        self.assertIn("apply --system: 10 change(s), 0 failed", out)
        self.assertNotIn("Warning: users", err)
        self.assertNotIn("Warning: instance.fqdn", err)
        self.assertEqual(self.read("etc/hosts"),
                         "127.0.1.1 blog.example.org blog\n")
        self.assertEqual(self.read("home/admin/.ssh/authorized_keys"),
                         f"{KEY}\n")
        keys = join(self.root, "home", "admin", ".ssh", "authorized_keys")
        self.assertEqual(os.stat(keys).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(dirname(keys)).st_mode & 0o777, 0o700)
        self.assertEqual(self.read("etc/timezone"), "Europe/Lisbon\n")
        self.assertEqual(os.readlink(join(self.root, "etc", "localtime")),
                         "/usr/share/zoneinfo/Europe/Lisbon")
        self.assertEqual(self.read("etc/default/locale"),
                         "LANG=en_US.UTF-8\n")

        code, out, _ = self.apply()
        self.assertEqual(code, exits.OK)
        self.assertIn("apply --system: 0 change(s), 0 failed", out)
        for line in out.splitlines()[2:-1]:
            self.assertIn("unchanged", line, line)

    def test_an_existing_user_is_never_recreated_and_keys_are_replaced(self):
        with open(join(self.root, "etc", "passwd"), "w") as fob:
            fob.write(f"admin:x:{os.getuid()}:{os.getgid()}::/srv/admin:/bin/sh\n")
        os.makedirs(join(self.root, "srv", "admin", ".ssh"))
        with open(join(self.root, "srv", "admin", ".ssh", "authorized_keys"),
                  "w") as fob:
            fob.write("ssh-rsa AAAAOld old@key\n")

        code, out, _ = self.apply()

        self.assertEqual(code, exits.OK)
        self.assertIn("users.admin: change shell from /bin/sh to /bin/bash"
                      " (usermod --root", out)
        self.assertIn("users.admin: add to groups sudo (usermod --root", out)
        self.assertNotIn("create user admin", out)
        self.assertEqual(self.read("srv/admin/.ssh/authorized_keys"),
                         f"{KEY}\n")

    def test_dry_run_prints_the_plan_and_writes_nothing(self):
        os.remove(join(self.root, "etc", "passwd"))
        code, out, err = self.apply("--dry-run")
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertEqual(out.splitlines()[0],
                         f"dry run: {self.conf} not written")
        self.assertIn("users.admin: would create user admin", out)
        self.assertIn("locale.timezone: would write /etc/timezone", out)
        self.assertIn("dry run: 10 change(s) planned, nothing written",
                      out)
        self.assertFalse(os.path.exists(self.conf))
        self.assertEqual(sorted(os.listdir(self.root)), ["etc"])
        self.assertEqual(os.listdir(join(self.root, "etc")), ["group"])

    def test_dry_run_needs_no_secret_files(self):
        self.write_spec(SPEC + "secrets:\n  root_password:\n"
                        f"    file: {join(self.tmpdir, 'absent')}\n")
        code, out, _ = self.apply("--dry-run")
        self.assertEqual(code, exits.OK)
        self.assertIn("nothing written", out)
        code, _, err = self.apply()
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIn("secret file not found", err)

    def test_a_failed_command_fails_its_field_and_the_exit_code(self):
        def failing(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, "", "useradd: no\n")

        with mock.patch.object(effects.subprocess, "run", side_effect=failing):
            code, out, _ = run_cli(
                "spec", "apply", "--spec", self.spec, "--conf", self.conf,
                "--system", "--root", self.root,
            )
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("users.admin: create user admin (useradd --root", out)
        self.assertIn("): failed: useradd exited 1: useradd: no", out)
        self.assertIn("users.admin.authorized_keys: ensure /home/admin/.ssh"
                      " (mode 0700, owner admin): failed: owner not set", out)
        self.assertIn("users.admin.authorized_keys: skipped: write", out)
        self.assertIn("locale.timezone: write /etc/timezone (mode 0644): done",
                      out)
        self.assertIn("apply --system: 4 change(s), 4 failed", out)
        self.assertTrue(os.path.exists(self.conf))

    def test_a_populated_conf_is_kept_and_the_system_still_converges(self):
        with open(self.conf, "w") as fob:
            fob.write("export ROOT_PASS=preseeded\n")
        code, out, err = self.apply()
        self.assertEqual(code, exits.OK)
        self.assertIn(f"Warning: {self.conf} is not empty, ignoring", err)
        self.assertIn("apply --system: 10 change(s), 0 failed", out)
        with open(self.conf) as fob:
            self.assertEqual(fob.read(), "export ROOT_PASS=preseeded\n")

    def test_the_live_system_refuses_a_user_before_writing_anything(self):
        with AS_USER:
            code, out, err = run_cli("spec", "apply", "--spec", self.spec,
                                     "--conf", self.conf, "--system")
        self.assertEqual(code, exits.APPLY_NEEDS_ROOT)
        self.assertIn("must run as root", err)
        self.assertIn("uid 1000", err)
        self.assertEqual(out, "")
        self.assertFalse(os.path.exists(self.conf))

    def test_the_live_system_as_root_runs_the_plan(self):
        """Root is stood in; observe and effects are replaced, / is untouched"""
        fake_state = mock.MagicMock()
        fake_plan = mock.MagicMock()
        outcome = mock.MagicMock(lines=("users.root: unchanged (x)",),
                                 failed=0)
        outcome.summary.return_value = "apply --system: 0 change(s), 0 failed"
        with AS_ROOT, \
                mock.patch.object(commands.system, "observe",
                                  return_value=fake_state) as observe, \
                mock.patch.object(commands.system, "plan",
                                  return_value=fake_plan), \
                mock.patch.object(commands.system, "execute",
                                  return_value=outcome) as execute:
            code, out, _ = run_cli("spec", "apply", "--spec", self.spec,
                                   "--conf", self.conf, "--system")
        self.assertEqual(code, exits.OK)
        self.assertEqual(observe.call_args.args[0], "/")
        self.assertEqual(execute.call_args.args[2], False)
        self.assertIn("users.root: unchanged (x)\napply --system", out)

    def test_dry_run_on_the_live_system_needs_no_root(self):
        with AS_USER:
            code, out, _ = run_cli("spec", "apply", "--spec", self.spec,
                                   "--conf", self.conf, "--system",
                                   "--dry-run")
        self.assertEqual(code, exits.OK)
        self.assertIn("nothing written", out)
        self.assertFalse(os.path.exists(self.conf))

    def test_dry_run_requires_system(self):
        with self.assertRaises(SystemExit) as raised:
            run_cli("spec", "apply", "--spec", self.spec, "--dry-run")
        self.assertEqual(raised.exception.code, exits.USAGE)

    def test_without_system_the_conf_is_written_and_the_sections_warned(self):
        code, out, err = run_cli("spec", "apply", "--spec", self.spec,
                                 "--conf", self.conf)
        self.assertEqual(code, exits.OK)
        self.assertNotIn("apply --system", out)
        self.assertIn("Warning: instance.fqdn: the /etc/hosts entry is"
                      " written by the system phase (--system,"
                      " --system-only) only", err)
        self.assertIn("Warning: users: accounts and authorized keys are"
                      " written by the system phase", err)
        self.assertIn("Warning: locale:", err)
        self.assertEqual(sorted(os.listdir(self.root)), ["etc"])

    def test_a_namespace_without_the_options_gets_the_conf_only(self):
        """confconsole builds a Namespace by hand, as the README shows"""
        args = Namespace(spec=self.spec, conf=self.conf, non_interactive=True)
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(commands.spec_apply(args), exits.OK)
        self.assertTrue(os.path.exists(self.conf))


class TestSystemOnly(ApplySystemTestCase):
    """--system-only: the system phase alone, with no conf phase at all

    The first boot runs the conf phase at hook 00 and the system phase at
    hook 10, so the second run must not repeat the first: resolving the
    secrets again would regenerate a `generate: true` password after the
    earlier hooks had already applied the first value.
    """

    def only(self, *extra: str) -> tuple[int, str, str]:
        with mock.patch.object(effects.subprocess, "run",
                               side_effect=fake_shadow_tools):
            return run_cli("spec", "apply", "--spec", self.spec, "--conf",
                           self.conf, "--system-only", "--root", self.root,
                           *extra)

    def test_converges_the_system_and_never_writes_the_conf(self):
        code, out, err = self.only()
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertEqual(out.splitlines()[0],
                         f"apply --system-only: {self.conf}"
                         " not read or written")
        self.assertNotIn(f"applied to {self.conf}", out)
        self.assertIn("apply --system-only: 10 change(s), 0 failed", out)
        self.assertEqual(self.read("etc/hosts"),
                         "127.0.1.1 blog.example.org blog\n")
        self.assertFalse(os.path.exists(self.conf))

    def test_a_populated_conf_is_left_exactly_as_it_was(self):
        with open(self.conf, "w") as fob:
            fob.write("export ROOT_PASS=set-by-the-conf-phase\n")
        code, out, err = self.only()
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertIn("not read or written", out)
        with open(self.conf) as fob:
            self.assertEqual(fob.read(),
                             "export ROOT_PASS=set-by-the-conf-phase\n")

    def test_no_secret_is_resolved_so_a_generated_password_survives(self):
        self.write_spec(SPEC + "first_login_wizard: true\n"
                        "secrets:\n  root_password:\n"
                        "    generate: true\n")
        with mock.patch.object(commands.spec, "resolve_secrets") as resolve:
            code, out, _ = self.only()
        self.assertEqual(code, exits.OK)
        resolve.assert_not_called()
        self.assertIn("apply --system-only: 10 change(s), 0 failed", out)

    def test_a_secret_file_that_does_not_exist_is_not_an_error(self):
        self.write_spec(SPEC + "secrets:\n  root_password:\n"
                        f"    file: {join(self.tmpdir, 'absent')}\n")
        code, out, err = self.only()
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertIn("apply --system-only: 10 change(s), 0 failed", out)

    def test_a_spec_declaring_nothing_this_phase_converges_is_a_no_op(self):
        self.write_spec("version: 1\ninstance:\n  hostname: blog\n")
        code, out, err = self.only()
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertIn("apply --system-only: nothing declared that this"
                      " phase converges", out)
        self.assertNotIn("change(s)", out)
        self.assertEqual(sorted(os.listdir(join(self.root, "etc"))),
                         ["group", "passwd"])

    def test_a_failed_action_names_the_flag_in_the_summary(self):
        def failing(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, "", "useradd: no\n")

        with mock.patch.object(effects.subprocess, "run", side_effect=failing):
            code, out, _ = run_cli(
                "spec", "apply", "--spec", self.spec, "--conf", self.conf,
                "--system-only", "--root", self.root,
            )
        self.assertEqual(code, exits.APPLY_FAILED)
        self.assertIn("apply --system-only: 4 change(s), 4 failed", out)
        self.assertFalse(os.path.exists(self.conf))

    def test_dry_run_prints_the_plan_and_writes_nothing(self):
        code, out, err = self.only("--dry-run")
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertEqual(out.splitlines()[0],
                         f"apply --system-only: {self.conf}"
                         " not read or written")
        self.assertIn("instance.fqdn: would write /etc/hosts", out)
        self.assertIn("dry run: 10 change(s) planned, nothing written", out)
        self.assertEqual(sorted(os.listdir(join(self.root, "etc"))),
                         ["group", "passwd"])

    def test_the_live_system_refusal_names_the_flag_that_asked(self):
        with AS_USER:
            code, out, err = run_cli("spec", "apply", "--spec", self.spec,
                                     "--conf", self.conf, "--system-only")
        self.assertEqual(code, exits.APPLY_NEEDS_ROOT)
        self.assertIn("apply --system-only on the live system must run as"
                      " root", err)
        self.assertEqual(out, "")

    def test_dry_run_on_the_live_system_needs_no_root(self):
        with AS_USER:
            code, out, _ = run_cli("spec", "apply", "--spec", self.spec,
                                   "--conf", self.conf, "--system-only",
                                   "--dry-run")
        self.assertEqual(code, exits.OK)
        self.assertIn("nothing written", out)

    def test_both_phase_flags_at_once_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as raised:
            run_cli("spec", "apply", "--spec", self.spec, "--system",
                    "--system-only")
        self.assertEqual(raised.exception.code, exits.USAGE)

    def test_dry_run_alone_still_requires_a_phase_flag(self):
        with self.assertRaises(SystemExit) as raised:
            run_cli("spec", "apply", "--spec", self.spec, "--dry-run")
        self.assertEqual(raised.exception.code, exits.USAGE)

    def test_an_absent_spec_is_a_no_op_before_anything_else(self):
        os.remove(self.spec)
        code, out, err = self.only()
        self.assertEqual((code, out), (exits.OK, ""))
        self.assertIn("not found, nothing to do", err)


class TestBootThenDiff(ApplySystemTestCase):
    """The loop a first boot closes, on a tree in the state 09hostname leaves

    The hook at 10keel-system runs the system phase, so the operator who
    runs keel diff after a boot must find exit 0 without running anything
    by hand. The field is compared, not excused: before the phase it is
    unknown and the reason names what writes it, after it is same
    (docs/diff.md).
    """

    def setUp(self):
        super().setUp()
        self.machine = join(self.tmpdir, "machine")
        shutil.copytree(TURNKEY, self.machine)
        with open(join(self.machine, "etc", "hosts"), "w") as fob:
            fob.write("::1 localhost ip6-localhost\n127.0.1.1 blog\n")

    def declare(self) -> None:
        """The spec inspect writes, less the sections this test is not about

        users and locale have their own tests (TestRoundTrip). Writing
        another account's authorized_keys into the fixture's home
        directories would need root, and this test is about the one field
        the boot settles.
        """
        code, _, _ = run_cli("inspect", "--root", TURNKEY, "--output",
                             self.spec)
        self.assertEqual(code, exits.OK)
        document = spec.load(self.spec)
        for section in ("users", "locale"):
            document.pop(section)
        with open(self.spec, "w") as fob:
            yaml.safe_dump(document, fob, sort_keys=False)

    def diff(self) -> tuple[int, dict]:
        code, out, _ = run_cli("diff", "--spec", self.spec, "--root",
                               self.machine, "--format", "json")
        return code, json.loads(out)

    def field(self, report: dict, name: str) -> dict:
        return next(f for f in report["fields"] if f["field"] == name)

    def test_unknown_with_the_remedy_before_the_phase_and_same_after(self):
        self.declare()

        code, report = self.diff()
        self.assertEqual(code, exits.INSPECT_INCOMPLETE)
        fqdn = self.field(report, "instance.fqdn")
        self.assertEqual(fqdn["status"], "unknown")
        self.assertIn("has no fully qualified name for blog", fqdn["reason"])
        self.assertIn("the system phase of apply writes it"
                      " (spec apply --system-only)", fqdn["reason"])

        code, out, err = run_cli("spec", "apply", "--spec", self.spec,
                                 "--conf", self.conf, "--system-only",
                                 "--root", self.machine)
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertIn("apply --system-only: 1 change(s), 0 failed", out)
        with open(join(self.machine, "etc", "hosts")) as fob:
            self.assertEqual(fob.read(), "::1 localhost ip6-localhost\n"
                             "2001:db8:1::10 blog.example.org blog\n")
        self.assertEqual(run_cli("spec", "apply", "--spec", self.spec,
                                 "--conf", self.conf, "--system-only",
                                 "--root", self.machine)[0], exits.OK)

        code, report = self.diff()
        self.assertEqual(code, exits.OK, report["fields"])
        self.assertEqual(self.field(report, "instance.fqdn")["status"], "same")
        self.assertEqual(report["counts"]["unknown"], 0)
        self.assertEqual(report["counts"]["drift"], 0)

    def test_an_entry_a_short_name_line_shadows_is_unknown_and_converged(self):
        """The file a resolver does not answer from is not a converged file

        127.0.1.1 blog before the entry makes hostname -f answer blog, so
        diff must not call the field same: the file gives the host no
        fully qualified name, and the phase drops the line.
        """
        self.declare()
        with open(join(self.machine, "etc", "hosts"), "w") as fob:
            fob.write("127.0.0.1 localhost\n127.0.1.1 blog\n"
                      "2001:db8:1::10 blog.example.org blog\n")

        code, report = self.diff()
        self.assertEqual(code, exits.INSPECT_INCOMPLETE)
        self.assertEqual(self.field(report, "instance.fqdn")["status"],
                         "unknown")

        code, out, _ = run_cli("spec", "apply", "--spec", self.spec, "--conf",
                               self.conf, "--system-only", "--root",
                               self.machine)
        self.assertEqual(code, exits.OK)
        self.assertIn("apply --system-only: 1 change(s), 0 failed", out)
        with open(join(self.machine, "etc", "hosts")) as fob:
            self.assertEqual(fob.read(), "127.0.0.1 localhost\n"
                             "2001:db8:1::10 blog.example.org blog\n")

        code, report = self.diff()
        self.assertEqual(code, exits.OK)
        self.assertEqual(self.field(report, "instance.fqdn")["status"], "same")

    def test_the_field_is_compared_and_not_in_the_not_compared_table(self):
        """Editing the file behind the spec is drift, not an excused field"""
        self.declare()
        with open(join(self.machine, "etc", "hosts"), "w") as fob:
            fob.write("127.0.1.1 blog.elsewhere.example blog\n")

        code, report = self.diff()

        self.assertEqual(code, exits.DRIFT_FOUND)
        fqdn = self.field(report, "instance.fqdn")
        self.assertEqual(fqdn["status"], "drift")
        self.assertEqual(fqdn["declared"], "blog.example.org")
        self.assertEqual(fqdn["observed"], "blog.elsewhere.example")


class TestRoundTrip(ApplySystemTestCase):
    """inspect a tree, apply --system into a fresh tree, inspect, diff"""

    def setUp(self):
        super().setUp()
        self.secrets = join(self.tmpdir, "secrets")
        os.mkdir(self.secrets)
        for name in ("root_password", "db_password"):
            path = join(self.secrets, name)
            with open(path, "w") as fob:
                fob.write("provided-by-the-operator\n")
            os.chmod(path, 0o600)

    def test_users_locale_and_the_fqdn_show_no_drift_after_apply(self):
        code, _, _ = run_cli("inspect", "--root", TURNKEY, "--output",
                             self.spec, "--secrets-dir", self.secrets)
        self.assertEqual(code, exits.OK)
        declared = spec.load(self.spec)
        self.assertEqual(declared["users"]["admin"]["groups"], ["adm", "sudo"])
        with open(join(self.root, "etc", "hostname"), "w") as fob:
            fob.write("blog\n")

        code, out, _ = self.apply()
        self.assertEqual(code, exits.OK, out)
        self.assertIn("apply --system: 10 change(s), 0 failed", out)
        self.assertEqual(self.read("etc/hosts"),
                         "2001:db8:1::10 blog.example.org blog\n")

        code, out, _ = run_cli("diff", "--spec", self.spec, "--root",
                               self.root, "--format", "json")
        fields = {
            field["field"]: field["status"]
            for field in json.loads(out)["fields"]
            if field["field"].split(".")[0] in ("users", "locale", "instance")
        }
        self.assertEqual(set(fields.values()), {"same"}, fields)
        self.assertEqual(sorted(fields), [
            "instance.fqdn", "instance.hostname",
            "locale.lang", "locale.timezone", "users.admin.authorized_keys",
            "users.admin.groups", "users.admin.shell",
            "users.root.authorized_keys", "users.root.shell",
        ])

        code, out, _ = self.apply()
        self.assertEqual(code, exits.OK)
        self.assertIn("apply --system: 0 change(s), 0 failed", out)


if __name__ == "__main__":
    unittest.main()
