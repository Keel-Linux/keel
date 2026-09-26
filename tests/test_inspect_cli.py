# Copyright (c) 2026 KeelLinux maintainers
"""keel inspect end to end: the reader, the collector, the CLI, the round trip

The fixture trees under tests/fixtures/inspect stand in for machines:
`turnkey` is a TurnKey like appliance with a static IPv6 address, `dhcp`
a container with DHCP on both families, `static` the interfaces file the
01ipconfig hook writes from IP_* and IP6_* keys, `missing` a tree with
almost nothing in it. The round trip tests inspect a tree, then run
`keel spec validate`, `keel spec render` and `keel diff` on the result.
"""

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from os.path import abspath, dirname, join
from unittest import mock

from helpers import spec

from keel import exits
from keel.cli import main
from keel.inspect import collect, constants, inspect_root
from keel.inspect.tree import NOT_PRESENT, PERMISSION_DENIED, Tree

FIXTURES = join(dirname(abspath(__file__)), "fixtures", "inspect")
TURNKEY = join(FIXTURES, "turnkey")
DHCP = join(FIXTURES, "dhcp")
STATIC = join(FIXTURES, "static")
MISSING = join(FIXTURES, "missing")


def run_cli(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def exports(rendered: str) -> dict[str, str]:
    found = {}
    for line in rendered.splitlines():
        key, _, value = line[len("export "):].partition("=")
        found[key] = value
    return found


class TestTree(unittest.TestCase):
    def setUp(self):
        self.tree = Tree(TURNKEY)

    def test_paths_are_joined_under_the_root(self):
        self.assertEqual(self.tree.read("etc/hostname").text, "blog\n")
        self.assertEqual(self.tree.path("etc/hostname"),
                         join(TURNKEY, "etc", "hostname"))

    def test_missing_and_unreadable_files_name_their_problem(self):
        self.assertEqual(self.tree.read("etc/nonsense").problem, NOT_PRESENT)
        directory = self.tree.read("etc")
        self.assertFalse(directory.readable)
        self.assertTrue(directory.problem.startswith("not readable: "))

    def test_permission_denied_is_reported_as_root_only(self):
        with mock.patch("builtins.open", side_effect=PermissionError):
            self.assertEqual(self.tree.read("etc/hostname").problem,
                             PERMISSION_DENIED)

    def test_glob_and_read_dir_return_regular_files_only(self):
        self.assertEqual(self.tree.glob("home/*/.ssh/authorized_keys"),
                         ["home/admin/.ssh/authorized_keys"])
        self.assertEqual(self.tree.read_dir("etc/network/interfaces.d"), [])
        sourced = Tree(DHCP).read_dir("etc/network/interfaces.d")
        self.assertEqual([f.path for f in sourced],
                         [join(DHCP, "etc/network/interfaces.d/eth0")])
        self.assertEqual([f.path for f in self.tree.read_dir("etc/cron-apt")],
                         [join(TURNKEY, "etc/cron-apt/config")])

    def test_readlink_answers_none_for_anything_but_a_symlink(self):
        self.assertEqual(Tree(DHCP).readlink("etc/localtime"),
                         "/usr/share/zoneinfo/Etc/UTC")
        self.assertIsNone(self.tree.readlink("etc/timezone"))
        self.assertIsNone(self.tree.readlink("etc/nonsense"))


class TestCollector(unittest.TestCase):
    @staticmethod
    def reason(result, field: str) -> str:
        return next(f.source for f in result.findings if f.field == field)

    def test_turnkey_tree_yields_a_complete_spec(self):
        result = inspect_root(TURNKEY, "/run/keel/secrets")
        self.assertTrue(result.complete)
        self.assertEqual(result.appliance, "wordpress 19.0 (trixie, amd64)")
        self.assertEqual(result.spec["instance"],
                         {"hostname": "blog", "fqdn": "blog.example.org"})
        eth0 = result.spec["network"]["interfaces"]["eth0"]
        self.assertEqual(eth0["ipv6"]["address"], "2001:db8:1::10/64")
        self.assertEqual(result.spec["network"]["nameservers"],
                         ["2001:db8:1::53", "2001:db8:1::54", "192.0.2.53"])
        self.assertEqual(result.spec["tls"]["acme"]["challenge"], "dns-01")
        self.assertEqual(list(result.spec["secrets"]),
                         ["root_password", "db_password"])
        self.assertEqual(
            result.spec["security"],
            {"alerts": "admin@example.org",
             "updates_at_first_boot": "force"},
        )
        self.assertEqual(list(result.spec["users"]), ["root", "admin"])
        self.assertEqual(result.spec["locale"]["timezone"], "Europe/Lisbon")

    def test_dhcp_container_tree_reads_the_conf_and_the_sourced_files(self):
        result = inspect_root(DHCP)
        self.assertEqual(result.missing_required, ("instance.fqdn",))
        network = result.spec["network"]
        self.assertEqual(network["managed_by"], "host")
        self.assertEqual(network["interfaces"],
                         {"eth0": {"ipv6": {"method": "dhcp"},
                                   "ipv4": {"method": "dhcp"}}})
        self.assertIn("holds a DHCPv6 lease", self.reason(
            result, "network.interfaces.eth0.ipv6"
        ))
        self.assertEqual(result.spec["app"]["options"],
                         {"ip_bind": "[2001:db8:2::10]"})
        self.assertEqual(result.spec["secrets"]["app_password"],
                         {"file": "/etc/keel/secrets/app_password"})
        self.assertEqual(result.spec["locale"], {"timezone": "Etc/UTC"})
        self.assertNotIn("users", result.spec)
        self.assertNotIn("never", str(result.spec))

    def test_missing_tree_still_yields_a_spec_with_placeholders(self):
        result = inspect_root(MISSING)
        self.assertEqual(result.missing_required, (
            "instance.hostname", "instance.fqdn", "network.interfaces",
            "security.alerts",
        ))
        self.assertEqual(result.appliance, "unknown appliance")
        self.assertEqual(result.spec, {
            "version": 1,
            "tls": {"acme": {"enabled": False}},
            "secrets": {"root_password": {
                "file": "/etc/keel/secrets/root_password"}},
            "security": {"updates_at_first_boot": "skip"},
            "hub": {"api_key": "skip"},
        })

    def test_hostname_f_runs_only_on_the_live_root(self):
        with mock.patch.object(collect.subprocess, "run") as run:
            offline = collect.hostname_f(Tree(TURNKEY))
        run.assert_not_called()
        self.assertEqual(offline.problem, collect.OFFLINE)

        completed = subprocess.CompletedProcess(
            [], 0, "blog.example.org\n", ""
        )
        with mock.patch.object(collect.subprocess, "run",
                               return_value=completed) as run:
            live = collect.hostname_f(Tree("/"))
        self.assertEqual(live.text, "blog.example.org\n")
        self.assertEqual(run.call_args.args[0], ["hostname", "-f"])

    def test_the_ipv6_evidence_is_the_command_and_the_lease_files(self):
        tree = Tree(DHCP)
        self.assertEqual([file.path for file in collect.leases(tree)],
                         [join(DHCP, "var/lib/dhcpcd/eth0.lease6")])
        self.assertEqual(collect.leases(Tree(TURNKEY)), ())
        offline = collect.run_command(tree, constants.IP_ADDR_COMMAND)
        self.assertEqual(offline.path, "ip -6 addr show")
        self.assertEqual(offline.problem, collect.OFFLINE)

        completed = subprocess.CompletedProcess([], 0, "1: lo: <UP>\n", "")
        with mock.patch.object(collect.subprocess, "run",
                               return_value=completed) as run:
            live = collect.run_command(Tree("/"), constants.IP_ADDR_COMMAND)
        self.assertEqual(live.text, "1: lo: <UP>\n")
        self.assertEqual(run.call_args.args[0],
                         ["ip", "-6", "addr", "show"])

    def test_hostname_f_failures_are_recorded_not_raised(self):
        failed = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(collect.subprocess, "run",
                               return_value=failed):
            self.assertEqual(collect.hostname_f(Tree("/")).problem, "exited 1")
        with mock.patch.object(collect.subprocess, "run",
                               side_effect=FileNotFoundError(2, "No such")):
            self.assertEqual(collect.hostname_f(Tree("/")).problem,
                             "failed: No such")


class TestInspectCommand(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_complete_spec_exits_ok_with_the_report_on_stderr(self):
        code, out, err = run_cli("inspect", "--root", TURNKEY)
        self.assertEqual(code, exits.OK)
        self.assertTrue(out.startswith("# Written by keel inspect from"))
        self.assertIn("hostname: blog\n", out)
        self.assertIn("instance.hostname: blog (from", err)
        self.assertIn("secrets.root_password: file:"
                      " /etc/keel/secrets/root_password (not extracted", err)
        self.assertIn("spec complete\n", err)

    def test_missing_required_fields_exit_incomplete_after_writing(self):
        output = join(self.tmpdir, "instance.yaml")
        report = join(self.tmpdir, "report.txt")
        code, out, err = run_cli(
            "inspect", "--root", MISSING, "--output", output,
            "--report", report, "--non-interactive",
        )
        self.assertEqual(code, exits.INSPECT_INCOMPLETE)
        self.assertEqual(out, "")
        self.assertEqual(
            err,
            "Error: inspect: required fields not inferred: instance.hostname,"
            " instance.fqdn, network.interfaces, security.alerts\n",
        )
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
        with open(output) as fob:
            self.assertIn("root_password", fob.read())
        with open(report) as fob:
            self.assertIn("spec incomplete", fob.read())

    def test_unwritable_output_exits_conf_error(self):
        output = join(self.tmpdir, "absent", "instance.yaml")
        code, _, err = run_cli("inspect", "--root", TURNKEY, "--output",
                               output)
        self.assertEqual(code, exits.CONF_ERROR)
        self.assertIn("Error: inspect:", err)

    def test_unwritable_report_exits_conf_error(self):
        report = join(self.tmpdir, "absent", "report.txt")
        code, _, _ = run_cli("inspect", "--root", TURNKEY, "--report", report)
        self.assertEqual(code, exits.CONF_ERROR)

    def test_secrets_dir_moves_the_placeholders(self):
        code, out, _ = run_cli("inspect", "--root", DHCP, "--secrets-dir",
                               "/run/keel/secrets")
        self.assertEqual(code, exits.INSPECT_INCOMPLETE)
        self.assertIn("file: /run/keel/secrets/root_password", out)


class TestRoundTrip(unittest.TestCase):
    """inspect, then validate and render what it wrote, as an operator would"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.secrets = join(self.tmpdir, "secrets")
        os.mkdir(self.secrets)
        for name in ("root_password", "db_password"):
            path = join(self.secrets, name)
            with open(path, "w") as fob:
                fob.write("provided-by-the-operator\n")
            os.chmod(path, 0o600)
        self.output = join(self.tmpdir, "instance.yaml")

    def test_inspected_turnkey_tree_validates_and_renders(self):
        code, _, _ = run_cli(
            "inspect", "--root", TURNKEY, "--output", self.output,
            "--secrets-dir", self.secrets,
        )
        self.assertEqual(code, exits.OK)

        code, out, err = run_cli("spec", "validate", "--spec", self.output)
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertEqual(out, f"{self.output}: ok (secret files checked)\n")

        code, out, _ = run_cli("spec", "render", "--spec", self.output)
        self.assertEqual(code, exits.OK)
        env = exports(out)
        self.assertEqual(env["HOSTNAME"], "blog")
        self.assertEqual(env["FQDN"], "blog.example.org")
        self.assertEqual(env["APP_DOMAIN"], "blog.example.org")
        self.assertEqual(env["SEC_UPDATES"], "FORCE")
        self.assertEqual(env["SEC_ALERTS"], "admin@example.org")
        self.assertEqual(env["HUB_APIKEY"], "SKIP")
        self.assertEqual(env["ROOT_PASS"], spec.MASK)
        self.assertNotIn("provided-by-the-operator", out)

        # The file owns the addresses now that the hook writes static IPv6.
        # The hook configures one interface and the last block of each
        # family wins: eth1 brings inet static and inet6 auto, so the conf
        # carries eth1's IPv4 address and IP6_CONFIG=dhcp, no IP6_ADDRESS.
        document = spec.load(self.output)
        self.assertEqual(document["network"]["managed_by"], "file")
        self.assertEqual(
            document["network"]["interfaces"]["eth0"]["ipv6"]["address"],
            "2001:db8:1::10/64",
        )
        self.assertEqual(env["IP_CONFIG"], "static")
        self.assertEqual(env["IP_ADDRESS"], "192.0.2.10")
        self.assertEqual(env["IP_DNS1"], "192.0.2.53")
        self.assertEqual(env["IP6_CONFIG"], "dhcp")
        self.assertEqual(env["IP6_DNS1"], "2001:db8:1::53")
        self.assertEqual(env["IP6_DNS2"], "2001:db8:1::54")
        self.assertNotIn("IP6_ADDRESS", env)

    def test_static_stanzas_the_hook_wrote_render_the_keys_behind_them(self):
        """inspect, render and diff agree on a file 01ipconfig produced"""
        code, _, _ = run_cli(
            "inspect", "--root", STATIC, "--output", self.output,
            "--secrets-dir", self.secrets,
        )
        self.assertEqual(code, exits.OK)

        code, out, _ = run_cli("spec", "render", "--spec", self.output)
        self.assertEqual(code, exits.OK)
        ip_keys = [line for line in out.splitlines()
                   if line.startswith("export IP")]
        self.assertEqual(ip_keys, [
            "export IP_CONFIG=static",
            "export IP_ADDRESS=192.0.2.10",
            "export IP_NETMASK=255.255.255.0",
            "export IP_GW=192.0.2.1",
            "export IP_DNS1=192.0.2.53",
            "export IP6_CONFIG=static",
            "export IP6_ADDRESS=2001:db8:1::10/64",
            "export IP6_GW=fe80::1",
            "export IP6_DNS1=2001:db8:1::53",
            "export IP6_DNS2=2001:db8:2::53",
        ])

        code, out, err = run_cli("diff", "--spec", self.output, "--root",
                                 STATIC)
        self.assertEqual((code, err), (exits.OK, ""))
        self.assertIn("network.managed_by: same (file)\n", out)
        self.assertIn("network.interfaces.eth0.ipv6.address: same"
                      " (2001:db8:1::10/64)\n", out)
        self.assertIn("network.interfaces.eth0.ipv4.address: same"
                      " (192.0.2.10/24)\n", out)
        self.assertIn(" 0 drift, 0 unknown, 0 not declared,", out)

    def test_inspected_container_tree_validates_once_the_fqdn_is_added(self):
        code, _, _ = run_cli(
            "inspect", "--root", DHCP, "--output", self.output,
            "--secrets-dir", self.secrets,
        )
        self.assertEqual(code, exits.INSPECT_INCOMPLETE)
        document = spec.load(self.output)
        document["instance"]["fqdn"] = "core.example.org"
        document["secrets"].pop("app_password")
        self.assertEqual(spec.validate(document), [])


if __name__ == "__main__":
    unittest.main()
