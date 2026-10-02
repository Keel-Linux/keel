# Copyright (c) 2026 KeelLinux maintainers
"""The cloud section (handbook decision 0046) and `keel cloud`

keel validates the section and never compares it; Keel Cloud's node
agent reads it. `keel cloud` hands its arguments to that agent.
"""

import argparse
import contextlib
import io
import os
import tempfile
import unittest
from os.path import join

from helpers import errors

from keel import commands, exits
from keel.cli import build_parser
from keel.diff import NOT_COMPARED, compare
from keel.inspect.report import Inspection

KEY_FILE = "/etc/keel/secrets/cloud_api_key"
SECRET_FILE = "/etc/keel/secrets/cloud_entry_secret"
JOINED = (
    "version: 1\n"
    "cloud:\n"
    "  endpoint: https://cloud.example.org:8443\n"
    f"  api_key:\n    file: {KEY_FILE}\n"
    f"  entry_secret:\n    file: {SECRET_FILE}\n"
    "  set: shop\n"
    "  ca_file: /etc/keel/cloud-ca.pem\n"
)


def structural(text: str) -> list[str]:
    return errors(text, check_secret_files=False)


def only(found: list[str], fragment: str) -> None:
    matching = [error for error in found if fragment in error]
    if len(matching) != 1 or len(found) != 1:
        raise AssertionError(f"expected one error with {fragment!r}: {found}")


class TestCloudSection(unittest.TestCase):
    def test_a_joined_node_is_valid(self):
        self.assertEqual(structural(JOINED), [])

    def test_skip_alone_is_a_standalone_node(self):
        self.assertEqual(structural("version: 1\ncloud:\n  api_key: skip\n"),
                         [])
        self.assertEqual(structural("version: 1\ncloud:\n  api_key: SKIP\n"),
                         [])

    def test_an_empty_section_is_accepted(self):
        self.assertEqual(structural("version: 1\ncloud: {}\n"), [])

    def test_the_section_is_a_mapping(self):
        only(structural("version: 1\ncloud: yes\n"), "cloud: must be a"
             " mapping")

    def test_unknown_keys_are_named(self):
        only(structural(JOINED + "  colour: blue\n"),
             "cloud.colour: unknown key")

    def test_the_api_key_is_skip_or_a_reference(self):
        only(structural("version: 1\ncloud:\n  set: shop\n"),
             "cloud.api_key: must be 'skip' or a secret mapping")
        only(structural("version: 1\ncloud:\n  api_key: kc1e_x\n"),
             "cloud.api_key: must be 'skip'")

    def test_secrets_are_file_references_never_generated(self):
        text = JOINED.replace(f"file: {SECRET_FILE}", "generate: true")
        only(structural(text), "cloud.entry_secret: a file reference only")
        text = JOINED.replace(f"file: {KEY_FILE}", "vault: kv/x")
        found = structural(text)
        self.assertTrue(any("cloud.api_key.vault" in e for e in found),
                        found)

    def test_a_joined_node_names_its_set(self):
        text = JOINED.replace("  set: shop\n", "")
        only(structural(text), "cloud.set: required")
        only(structural(JOINED.replace("set: shop", "set: Shop_1")),
             "cloud.set: a lower case DNS label")
        only(structural(JOINED.replace("set: shop", 'set: "shop\\n"')),
             "cloud.set: a lower case DNS label")

    def test_the_endpoint_is_https_with_no_path(self):
        for endpoint in ("http://cloud.example.org", "https://", "ftp://x",
                         "https://cloud.example.org/v1",
                         "https://u:p@cloud.example.org",
                         "https://cloud.example.org:99999", "5"):
            text = JOINED.replace("https://cloud.example.org:8443", endpoint)
            only(structural(text), "cloud.endpoint: an https:// URL")
        text = JOINED.replace("  endpoint: https://cloud.example.org:8443\n",
                              "")
        self.assertEqual(structural(text), [])
        text = JOINED.replace("https://cloud.example.org:8443",
                              "https://[2001:db8::1]:8443/")
        self.assertEqual(structural(text), [])

    def test_the_ca_file_is_an_absolute_path(self):
        only(structural(JOINED.replace("/etc/keel/cloud-ca.pem", "ca.pem")),
             "cloud.ca_file: an absolute path")

    def test_secret_files_are_checked_like_every_secret(self):
        found = errors(JOINED)
        self.assertEqual(len(found), 2, found)
        directory = tempfile.mkdtemp()
        paths = []
        for name in ("key", "secret"):
            path = join(directory, name)
            with open(path, "w") as stream:
                stream.write("value\n")
            os.chmod(path, 0o600)
            paths.append(path)
        text = JOINED.replace(KEY_FILE, paths[0]).replace(SECRET_FILE,
                                                          paths[1])
        self.assertEqual(errors(text), [])

    def test_diff_never_compares_it(self):
        declared = {"version": 1, "cloud": {"api_key": "skip"}}
        result = compare(declared, Inspection("/", "core", {}, ()))
        fields = [(f.field, f.status) for f in result.fields]
        self.assertEqual(fields, [("cloud", NOT_COMPARED)])
        self.assertIn("node agent", result.fields[0].reason)


class TestCloudCommand(unittest.TestCase):
    def test_every_argument_goes_to_the_agent(self):
        args = build_parser().parse_args(["cloud", "sync", "--wait", "5",
                                          "--help"])
        calls = []
        code = commands.cloud(args, execvp=lambda *a: calls.append(a))
        self.assertEqual(code, exits.OK)
        self.assertEqual(calls, [("keel-cloud-node", [
            "keel-cloud-node", "sync", "--wait", "5", "--help"])])

    def test_without_the_package_it_says_which_to_install(self):
        def missing(*_):
            raise FileNotFoundError
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = commands.cloud(argparse.Namespace(arguments=[]),
                                  execvp=missing)
        self.assertEqual(code, exits.NOT_IMPLEMENTED)
        self.assertIn("keel-overlay-cloud", err.getvalue())


if __name__ == "__main__":
    unittest.main()
