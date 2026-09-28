# Copyright (c) 2026 KeelLinux maintainers
"""The channel options of keel pull, and what keel inspect says about one"""

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from os.path import exists, join

from channel_helpers import build_mirror, channel_body, keys, tools_missing
from layers_helpers import write

from keel import exits
from keel.cli import main
from keel.layers import channel as channels
from keel.layers.constants import KEYRING_ENV, STATE_ENV

MISSING = tools_missing()


@unittest.skipIf(MISSING, f"{MISSING} is not installed")
class ChannelCLITestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.source = join(self.tmpdir, "source")
        self.cache = join(self.tmpdir, "cache")
        self.root = join(self.tmpdir, "root")
        self.state = join(self.root, "var", "lib", "keel", "channel")
        self.spec = join(self.tmpdir, "absent.yaml")
        self.mirror = build_mirror(self.source)
        os.makedirs(self.root)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def pull(self, *extra: str) -> tuple[int, str, str]:
        return self.run_cli(
            "pull", "lamp", "--source", self.source,
            "--cache-dir", self.cache, "--channel", "stable",
            "--channel-keyring", keys().keyring,
            "--channel-state", self.state, *extra,
        )


class TestPullByChannel(ChannelCLITestCase):
    def test_the_pointer_it_followed_is_printed_before_the_layers(self):
        code, out, _ = self.pull()
        self.assertEqual(code, exits.OK)
        lines = out.splitlines()
        self.assertIn("channel stable: release 2026-09-28/1", lines[0])
        self.assertIn("core: fetched", lines[1])

    def test_an_expired_pointer_exits_channel_expired(self):
        from datetime import timedelta
        signed = channels.now() - timedelta(days=30)
        build_mirror(
            self.source, signed_at=signed,
            expires_at=signed + timedelta(days=7),
        )
        code, _, err = self.pull()
        self.assertEqual(code, exits.CHANNEL_EXPIRED)
        self.assertIn("Error:", err)

    def test_a_pointer_signed_by_the_wrong_key_exits_channel_unverified(self):
        write(
            join(self.source, "stable"),
            keys().clearsign(
                channel_body(digests=self.mirror["digests"]), keys().other
            ),
        )
        code, _, err = self.pull()
        self.assertEqual(code, exits.CHANNEL_UNVERIFIED)
        self.assertIn("Error:", err)

    def test_the_keyring_may_come_from_the_environment(self):
        with mock_env({KEYRING_ENV: keys().keyring, STATE_ENV: self.state}):
            code, out, _ = self.run_cli(
                "pull", "lamp", "--source", self.source,
                "--cache-dir", self.cache, "--channel", "stable",
            )
        self.assertEqual(code, exits.OK)
        self.assertIn("channel stable", out)

    def test_a_channel_that_is_not_one_of_the_two_exits_usage(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_cli(
                "pull", "lamp", "--source", self.source,
                "--cache-dir", self.cache, "--channel", "nightly",
            )
        self.assertEqual(raised.exception.code, exits.USAGE)

    def test_a_release_without_a_revision_exits_usage(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_cli(
                "pull", "lamp", "--source", self.source,
                "--cache-dir", self.cache, "--release", "2026-09-28",
            )
        self.assertEqual(raised.exception.code, exits.USAGE)

    def test_a_release_that_is_not_a_date_exits_usage(self):
        with self.assertRaises(SystemExit) as raised:
            self.run_cli(
                "pull", "lamp", "--source", self.source,
                "--cache-dir", self.cache, "--release", "latest",
                "--rev", "1",
            )
        self.assertEqual(raised.exception.code, exits.USAGE)

    def test_a_revision_named_by_hand_needs_no_keyring(self):
        code, out, _ = self.run_cli(
            "pull", "lamp", "--source", self.source,
            "--cache-dir", self.cache, "--release", "2026-09-28", "--rev", "1",
        )
        self.assertEqual(code, exits.OK)
        self.assertIn("named on the command line", out)

    def test_allow_rollback_is_accepted_and_moves_the_state_back(self):
        build_mirror(self.source, release="2026-09-29", rev=1)
        self.pull()
        build_mirror(self.source, release="2026-09-28", rev=1)
        code, _, _ = self.pull("--allow-rollback")
        self.assertEqual(code, exits.OK)
        self.assertEqual(
            channels.read_state(self.state).describe(), "stable 2026-09-28/1"
        )

    def test_a_pointer_that_goes_backwards_exits_channel_rollback(self):
        build_mirror(self.source, release="2026-09-29", rev=1)
        self.pull()
        build_mirror(self.source, release="2026-09-28", rev=1)
        code, _, err = self.pull()
        self.assertEqual(code, exits.CHANNEL_ROLLBACK)
        self.assertIn("--allow-rollback", err)

    def test_a_pull_with_no_channel_at_all_is_the_flat_layout(self):
        code, out, _ = self.run_cli(
            "pull", "lamp", "--source", self.source, "--cache-dir", self.cache,
        )
        self.assertEqual(code, exits.OK)
        self.assertNotIn("channel", out)
        self.assertFalse(exists(self.state))


class TestInspectChannel(ChannelCLITestCase):
    def inspect(self, *extra: str) -> tuple[int, str, str]:
        """An inspect of a bare root, which is always INSPECT_INCOMPLETE

        The root here holds nothing but the channel record, so the spec
        can never be complete; what these tests read is the channel
        lines and the codes the channel check sets over that one.
        """
        return self.run_cli(
            "inspect", "--root", self.root, "--spec", self.spec,
            "--channel-keyring", keys().keyring, *extra,
        )

    def test_an_instance_that_follows_no_channel_says_nothing_about_one(self):
        _, _, err = self.inspect()
        self.assertNotIn("layers.channel", err)

    def test_the_channel_and_the_revision_are_reported(self):
        self.pull()
        _, _, err = self.inspect()
        self.assertIn("layers.channel: stable", err)
        self.assertIn("layers.revision: 2026-09-28/1", err)

    def test_a_state_that_does_not_parse_is_reported_as_not_inferred(self):
        os.makedirs(os.path.dirname(self.state))
        write(self.state, "channel stable\n")
        code, _, err = self.inspect()
        self.assertIn("layers.channel: not inferred", err)
        self.assertNotEqual(code, exits.CHANNEL_INVALID)

    def test_check_channel_says_the_instance_is_up_to_date(self):
        self.pull()
        code, _, err = self.inspect("--check-channel")
        self.assertEqual(code, exits.INSPECT_INCOMPLETE)
        self.assertIn("layers.available: up to date", err)

    def test_check_channel_says_how_far_behind_the_instance_is(self):
        self.pull()
        build_mirror(self.source, release="2026-09-29", rev=2)
        code, _, err = self.inspect("--check-channel")
        self.assertEqual(code, exits.INSPECT_INCOMPLETE)
        self.assertIn(
            "stable is at 2026-09-29/2, this instance is on 2026-09-28/1",
            err,
        )

    def test_check_channel_on_an_expired_pointer_wins_over_incomplete(self):
        from datetime import timedelta
        self.pull()
        signed = channels.now() - timedelta(days=30)
        build_mirror(
            self.source, release="2026-09-29", rev=2, signed_at=signed,
            expires_at=signed + timedelta(days=7),
        )
        code, _, err = self.inspect("--check-channel")
        self.assertEqual(code, exits.CHANNEL_EXPIRED)
        self.assertIn("holding this instance back", err)

    def test_check_channel_with_no_state_says_so_and_checks_nothing(self):
        code, _, err = self.inspect("--check-channel")
        self.assertEqual(code, exits.INSPECT_INCOMPLETE)
        self.assertIn("follows no channel", err)

    def test_check_channel_needs_the_keyring_it_is_given(self):
        self.pull()
        code, _, err = self.inspect(
            "--check-channel", "--channel-keyring",
            join(self.tmpdir, "absent.gpg"),
        )
        self.assertEqual(code, exits.CHANNEL_UNVERIFIED)
        self.assertIn("absent.gpg", err)


@contextlib.contextmanager
def mock_env(values: dict):
    before = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in before.items():
            if value is None:
                del os.environ[key]
            else:
                os.environ[key] = value
