# Copyright (c) 2026 KeelLinux maintainers
"""The channel pointer: parsing, expiry, ordering and the state record"""

import os
import shutil
import tempfile
import unittest
from datetime import timedelta
from os.path import join

from channel_helpers import channel_body, now, stamp

from keel.layers import channel as channels
from keel.layers.errors import ChannelError


class TestParse(unittest.TestCase):
    def parsed(self, **fields):
        return channels.from_text("stable", channel_body(**fields))

    def test_reads_the_five_fields_a_pointer_must_carry(self):
        signed = now()
        found = self.parsed(signed_at=signed)
        self.assertEqual(found.name, "stable")
        self.assertEqual(found.release, "2026-09-28")
        self.assertEqual(found.rev, 1)
        self.assertEqual(found.signed_at, signed)
        self.assertEqual(found.expires_at, signed + timedelta(days=7))
        self.assertEqual(found.layers, {"core": "a" * 64})

    def test_layer_lines_name_the_manifest_digest_of_each_layer(self):
        found = self.parsed(digests={"core": "a" * 64, "lamp": "b" * 64})
        self.assertEqual(found.layers, {"core": "a" * 64, "lamp": "b" * 64})

    def test_describe_names_the_channel_the_release_and_the_revision(self):
        self.assertEqual(self.parsed().describe(), "stable 2026-09-28/1")

    def test_revision_orders_by_release_then_by_number(self):
        self.assertLess(
            self.parsed(release="2026-09-28", rev=9).revision,
            self.parsed(release="2026-09-29", rev=1).revision,
        )
        self.assertLess(
            self.parsed(rev=2).revision, self.parsed(rev=10).revision
        )

    def test_an_unknown_key_is_kept_and_never_a_problem(self):
        found = self.parsed(extra="future_field whatever it says\n")
        self.assertEqual(found.fields["future_field"], "whatever it says")

    def test_a_missing_field_names_every_one_that_is_missing(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", "channel stable\nrev 1\n")
        self.assertIn(
            "missing keys: release, signed_at, expires_at",
            raised.exception.errors,
        )

    def test_a_line_with_no_value_is_a_problem_that_names_the_line(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", channel_body() + "release\n")
        self.assertIn(
            "line 7: release: missing value", raised.exception.errors
        )

    def test_a_repeated_field_is_a_problem(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", channel_body() + "rev 2\n")
        self.assertIn("line 7: rev: repeated key", raised.exception.errors)

    def test_an_invalid_key_is_a_problem(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", channel_body() + "Rev 2\n")
        self.assertIn("line 7: invalid key 'Rev'", raised.exception.errors)

    def test_a_channel_naming_another_channel_is_refused(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", channel_body(name="testing"))
        self.assertEqual(
            raised.exception.errors,
            ["channel: names 'testing', fetched as 'stable'"],
        )

    def test_a_channel_name_that_is_not_a_channel_is_refused(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("nightly", channel_body(name="nightly"))
        self.assertIn(
            "channel: 'nightly' is not one of stable, testing",
            raised.exception.errors,
        )

    def test_a_release_that_is_not_a_date_is_refused(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", channel_body(release="latest"))
        self.assertIn(
            "release: must be YYYY-MM-DD, got 'latest'",
            raised.exception.errors,
        )

    def test_a_revision_that_is_not_a_positive_number_is_refused(self):
        for value in ("0", "-1", "one", "01"):
            with self.subTest(rev=value):
                with self.assertRaises(ChannelError) as raised:
                    channels.from_text("stable", channel_body(rev=value))
                self.assertIn(
                    f"rev: must be a whole number above zero, got {value!r}",
                    raised.exception.errors,
                )

    def test_a_timestamp_that_is_not_utc_iso_is_refused(self):
        body = channel_body().replace(
            stamp(now()), "Mon Sep 28 04:00:00 2026", 1
        )
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", body)
        self.assertTrue(
            any("signed_at:" in p for p in raised.exception.errors),
            raised.exception.errors,
        )

    def test_an_expiry_before_the_signature_is_refused(self):
        signed = now()
        with self.assertRaises(ChannelError) as raised:
            channels.from_text(
                "stable",
                channel_body(signed_at=signed, expires_at=signed),
            )
        self.assertIn(
            "expires_at: must be after signed_at", raised.exception.errors
        )

    def test_a_layer_line_needs_a_name_and_a_sha256(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", channel_body() + "layer core\n")
        self.assertIn(
            "layer: needs a layer name and a sha256, got 'core'",
            raised.exception.errors,
        )

    def test_a_layer_line_with_a_digest_that_is_not_a_sha256_is_refused(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text(
                "stable", channel_body(digests={}) + "layer core beef\n"
            )
        self.assertIn(
            "layer core: sha256 must be 64 lowercase hex digits",
            raised.exception.errors,
        )

    def test_the_same_layer_twice_is_refused(self):
        body = channel_body()
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", body + f"layer core {'b' * 64}\n")
        self.assertIn("layer core: named twice", raised.exception.errors)

    def test_every_problem_is_reported_not_only_the_first(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text(
                "stable", channel_body(release="latest", rev="0")
            )
        self.assertEqual(len(raised.exception.errors), 2)

    def test_a_pointer_that_names_no_layer_is_refused(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text("stable", channel_body(digests={}))
        self.assertIn(
            "layer: the pointer must name at least one layer",
            raised.exception.errors,
        )


class TestExpiry(unittest.TestCase):
    """An expired pointer is an error, so the question is never fuzzy"""

    def channel(self, expires_in: timedelta):
        signed = now() - timedelta(days=1)
        return channels.from_text(
            "stable",
            channel_body(signed_at=signed, expires_at=now() + expires_in),
        )

    def test_a_pointer_inside_its_expiry_is_fresh(self):
        found = self.channel(timedelta(days=6))
        self.assertFalse(found.expired(now()))
        self.assertIsNone(found.staleness(now()))

    def test_a_pointer_past_its_expiry_is_expired(self):
        found = self.channel(timedelta(seconds=-1))
        self.assertTrue(found.expired(now()))

    def test_the_moment_of_expiry_is_already_expired(self):
        signed = now() - timedelta(days=7)
        found = channels.from_text(
            "stable", channel_body(signed_at=signed, expires_at=now())
        )
        self.assertTrue(found.expired(now()))

    def test_staleness_says_how_long_ago_and_when_it_was_signed(self):
        found = self.channel(timedelta(hours=-2))
        self.assertEqual(
            found.staleness(now()),
            f"stable expired at {stamp(found.expires_at)}, signed at"
            f" {stamp(found.signed_at)}: the mirror is not being updated,"
            " or is holding this instance back",
        )


class TestState(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = join(self.tmpdir, "var", "lib", "keel", "channel")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def channel(self, **fields):
        return channels.from_text(
            fields.pop("fetched_as", "stable"), channel_body(**fields)
        )

    def test_no_file_is_no_state_and_not_an_error(self):
        self.assertIsNone(channels.read_state(self.path))

    def test_what_was_written_reads_back(self):
        channels.record(self.path, self.channel(), "https://m/layers")
        found = channels.read_state(self.path)
        self.assertEqual(found.channel, "stable")
        self.assertEqual(found.release, "2026-09-28")
        self.assertEqual(found.rev, 1)
        self.assertEqual(found.source, "https://m/layers")
        self.assertEqual(found.describe(), "stable 2026-09-28/1")

    def test_the_state_records_when_it_was_written(self):
        channels.record(self.path, self.channel(), "https://m/layers")
        self.assertEqual(len(channels.read_state(self.path).pulled_at), 20)

    def test_the_directory_is_made_when_it_is_not_there(self):
        channels.record(self.path, self.channel(), "d")
        self.assertTrue(os.path.exists(self.path))

    def test_a_state_that_cannot_be_written_raises_oserror(self):
        blocked = join(self.tmpdir, "blocked")
        with open(blocked, "w"):
            pass
        with self.assertRaises(OSError):
            channels.record(
                join(blocked, "channel"), self.channel(), "d"
            )

    def test_an_unreadable_state_is_a_channel_error(self):
        os.makedirs(self.path)
        with self.assertRaises(ChannelError):
            channels.read_state(self.path)

    def test_a_state_missing_a_field_is_a_channel_error(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as fob:
            fob.write("channel stable\n")
        with self.assertRaises(ChannelError) as raised:
            channels.read_state(self.path)
        self.assertIn(
            "missing keys: release, rev, source", raised.exception.errors
        )

    def test_a_state_revision_orders_against_a_channel_revision(self):
        channels.record(self.path, self.channel(rev=2), "d")
        state = channels.read_state(self.path)
        self.assertTrue(channels.is_rollback(state, self.channel(rev=1)))
        self.assertFalse(channels.is_rollback(state, self.channel(rev=2)))
        self.assertFalse(channels.is_rollback(state, self.channel(rev=3)))

    def test_a_different_channel_is_never_a_rollback(self):
        channels.record(self.path, self.channel(rev=2), "d")
        state = channels.read_state(self.path)
        other = self.channel(name="testing", fetched_as="testing", rev=1)
        self.assertFalse(channels.is_rollback(state, other))

    def test_no_state_at_all_is_never_a_rollback(self):
        self.assertFalse(channels.is_rollback(None, self.channel()))

    def test_behind_says_what_the_channel_holds_that_this_one_does_not(self):
        channels.record(self.path, self.channel(rev=1), "d")
        state = channels.read_state(self.path)
        self.assertEqual(
            channels.behind(state, self.channel(rev=3)),
            "stable is at 2026-09-28/3, this instance is on 2026-09-28/1",
        )
        self.assertIsNone(channels.behind(state, self.channel(rev=1)))
        self.assertEqual(
            channels.behind(state, self.channel(rev=1, release="2026-10-01")),
            "stable is at 2026-10-01/1, this instance is on 2026-09-28/1",
        )


class TestCorners(unittest.TestCase):
    """The paths a well formed mirror never takes, and a broken one does"""

    def test_a_blank_line_in_a_pointer_is_ignored(self):
        found = channels.from_text("stable", "\n" + channel_body())
        self.assertEqual(found.rev, 1)

    def test_a_layer_line_with_an_invalid_layer_name_is_refused(self):
        with self.assertRaises(ChannelError) as raised:
            channels.from_text(
                "stable", channel_body() + f"layer Core {'b' * 64}\n"
            )
        self.assertIn(
            "layer: invalid layer name 'Core'", raised.exception.errors
        )

    def test_a_state_written_without_a_directory_lands_in_the_cwd(self):
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir)
        cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            channels.write_state("channel", "stable", "2026-09-28", 1, "d")
        finally:
            os.chdir(cwd)
        self.assertEqual(
            channels.read_state(join(tmpdir, "channel")).rev, 1
        )

    def test_a_state_whose_revision_is_not_a_number_is_a_channel_error(self):
        with self.assertRaises(ChannelError) as raised:
            channels.state_from_text(
                "channel",
                "channel stable\nrelease 2026-09-28\nrev x\nsource d\n",
            )
        self.assertIn(
            "rev: must be a whole number, got 'x'", raised.exception.errors
        )

    def test_an_instance_ahead_of_the_channel_is_not_behind_it(self):
        state = channels.State("p", "stable", "2026-09-29", 1, "d")
        older = channels.from_text("stable", channel_body(rev=1))
        self.assertIsNone(channels.behind(state, older))

    def pointer(self):
        return channels.from_text("stable", channel_body())

    def test_an_instance_on_another_channel_is_not_behind_this_one(self):
        state = channels.State("p", "testing", "2026-09-01", 1, "d")
        self.assertIsNone(
            channels.behind(state, self.pointer())
        )
        self.assertIsNone(
            channels.behind(None, self.pointer())
        )
