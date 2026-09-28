# Copyright (c) 2026 KeelLinux maintainers
"""Pulling by channel and by release revision, and every way it is refused

The happy path here is one test. The rest are the cases a mirror that is
stale, broken or hostile produces, because a pointer nobody attacks is a
pointer nobody needs.
"""

import os
import shutil
import tempfile
import unittest
from datetime import timedelta
from os.path import exists, join

from channel_helpers import (
    build_mirror,
    channel_body,
    keys,
    manifest_digest,
    now,
    tools_missing,
    write_channel,
)
from layers_helpers import Server, write

from keel import exits
from keel.layers import channel as channels
from keel.layers import layout
from keel.layers.errors import LayerError
from keel.layers.pull import Resolution, pull

MISSING = tools_missing()


@unittest.skipIf(MISSING, f"{MISSING} is not installed")
class ChannelPullTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.source = join(self.tmpdir, "source")
        self.cache = join(self.tmpdir, "cache")
        self.state = join(self.tmpdir, "var", "lib", "keel", "channel")
        self.mirror = build_mirror(self.source)
        self.fields = self.mirror["fields"]
        self.digests = self.mirror["digests"]

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def resolution(self, **changes) -> Resolution:
        options = {
            "channel": "stable",
            "keyring": keys().keyring,
            "state": self.state,
        }
        options.update(changes)
        return Resolution(**options)

    def pull(self, layer="lamp", source=None, **changes):
        return pull(
            layer, source or self.source, self.cache,
            self.resolution(**changes),
        )

    def failing(self, layer="lamp", source=None, **changes) -> LayerError:
        with self.assertRaises(LayerError) as raised:
            self.pull(layer, source, **changes)
        return raised.exception

    def rewrite_channel(self, fpr=None, **fields):
        fields.setdefault("digests", self.digests)
        body = channel_body(**fields)
        write_channel(self.source, "stable", body, fpr)
        return body

    def cached(self, name, suffix=".tar.zst") -> str:
        return join(
            self.cache, f"{name}-{self.fields[name]['sha256']}{suffix}"
        )


class TestByChannel(ChannelPullTestCase):
    def test_a_channel_resolves_to_the_release_the_blobs_and_the_cache(self):
        report = self.pull()
        self.assertEqual([r.name for r in report.results], ["core", "lamp"])
        for name in ("core", "lamp"):
            self.assertTrue(exists(self.cached(name)))
            self.assertTrue(exists(self.cached(name, ".manifest")))
        self.assertEqual(report.channel.describe(), "stable 2026-09-28/1")

    def test_the_report_says_which_pointer_it_followed_and_until_when(self):
        report = self.pull()
        line = report.resolution_line()
        self.assertIn("channel stable", line)
        self.assertIn("release 2026-09-28/1", line)
        self.assertIn("expires ", line)

    def test_the_blob_is_fetched_from_the_content_addressed_path(self):
        os.remove(join(self.source, self.fields["core"]["tarball"]))
        os.remove(join(self.source, self.fields["lamp"]["tarball"]))
        self.pull()
        self.assertTrue(exists(self.cached("core")))

    def test_a_flat_mirror_still_serves_a_pull_that_names_no_channel(self):
        report = pull("lamp", self.source, self.cache)
        self.assertEqual([r.name for r in report.results], ["core", "lamp"])
        self.assertIsNone(report.channel)

    def test_a_flat_pull_says_it_read_no_pointer(self):
        """A pull that verified nothing must not look like one that did"""
        report = pull("lamp", self.source, self.cache)
        self.assertIn("flat layout", report.resolution_line())
        self.assertIn("nothing here is signed for", report.resolution_line())

    def test_one_blob_serves_two_releases_and_is_fetched_once(self):
        """The second pull names the *other* release, or it proves nothing"""
        build_mirror(self.source, release="2026-09-29", rev=1)
        first = self.pull()
        second = pull(
            "lamp", self.source, self.cache,
            self.resolution(release="2026-09-28", rev=1, channel=None),
        )
        self.assertEqual([r.status for r in first.results],
                         ["fetched", "fetched"])
        self.assertEqual([r.status for r in second.results],
                         ["cached", "cached"])
        blobs = os.listdir(join(self.source, layout.BLOB_DIR))
        self.assertEqual(len(blobs), 2)

    def test_the_state_records_the_channel_and_the_revision(self):
        self.pull()
        state = channels.read_state(self.state)
        self.assertEqual(state.describe(), "stable 2026-09-28/1")
        self.assertEqual(state.source, self.source)

    def test_a_second_pull_of_the_same_revision_is_not_a_rollback(self):
        self.pull()
        report = self.pull()
        self.assertEqual([r.status for r in report.results],
                         ["cached", "cached"])

    def test_a_newer_revision_moves_the_state_forward(self):
        self.pull()
        build_mirror(self.source, release="2026-09-29", rev=2)
        self.pull()
        self.assertEqual(
            channels.read_state(self.state).describe(), "stable 2026-09-29/2"
        )

    def test_no_state_path_pulls_and_records_nothing(self):
        report = self.pull(state=None)
        self.assertEqual(len(report.results), 2)
        self.assertFalse(exists(self.state))

    def test_a_state_that_cannot_be_written_is_a_conf_error(self):
        blocked = join(self.tmpdir, "blocked")
        write(blocked, "")
        problem = self.failing(state=join(blocked, "channel"))
        self.assertEqual(problem.code, exits.CONF_ERROR)


@unittest.skipIf(MISSING, f"{MISSING} is not installed")
class TestOverIPv6(ChannelPullTestCase):
    def test_a_channel_resolves_over_http(self):
        server = Server(self.source)
        self.addCleanup(server.close)
        report = self.pull(source=server.url + "")
        self.assertEqual([r.name for r in report.results], ["core", "lamp"])
        self.assertEqual(report.channel.describe(), "stable 2026-09-28/1")

    def test_a_mirror_without_the_channel_is_unavailable(self):
        server = Server(self.source)
        self.addCleanup(server.close)
        os.remove(join(self.source, "stable"))
        problem = self.failing(source=server.url)
        self.assertEqual(problem.code, exits.LAYER_UNAVAILABLE)
        self.assertIn("stable", str(problem))


class TestExpiredChannel(ChannelPullTestCase):
    def test_an_expired_pointer_is_an_error_and_nothing_is_fetched(self):
        signed = now() - timedelta(days=30)
        self.rewrite_channel(
            signed_at=signed, expires_at=signed + timedelta(days=7)
        )
        problem = self.failing()
        self.assertEqual(problem.code, exits.CHANNEL_EXPIRED)
        self.assertIn("holding this instance back", str(problem))
        self.assertFalse(exists(self.cached("core")))

    def test_an_expired_pointer_does_not_move_the_state(self):
        self.pull()
        signed = now() - timedelta(days=30)
        build_mirror(
            self.source, release="2026-09-29", rev=2,
            signed_at=signed, expires_at=signed + timedelta(days=7),
        )
        self.failing()
        self.assertEqual(
            channels.read_state(self.state).describe(), "stable 2026-09-28/1"
        )

    def test_an_expired_pointer_is_never_only_a_warning(self):
        signed = now() - timedelta(days=30)
        self.rewrite_channel(
            signed_at=signed, expires_at=signed + timedelta(days=7)
        )
        with self.assertRaises(LayerError):
            self.pull()


class TestWrongKey(ChannelPullTestCase):
    def test_a_pointer_signed_by_another_key_is_unverified(self):
        self.rewrite_channel(fpr=keys().other)
        problem = self.failing()
        self.assertEqual(problem.code, exits.CHANNEL_UNVERIFIED)
        self.assertFalse(exists(self.cached("core")))

    def test_a_key_in_the_keyring_that_may_not_move_a_channel_is_refused(self):
        self.rewrite_channel(fpr=keys().other)
        problem = self.failing(
            keyring=keys().both, signers=(keys().channel,)
        )
        self.assertEqual(problem.code, exits.CHANNEL_UNVERIFIED)
        self.assertIn("not the key that may move a channel", str(problem))

    def test_a_pointer_changed_after_signing_is_unverified(self):
        path = join(self.source, "stable")
        with open(path, encoding="utf-8") as fob:
            text = fob.read()
        write(path, text.replace("rev 1", "rev 2"))
        self.assertEqual(self.failing().code, exits.CHANNEL_UNVERIFIED)

    def test_an_unsigned_pointer_is_unverified(self):
        write(join(self.source, "stable"), channel_body(digests=self.digests))
        self.assertEqual(self.failing().code, exits.CHANNEL_UNVERIFIED)

    def test_no_keyring_at_all_refuses_rather_than_trusting_the_mirror(self):
        problem = self.failing(keyring=None)
        self.assertEqual(problem.code, exits.CHANNEL_UNVERIFIED)
        self.assertIn("no keyring", str(problem))

    def test_a_pointer_signed_by_a_revoked_key_is_unverified(self):
        """Revocation is the one answer to the theft of the online key

        gpgv exits 0 for a revoked key and prints VALIDSIG, so this has to
        be proven end to end and not only at the status-line level.
        """
        body = channel_body(digests=self.digests)
        write(join(self.source, "stable"), keys().sign_revoked(body))
        problem = self.failing(keyring=keys().keyring_revoked)
        self.assertEqual(problem.code, exits.CHANNEL_UNVERIFIED)
        self.assertIn("revoked or expired", str(problem))
        self.assertFalse(exists(self.cached("core")))

    def test_a_revoked_key_is_refused_even_when_pinned_as_the_signer(self):
        body = channel_body(digests=self.digests)
        write(join(self.source, "stable"), keys().sign_revoked(body))
        problem = self.failing(
            keyring=keys().keyring_revoked, signers=(keys().revoked,)
        )
        self.assertEqual(problem.code, exits.CHANNEL_UNVERIFIED)

    def test_a_pointer_signed_by_an_expired_key_is_unverified(self):
        write(join(self.source, "stable"), keys().expired_signature)
        problem = self.failing(keyring=keys().keyring_expired)
        self.assertEqual(problem.code, exits.CHANNEL_UNVERIFIED)
        self.assertIn("revoked or expired", str(problem))

    def test_a_pointer_that_does_not_parse_is_a_channel_error(self):
        write_channel(self.source, "stable", "channel stable\n")
        problem = self.failing()
        self.assertEqual(problem.code, exits.CHANNEL_INVALID)

    def test_a_pointer_for_another_channel_is_a_channel_error(self):
        self.rewrite_channel(name="testing")
        problem = self.failing()
        self.assertEqual(problem.code, exits.CHANNEL_INVALID)
        self.assertIn("fetched as 'stable'", str(problem))


class TestDigestChain(ChannelPullTestCase):
    def manifest_path(self, name, release="2026-09-28", rev=1):
        return join(self.source, layout.manifest_path(release, rev, name))

    def test_a_manifest_the_pointer_does_not_name_is_a_mismatch(self):
        self.rewrite_channel(
            digests={"core": self.digests["core"]},
        )
        problem = self.failing()
        self.assertEqual(problem.code, exits.LAYER_MISMATCH)
        self.assertIn("the channel does not name", str(problem))

    def test_a_manifest_whose_bytes_changed_is_a_mismatch(self):
        path = self.manifest_path("core")
        with open(path, encoding="utf-8") as fob:
            text = fob.read()
        write(path, text + "\n")
        problem = self.failing()
        self.assertEqual(problem.code, exits.LAYER_MISMATCH)
        self.assertIn("the channel says", str(problem))

    def test_a_blob_that_is_not_what_the_manifest_records_is_a_mismatch(self):
        blob = join(
            self.source, layout.blob_path(self.fields["core"]["sha256"])
        )
        write(blob, b"not the layer")
        os.remove(join(self.source, self.fields["core"]["tarball"]))
        problem = self.failing()
        self.assertEqual(problem.code, exits.LAYER_MISMATCH)
        self.assertFalse(exists(self.cached("core")))

    def test_a_missing_blob_names_every_place_it_was_looked_for(self):
        os.remove(
            join(self.source, layout.blob_path(self.fields["core"]["sha256"]))
        )
        os.remove(join(self.source, self.fields["core"]["tarball"]))
        problem = self.failing()
        self.assertEqual(problem.code, exits.LAYER_UNAVAILABLE)
        self.assertIn(layout.BLOB_DIR, str(problem))

    def test_a_release_revision_that_is_not_there_is_unavailable(self):
        shutil.rmtree(join(self.source, layout.release_dir("2026-09-28", 1)))
        problem = self.failing()
        self.assertEqual(problem.code, exits.LAYER_UNAVAILABLE)

    def test_a_parent_that_moved_on_inside_a_release_is_a_mismatch(self):
        core = dict(self.fields["core"])
        core["sha256"] = "c" * 64
        text = "".join(f"{key} {value}\n" for key, value in core.items())
        write(self.manifest_path("core"), text)
        self.rewrite_channel(
            digests={"core": manifest_digest(text),
                     "lamp": self.digests["lamp"]},
        )
        problem = self.failing()
        self.assertEqual(problem.code, exits.LAYER_MISMATCH)
        # Named, because the flat tarball fallback makes the download
        # digest check produce the same code for a different reason.
        self.assertIn("parent_sha256", str(problem))


class TestRollback(ChannelPullTestCase):
    def test_a_pointer_that_goes_backwards_is_refused(self):
        build_mirror(self.source, release="2026-09-29", rev=1)
        self.pull()
        build_mirror(self.source, release="2026-09-28", rev=1)
        problem = self.failing()
        self.assertEqual(problem.code, exits.CHANNEL_ROLLBACK)
        self.assertIn("2026-09-29/1", str(problem))

    def test_a_pointer_that_goes_backwards_may_be_allowed_on_purpose(self):
        build_mirror(self.source, release="2026-09-29", rev=1)
        self.pull()
        build_mirror(self.source, release="2026-09-28", rev=1)
        report = self.pull(allow_rollback=True)
        self.assertEqual(report.channel.describe(), "stable 2026-09-28/1")
        self.assertEqual(
            channels.read_state(self.state).describe(), "stable 2026-09-28/1"
        )

    def test_an_earlier_revision_asked_for_by_hand_is_pulled(self):
        build_mirror(self.source, release="2026-09-29", rev=1)
        self.pull()
        report = pull(
            "lamp", self.source, self.cache,
            self.resolution(channel="stable", release="2026-09-28", rev=1),
        )
        self.assertIsNone(report.channel)
        self.assertIn("release 2026-09-28/1", report.resolution_line())
        self.assertEqual(
            channels.read_state(self.state).describe(), "stable 2026-09-28/1"
        )

    def test_a_revision_asked_for_by_hand_is_verified_too(self):
        """Rollback is the path used when the mirror is least trusted

        It resolves through the revision's own archived pointer, so the
        digest chain is the same as the channel path's. Only the expiry
        is not enforced: an old revision is old on purpose.
        """
        report = pull(
            "lamp", self.source, self.cache,
            self.resolution(channel=None, release="2026-09-28", rev=1),
        )
        self.assertEqual([r.name for r in report.results], ["core", "lamp"])
        self.assertIn("verified against", report.resolution_line())

    def test_a_revision_asked_for_by_hand_needs_the_keyring(self):
        problem = self.failing(
            channel=None, release="2026-09-28", rev=1, keyring=None
        )
        self.assertEqual(problem.code, exits.CHANNEL_UNVERIFIED)

    def test_a_revision_whose_pointer_is_absent_is_unavailable(self):
        os.remove(
            join(self.source, layout.revision_path("2026-09-28", 1))
        )
        problem = self.failing(channel=None, release="2026-09-28", rev=1)
        self.assertEqual(problem.code, exits.LAYER_UNAVAILABLE)
        self.assertIn(layout.REVISION_POINTER, str(problem))

    def test_a_revision_pointer_signed_by_the_wrong_key_is_refused(self):
        body = channel_body(digests=self.digests)
        write(
            join(self.source, layout.revision_path("2026-09-28", 1)),
            keys().clearsign(body, keys().other),
        )
        problem = self.failing(channel=None, release="2026-09-28", rev=1)
        self.assertEqual(problem.code, exits.CHANNEL_UNVERIFIED)

    def test_a_revision_pointer_for_another_revision_is_refused(self):
        body = channel_body(rev=9, digests=self.digests)
        write(
            join(self.source, layout.revision_path("2026-09-28", 1)),
            keys().clearsign(body),
        )
        problem = self.failing(channel=None, release="2026-09-28", rev=1)
        self.assertEqual(problem.code, exits.CHANNEL_INVALID)
        self.assertIn("names 2026-09-28/9", str(problem))

    def test_a_hostile_mirror_cannot_rewrite_a_manifest_on_the_rollback_path(
        self,
    ):
        path = join(
            self.source, layout.manifest_path("2026-09-28", 1, "core")
        )
        with open(path, encoding="utf-8") as fob:
            text = fob.read()
        write(path, text + "\n")
        problem = self.failing(channel=None, release="2026-09-28", rev=1)
        self.assertEqual(problem.code, exits.LAYER_MISMATCH)
        self.assertFalse(exists(self.cached("core")))

    def test_an_expired_revision_pointer_still_rolls_back(self):
        """An old revision is old on purpose; only a channel must be fresh"""
        signed = now() - timedelta(days=400)
        build_mirror(
            self.source, release="2026-09-28", rev=1, signed_at=signed,
            expires_at=signed + timedelta(days=7),
        )
        report = pull(
            "lamp", self.source, self.cache,
            self.resolution(channel=None, release="2026-09-28", rev=1),
        )
        self.assertEqual([r.name for r in report.results], ["core", "lamp"])

    def test_a_revision_asked_for_by_hand_records_nothing_without_a_channel(
        self,
    ):
        pull(
            "lamp", self.source, self.cache,
            self.resolution(channel=None, release="2026-09-28", rev=1),
        )
        self.assertIsNone(channels.read_state(self.state))

    def test_a_state_that_does_not_parse_is_a_channel_error(self):
        os.makedirs(os.path.dirname(self.state))
        write(self.state, "channel stable\n")
        self.assertEqual(self.failing().code, exits.CHANNEL_INVALID)


class TestResolution(unittest.TestCase):
    def test_nothing_named_is_the_flat_layout(self):
        self.assertTrue(Resolution().flat)

    def test_a_channel_alone_follows_the_pointer(self):
        found = Resolution(channel="stable")
        self.assertTrue(found.by_channel)
        self.assertFalse(found.flat)

    def test_a_release_without_a_revision_is_refused(self):
        with self.assertRaises(ValueError) as raised:
            Resolution(release="2026-09-28")
        self.assertIn("--rev", str(raised.exception))

    def test_a_revision_without_a_release_is_refused(self):
        with self.assertRaises(ValueError) as raised:
            Resolution(rev=1)
        self.assertIn("--release", str(raised.exception))

    def test_a_release_that_is_not_a_date_is_refused(self):
        with self.assertRaises(ValueError):
            Resolution(release="latest", rev=1)

    def test_a_revision_that_is_not_a_number_above_zero_is_refused(self):
        with self.assertRaises(ValueError):
            Resolution(release="2026-09-28", rev=0)

    def test_a_channel_that_is_not_one_of_the_two_is_refused(self):
        with self.assertRaises(ValueError) as raised:
            Resolution(channel="nightly")
        self.assertIn("stable, testing", str(raised.exception))


@unittest.skipIf(MISSING, f"{MISSING} is not installed")
class TestHashFile(ChannelPullTestCase):
    """The one file on the mirror that nothing authenticates"""

    def hash_at(self, name: str, digest: str) -> str:
        path = join(self.source, self.fields[name]["tarball"] + ".hash")
        write(path, f"{digest}  {self.fields[name]['tarball']}\n")
        return path

    def cached_hash(self, name: str) -> str:
        return self.cached(name, ".tar.zst.hash")

    def test_a_truthful_hash_file_is_copied(self):
        self.hash_at("core", self.fields["core"]["sha256"])
        self.pull()
        self.assertTrue(exists(self.cached_hash("core")))

    def test_a_hash_file_that_disagrees_with_the_manifest_is_not_stored(self):
        """A mirror must not get to pick keel verify's exit code"""
        self.hash_at("core", "b" * 64)
        self.pull()
        self.assertFalse(exists(self.cached_hash("core")))

    def test_a_hash_file_with_no_digest_line_is_still_copied(self):
        path = join(self.source, self.fields["core"]["tarball"] + ".hash")
        write(path, "prose with no digest in it\n")
        self.pull()
        self.assertTrue(exists(self.cached_hash("core")))

    def test_a_hash_file_is_read_with_a_bound(self):
        path = join(self.source, self.fields["core"]["tarball"] + ".hash")
        write(path, "x" * (2 << 16))
        self.pull()
        self.assertLessEqual(
            os.path.getsize(self.cached_hash("core")), 1 << 16
        )


class TestFutureChannel(ChannelPullTestCase):
    def test_a_pointer_signed_in_the_future_is_refused(self):
        signed = now() + timedelta(days=3)
        self.rewrite_channel(
            signed_at=signed, expires_at=signed + timedelta(days=7)
        )
        problem = self.failing()
        self.assertEqual(problem.code, exits.CHANNEL_INVALID)
        self.assertIn("from the future", str(problem))
        self.assertFalse(exists(self.cached("core")))

    def test_a_pointer_claiming_a_decade_of_life_is_refused(self):
        signed = now()
        self.rewrite_channel(
            signed_at=signed, expires_at=signed + timedelta(days=3650)
        )
        problem = self.failing()
        self.assertEqual(problem.code, exits.CHANNEL_INVALID)
        self.assertIn("permanent freeze", str(problem))
