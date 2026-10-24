# Copyright (c) 2026 KeelLinux maintainers
"""keel.system.filesync.follow_flip: the folders' direction with the
database role (0050's amendment, point 5)

A flip first writes the folders' state, then sets the running syncthing
through its REST API; it never raises, and a flip that did not reach the
wanted state is a follow problem the database watch retries.
"""

import json
import os
import subprocess
import unittest
from contextlib import ExitStack
from unittest import mock

from filesync_helpers import (CONTENT, DEVICE, MEDIA, OTHER_PEER, PEER,
                              PEER_ADDRESS, FakeApi, Runner, SyncCase, doc,
                              flip_patches, pair_of, quiet)

from keel.mesh.memberlink import LinkError
from keel.system import filesync


class Here:
    """The members' channel: answers with a device ID, and records what
    the folders looked like when it was asked"""

    def __init__(self, answer=PEER, check=None, error=None):
        self.answer = answer
        self.check = check
        self.error = error
        self.asked: list[tuple] = []

    def say(self, kind, at, body):
        self.asked.append((kind, at, body))
        if self.check:
            self.check()
        if self.error:
            raise self.error
        return json.dumps({"id": self.answer}).encode()


class FlipCase(SyncCase):
    def flip(self, role, runner=None, api=None, here=None, pair=None,
             hooks=None, document=None, root=None, applied=True):
        """`applied`: the drop-in is there as apply wrote it, so the unit
        has the paths it may write and a flip sets the folders through
        the API"""
        found = quiet()
        api = api if api is not None else FakeApi()
        root = root or self.root
        runner = runner or Runner(on_restart=lambda: api.cold_start(root))
        if applied and not self.exists(filesync.DROP_IN):
            application = self.resolved().application.item
            self.put_file(filesync.DROP_IN, filesync.drop_in(
                filesync.effective_paths(application, "cloud_simple")))
        with ExitStack() as stack:
            for patch in flip_patches(hooks):
                stack.enter_context(patch)
            stack.enter_context(mock.patch(
                "keel.system.filesync_api.request", api))
            filesync.follow_flip(
                root, document or doc(),
                pair if pair is not None else pair_of(), role, found,
                runner, here=here)
        return found, runner, api

    def role_of_state(self):
        return self.wrote(filesync.STATE_FILE).strip()


class TestTheDirection(FlipCase):
    def test_a_primary_flip_sets_the_folders_through_the_api(self):
        found, ran, api = self.flip("primary", here=Here())
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(self.role_of_state(), "primary")
        self.assertEqual(self.wrote(filesync.DEVICE_FILE), DEVICE + "\n")
        config = self.wrote(filesync.CONFIG)
        self.assertIn(f'path="{CONTENT}" type="sendonly"', config)
        self.assertIn("<paused>false</paused>", config)
        for path in (CONTENT, MEDIA):
            folder = api.folders[filesync.folder_id(path)]
            self.assertEqual(folder["type"], "sendonly")
            self.assertFalse(folder["paused"])
        # a running syncthing keeps running
        self.assertEqual(ran.ran("systemctl", "restart"), [])
        mode = os.stat(os.path.join(self.root, filesync.CONFIG)).st_mode
        self.assertEqual(mode & 0o777, filesync.CONFIG_MODE)

    def test_a_replica_flip_receives_and_keeps_versions(self):
        found, _, api = self.flip("replica", here=Here())
        self.assertIsNone(found.problem, found.lines)
        folder = api.folders[filesync.folder_id(CONTENT)]
        self.assertEqual(folder["type"], "receiveonly")
        self.assertEqual(folder["versioning"]["type"], "simple")
        self.assertIn('<versioning type="simple">',
                      self.wrote(filesync.CONFIG))

    def test_an_unproven_flip_pauses_and_runs_no_hook(self):
        found, ran, api = self.flip(None)
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(self.role_of_state(), "paused")
        self.assertIn("<paused>true</paused>", self.wrote(filesync.CONFIG))
        folder = api.folders[filesync.folder_id(CONTENT)]
        self.assertTrue(folder["paused"])
        self.assertEqual(ran.ran("systemctl", "restart"), [])

    def test_the_hooks_run_with_the_role_after_the_flip(self):
        hooks = mock.Mock(return_value=[])
        self.flip("replica", here=Here(), hooks=hooks)
        hooks.assert_called_once()
        self.assertEqual(hooks.call_args.args[:2], (self.root, "replica"))

    def test_an_unproven_flip_runs_no_hook(self):
        hooks = mock.Mock(return_value=[])
        self.flip(None, hooks=hooks)
        hooks.assert_not_called()

    def test_a_stopped_unit_gets_the_files_for_its_cold_start(self):
        found, ran, api = self.flip("primary", runner=Runner(active=False))
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(api.calls, [])
        self.assertEqual(ran.ran("systemctl", "restart"), [])
        self.assertIn("type=\"sendonly\"", self.wrote(filesync.CONFIG))

    def test_the_drop_in_change_reloads_and_restarts(self):
        # the paths the unit may write changed: only a restart takes it
        self.put_file(filesync.DROP_IN, "[Service]\nReadWritePaths=/old\n")
        found, ran, api = self.flip("primary", here=Here(), applied=False)
        self.assertEqual(len(ran.ran("systemctl", "daemon-reload")), 1)
        self.assertEqual(len(ran.ran("systemctl", "restart", "syncthing"
                                     ".service")), 1)
        self.assertIsNone(found.problem, found.lines)
        # the second flip finds the drop-in as written: no reload
        found, ran, _ = self.flip("replica", here=Here())
        self.assertEqual(ran.ran("systemctl", "daemon-reload"), [])
        self.assertEqual(ran.ran("systemctl", "restart"), [])

    def test_nothing_without_the_overlay_or_without_a_path(self):
        found, ran, api = self.flip("primary",
                                    document=doc(enabled="disabled"))
        self.assertFalse(self.exists(filesync.CONFIG))
        self.assertFalse(self.exists(filesync.STATE_FILE))
        core = {"version": 1, "appliance": {"name": "core"},
                "overlays": {filesync.OVERLAY: "enabled"}}
        self.flip("primary", document=core)
        self.assertFalse(self.exists(filesync.CONFIG))

    def test_no_syncthing_binary_says_and_changes_nothing(self):
        found = quiet()
        with mock.patch("keel.system.filesync.shutil.which",
                        return_value=None):
            filesync.follow_flip(self.root, doc(), None, "primary", found,
                                 Runner())
        self.assertTrue(any("not installed" in line for line in found.lines))
        self.assertIsNone(found.problem)
        self.assertFalse(self.exists(filesync.CONFIG))

    def test_a_flip_that_is_done_leaves_no_pending_mark(self):
        found, _, _ = self.flip("primary", here=Here())
        self.assertFalse(self.exists(filesync.PENDING))
        self.assertFalse(filesync.flip_pending(self.root, doc()))

    def test_the_flip_never_leaks_the_api_key_in_a_command(self):
        found, ran, api = self.flip("primary", here=Here())
        key = self.wrote(filesync.APIKEY).strip()
        self.assertTrue(key)
        for call in ran.calls:
            self.assertNotIn(key, " ".join(call))
        self.assertTrue(all(call[0] == key for call in api.calls))

    def test_the_files_keel_keeps_are_private(self):
        self.flip("primary", here=Here())
        base = os.path.join(self.root, filesync.DIR)
        self.assertEqual(os.stat(base).st_mode & 0o777, 0o700)
        key = os.path.join(self.root, filesync.APIKEY)
        self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
        leftovers = [one for one in os.listdir(base) if one.endswith(".tmp")]
        self.assertEqual(leftovers, [])


class TestTheFailures(FlipCase):
    """A flip that fails pauses as far as it can and says so"""

    def test_a_failed_restart_is_a_follow_problem_not_a_hidden_one(self):
        found, ran, api = self.flip("primary", runner=Runner(restart=1),
                                    api=FakeApi(down=True), here=Here())
        self.assertIsNotNone(found.problem)
        self.assertIn("restart", found.problem)
        self.assertTrue(self.exists(filesync.PENDING))
        self.assertTrue(filesync.flip_pending(self.root, doc()))
        # the files are what the state says, for a cold start
        self.assertEqual(self.role_of_state(), "paused")

    def test_the_api_down_restarts_and_reads_the_folders_back(self):
        api = FakeApi(down=True)
        ran = Runner(on_restart=lambda: api.cold_start(self.root))
        found, ran, api = self.flip("primary", runner=ran, api=api,
                                    here=Here())
        self.assertIsNone(found.problem, found.lines)
        self.assertEqual(len(ran.ran("systemctl", "restart")), 1)
        self.assertTrue(any("restarting syncthing" in line
                            for line in found.lines))
        self.assertFalse(self.exists(filesync.PENDING))

    def test_folders_that_are_not_as_asked_after_the_restart_fail(self):
        api = FakeApi(ignore_patch=True)
        found, ran, api = self.flip("primary", api=api, here=Here(),
                                    runner=Runner())
        self.assertIsNotNone(found.problem)
        self.assertIn("not as asked", found.problem)
        self.assertTrue(self.exists(filesync.PENDING))

    def test_a_reload_that_fails_is_a_follow_problem(self):
        self.put_file(filesync.DROP_IN, "[Service]\n")
        found, _, _ = self.flip("primary", runner=Runner(reload=1),
                                here=Here(), applied=False)
        self.assertIn("daemon-reload", found.problem)

    def test_no_identity_pauses_and_says_it(self):
        found, _, api = self.flip("primary", runner=Runner(device=None))
        self.assertIn("identity", found.problem)
        self.assertEqual(self.role_of_state(), "paused")
        self.assertTrue(self.exists(filesync.PENDING))

    def test_a_command_that_times_out_never_escapes(self):
        class Slow(Runner):
            def __call__(self, argv, **kwargs):
                if argv[:2] == ["systemctl", "is-active"]:
                    raise subprocess.TimeoutExpired(argv, 60)
                return super().__call__(argv, **kwargs)

        found, _, _ = self.flip("primary", runner=Slow(), here=Here())
        self.assertIn("flip failed", found.problem)
        self.assertEqual(self.role_of_state(), "paused")

    def test_a_file_that_cannot_be_written_never_escapes(self):
        with mock.patch("keel.system.filesync_io.write",
                        side_effect=OSError("disk full")):
            found, _, _ = self.flip("primary", here=Here())
        self.assertIn("disk full", found.problem)

    def test_a_peer_ask_that_raises_is_said_and_the_flip_goes_on(self):
        for error in (OSError("link down"), LinkError("no answer"),
                      TimeoutError("late")):
            with self.subTest(error=error):
                found, _, api = self.flip(
                    "primary", here=Here(error=error))
                self.assertTrue(any("answer" in line or "link down" in line
                                    or "late" in line
                                    for line in found.lines), found.lines)
                self.assertTrue(api.folders)

    def test_a_failing_hook_is_a_follow_problem_and_is_retried(self):
        found, _, _ = self.flip("replica", here=Here(),
                                hooks=["/usr/lib/keel/roles.d/10scan"])
        self.assertIn("10scan", found.problem)
        self.assertTrue(self.exists(filesync.PENDING))
        found, _, _ = self.flip("replica", here=Here())
        self.assertIsNone(found.problem, found.lines)
        self.assertFalse(self.exists(filesync.PENDING))

    def test_a_refused_path_pauses_and_fails(self):
        self.with_paths("/srv/ok", "/var/lib/keel")
        found, _, api = self.flip("primary", here=Here())
        self.assertIn("/var/lib/keel", found.problem)
        self.assertEqual(self.role_of_state(), "paused")
        self.assertTrue(api.folders[filesync.folder_id("/srv/ok")]["paused"])

    def test_a_state_file_that_cannot_be_written_does_not_skip_the_pause(
            self):
        from keel.system import filesync_io
        real = filesync_io.write

        def write(root, path, *args, **kwargs):
            if path == filesync.STATE_FILE:
                raise OSError("read-only file system")
            return real(root, path, *args, **kwargs)

        api = FakeApi()
        with mock.patch("keel.system.filesync_io.write", write):
            found, _, _ = self.flip("primary", api=api, here=Here())
        self.assertIsNotNone(found.problem)
        self.assertTrue(api.folders[filesync.folder_id(CONTENT)]["paused"])
        self.assertTrue(any("state" in line for line in found.lines))

    def test_with_no_identity_the_api_pause_still_goes_out(self):
        api = FakeApi()
        self.put_file(filesync.APIKEY, "key\n")
        found, _, _ = self.flip("primary", runner=Runner(device=None),
                                api=api, here=Here())
        self.assertTrue(api.folders[filesync.folder_id(CONTENT)]["paused"])

    def test_an_unreachable_api_after_a_failure_still_leaves_paused_files(
            self):
        found, _, _ = self.flip("primary", runner=Runner(device=None))
        self.assertEqual(self.role_of_state(), "paused")
        # the next apply renders from that state, never from the role
        self.put_file("var/lib/keel/role",
                      "role=primary\nreplicates=database,files\nvip=x\n")
        self.assertIsNone(self.state().role)


class TestAnInDoubtNodeStaysPaused(FlipCase):
    """The state is what apply renders from: a later `keel spec apply`
    never sends again what a flip paused"""

    def test_in_doubt_then_apply_renders_paused(self):
        self.flip("primary", here=Here())
        self.flip(None)
        # the role file still says primary: the database flip stands
        self.put_file("var/lib/keel/role",
                      "role=primary\nreplicates=database,files\nvip=x\n")
        state = filesync.FileSyncState(**{**self.state().__dict__,
                                          "peer_address": PEER_ADDRESS})
        self.assertIsNone(state.role)
        actions, restart = filesync.plan_filesync(state, True)
        written = [a for a in actions if isinstance(a, filesync.WriteFile)
                   and a.path == filesync.CONFIG]
        # the flip rendered it already: nothing to write, no restart
        self.assertEqual(written, [])
        self.assertFalse(restart)
        self.assertIn("<paused>true</paused>", self.wrote(filesync.CONFIG))

    def test_a_stale_state_apply_does_not_send(self):
        self.put_file(filesync.STATE_FILE, "paused\n")
        state = filesync.FileSyncState(**{**self.state().__dict__,
                                          "device": DEVICE, "apikey": "key"})
        actions, _ = filesync.plan_filesync(state, False)
        config = next(a for a in actions
                      if isinstance(a, filesync.WriteFile)
                      and a.path == filesync.CONFIG)
        self.assertIn("<paused>true</paused>", config.content)


class TestThePeer(FlipCase):
    def test_the_folders_get_their_direction_before_the_peer_is_asked(self):
        seen = []

        def check():
            seen.append(self.wrote(filesync.CONFIG))

        found, _, api = self.flip("primary", here=Here(check=check))
        self.assertIn('type="sendonly"', seen[0])
        self.assertIn("<paused>false</paused>", seen[0])
        self.assertNotIn(PEER, seen[0])
        self.assertIn(PEER, self.wrote(filesync.CONFIG))
        self.assertEqual(self.wrote(filesync.PEER_FILE), PEER + "\n")
        self.assertIn(PEER, api.devices)
        self.assertEqual(api.devices[PEER]["addresses"],
                         [f"tcp://[{PEER_ADDRESS}]:22000"])

    def test_the_peer_is_asked_at_each_flip_and_a_changed_id_replaces(self):
        here = Here()
        self.flip("primary", here=here)
        here.answer = OTHER_PEER
        found, _, api = self.flip("replica", here=here)
        self.assertEqual(len(here.asked), 2)
        self.assertEqual(here.asked[0][0], "device")
        self.assertEqual(here.asked[0][1], PEER_ADDRESS)
        self.assertEqual(self.wrote(filesync.PEER_FILE), OTHER_PEER + "\n")
        self.assertIn(OTHER_PEER, self.wrote(filesync.CONFIG))
        self.assertNotIn(f'<device id="{PEER}"', self.wrote(filesync.CONFIG))
        self.assertIsNone(found.problem, found.lines)

    def test_an_unchanged_id_renders_once(self):
        here = Here()
        self.flip("primary", here=here)
        found, ran, api = self.flip("replica", here=here)
        self.assertEqual(api.methods("PUT"), [api.methods("PUT")[0]])
        self.assertEqual(self.wrote(filesync.PEER_FILE), PEER + "\n")

    def test_its_own_id_as_the_peers_is_refused(self):
        found, _, _ = self.flip("primary", here=Here(answer=DEVICE))
        self.assertIn("own", found.problem)
        self.assertFalse(self.exists(filesync.PEER_FILE))

    def test_a_pause_asks_nobody(self):
        here = Here()
        self.flip(None, here=here)
        self.assertEqual(here.asked, [])

    def test_a_peer_that_holds_no_identity_yet_says_so_and_is_retried(self):
        found, _, _ = self.flip("primary", here=Here(error=LinkError(
            "[x]:51821 refused: b'this node holds no syncthing identity"
            " yet'")))
        self.assertTrue(any("no syncthing identity" in line
                            for line in found.lines))
        self.assertNotIn(f'<device id="{PEER}"', self.wrote(filesync.CONFIG))
        self.assertIsNone(found.problem)
        self.assertTrue(self.exists(filesync.PENDING))

    def test_an_answer_of_the_wrong_shape_is_not_kept(self):
        found, _, _ = self.flip("primary", here=Here(answer="not-an-id"))
        self.assertTrue(any("no device ID" in line for line in found.lines))
        self.assertFalse(self.exists(filesync.PEER_FILE))


class TestTheIdentity(SyncCase):
    def test_a_failing_generate_gives_none_never_an_exception(self):
        def run(argv, **kwargs):
            if "generate" in argv:
                raise subprocess.CalledProcessError(1, argv)
            return subprocess.CompletedProcess(argv, 0, DEVICE + "\n", "")

        with mock.patch("keel.system.filesync.shutil.which",
                        return_value="/usr/bin/syncthing"):
            self.assertIsNone(filesync.ensure_identity(self.root, run))

    def test_a_timeout_gives_none(self):
        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 1)

        with mock.patch("keel.system.filesync.shutil.which",
                        return_value="/usr/bin/syncthing"):
            self.assertIsNone(filesync.ensure_identity(self.root, run))

    def test_no_binary_gives_none(self):
        with mock.patch("keel.system.filesync.shutil.which",
                        return_value=None):
            self.assertIsNone(filesync.ensure_identity(self.root, Runner()))

    def test_the_made_identity_is_kept_and_not_made_twice(self):
        runner = Runner()
        with mock.patch("keel.system.filesync.shutil.which",
                        return_value="/usr/bin/syncthing"):
            self.assertEqual(filesync.ensure_identity(self.root, runner),
                             DEVICE)
            made = len(runner.calls)
            self.assertEqual(filesync.ensure_identity(self.root, runner),
                             DEVICE)
        self.assertEqual(len(runner.calls), made)
        self.assertEqual(self.wrote(filesync.DEVICE_FILE), DEVICE + "\n")


class TestTheWrite(SyncCase):
    def test_a_write_is_atomic_private_and_owned(self):
        from keel.system import filesync_io as io
        with mock.patch("os.fchown") as chown, \
                mock.patch("pwd.getpwnam", return_value=mock.Mock(
                    pw_uid=999, pw_gid=998)):
            io.write(self.root, filesync.CONFIG, "a\n", 0o600, owner="x")
        chown.assert_called_once()
        self.assertEqual(chown.call_args.args[1:], (999, 998))
        self.assertEqual(self.wrote(filesync.CONFIG), "a\n")

    def test_a_failed_write_leaves_neither_a_temp_file_nor_the_old_text(
            self):
        from keel.system import filesync_io as io
        io.write(self.root, filesync.DEVICE_FILE, "old\n", 0o644,
                 private_dir=True)
        with mock.patch("os.fsync", side_effect=OSError("io")):
            with self.assertRaises(OSError):
                io.write(self.root, filesync.DEVICE_FILE, "new\n", 0o644)
        self.assertEqual(self.wrote(filesync.DEVICE_FILE), "old\n")
        base = os.path.join(self.root, filesync.DIR)
        self.assertEqual([one for one in os.listdir(base)
                          if one.endswith(".tmp")], [])

    def test_remove_ignores_a_missing_file(self):
        from keel.system import filesync_io as io
        io.remove(self.root, filesync.PENDING)

    def test_the_directory_is_made_0700_even_when_it_was_wider(self):
        from keel.system import filesync_io as io
        base = os.path.join(self.root, filesync.DIR)
        os.makedirs(base, mode=0o755)
        os.chmod(base, 0o755)
        io.write(self.root, filesync.APIKEY, "k\n", 0o600, private_dir=True)
        self.assertEqual(os.stat(base).st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
