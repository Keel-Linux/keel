# Copyright (c) 2026 KeelLinux maintainers
"""keel.system.filesync_watch: one alert per change of the set of counts

The set is the (path, counter) pairs that are not zero, a folder in error
and a folder paused while the node is proven. needFiles counts after
NEED_RUNS runs in a row. The state is kept only after an alert was taken.
"""

import json
import unittest
from unittest import mock

from filesync_helpers import CONTENT, MEDIA, SyncCase, doc

from keel.system import filesync, filesync_io, filesync_watch


def row(content=0, need=0, **more):
    return {"receiveOnlyChangedFiles": content, "needFiles": need,
            "state": "idle", "error": "", "paused": False,
            "type": "sendonly", **more}


def clean():
    return {CONTENT: row(), MEDIA: row()}


class WatchCase(SyncCase):
    def watch(self, counts, taken=True, said=None, document=None):
        said = said if said is not None else []
        delivered = []

        def deliver(title, text, check, level):
            delivered.append((title, text, check, level))
            return taken

        with mock.patch("keel.system.filesync_api.counts",
                        return_value=counts):
            filesync_watch.watch_counts(self.root, document or doc(),
                                        said.append, deliver)
        return delivered

    def saved(self):
        return json.loads(self.wrote(filesync_io.WATCH_STATE))


class TestTheAlertOnTheSet(WatchCase):
    def test_a_local_change_alerts_once_and_the_recovery_once(self):
        dirty = {CONTENT: row(content=1), MEDIA: row()}
        first = self.watch(dirty)
        self.assertEqual(len(first), 1)
        title, text, check, level = first[0]
        self.assertEqual((check, level), ("filesync-counts", "critical"))
        self.assertIn(CONTENT, text)
        self.assertIn("receiveOnlyChangedFiles 1", text)
        # the same set again, and the same count changed: no new alert
        self.assertEqual(self.watch(dirty), [])
        self.assertEqual(self.watch({CONTENT: row(content=7),
                                     MEDIA: row()}), [])
        back = self.watch(clean())
        self.assertEqual([one[3] for one in back], ["recovery"])
        self.assertEqual(self.watch(clean()), [])

    def test_a_new_member_of_the_set_is_a_new_alert(self):
        self.watch({CONTENT: row(content=1), MEDIA: row()})
        more = self.watch({CONTENT: row(content=1),
                           MEDIA: row(content=2)})
        self.assertEqual(len(more), 1)
        self.assertIn(MEDIA, more[0][1])

    def test_a_smaller_set_that_is_not_empty_is_silent_but_remembered(self):
        self.watch({CONTENT: row(content=1), MEDIA: row(content=1)})
        self.assertEqual(self.watch({CONTENT: row(content=1),
                                     MEDIA: row()}), [])
        # MEDIA coming back is new again
        self.assertEqual(len(self.watch({CONTENT: row(content=1),
                                         MEDIA: row(content=1)})), 1)

    def test_need_files_waits_for_a_run_of_runs(self):
        waiting = {CONTENT: row(need=4), MEDIA: row()}
        for _ in range(filesync_watch.NEED_RUNS - 1):
            self.assertEqual(self.watch(waiting), [])
        alert = self.watch(waiting)
        self.assertEqual(len(alert), 1)
        self.assertIn("needFiles 4", alert[0][1])

    def test_a_catch_up_that_ends_resets_the_need_files_runs(self):
        waiting = {CONTENT: row(need=4), MEDIA: row()}
        for _ in range(filesync_watch.NEED_RUNS - 1):
            self.watch(waiting)
        self.assertEqual(self.watch(clean()), [])
        for _ in range(filesync_watch.NEED_RUNS - 1):
            self.assertEqual(self.watch(waiting), [])

    def test_an_alert_no_channel_took_is_sent_again(self):
        dirty = {CONTENT: row(content=1), MEDIA: row()}
        self.assertEqual(len(self.watch(dirty, taken=False)), 1)
        self.assertEqual(len(self.watch(dirty, taken=False)), 1)
        self.assertEqual(len(self.watch(dirty, taken=True)), 1)
        self.assertEqual(self.watch(dirty), [])

    def test_a_recovery_no_channel_took_is_sent_again(self):
        self.watch({CONTENT: row(content=1), MEDIA: row()})
        self.assertEqual(len(self.watch(clean(), taken=False)), 1)
        self.assertEqual(len(self.watch(clean(), taken=True)), 1)

    def test_everything_clean_from_the_start_is_silent(self):
        self.assertEqual(self.watch(clean()), [])

    def test_the_state_file_is_private(self):
        import os
        self.watch({CONTENT: row(content=1), MEDIA: row()})
        full = os.path.join(self.root, filesync_io.WATCH_STATE)
        self.assertEqual(os.stat(full).st_mode & 0o777, 0o600)


class TestTheOtherMembers(WatchCase):
    def test_a_folder_in_error_is_a_member(self):
        broken = {CONTENT: row(state="error", error="folder path missing"),
                  MEDIA: row()}
        found = self.watch(broken)
        self.assertEqual(len(found), 1)
        self.assertIn("folder path missing", found[0][1])

    def test_an_error_text_is_not_needed_for_the_state_error(self):
        found = self.watch({CONTENT: row(state="error"), MEDIA: row()})
        self.assertEqual(len(found), 1)

    def test_paused_while_proven_is_a_member_paused_while_paused_is_not(
            self):
        paused = {CONTENT: row(paused=True, state="paused"),
                  MEDIA: row(paused=True, state="paused")}
        self.assertEqual(self.watch(paused), [])
        self.put_file(filesync_io.STATE_FILE, "primary\n")
        found = self.watch(paused)
        self.assertEqual(len(found), 1)
        self.assertIn("paused while this node is the primary", found[0][1])


class TestNothingToWatch(WatchCase):
    def test_the_cases_that_watch_nothing(self):
        self.assertEqual(self.watch(clean(),
                                    document=doc(enabled="disabled")), [])
        self.assertEqual(self.watch(clean(), document={"version": 1}), [])
        self.assertEqual(self.watch(clean(), document={
            "version": 1, "appliance": {"name": "core"},
            "overlays": {filesync.OVERLAY: "enabled"}}), [])
        self.assertEqual(self.watch(clean(), document={
            "version": 1, "appliance": {"name": "nothing-here"},
            "overlays": {filesync.OVERLAY: "enabled"}}), [])

    def test_no_answer_is_said_and_is_not_a_clean_run(self):
        self.watch({CONTENT: row(content=1), MEDIA: row()})
        said = []
        self.assertEqual(self.watch(None, said=said), [])
        self.assertTrue(any("not readable" in line for line in said))
        # the state stands: the same count is still no new alert
        self.assertEqual(self.watch({CONTENT: row(content=1),
                                     MEDIA: row()}), [])

    def test_a_state_file_of_the_wrong_shape_is_a_fresh_start(self):
        self.put_file(filesync_io.WATCH_STATE, "[1, 2]\n")
        self.assertEqual(len(self.watch({CONTENT: row(content=1),
                                         MEDIA: row()})), 1)
        self.put_file(filesync_io.WATCH_STATE, "not json\n")
        self.assertEqual(len(self.watch({CONTENT: row(content=1),
                                         MEDIA: row()})), 1)


class TestTheDatabaseWatchWiring(SyncCase):
    """The database watch follows again while a flip is pending, and
    delivers the alert through the monitor's channels"""

    def test_a_pending_flip_is_followed_again(self):
        self.assertFalse(filesync.flip_pending(self.root, doc()))
        self.put_file(filesync_io.PENDING, "1\n")
        self.assertTrue(filesync.flip_pending(self.root, doc()))
        self.assertFalse(filesync.flip_pending(
            self.root, doc(enabled="disabled")))


if __name__ == "__main__":
    unittest.main()
