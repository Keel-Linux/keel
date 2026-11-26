# Copyright (c) 2026 KeelLinux maintainers
"""keel diff: the row of syncthing's rendered files (keel#347)

keel diff shows each change that the next keel spec apply --system
makes. The apply writes /var/lib/syncthing/config.xml and restarts
syncthing when the digest record differs from the configuration it
renders now (keel.system.filesync.plan_filesync). keel 0.23.100 changed
the render (the loopback listen address, decision 0097), and keel diff
said `overlays.syncthing: same` before an apply that restarted
syncthing. The row filesync.config compares the same plan.
"""

import os
import unittest
from unittest import mock

from filesync_helpers import CONTENT, DEVICE, MEDIA, SyncCase, doc

from keel.diff.filesync import filesync_fields
from keel.diff.report import DRIFT, NOT_COMPARED, SAME, UNKNOWN
from keel.system import filesync
from keel.system.actions import WriteFile

FIELD = "filesync.config"
CLEAN = {"receiveOnlyChangedFiles": 0, "needFiles": 0, "state": "idle",
         "error": "", "paused": False, "type": "sendonly"}


class TestTheRenderRow(SyncCase):
    def setUp(self):
        super().setUp()
        self.put_file(filesync.DEVICE_FILE, DEVICE + "\n")
        self.put_file(filesync.APIKEY, "key\n")

    def applied(self) -> None:
        """Write what the apply writes, as the apply does, on a node
        where the application made its directories"""
        for path in (CONTENT, MEDIA):
            os.makedirs(os.path.join(self.root, path.lstrip("/")),
                        exist_ok=True)
        actions, _ = filesync.plan_filesync(self.state(), True)
        for action in actions:
            if isinstance(action, WriteFile):
                self.put_file(action.path, action.content)

    def row(self, live: bool = True):
        counts = {path: dict(CLEAN) for path in (CONTENT, MEDIA)}
        with mock.patch("keel.system.filesync_api.counts",
                        return_value=counts), \
                mock.patch("keel.system.filesync_api.peer_connected",
                           return_value=True):
            found = filesync_fields(doc(), self.root, live)
        return next((one for one in found if one.field == FIELD), None)

    def test_the_render_the_apply_wrote_is_same(self):
        self.applied()
        found = self.row()
        self.assertIsNotNone(found)
        self.assertEqual(found.status, SAME)

    def test_a_digest_record_of_an_older_render_is_drift(self):
        self.applied()
        self.put_file(filesync.RECORD, "0" * 64 + "\n")
        found = self.row()
        self.assertEqual(found.status, DRIFT)
        self.assertIn(filesync.CONFIG, found.note)
        self.assertIn("restarts syncthing.service", found.note)

    def test_a_changed_drop_in_is_drift_with_no_restart(self):
        self.applied()
        self.put_file(filesync.DROP_IN, "[Service]\n")
        found = self.row()
        self.assertEqual(found.status, DRIFT)
        self.assertIn(filesync.DROP_IN, found.note)
        self.assertNotIn("restarts syncthing.service", found.note)

    def test_no_identity_yet_is_not_compared(self):
        os.remove(os.path.join(self.root, filesync.DEVICE_FILE))
        found = self.row()
        self.assertEqual(found.status, NOT_COMPARED)
        self.assertIn("identity", found.reason)

    def test_a_refused_plan_is_unknown(self):
        self.applied()
        with open(os.path.join(self.root, "etc", "passwd"), "w") as fob:
            fob.write("root:x:0:0:root:/root:/bin/sh\n")
        found = self.row()
        self.assertEqual(found.status, UNKNOWN)
        self.assertIn("no syncthing user", found.reason)

    def test_not_live_has_no_row(self):
        self.applied()
        self.put_file(filesync.RECORD, "0" * 64 + "\n")
        self.assertIsNone(self.row(live=False))


if __name__ == "__main__":
    unittest.main()
