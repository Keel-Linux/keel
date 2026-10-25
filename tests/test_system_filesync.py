# Copyright (c) 2026 KeelLinux maintainers
"""keel.system.filesync: the file replication's render, plan and diff rows

0050's amendment (handbook docs/decisions/0050-*.md, 2026-10-20): the
manifest's state.replicate is one syncthing folder per path, send-only
on the proven primary, receive-only on the replica, paused while a node
is in doubt or not proven; state.exclude is the folder's .stignore; the
configuration is rendered and restarts syncthing as etcd's does; the
flip is one operation with the database role's; receiveOnlyChangedFiles
and needFiles feed keel diff and one alert per lasting count.

The blog fixture (tests/fixtures/manifest/app) replicates
/var/www/blog/content always, /var/www/blog/media unless the search
service is placed (cloud advanced), and excludes
/var/www/blog/content/cache. The flip is tested in test_system_filesync_flip,
the REST API in test_system_filesync_api, the alert in
test_system_filesync_watch.
"""

import json
import os
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from manifest_helpers import app_fixture, put
from filesync_helpers import (ADDRESS, CACHE, CONTENT, DEVICE, MEDIA, PEER,
                              PEER_ADDRESS, Runner, SyncCase, doc)
from vip_helpers import KEYS, MESH, NOW, VIP, Pair, address

from keel.diff.filesync import filesync_fields
from keel.diff.report import DRIFT, SAME, UNKNOWN
from keel.inspect.tree import Tree
from keel.manifest.facts import gather
from keel.system import dbfollow, filesync
from keel.system.actions import Note, Refuse, Run, WriteFile


class TestThePaths(SyncCase):
    def test_one_folder_per_replicated_path(self):
        self.assertEqual(filesync.folder_id(CONTENT),
                         filesync.folder_id(CONTENT))
        self.assertNotEqual(filesync.folder_id(CONTENT),
                            filesync.folder_id(MEDIA))
        self.assertTrue(filesync.folder_id(CONTENT).startswith("keel-"))

    def test_the_unless_path_is_not_replicated_when_the_service_is_placed(
            self):
        application = self.resolved().application.item
        self.assertEqual(filesync.effective_paths(application, "simple"),
                         (CONTENT, MEDIA))
        self.assertEqual(
            filesync.effective_paths(application, "cloud_simple"),
            (CONTENT, MEDIA))
        self.assertEqual(
            filesync.effective_paths(application, "cloud_advanced"),
            (CONTENT,))

    def test_a_replicate_entry_that_is_not_a_shape_is_ignored(self):
        application = {"state": {"replicate": ["/x", 3, {"path": "/y"},
                                               {"unless": "search"}]}}
        self.assertEqual(filesync.effective_paths(application, "simple"),
                         ("/x", "/y"))

    def test_the_exclude_is_the_stignore_of_its_folder(self):
        text = filesync.stignore((CACHE, "/var/lib/other"), CONTENT)
        self.assertEqual(text, "/cache\n/cache/**\n")
        self.assertEqual(filesync.stignore((CACHE,), MEDIA), "")
        self.assertEqual(filesync.stignore((), CONTENT), "")

    def test_a_path_that_is_not_safe_is_refused_with_its_reason(self):
        bad = {
            "var/www": "is not an absolute path",
            "/srv/a b": "space",
            "/srv/a\nb": "control",
            "/srv/a\tb": "space",
            "/srv/a*": "pattern",
            "/srv/../etc": "'..'",
            "/srv//data": "normalised",
            "/srv/data/": "normalised",
            "/srv/./data": "normalised",
            "/": "normalised",
            "/var/lib/syncthing": "never replicated",
            "/var/lib/syncthing/index": "never replicated",
            "/var/lib/keel": "never replicated",
            "/etc/ssh": "never replicated",
            "/tmp": "never replicated",
            3: "absolute",
        }
        for path, why in bad.items():
            with self.subTest(path=path):
                found = filesync.path_problem(path)
                self.assertIsNotNone(found)
                self.assertIn(why, found)
        for path in ("/srv/data", "/var/www/blog/content", "/data/a-b_c.d"):
            with self.subTest(path=path):
                self.assertIsNone(filesync.path_problem(path))

    def test_an_injection_path_reaches_no_file(self):
        evil = "/srv/data\n[Service]\nExecStartPre=/bin/sh -c x"
        application = {"state": {"replicate": [evil, "/srv/ok"],
                                 "exclude": ["/srv/ok/a\n#include /x"]}}
        self.assertEqual(filesync.effective_paths(application, "simple"),
                         ("/srv/ok",))
        refused = filesync.rejected_paths(application, "simple")
        self.assertEqual(len(refused), 2)
        self.assertTrue(refused[0].startswith("state.replicate"))
        self.assertTrue(refused[1].startswith("state.exclude"))
        self.assertEqual(filesync.stignore(("/srv/ok/a\n#include /x",),
                                           "/srv/ok"), "")
        unit = filesync.drop_in(filesync.effective_paths(application,
                                                         "simple"))
        self.assertNotIn("/bin/sh -c x", unit)
        self.assertEqual(unit.count("ExecStartPre="), 1)

    def test_a_refused_path_stops_apply_and_the_flip_names_it(self):
        self.with_paths("/srv/ok", "/var/lib/keel")
        found = self.state()
        actions, _ = filesync.plan_filesync(found, False)
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], Refuse)
        self.assertIn("/var/lib/keel", actions[0].summary)

    def test_the_folder_type_with_the_role(self):
        self.assertEqual(filesync.folder_type("primary"), "sendonly")
        self.assertEqual(filesync.folder_type("replica"), "receiveonly")
        self.assertEqual(filesync.folder_type(None), "sendonly")


class TestTheRender(SyncCase):
    def test_a_replica_receives_only_and_keeps_versions(self):
        text = filesync.config_xml(DEVICE, PEER, PEER_ADDRESS, ADDRESS,
                                   "key", (CONTENT, MEDIA), "replica")
        self.assertIn(f'<folder id="{filesync.folder_id(CONTENT)}"', text)
        self.assertIn(f'path="{CONTENT}" type="receiveonly"', text)
        self.assertIn(f'<device id="{DEVICE}" />', text)
        self.assertIn(f'<device id="{PEER}" />', text)
        self.assertIn("<copyOwnershipFromParent>true"
                      "</copyOwnershipFromParent>", text)
        self.assertIn("<paused>false</paused>", text)
        self.assertIn('<versioning type="simple">', text)
        self.assertIn('<param key="keep" val="5" />', text)
        self.assertIn(f"<address>tcp://[{PEER_ADDRESS}]:22000</address>",
                      text)
        self.assertIn(f"<listenAddress>tcp://[{ADDRESS}]:22000"
                      "</listenAddress>", text)
        self.assertIn("<globalAnnounceEnabled>false"
                      "</globalAnnounceEnabled>", text)
        self.assertIn("<localAnnounceEnabled>false</localAnnounceEnabled>",
                      text)
        self.assertIn("<relaysEnabled>false</relaysEnabled>", text)
        self.assertIn("<natEnabled>false</natEnabled>", text)
        self.assertIn("<urAccepted>-1</urAccepted>", text)
        self.assertIn("<crashReportingEnabled>false"
                      "</crashReportingEnabled>", text)
        self.assertIn("<address>127.0.0.1:8384</address>", text)
        self.assertIn("<apikey>key</apikey>", text)
        self.assertIn('fsWatcherDelayS="1"', text)

    def test_a_primary_sends_only_and_keeps_no_versions(self):
        text = filesync.config_xml(DEVICE, PEER, PEER_ADDRESS, ADDRESS,
                                   "key", (CONTENT,), "primary")
        self.assertIn(f'path="{CONTENT}" type="sendonly"', text)
        self.assertNotIn("versioning", text)

    def test_an_unproven_node_pauses_its_folders(self):
        text = filesync.config_xml(DEVICE, None, None, ADDRESS, "key",
                                   (CONTENT,), None)
        self.assertIn("<paused>true</paused>", text)
        self.assertNotIn(f'<device id="{PEER}">', text)

    def test_without_addresses_it_renders_no_peer_and_a_fallback_listen(
            self):
        text = filesync.config_xml(DEVICE, None, None, None, "key",
                                   (CONTENT,), "primary")
        self.assertIn("<listenAddress>tcp://:0</listenAddress>", text)
        self.assertNotIn("<address>tcp://", text)

    def test_the_drop_in_grants_the_home_and_the_paths(self):
        self.assertEqual(filesync.drop_in((CONTENT, MEDIA)), (
            "# Written by keel (keel system filesync): the syncthing unit"
            " may\n"
            "# write its home and the replicated paths only (0050's\n"
            "# amendment, point 6).\n"
            "[Service]\n"
            "ReadWritePaths=/var/lib/syncthing -/var/www/blog/content"
            " -/var/www/blog/media\n"
            f"ExecStartPre=+{filesync.START_PAUSED}\n"))

    def test_a_path_that_is_not_there_yet_does_not_stop_the_unit(self):
        # systemd skips a "-" path that is missing; without the prefix
        # the unit fails with 226/NAMESPACE
        line = [one for one in filesync.drop_in((CONTENT,)).splitlines()
                if one.startswith("ReadWritePaths=")][0]
        paths = line.split("=", 1)[1].split()
        self.assertEqual(paths[1:], [f"-{CONTENT}"])

    def start_paused(self, state: str | None, config: str | None):
        """Run the drop-in's ExecStartPre, as a boot would, on a copy of
        the paths under the test root"""
        import subprocess
        line = [one for one in filesync.drop_in((CONTENT,)).splitlines()
                if one.startswith("ExecStartPre=")][0]
        command = line.split("=+", 1)[1]
        for name in (filesync.STATE_FILE, filesync.CONFIG):
            command = command.replace("/" + name,
                                      os.path.join(self.root, name))
        if state is not None:
            self.put_file(filesync.STATE_FILE, state)
        if config is not None:
            self.put_file(filesync.CONFIG, config)
        script = command.split("'")[1]
        done = subprocess.run(["/bin/sh", "-c", script], check=False)
        self.assertEqual(done.returncode, 0)
        return self.wrote(filesync.CONFIG) if config is not None else None

    def test_a_boot_without_state_starts_every_folder_paused(self):
        sent = filesync.config_xml(DEVICE, PEER, PEER_ADDRESS, ADDRESS, "k",
                                   (CONTENT, MEDIA), "primary")
        self.assertEqual(sent.count("<paused>false</paused>"), 2)
        text = self.start_paused(None, sent)
        self.assertEqual(text.count("<paused>true</paused>"), 2)
        self.assertNotIn("<paused>false</paused>", text)
        # the rest of the file is what keel wrote
        self.assertEqual(text.replace("<paused>true", "<paused>false"), sent)

    def test_a_start_with_a_state_leaves_the_file_alone(self):
        sent = filesync.config_xml(DEVICE, PEER, PEER_ADDRESS, ADDRESS, "k",
                                   (CONTENT,), "primary")
        self.assertEqual(self.start_paused("primary\n", sent), sent)

    def test_a_first_start_without_a_file_does_not_fail(self):
        self.start_paused(None, None)

    def test_the_state_does_not_survive_a_reboot(self):
        # /run is empty at boot: no state is paused
        self.assertTrue(filesync.STATE_FILE.startswith("run/"))

    def test_an_empty_api_key_is_not_rendered(self):
        with self.assertRaises(ValueError):
            filesync.config_xml(DEVICE, None, None, ADDRESS, "",
                                (CONTENT,), "primary")

    def test_a_path_cannot_break_out_of_the_xml(self):
        path = '/srv/a"><x/>'
        text = filesync.config_xml(DEVICE, None, None, ADDRESS, "key",
                                   (path,), "primary")
        from xml.etree import ElementTree
        folder = ElementTree.fromstring(text).find("folder")
        self.assertEqual(folder.get("path"), path)
        self.assertIsNone(folder.find("x"))
        self.assertNotIn('"><x/>', text)


class TestTheObservation(SyncCase):
    def test_nothing_when_the_chain_has_no_syncthing_overlay(self):
        put(self.root, "appliances", "blog",
            app_fixture("appliances", "blog"))
        self.assertIsNone(self.observed())

    def test_nothing_when_the_application_replicates_no_path(self):
        facts = gather(self.root, "core")
        found = filesync.observe_filesync(Tree(self.root), doc(),
                                          facts.resolved)
        self.assertIsNone(found)

    def test_the_state_reads_what_is_there(self):
        found = self.state()
        self.assertEqual(found.paths, (CONTENT, MEDIA))
        self.assertEqual(found.excludes, (CACHE,))
        self.assertIsNone(found.role)
        self.assertIsNone(found.device)
        self.assertEqual(found.address, ADDRESS)
        self.assertIsNone(found.problem)

    def test_an_enabled_overlay_without_the_user_is_a_problem(self):
        passwd = os.path.join(self.root, "etc", "passwd")
        with open(passwd, "w") as fob:
            fob.write("root:x:0:0:root:/root:/bin/sh\n")
        found = self.state()
        self.assertIsNotNone(found.problem)

    def test_a_disabled_overlay_is_no_problem(self):
        found = self.state(enabled="disabled")
        self.assertIsNone(found.problem)

    def test_the_state_file_of_the_flips_is_read(self):
        self.put_file(filesync.STATE_FILE, "replica\n")
        self.assertEqual(self.state().role, "replica")
        self.put_file(filesync.STATE_FILE, "primary\n")
        self.assertEqual(self.state().role, "primary")

    def test_nothing_proven_is_paused_whatever_the_role_file_says(self):
        # a stale role file must not send again what a flip paused
        self.put_file("var/lib/keel/role",
                      "role=primary\nreplicates=database,files\nvip=x\n")
        self.assertIsNone(self.state().role)
        self.put_file(filesync.STATE_FILE, "paused\n")
        self.assertIsNone(self.state().role)
        self.put_file(filesync.STATE_FILE, "nonsense\n")
        self.assertIsNone(self.state().role)

    def test_a_path_the_manifest_gets_wrong_is_a_problem(self):
        self.with_paths("/srv/data", "/var/lib/keel")
        found = self.state()
        self.assertEqual(found.paths, ("/srv/data",))
        self.assertIn("/var/lib/keel", found.problem)
        actions, restart = filesync.plan_filesync(found, False)
        self.assertEqual(actions, [Refuse(found.problem)])

    def test_a_missing_stfolder_of_an_existing_path_is_a_marker(self):
        os.makedirs(os.path.join(self.root, CONTENT.lstrip("/")))
        found = self.state()
        self.assertEqual(found.markers, (CONTENT.lstrip("/"),))

    def test_a_live_run_makes_the_identity_and_the_api_key(self):
        done = subprocess.CompletedProcess([], 0, DEVICE + "\n", "")
        with mock.patch("keel.system.filesync.ROOT_DEFAULT", self.root), \
                mock.patch("keel.system.filesync.shutil.which",
                           return_value="/usr/bin/syncthing"), \
                mock.patch("keel.system.filesync.subprocess.run",
                           return_value=done) as ran:
            found = self.state(start=True)
        self.assertEqual(found.device, DEVICE)
        self.assertEqual(self.wrote(filesync.DEVICE_FILE), DEVICE + "\n")
        self.assertTrue(os.path.isfile(
            os.path.join(self.root, filesync.APIKEY)))
        mode = os.stat(os.path.join(self.root, filesync.APIKEY)).st_mode
        self.assertEqual(mode & 0o777, filesync.SECRET_MODE)
        self.assertEqual(found.apikey, self.wrote(filesync.APIKEY).strip())
        self.assertTrue(any(call.args[0][:2] == ["runuser", "-u"]
                            for call in ran.call_args_list))

    def test_an_identity_of_the_wrong_shape_is_not_kept(self):
        done = subprocess.CompletedProcess([], 0, "not-a-device\n", "")
        with mock.patch("keel.system.filesync.ROOT_DEFAULT", self.root), \
                mock.patch("keel.system.filesync.shutil.which",
                           return_value="/usr/bin/syncthing"), \
                mock.patch("keel.system.filesync.subprocess.run",
                           return_value=done):
            found = self.state(start=True)
        self.assertIsNone(found.device)
        self.assertFalse(os.path.exists(
            os.path.join(self.root, filesync.DEVICE_FILE)))


class TestThePlan(SyncCase):
    def test_without_an_identity_only_a_note(self):
        actions, restart = filesync.plan_filesync(self.state(), False)
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], Note)
        self.assertFalse(restart)

    def test_a_refused_problem(self):
        state = self.state()
        state = filesync.FileSyncState(**{**state.__dict__,
                                          "problem": "no user"})
        actions, restart = filesync.plan_filesync(state, False)
        self.assertEqual(actions, [Refuse("no user")])
        self.assertFalse(restart)

    def test_a_full_first_render_writes_everything_and_restarts(self):
        state = filesync.FileSyncState(**{**self.state().__dict__,
                                          "device": DEVICE,
                                          "apikey": "key"})
        actions, restart = filesync.plan_filesync(state, False)
        paths = [action.path for action in actions
                 if isinstance(action, WriteFile)]
        self.assertIn(filesync.CONFIG, paths)
        self.assertIn(filesync.RECORD, paths)
        self.assertIn(filesync.DROP_IN, paths)
        self.assertIn(f"{CONTENT.lstrip('/')}/.stignore", paths)
        self.assertTrue(restart)
        config = next(action for action in actions
                      if isinstance(action, WriteFile)
                      and action.path == filesync.CONFIG)
        self.assertEqual(config.mode, filesync.CONFIG_MODE)
        self.assertEqual(config.owner, filesync.USER)
        record = next(action for action in actions
                      if isinstance(action, WriteFile)
                      and action.path == filesync.RECORD)
        self.assertEqual(record.content,
                         filesync.render_digest(config.content) + "\n")
        self.assertFalse(any(isinstance(action, Run) for action in actions))

    def test_no_api_key_renders_nothing(self):
        state = filesync.FileSyncState(**{**self.state().__dict__,
                                          "device": DEVICE, "apikey": None})
        actions, restart = filesync.plan_filesync(state, False)
        self.assertEqual(len(actions), 1)
        self.assertIsInstance(actions[0], Note)
        self.assertFalse(restart)

    def test_the_render_comes_from_the_state_file_alone(self):
        # in doubt after a primary: the role file may still say primary
        self.put_file("var/lib/keel/role",
                      "role=primary\nreplicates=database,files\nvip=x\n")
        state = filesync.FileSyncState(**{**self.state().__dict__,
                                          "device": DEVICE, "apikey": "key"})
        actions, _ = filesync.plan_filesync(state, False)
        config = next(a for a in actions if isinstance(a, WriteFile)
                      and a.path == filesync.CONFIG)
        self.assertIn("<paused>true</paused>", config.content)
        self.assertNotIn("<paused>false</paused>", config.content)

    def matched(self, before):
        """The state with everything the render would write already
        there, so one asked difference stays the only difference"""
        rendered = filesync.config_xml(DEVICE, None, None, ADDRESS, "key",
                                       before.paths, before.role)
        return filesync.FileSyncState(**{
            **before.__dict__, "device": DEVICE, "apikey": "key",
            "record": filesync.render_digest(rendered),
            "drop_in": filesync.drop_in(before.paths),
            "stignore": {path: filesync.stignore(before.excludes, path)
                         for path in before.paths},
            "markers": ()})

    def test_a_drop_in_change_reloads_only(self):
        before = self.state()
        state = filesync.FileSyncState(**{
            **self.matched(before).__dict__,
            "drop_in": "# an older drop-in\n"})
        actions, restart = filesync.plan_filesync(state, True)
        self.assertFalse(restart)
        writes = [a.path for a in actions if isinstance(a, WriteFile)]
        self.assertEqual(writes, [filesync.DROP_IN])
        runs = [a for a in actions if isinstance(a, Run)]
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].argv, ("systemctl", "daemon-reload"))

    def test_a_drop_in_change_under_another_root_reloads_not(self):
        state = self.matched(self.state())
        actions, _ = filesync.plan_filesync(state, False)
        self.assertFalse(any(isinstance(action, Run) for action in actions))

    def test_the_stignore_and_the_marker_follow_what_is_there(self):
        os.makedirs(os.path.join(self.root, CONTENT.lstrip("/")))
        before = self.state()
        state = filesync.FileSyncState(
            **{**self.matched(before).__dict__, "markers": before.markers,
               "stignore": {path: None for path in before.paths}})
        actions, _ = filesync.plan_filesync(state, False)
        paths = [action.path for action in actions
                 if isinstance(action, WriteFile)]
        self.assertIn(f"{CONTENT.lstrip('/')}/.stignore", paths)
        self.assertIn(f"{CONTENT.lstrip('/')}/.stfolder", paths)
        self.assertNotIn(f"{MEDIA.lstrip('/')}/.stfolder", paths)


def row(content=0, need=0, **more):
    return {"receiveOnlyChangedFiles": content, "needFiles": need,
            "state": "idle", "error": "", "paused": False,
            "type": "sendonly", **more}


class TestTheDiffRows(SyncCase):
    def fields(self, counts, live=True, mode="cloud_simple", state=None,
               peer=PEER, connected=True):
        document = doc(mode=mode)
        if state:
            self.put_file(filesync.STATE_FILE, state + "\n")
        if peer:
            self.put_file(filesync.PEER_FILE, peer + "\n")
        with mock.patch("keel.system.filesync_api.counts",
                        return_value=counts) as asked, \
                mock.patch("keel.system.filesync_api.peer_connected",
                           return_value=connected):
            found = filesync_fields(document, self.root, live)
        return found, asked

    def named(self, found, name):
        return next(one for one in found if one.field == name)

    def test_four_rows_per_path_and_the_peer(self):
        clean = {path: row() for path in (CONTENT, MEDIA)}
        found, asked = self.fields(clean, state="primary")
        self.assertEqual(len(found), 7)
        self.assertTrue(all(one.status == SAME for one in found), found)
        self.assertEqual(asked.call_args.args[1], (CONTENT, MEDIA))

    def test_a_count_is_drift_with_the_note(self):
        dirty = {CONTENT: row(content=4), MEDIA: row()}
        found, _ = self.fields(dirty, state="primary")
        drift = self.named(found, f"filesync.{CONTENT}"
                                  ".receiveOnlyChangedFiles")
        self.assertEqual(drift.status, DRIFT)
        self.assertEqual(drift.observed, "4")
        self.assertIn("one-writer", drift.note)

    def test_no_answer_is_unknown(self):
        found, _ = self.fields(None)
        self.assertTrue(all(one.status == UNKNOWN for one in found))

    def test_a_paused_folder_is_shown_as_drift(self):
        paused = {CONTENT: row(paused=True, state="paused"),
                  MEDIA: row(paused=True, state="paused")}
        found, _ = self.fields(paused)
        one = self.named(found, f"filesync.{CONTENT}.folder")
        self.assertEqual(one.status, DRIFT)
        self.assertEqual(one.observed, "paused")
        self.assertEqual(one.declared, "paused")
        self.assertIn("in doubt", one.note)

    def test_the_direction_is_compared_with_the_last_flip(self):
        replica = {path: row(type="receiveonly") for path in (CONTENT, MEDIA)}
        found, _ = self.fields(replica, state="replica")
        self.assertEqual(self.named(
            found, f"filesync.{CONTENT}.folder").status, SAME)
        found, _ = self.fields(replica, state="primary")
        one = self.named(found, f"filesync.{CONTENT}.folder")
        self.assertEqual((one.status, one.declared, one.observed),
                         (DRIFT, "sendonly", "receiveonly"))

    def test_a_folder_in_error_is_not_a_clean_one(self):
        broken = {CONTENT: row(state="error", error="folder path missing"),
                  MEDIA: row()}
        found, _ = self.fields(broken, state="primary")
        one = self.named(found, f"filesync.{CONTENT}.folder")
        self.assertEqual(one.status, DRIFT)
        self.assertIn("folder path missing", one.observed)

    def test_a_peer_that_is_unknown_or_not_connected_is_drift(self):
        clean = {path: row() for path in (CONTENT, MEDIA)}
        found, _ = self.fields(clean, state="primary", peer=None)
        one = self.named(found, "filesync.peer")
        self.assertEqual((one.status, one.observed), (DRIFT, "unknown"))
        self.assertIn("peer unknown or not connected", one.note)
        found, _ = self.fields(clean, state="primary", connected=False)
        one = self.named(found, "filesync.peer")
        self.assertEqual((one.status, one.observed),
                         (DRIFT, "not connected"))

    def test_not_live_or_not_enabled_compares_nothing(self):
        clean = {path: row() for path in (CONTENT, MEDIA)}
        found, _ = self.fields(clean, live=False)
        self.assertEqual(found, [])
        document = doc(enabled="disabled")
        with mock.patch("keel.system.filesync_api.counts") as asked:
            self.assertEqual(filesync_fields(document, self.root, True), [])
        asked.assert_not_called()

    def test_the_advanced_mode_skips_the_unless_path(self):
        clean = {CONTENT: row()}
        found, asked = self.fields(clean, mode="cloud_advanced",
                                   state="primary")
        self.assertEqual(asked.call_args.args[1], (CONTENT,))
        self.assertEqual(len(found), 4)


class TestAnApplianceWithoutReplicatedPaths(SyncCase):
    """The coordinator's rule: an appliance with no state.replicate
    sees no change at all — no identity, no members' message, no diff
    row, and the role file keeps replicates=database"""

    def setUp(self):
        super().setUp()
        put(self.root, "appliances", "blog",
            app_fixture("appliances", "blog").replace(
                "state:\n"
                "  replicate:\n"
                "    - /var/www/blog/content\n"
                "    - {path: /var/www/blog/media, unless: search}\n"
                "  exclude:\n"
                "    - /var/www/blog/content/cache\n", ""))

    def test_observe_plans_nothing(self):
        self.assertIsNone(self.observed())
        found = filesync.replicates_files(self.root, doc())
        self.assertFalse(found)

    def test_the_flip_makes_no_identity_and_asks_nobody(self):
        class Here:
            def say(self, kind, at, body):
                raise AssertionError("the members' channel was used")

        found = dbfollow.Followed(lambda line: None)
        with mock.patch("keel.system.filesync.shutil.which",
                        return_value="/usr/bin/syncthing"), \
                mock.patch("keel.system.roles.run") as hooks:
            filesync.follow_flip(self.root, doc(), None, "primary", found,
                                 Runner(), here=Here())
        hooks.assert_not_called()
        for path in (filesync.DEVICE_FILE, filesync.PEER_FILE, filesync.APIKEY,
                     filesync.CONFIG, filesync.RECORD, filesync.STATE_FILE,
                     filesync.PENDING):
            self.assertFalse(os.path.exists(os.path.join(self.root, path)),
                             path)

    def test_no_diff_rows_and_the_database_role_text(self):
        self.assertEqual(filesync_fields(doc(), self.root, True), [])
        self.assertFalse(filesync.replicates_files(self.root, doc()))
        self.assertFalse(filesync.replicates_files(self.root,
                                                   doc(mode="simple")))
        self.assertFalse(filesync.flip_pending(self.root, doc()))


class TestTheUndeclaredOverlay(SyncCase):
    """keel#224: a manifest default is not enough, the spec must write
    `overlays.syncthing` out, or the pair forms with the files off"""

    def undeclared(self, document):
        return filesync.undeclared_problem(self.root, document)

    def test_a_spec_without_the_overlay_is_refused(self):
        document = doc()
        del document["overlays"]
        problem = self.undeclared(document)
        self.assertIn("overlays.syncthing", problem)
        self.assertIn("0027", problem)

    def test_apply_refuses_a_spec_without_the_overlay(self):
        from keel import commands, exits
        document = doc()
        del document["overlays"]
        with mock.patch("keel.commands.system.observe") as observed, \
                mock.patch("keel.commands.error") as said:
            code = commands.apply_system(document, self.root, True)
        self.assertEqual(code, exits.SPEC_INVALID)
        self.assertIn("overlays.syncthing", said.call_args.args[0])
        observed.assert_not_called()

    def test_a_spec_that_declares_the_overlay_is_not_refused(self):
        self.assertIsNone(self.undeclared(doc()))

    def test_a_spec_that_turns_the_overlay_off_is_not_refused(self):
        self.assertIsNone(self.undeclared(doc(enabled="disabled")))

    def test_an_appliance_without_replicated_paths_is_not_refused(self):
        self.with_paths()
        document = doc()
        del document["overlays"]
        self.assertIsNone(self.undeclared(document))

    def test_a_spec_without_an_appliance_is_not_refused(self):
        self.assertIsNone(self.undeclared({"version": 1}))


class TestTheFollowWiring(SyncCase):
    def test_the_flip_is_delegated_with_a_channel(self):
        root = self.root
        spec = os.path.join(self.tmpdir, "instance.yaml")
        with open(spec, "w") as fob:
            fob.write("version: 1\n")
        found = dbfollow.Followed(lambda line: None)
        pair = SimpleNamespace(peer_address=PEER_ADDRESS, vip="vip-1")
        with mock.patch("keel.system.filesync.follow_flip") as flipped:
            dbfollow._filesync_flip(root, doc(), pair, "primary", found,
                                    Runner(), spec)
        flipped.assert_called_once()
        args, kwargs = flipped.call_args
        self.assertEqual(args[:6], (root, doc(), pair, "primary", found,
                                    args[5]))
        self.assertEqual(args[3], "primary")
        self.assertEqual(kwargs["here"].node.root, root)


class TestTheDeviceAsk(Pair):
    """The `device` vipmsg kind over the members' channel (0050's
    amendment, point 3): answered only to the pair's other member,
    404 while this node holds no identity"""

    def test_answered_to_the_pair_member_alone(self):
        from keel.mesh import vipmsg, vipserve
        from keel.mesh.memberlink import LinkError
        from keel.system import filesync
        self.nodes()
        a, b = self.all[0], self.all[1]
        self.assertIsNone(filesync.device_id(a.root))
        with self.assertRaises(LinkError):
            b.say(vipmsg.DEVICE, address(0), {"vip": VIP})
        os.makedirs(os.path.join(a.root, filesync.DIR), exist_ok=True)
        with open(os.path.join(a.root, filesync.DEVICE_FILE), "w") as fob:
            fob.write(DEVICE + "\n")
        answer = b.say(vipmsg.DEVICE, address(0), {"vip": VIP})
        self.assertEqual(json.loads(answer.decode()), {"id": DEVICE})
        self.assertIn("device ID given to", self.text(0))
        # a node that is not of the pair is refused
        body = vipmsg.signed(self.all[2].root, vipmsg.DEVICE, MESH.hex(),
                             KEYS[2], NOW, {"vip": VIP})
        found = vipserve.answer(a, body, KEYS[2])
        self.assertEqual(found.status, 403)


if __name__ == "__main__":
    unittest.main()
