# Copyright (c) 2026 KeelLinux maintainers
"""keel.system.filesync_api: syncthing's REST API on the loopback

The API key goes in a header held in this process; it is never in the
arguments of a command, which any user can read in /proc.
"""

import http.client
import json
import unittest
from unittest import mock

from filesync_helpers import CONTENT, DEVICE, MEDIA, PEER, FakeApi, SyncCase

from keel.system import filesync_api, filesync_io


class FakeConnection:
    """http.client.HTTPConnection for one answer"""

    made: list["FakeConnection"] = []

    def __init__(self, status=200, body=b"{}", error=None):
        self.status = status
        self.body = body
        self.error = error
        self.sent: tuple | None = None
        self.closed = False

    def request(self, method, path, body=None, headers=None):
        self.sent = (method, path, body, headers)
        if self.error:
            raise self.error

    def getresponse(self):
        return mock.Mock(status=self.status, read=lambda: self.body)

    def close(self):
        self.closed = True


def connecting(connection):
    def make(host, port, timeout=None):
        connection.host, connection.port = host, port
        return connection
    return mock.patch("keel.system.filesync_api.http.client.HTTPConnection",
                      make)


class TestTheRequest(unittest.TestCase):
    def test_the_key_is_a_header_and_the_call_goes_to_the_loopback(self):
        connection = FakeConnection(body=b'{"a": 1}')
        with connecting(connection):
            found = filesync_api.request("secret", "PATCH", "/rest/x",
                                         {"paused": True})
        self.assertEqual(found, {"a": 1})
        method, path, body, headers = connection.sent
        self.assertEqual((method, path), ("PATCH", "/rest/x"))
        self.assertEqual(headers["X-API-Key"], "secret")
        self.assertEqual(json.loads(body), {"paused": True})
        self.assertEqual((connection.host, connection.port),
                         ("127.0.0.1", 8384))
        self.assertTrue(connection.closed)

    def test_no_secret_is_in_a_command_line(self):
        # the old way ran curl with -H "X-API-Key: ..."; now there is no
        # command at all
        import subprocess
        with connecting(FakeConnection()), \
                mock.patch.object(subprocess, "run") as ran, \
                mock.patch.object(subprocess, "Popen") as popen:
            filesync_api.request("secret", "GET", "/rest/x")
        ran.assert_not_called()
        popen.assert_not_called()

    def test_an_empty_answer_is_none(self):
        with connecting(FakeConnection(status=200, body=b"")):
            self.assertIsNone(filesync_api.request("k", "PUT", "/x", {}))

    def test_a_refusal_has_its_status_and_not_the_key(self):
        with connecting(FakeConnection(status=404)):
            with self.assertRaises(filesync_api.ApiError) as raised:
                filesync_api.request("secret", "GET", "/rest/x")
        self.assertEqual(raised.exception.status, 404)
        self.assertNotIn("secret", str(raised.exception))

    def test_no_answer_has_no_status(self):
        for error in (ConnectionRefusedError("down"),
                      http.client.BadStatusLine("x"), TimeoutError()):
            with self.subTest(error=error):
                with connecting(FakeConnection(error=error)):
                    with self.assertRaises(filesync_api.ApiError) as raised:
                        filesync_api.request("k", "GET", "/x")
                self.assertIsNone(raised.exception.status)

    def test_a_body_that_is_not_json_is_an_error(self):
        with connecting(FakeConnection(body=b"<html>")):
            with self.assertRaises(filesync_api.ApiError):
                filesync_api.request("k", "GET", "/x")

    def test_no_key_is_refused_before_any_call(self):
        with connecting(FakeConnection()):
            with self.assertRaises(filesync_api.ApiError):
                filesync_api.request("", "GET", "/x")


class TestTheFolders(unittest.TestCase):
    def test_a_pause_sets_the_pause_only(self):
        self.assertEqual(filesync_api.folder_body(
            CONTENT, "paused", DEVICE, PEER), {"paused": True})

    def test_a_primary_sends_and_a_replica_receives_with_versions(self):
        primary = filesync_api.folder_body(CONTENT, "primary", DEVICE, PEER)
        self.assertEqual(primary["type"], "sendonly")
        self.assertFalse(primary["paused"])
        self.assertEqual(primary["versioning"]["type"], "")
        self.assertEqual(len(primary["devices"]), 2)
        replica = filesync_api.folder_body(CONTENT, "replica", DEVICE, None)
        self.assertEqual(replica["type"], "receiveonly")
        self.assertEqual(replica["versioning"]["params"], {"keep": "5"})
        self.assertEqual(len(replica["devices"]), 1)

    def test_apply_sets_the_peer_and_the_folders_and_reads_them_back(self):
        api = FakeApi()
        with mock.patch("keel.system.filesync_api.request", api):
            filesync_api.apply_folders("k", (CONTENT, MEDIA), "primary",
                                       DEVICE, PEER, "fd42::1")
        self.assertEqual(api.devices[PEER]["addresses"],
                         ["tcp://[fd42::1]:22000"])
        self.assertEqual(len(api.methods("PATCH")), 2)
        self.assertEqual(len(api.methods("GET")), 2)

    def test_apply_without_a_peer_address_uses_dynamic(self):
        api = FakeApi()
        with mock.patch("keel.system.filesync_api.request", api):
            filesync_api.apply_folders("k", (CONTENT,), "replica", DEVICE,
                                       PEER, None)
        self.assertEqual(api.devices[PEER]["addresses"], ["dynamic"])

    def test_a_folder_that_is_not_as_asked_is_an_error(self):
        wrong = (
            ({"paused": False}, "paused"),
            ({"paused": False, "type": "sendonly", "devices": []}, "type"),
            ({"paused": False, "type": "receiveonly", "devices": []},
             "peer"),
        )
        for config, why in wrong:
            with self.subTest(why=why):
                target = "paused" if why == "paused" else (
                    "primary" if why == "type" else "replica")
                if why == "paused":
                    config = {"paused": False}
                with mock.patch("keel.system.filesync_api.request",
                                return_value=config):
                    with self.assertRaises(filesync_api.ApiError):
                        filesync_api.verify("k", (CONTENT,), target, PEER)

    def test_no_configuration_is_an_error(self):
        with mock.patch("keel.system.filesync_api.request",
                        return_value=None):
            with self.assertRaises(filesync_api.ApiError):
                filesync_api.verify("k", (CONTENT,), "primary", None)


class TestTheCounts(SyncCase):
    def key(self):
        self.put_file(filesync_io.APIKEY, "key\n")

    def counts(self, api, paths=(CONTENT, MEDIA)):
        with mock.patch("keel.system.filesync_api.request", api):
            return filesync_api.counts(self.root, paths)

    def test_the_counters_state_and_pause_of_every_folder(self):
        self.key()
        api = FakeApi(receive_changed=2, need=1)
        api.folders = {filesync_io.folder_id(p): {"paused": False,
                                                  "type": "receiveonly"}
                       for p in (CONTENT, MEDIA)}
        found = self.counts(api)
        self.assertEqual(found[CONTENT], {
            "receiveOnlyChangedFiles": 2, "needFiles": 1, "state": "idle",
            "error": "", "paused": False, "type": "receiveonly"})
        self.assertEqual(set(found), {CONTENT, MEDIA})

    def test_a_paused_folder_is_not_asked_for_its_status(self):
        self.key()
        api = FakeApi()
        api.folders = {filesync_io.folder_id(CONTENT): {"paused": True,
                                                        "type": "sendonly"}}
        found = self.counts(api, (CONTENT,))
        self.assertTrue(found[CONTENT]["paused"])
        self.assertEqual(found[CONTENT]["state"], "paused")
        self.assertFalse([c for c in api.calls
                          if c[2].startswith("/rest/db/status")])

    def test_a_folder_the_api_refuses_has_the_error_not_a_clean_row(self):
        self.key()

        def api(key, method, path, body=None):
            if path.startswith("/rest/db/status"):
                raise filesync_api.ApiError("GET status: HTTP 500", 500)
            return {"paused": False, "type": "sendonly"}

        found = self.counts(api, (CONTENT,))
        self.assertIn("HTTP 500", found[CONTENT]["error"])

    def test_no_key_or_no_answer_is_none(self):
        self.assertIsNone(filesync_api.counts(self.root, (CONTENT,)))
        self.key()
        self.assertIsNone(self.counts(FakeApi(down=True), (CONTENT,)))

    def test_an_answer_of_the_wrong_shape_is_none(self):
        self.key()
        self.assertIsNone(self.counts(lambda *a, **k: None, (CONTENT,)))
        self.assertIsNone(self.counts(lambda *a, **k: [1], (CONTENT,)))

    def test_the_peer_is_connected_or_not_or_unknown(self):
        self.key()
        with mock.patch("keel.system.filesync_api.request",
                        FakeApi(connected=True)):
            self.assertTrue(filesync_api.peer_connected(self.root, PEER))
        with mock.patch("keel.system.filesync_api.request",
                        FakeApi(connected=False)):
            self.assertFalse(filesync_api.peer_connected(self.root, PEER))
        with mock.patch("keel.system.filesync_api.request",
                        FakeApi(down=True)):
            self.assertIsNone(filesync_api.peer_connected(self.root, PEER))
        self.assertIsNone(filesync_api.peer_connected(self.root, None))

    def test_the_peer_without_a_key_is_unknown(self):
        self.assertIsNone(filesync_api.peer_connected(self.root, PEER))


if __name__ == "__main__":
    unittest.main()
