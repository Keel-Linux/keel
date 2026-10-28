# Copyright (c) 2026 KeelLinux maintainers
"""The blog application carrying the syncthing overlay, and the doubles
the file replication tests share (keel.system.filesync)

The blog fixture (tests/fixtures/manifest/app) replicates
/var/www/blog/content always, /var/www/blog/media unless the search
service is placed (cloud advanced), and excludes
/var/www/blog/content/cache.
"""

import os
import re
import subprocess
from types import SimpleNamespace
from unittest import mock

from manifest_helpers import ManifestCase, app_fixture, install_app, overlay
from manifest_helpers import put, unit

from keel.inspect.tree import Tree
from keel.manifest.facts import gather
from keel.system import dbfollow, filesync, filesync_api

DEVICE = "-".join(["AAAAAAA"] * 8)
PEER = "-".join(["BBBBBBB"] * 8)
OTHER_PEER = "-".join(["CCCCCCC"] * 8)
ADDRESS = "fd42:7a53::10"
PEER_ADDRESS = "fd42:7a53::11"
VIP = "fd00:6b65:1::ffff:100"
CONTENT = "/var/www/blog/content"
MEDIA = "/var/www/blog/media"
CACHE = "/var/www/blog/content/cache"


def doc(mode: str = "cloud_simple", enabled: str = "enabled") -> dict:
    return {
        "version": 1,
        "appliance": {"name": "blog"},
        "installation": {"mode": mode},
        "overlays": {filesync.OVERLAY: enabled},
        "network": {"overlay": {"wireguard": {"address": ADDRESS + "/64"}}},
    }


class SyncCase(ManifestCase):
    """The blog application, carrying the syncthing overlay"""

    def setUp(self):
        super().setUp()
        install_app(self.root)
        text = app_fixture("appliances", "blog").replace(
            "overlays:\n  mariadb:",
            "overlays:\n  syncthing:"
            " {simple: enabled, cloud_simple: enabled,"
            " cloud_advanced: enabled}\n  mariadb:")
        put(self.root, "appliances", "blog", text)
        put(self.root, "overlays", "syncthing", overlay(
            filesync.OVERLAY,
            "processes:\n"
            "  - name: syncthing\n"
            "    unit: syncthing.service\n"
            "    listen: [{port: 22000, protocol: tcp, expose: mesh}]\n"))
        unit(self.root, "syncthing")
        passwd = os.path.join(self.root, "etc", "passwd")
        os.makedirs(os.path.dirname(passwd), exist_ok=True)
        with open(passwd, "w") as fob:
            fob.write("root:x:0:0:root:/root:/bin/sh\n"
                      "syncthing:x:999:999::/var/lib/syncthing:"
                      "/usr/sbin/nologin\n")

    def resolved(self):
        facts = gather(self.root, "blog")
        self.assertEqual(facts.problems, ())
        return facts.resolved

    def observed(self, root: str | None = None, start: bool = False,
                 **kwargs):
        tree = Tree(root or self.root)
        return filesync.observe_filesync(tree, doc(**kwargs),
                                         self.resolved(), start)

    def state(self, **kwargs):
        found = self.observed(**kwargs)
        self.assertIsNotNone(found)
        return found

    def wrote(self, path: str) -> str:
        with open(os.path.join(self.root, path.lstrip("/"))) as fob:
            return fob.read()

    def exists(self, path: str) -> bool:
        return os.path.exists(os.path.join(self.root, path.lstrip("/")))

    def put_file(self, path: str, text: str) -> None:
        full = os.path.join(self.root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fob:
            fob.write(text)

    def with_paths(self, *paths: str, exclude: tuple[str, ...] = ()) -> None:
        """The blog application, replicating `paths`"""
        text = app_fixture("appliances", "blog").replace(
            "overlays:\n  mariadb:",
            "overlays:\n  syncthing:"
            " {simple: enabled, cloud_simple: enabled,"
            " cloud_advanced: enabled}\n  mariadb:")
        old = text[text.index("state:\n  replicate:"):]
        old = old[:old.index("workers:\n")]
        new = "state:\n  replicate:\n" + "".join(
            f"    - '{path}'\n" for path in paths)
        if exclude:
            new += "  exclude:\n" + "".join(
                f"    - '{path}'\n" for path in exclude)
        text = text.replace(old, new)
        put(self.root, "appliances", "blog", text)


class Runner:
    """A subprocess.run stand-in, keyed on the command's words"""

    def __init__(self, device: str = DEVICE, active: bool = True,
                 restart: int = 0, reload: int = 0, on_restart=None):
        self.device = device
        self.active = active
        self.restart = restart
        self.reload = reload
        self.on_restart = on_restart
        self.calls: list[list[str]] = []
        self.kwargs: list[dict] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        self.kwargs.append(kwargs)
        if argv[:2] == ["runuser", "-u"]:
            code = 0 if self.device else 1
            return subprocess.CompletedProcess(
                argv, code, (self.device or "") + "\n", "")
        if argv[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(argv, 0 if self.active
                                               else 3, "", "")
        if argv[:2] == ["systemctl", "restart"]:
            if self.on_restart:
                self.on_restart()
            return subprocess.CompletedProcess(argv, self.restart, "",
                                               "restart refused"
                                               if self.restart else "")
        if argv[:2] == ["systemctl", "daemon-reload"]:
            return subprocess.CompletedProcess(argv, self.reload, "",
                                               "reload refused"
                                               if self.reload else "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    def ran(self, *words: str) -> list[list[str]]:
        return [call for call in self.calls if call[:len(words)] ==
                list(words)]


class FakeApi:
    """syncthing's REST API: the folders' configuration kept as the
    PATCH calls leave it, the requests recorded"""

    def __init__(self, down: bool = False, state: str = "idle",
                 error: str = "", receive_changed: int = 0, need: int = 0,
                 connected: bool = True, ignore_patch: bool = False):
        self.down = down
        self.state = state
        self.error = error
        self.receive_changed = receive_changed
        self.need = need
        self.connected = connected
        self.ignore_patch = ignore_patch
        self.calls: list[tuple] = []
        self.folders: dict[str, dict] = {}
        self.devices: dict[str, dict] = {}

    def __call__(self, key, method, path, body=None):
        self.calls.append((key, method, path, body))
        if self.down:
            raise filesync_api.ApiError(f"{method} {path}: no answer")
        folder = re.match(r"/rest/config/folders/([^?]+)$", path)
        if folder:
            current = self.folders.setdefault(
                folder.group(1), {"paused": True, "type": "", "devices": [],
                                  "versioning": {}})
            if method == "PATCH" and not self.ignore_patch:
                current.update(body)
            return dict(current)
        device = re.match(r"/rest/config/devices/(.+)$", path)
        if device:
            self.devices[device.group(1)] = body
            return None
        if path.startswith("/rest/db/status"):
            return {"state": self.state, "error": self.error,
                    "receiveOnlyChangedFiles": self.receive_changed,
                    "needFiles": self.need}
        if path == "/rest/system/connections":
            return {"connections": {PEER: {"connected": self.connected}}}
        raise filesync_api.ApiError(f"{method} {path}: HTTP 404", 404)

    def cold_start(self, root: str) -> None:
        """What syncthing runs after a restart: the rendered file"""
        from xml.etree import ElementTree
        self.down = False
        top = ElementTree.parse(os.path.join(root, filesync.CONFIG)).getroot()
        for one in top.findall("folder"):
            self.folders[one.get("id")] = {
                "paused": one.findtext("paused") == "true",
                "type": one.get("type"),
                "devices": [{"deviceID": d.get("id")}
                            for d in one.findall("device")],
                "versioning": {"type": one.find("versioning").get("type")}
                if one.find("versioning") is not None else {}}

    def methods(self, method: str) -> list[tuple]:
        return [call for call in self.calls if call[1] == method]


def quiet() -> dbfollow.Followed:
    """A Followed that remembers what it was told"""
    said: list[str] = []
    found = dbfollow.Followed(said.append)
    found.lines = said
    return found


def pair_of(address: str = PEER_ADDRESS) -> SimpleNamespace:
    return SimpleNamespace(peer_address=address, vip=VIP)


def flip_patches(hooks=None):
    """What a flip needs on a machine without syncthing: the binary
    found, the user's uid, and the hooks of roles.d (`hooks` is the
    stand-in for roles.run, or the list of the hooks that failed)"""
    if not callable(hooks):
        hooks = mock.Mock(return_value=list(hooks or []))
    return (
        mock.patch("keel.system.filesync.shutil.which",
                   return_value="/usr/bin/syncthing"),
        mock.patch("keel.system.roles.run", hooks),
        mock.patch("os.fchown"),
        mock.patch("pwd.getpwnam", return_value=SimpleNamespace(
            pw_uid=999, pw_gid=999)),
        mock.patch("keel.system.filesync.time.sleep"),
    )
