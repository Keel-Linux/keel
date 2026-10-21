# Copyright (c) 2026 KeelLinux maintainers
"""Syncthing's REST API on the loopback (0050's amendment)

keel sets a folder's type and pause through the API, so a flip of the VIP
does not restart syncthing, and reads the folders' state through it. The
API key stays in this process: it goes in a request header and never in
the arguments of a command, which any user can read in /proc.
"""

import http.client
import json

from keel.system import filesync_io as io

GUI_ADDRESS = "127.0.0.1"
GUI_PORT = 8384
PORT = 22000
TIMEOUT = 5
VERSIONING_KEEP = 5
SEND = "sendonly"
RECEIVE = "receiveonly"
COUNTERS = ("receiveOnlyChangedFiles", "needFiles")


class ApiError(Exception):
    """The API did not do what was asked; `status` is the HTTP code, or
    None when there was no answer at all"""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def key_of(root: str) -> str | None:
    return io.read(root, io.APIKEY)


def request(key: str, method: str, path: str, body=None):
    """One call; the decoded JSON of the answer, or None for no body"""
    if not key:
        raise ApiError("there is no API key")
    headers = {"X-API-Key": key}
    data = None
    if body is not None:
        data = json.dumps(body)
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection(GUI_ADDRESS, GUI_PORT,
                                            timeout=TIMEOUT)
    try:
        connection.request(method, path, data, headers)
        answer = connection.getresponse()
        raw = answer.read()
    except (OSError, http.client.HTTPException) as e:
        raise ApiError(f"{method} {path}: no answer ({e})") from e
    finally:
        connection.close()
    if answer.status >= 300:
        raise ApiError(f"{method} {path}: HTTP {answer.status}",
                       answer.status)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError as e:
        raise ApiError(f"{method} {path}: the answer is not JSON") from e


def folder_body(path: str, target: str, device: str, peer: str | None
                ) -> dict:
    """The part of a folder's configuration a flip sets. A pause sets
    the pause only: the direction comes back with the proven role"""
    if target == io.PAUSED:
        return {"paused": True}
    devices = [{"deviceID": device}] + (
        [{"deviceID": peer}] if peer else [])
    versioning = ({"type": "simple", "params": {"keep": str(VERSIONING_KEEP)}}
                  if target == io.REPLICA else
                  {"type": "", "params": {}})
    return {"type": RECEIVE if target == io.REPLICA else SEND,
            "paused": False, "devices": devices, "versioning": versioning}


def apply_folders(key: str, paths: tuple[str, ...], target: str,
                  device: str, peer: str | None,
                  peer_address: str | None) -> None:
    """Set every folder to `target` and read it back; ApiError when a
    folder is not as asked"""
    if peer and target != io.PAUSED:
        device_body = {"deviceID": peer, "name": "keel-peer",
                       "compression": "metadata",
                       "addresses": ([f"tcp://[{peer_address}]:{PORT}"]
                                     if peer_address else ["dynamic"])}
        request(key, "PUT", f"/rest/config/devices/{peer}", device_body)
    for path in paths:
        folder = io.folder_id(path)
        request(key, "PATCH", f"/rest/config/folders/{folder}",
                folder_body(path, target, device, peer))
    verify(key, paths, target, peer)


def verify(key: str, paths: tuple[str, ...], target: str,
           peer: str | None) -> None:
    for path in paths:
        folder = io.folder_id(path)
        found = request(key, "GET", f"/rest/config/folders/{folder}")
        if not isinstance(found, dict):
            raise ApiError(f"folder {path}: no configuration")
        if bool(found.get("paused")) != (target == io.PAUSED):
            raise ApiError(f"folder {path}: paused is"
                           f" {found.get('paused')}, not asked")
        if target == io.PAUSED:
            continue
        wanted = RECEIVE if target == io.REPLICA else SEND
        if found.get("type") != wanted:
            raise ApiError(f"folder {path}: type is {found.get('type')},"
                           f" not {wanted}")
        if peer and peer not in {one.get("deviceID") for one in
                                 found.get("devices") or []
                                 if isinstance(one, dict)}:
            raise ApiError(f"folder {path}: the peer is not a device of it")


def peer_connected(root: str, peer: str | None) -> bool | None:
    """Whether the peer is connected now; None where it cannot be told"""
    key = key_of(root)
    if key is None or not peer:
        return None
    try:
        found = request(key, "GET", "/rest/system/connections")
        return bool(((found or {}).get("connections") or {}).get(
            peer, {}).get("connected"))
    except (ApiError, AttributeError):
        return None


def counts(root: str, paths: tuple[str, ...]) -> dict[str, dict] | None:
    """Per replicated path: the two counters, the folder's state and
    error and whether it is paused, from the API; None when the API
    gives no answer (no key, the service down)"""
    key = key_of(root)
    if key is None:
        return None
    found = {}
    for path in paths:
        folder = io.folder_id(path)
        row = {"receiveOnlyChangedFiles": 0, "needFiles": 0, "state": "",
               "error": "", "paused": False, "type": ""}
        try:
            config = request(key, "GET", f"/rest/config/folders/{folder}")
            row["paused"] = bool(config.get("paused"))
            row["type"] = str(config.get("type") or "")
            if row["paused"]:
                row["state"] = io.PAUSED
            else:
                data = request(key, "GET",
                               f"/rest/db/status?folder={folder}")
                row["state"] = str(data.get("state") or "")
                row["error"] = str(data.get("error") or "")
                for name in COUNTERS:
                    row[name] = int(data.get(name) or 0)
        except ApiError as e:
            if e.status is None:
                return None
            row["error"] = str(e)
        except (AttributeError, TypeError, ValueError):
            return None
        found[path] = row
    return found
