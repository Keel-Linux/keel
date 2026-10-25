# Copyright (c) 2026 KeelLinux maintainers
"""Syncthing's configuration, rendered from the manifest and the role
(0050's amendment, decision 0050 of 2026-10-20)

The spec says only `overlays.syncthing: enabled`; what is replicated is
the appliance manifest's `state.replicate`, minus a path whose `unless`
service is placed for this node's installation mode (0038). When the
overlay is enabled, apply writes from that state:

- /var/lib/syncthing/config.xml, rendered as etcd's environment is
  (keel.system.etcd): discovery, relays, NAT traversal and the usage
  report are off, the service listens on the overlay address only, the
  peer is the other member's overlay address, the GUI and the REST API
  listen on the loopback with an API key kept root only in
  /var/lib/keel/filesync/apikey (0600, in a directory of 0700), the
  watcher's delay is 1 s, and
  each folder sets copyOwnershipFromParent so a received file keeps the
  application's owner (the unprivileged-LXC proof of
  Keel-Linux/common#64). Each receive-only folder keeps old versions
  with simple versioning, so a demoted primary loses nothing the new
  primary replaces. The file is written 0600 owned by the syncthing
  user, which is what `syncthing generate` makes it;
- /var/lib/keel/filesync/render.sha256, the digest of the rendered
  configuration keel last wrote: syncthing rewrites the file itself
  (it adds its defaults on start), so the drift check is against what
  keel wrote, never against the daemon's text;
- the replicated paths' .stignore, from `state.exclude`, and the
  .stfolder marker where the application did not make one (the
  syncthing user cannot create it inside an application-owned
  directory);
- the systemd drop-in that grants the unit write access to the
  replicated paths, beside its home, followed by `systemctl
  daemon-reload` (0050's amendment, point 6: its home and the
  replicated paths only).

The identity is made on the machine, once, owned by the syncthing user:
`keel database follow` and the first live apply run `syncthing
generate` (as the user, into /var/lib/syncthing) when no certificate is
there, and keep the device ID, which is public, in
/var/lib/keel/filesync/device. The other member's ID is asked over the
members' channel in a `device` message, answered only to the pair's
other member as a `secret` is (keel.mesh.vipserve), and kept in
/var/lib/keel/filesync/peer.device; it works with and without etcd.
The flip is one operation with the database role's: keel.system.dbfollow
calls follow_flip next to the /var/lib/keel/role write, which then says
`replicates=database,files` (keel.system.dbpair). A proven primary's
folders send only, a replica's receive only, and a node in doubt or not
proven pauses its folders, so a cut primary sends no file the other
site did not write. Every flip first writes the direction of the folders
to /var/lib/keel/filesync/state (paused, primary or replica); apply
renders from that file and from nothing else, and a missing file means
paused, so a later apply never sends again what a flip paused. A running
syncthing gets the type and the pause through its REST API
(keel.system.filesync_api) and keeps running; the configuration file
stays for a cold start. When the API gives no answer, syncthing is
restarted and the result is read back. A flip that did not reach the
wanted state is a follow problem, and the file `pending` makes the
database watch follow again until it does. A flip to primary first restores
the application owner over the replicated paths, for an entry that a first
batch left with the syncthing user (keel.system.filesync_owner, keel#225).
After a flip each executable
in /usr/lib/keel/roles.d/ runs with the role (keel.system.roles); a
failing hook is a follow problem too.

A path of the manifest is checked before it reaches the configuration, the
unit's drop-in or a .stignore (path_problem).
"""

import hashlib
import json
import os
import posixpath
import pwd
import re
import secrets
import shutil
import subprocess
import time
from dataclasses import dataclass
from xml.etree import ElementTree

from keel.inspect.accounts import passwd_entries
from keel.inspect.constants import PASSWD, ROOT_DEFAULT
from keel.inspect.tree import Tree
from keel.manifest.constants import NEVER_REPLICATED
from keel.manifest.facts import gather
from keel.manifest.fields import inside
from keel.system import filesync_api as api
from keel.system import filesync_io as io
from keel.system import filesync_owner
from keel.system import roles
from keel.system.actions import Action, Note, Refuse, Run, WriteFile
from keel.system.filesync_api import (  # noqa: F401  (the names callers use)
    GUI_ADDRESS, GUI_PORT, PORT, RECEIVE, SEND, VERSIONING_KEEP)
from keel.system.filesync_io import (  # noqa: F401
    APIKEY, DEVICE_FILE, DIR, HOME, PEER_FILE, PENDING, PUBLIC_MODE, RECORD,
    SECRET_MODE, STATE_FILE, folder_id)

OVERLAY = "syncthing"
USER = "syncthing"
UNIT = "syncthing.service"
CONFIG = f"{HOME}/config.xml"
DROP_IN = "etc/systemd/system/syncthing.service.d/keel.conf"
CONFIG_MODE = 0o600
HOME_MODE = 0o700
# 0050's amendment, point 4: the watcher reacts in a second
WATCHER_DELAY_S = 1
DEVICE_ID_RE = re.compile(r"^[A-Z2-7]{7}(?:-[A-Z2-7]{7}){7}$")
# what keel runs for syncthing never waits longer than this
COMMAND_TIMEOUT = 60
# after a restart the API needs a moment: tries, and seconds between
VERIFY_TRIES = 10
VERIFY_PAUSE = 2
# keel's own state holds the API key: never a replicated path
NEVER_REPLICATED_HERE = NEVER_REPLICATED + ("/var/lib/keel", "/" + HOME)
# characters that are patterns in a .stignore, or break a line or a word
BAD_CHARS = re.compile(r"[\s\x00-\x1f\x7f*?\[\]{}\\]")


# Before syncthing reads its configuration: with no state (a boot, as
# /run is empty), every folder starts paused, whatever the file says. The
# first proven follow unpauses. "+" runs it as root (the state directory
# is for root alone); sed -i keeps the owner of the file when root runs it.
START_PAUSED = (
    "/bin/sh -c 'test -e /{state} || ! test -f /{config} || sed -i -e"
    " \"s|<paused>false</paused>|<paused>true</paused>|\" /{config}'"
).format(state=STATE_FILE, config=CONFIG)


class FlipError(Exception):
    """A flip that did not reach the wanted state"""


@dataclass(frozen=True)
class FileSyncState:
    """What apply renders from, and what is there now"""

    paths: tuple[str, ...]
    excludes: tuple[str, ...]
    # the direction the folders have now, from the state file the flips
    # keep; None is paused (nothing proven, or no flip yet) (0050,
    # point 5)
    role: str | None
    device: str | None
    peer_device: str | None
    address: str | None
    peer_address: str | None
    apikey: str | None
    record: str | None
    drop_in: str | None
    # the .stignore text now, by absolute path
    stignore: dict[str, str | None]
    # replicated paths whose .stfolder marker is missing while the path
    # is there (the syncthing user cannot make it in an app-owned dir)
    markers: tuple[str, ...]
    problem: str | None = None


def path_problem(path) -> str | None:
    """Why a manifest path may not reach syncthing's configuration, the
    unit's drop-in or a .stignore; None when it may"""
    if not isinstance(path, str) or not path.startswith("/"):
        return "is not an absolute path"
    if BAD_CHARS.search(path):
        return "holds a space, a control or a pattern character"
    if ".." in path.split("/"):
        return "holds '..'"
    if path == "/" or posixpath.normpath(path) != path or "//" in path:
        return "is not a normalised path of a directory"
    for directory in NEVER_REPLICATED_HERE:
        if inside(path, directory):
            return f"is {directory} or inside it, which is never replicated"
    return None


def _wanted(application: dict, mode: str) -> list:
    """The replicate entries in force for `mode`: a path whose `unless`
    service is placed (its placement for `mode` is not `none`) holds its
    data in object storage and is not replicated (0038)"""
    state = application.get("state") or {}
    services = application.get("services") or {}
    found = []
    for entry in state.get("replicate") or []:
        if isinstance(entry, dict):
            path = entry.get("path")
            unless = entry.get("unless")
            if unless and _placed(services.get(unless), mode):
                continue
        else:
            path = entry
        if isinstance(path, str):
            found.append(path)
    return found


def effective_paths(application: dict, mode: str) -> tuple[str, ...]:
    """The replicated paths in force for `mode` that pass path_problem"""
    return tuple(path for path in _wanted(application, mode)
                 if path_problem(path) is None)


def rejected_paths(application: dict, mode: str) -> tuple[str, ...]:
    """What the manifest names that path_problem refuses, each with its
    reason; a replicated path, and an exclude as well"""
    state = application.get("state") or {}
    named = [("state.replicate", path) for path in _wanted(application, mode)]
    named += [("state.exclude", str(one))
              for one in state.get("exclude") or ()]
    return tuple(f"{where} {path!r} {why}" for where, path in named
                 if (why := path_problem(path)) is not None)


def _placed(service: dict | None, mode: str) -> bool:
    placement = (service or {}).get("placement") or {}
    return placement.get(mode, "none") != "none"


def stignore(excludes: tuple[str, ...], folder: str) -> str:
    """The .stignore text for one folder: the excludes inside it, rooted
    patterns, a directory's contents excluded with it"""
    root = folder.rstrip("/")
    lines = []
    for path in excludes:
        if path_problem(path) is not None:
            continue
        if not (path + "/").startswith(root + "/"):
            continue
        relative = path[len(root):].lstrip("/")
        lines += [f"/{relative}", f"/{relative}/**"]
    return "\n".join(lines) + "\n" if lines else ""


def folder_type(role: str | None) -> str:
    """A proven primary sends only; a replica receives only"""
    if role == "replica":
        return RECEIVE
    return SEND


def _add(parent, tag: str, text: str | None = None, **attributes):
    element = ElementTree.SubElement(parent, tag, attributes)
    element.text = text
    return element


def config_xml(device: str, peer_device: str | None, peer_address: str | None,
               address: str | None, apikey: str, paths: tuple[str, ...],
               role: str | None) -> str:
    """The configuration, built as a tree so that nothing in it can break
    out of its place; syncthing adds its own defaults on start and
    rewrites the file, which is why the drift check is the digest
    record's, not this text's"""
    if not apikey:
        raise ValueError("there is no API key to render")
    paused = role is None
    kind = folder_type(role)
    top = ElementTree.Element("configuration", {"version": "52"})
    for path in paths:
        folder = _add(top, "folder", id=folder_id(path), label=path,
                      path=path, type=kind, fsWatcherEnabled="true",
                      fsWatcherDelayS=str(WATCHER_DELAY_S))
        _add(folder, "device", id=device)
        if peer_device:
            _add(folder, "device", id=peer_device)
        _add(folder, "copyOwnershipFromParent", "true")
        _add(folder, "paused", str(paused).lower())
        if kind == RECEIVE:
            versioning = _add(folder, "versioning", type="simple")
            _add(versioning, "param", key="keep", val=str(VERSIONING_KEEP))
    _add(top, "device", id=device, name="keel", compression="metadata")
    if peer_device:
        peer = _add(top, "device", id=peer_device, name="keel-peer",
                    compression="metadata")
        if peer_address:
            _add(peer, "address", f"tcp://[{peer_address}]:{PORT}")
    gui = _add(top, "gui", enabled="true", tls="false")
    _add(gui, "address", f"{GUI_ADDRESS}:{GUI_PORT}")
    _add(gui, "apikey", apikey)
    options = _add(top, "options")
    _add(options, "listenAddress",
         f"tcp://[{address}]:{PORT}" if address else "tcp://:0")
    for name, value in (("globalAnnounceEnabled", "false"),
                        ("localAnnounceEnabled", "false"),
                        ("relaysEnabled", "false"),
                        ("natEnabled", "false"),
                        ("urAccepted", "-1"),
                        ("crashReportingEnabled", "false"),
                        ("startBrowser", "false")):
        _add(options, name, value)
    ElementTree.indent(top, space="    ")
    return ElementTree.tostring(top, encoding="unicode") + "\n"


def drop_in(paths: tuple[str, ...]) -> str:
    """The unit may write its home and the replicated paths only; a
    path that is not there yet (a plugins directory before the install)
    is named with the "-" prefix, which systemd skips when it is
    missing; without it the unit fails to start (226/NAMESPACE)"""
    writable = " ".join([f"/{HOME}"] + [f"-{path}" for path in paths])
    return (
        "# Written by keel (keel system filesync): the syncthing unit may\n"
        "# write its home and the replicated paths only (0050's\n"
        "# amendment, point 6).\n"
        "[Service]\n"
        f"ReadWritePaths={writable}\n"
        f"ExecStartPre=+{START_PAUSED}\n"
    )


def render_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def observe_filesync(tree: Tree, doc: dict, resolved,
                     start: bool = False) -> FileSyncState | None:
    """None when the chain has no syncthing overlay or nothing to
    replicate; the side effect, when this run may change the machine,
    is the identity and the API key the first live apply makes, as
    keel.system.anubiskey asks the pair's key at observe"""
    if resolved is None or resolved.application is None:
        return None
    if OVERLAY not in {one.name for one in resolved.overlays}:
        return None
    application = resolved.application.item
    mode = _mode(doc)
    paths = effective_paths(application, mode)
    refused = rejected_paths(application, mode)
    if not paths and not refused:
        return None
    excludes = tuple(str(one) for one in
                     ((application.get("state") or {}).get("exclude") or ()))
    enabled = (doc.get("overlays") or {}).get(OVERLAY) == "enabled"
    has_user = USER in passwd_entries(tree.read(PASSWD))
    problem = None
    if refused:
        problem = "; ".join(refused)
    elif enabled and not has_user:
        problem = ("there is no syncthing user: is keel-overlay-syncthing"
                   " installed?")
    if enabled and has_user and start and tree.root == ROOT_DEFAULT \
            and not problem:
        ensure_identity(tree.root)
        ensure_apikey(tree.root)
    stignore_now = {}
    markers = []
    for path in paths:
        relative = path.lstrip("/")
        stignore_now[path] = tree.read(f"{relative}/.stignore").text
        if tree.exists(relative) and not tree.exists(
                f"{relative}/.stfolder"):
            markers.append(relative)
    return FileSyncState(
        paths=paths,
        excludes=excludes,
        role=_recorded_role(tree.root),
        device=_read(tree, DEVICE_FILE),
        peer_device=_read(tree, PEER_FILE),
        address=_overlay_address(doc),
        peer_address=_pair_of(tree, doc),
        apikey=_read(tree, APIKEY),
        record=_read(tree, RECORD),
        drop_in=tree.read(DROP_IN).text,
        stignore=stignore_now,
        markers=tuple(markers),
        problem=problem)


def _mode(doc: dict) -> str:
    return str(((doc.get("installation") or {}).get("mode")) or "simple")


def _overlay_address(doc: dict) -> str | None:
    wg = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    try:
        return str(wg["address"]).split("/")[0] if wg.get("address") \
            else None
    except (KeyError, AttributeError):
        return None


def _pair_of(tree: Tree, doc: dict) -> str | None:
    """The other member's overlay address, as dbpair sees it; None where
    the pair cannot be read (a node mid-install, say)"""
    from keel.system import dbpair
    try:
        pair = dbpair.observe_pair(tree.root, doc)
    except (OSError, ValueError):
        return None
    return pair.peer_address if pair else None


def _recorded_role(root: str) -> str | None:
    """primary or replica, as the last flip proved it; None is paused"""
    found = io.folder_state(root)
    return None if found == io.PAUSED else found


def _read(tree: Tree, path: str) -> str | None:
    text = tree.read(path).text
    return text.strip() if text else None


def ensure_identity(root: str, runner=None) -> str | None:
    """The device ID, made on this machine once, owned by the syncthing
    user; None where syncthing cannot make one"""
    runner = runner or subprocess.run
    cached = _read(Tree(root), DEVICE_FILE)
    if cached and DEVICE_ID_RE.match(cached):
        return cached
    home = os.path.join(root, HOME)
    try:
        if not os.path.exists(os.path.join(home, "cert.pem")):
            if shutil.which("syncthing") is None:
                return None
            runner(["install", "-d", "-o", USER, "-g", USER, "-m",
                    format(HOME_MODE, "o"), home], check=True,
                   timeout=COMMAND_TIMEOUT)
            runner(["runuser", "-u", USER, "--", "syncthing", "generate",
                    "--home", home], check=True, timeout=COMMAND_TIMEOUT)
        done = runner(["runuser", "-u", USER, "--", "syncthing",
                       "device-id", "--home", home], capture_output=True,
                      text=True, check=False, timeout=COMMAND_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None
    device = (done.stdout or "").strip()
    if done.returncode != 0 or not DEVICE_ID_RE.match(device):
        return None
    io.write(root, DEVICE_FILE, device + "\n", PUBLIC_MODE,
             private_dir=True)
    return device


def ensure_apikey(root: str) -> str:
    """The REST API's key, root only; the one made first stands"""
    found = _read(Tree(root), APIKEY)
    if found:
        return found
    made = secrets.token_urlsafe(32)
    io.write(root, APIKEY, made + "\n", SECRET_MODE, private_dir=True)
    return made


def device_id(root: str) -> str | None:
    """This node's device ID, or None before the identity is made"""
    return _read(Tree(root), DEVICE_FILE)


def plan_filesync(state: FileSyncState, live: bool
                  ) -> tuple[list[Action], bool]:
    """The files syncthing runs from, and whether a running syncthing
    restarts"""
    if state.problem:
        return [Refuse(state.problem)], False
    if not state.device or not state.apikey:
        return [Note("syncthing's identity and API key are not made yet:"
                     " this run makes them, and the next renders the"
                     " configuration")], False
    actions: list[Action] = []
    config = config_xml(state.device, state.peer_device, state.peer_address,
                        state.address, state.apikey, state.paths,
                        state.role)
    digest = render_digest(config)
    if state.record != digest:
        actions.append(WriteFile(
            CONFIG, config, CONFIG_MODE, USER,
            f"write /{CONFIG}: {len(state.paths)} replicated folder(s),"
            f" {state.role or 'paused'}"))
        actions.append(WriteFile(
            RECORD, digest + "\n", PUBLIC_MODE, None,
            f"write /{RECORD}: the digest of the rendered configuration"))
    rendered_drop_in = drop_in(state.paths)
    moved = state.drop_in != rendered_drop_in
    if moved:
        actions.append(WriteFile(
            DROP_IN, rendered_drop_in, PUBLIC_MODE, None,
            f"write /{DROP_IN}: write access to the replicated paths"))
        if live:
            actions.append(Run(("systemctl", "daemon-reload"),
                               "systemctl daemon-reload: syncthing's"
                               " drop-in"))
    for path in state.paths:
        text = stignore(state.excludes, path)
        if text and state.stignore.get(path) != text:
            actions.append(WriteFile(
                f"{path.lstrip('/')}/.stignore", text, PUBLIC_MODE, None,
                f"write {path}/.stignore: the paths not replicated"))
    for marker in state.markers:
        actions.append(WriteFile(
            f"{marker}/.stfolder", "", PUBLIC_MODE, None,
            f"write /{marker}/.stfolder: the folder marker syncthing"
            " cannot make in an application-owned directory"))
    # a written configuration restarts a running syncthing; a drop-in
    # change is a daemon-reload only, as for etcd's
    return actions, state.record != digest


def applies(doc: dict, resolved) -> bool:
    """Whether this node replicates files: the overlay is enabled in
    the chain and in the spec, and the appliance names a path"""
    if (doc.get("overlays") or {}).get(OVERLAY) != "enabled":
        return False
    if resolved is None or resolved.application is None:
        return False
    if OVERLAY not in {one.name for one in resolved.overlays}:
        return False
    application = resolved.application.item
    return bool(_wanted(application, _mode(doc)))


def _resolved(root: str, doc: dict):
    appliance = doc.get("appliance")
    if not isinstance(appliance, dict):
        return None
    return gather(root, str(appliance.get("name") or "")).resolved


def replicates_files(root: str, doc: dict) -> bool:
    """Whether this node replicates files: the appliance declares a
    replicated path for this node's mode, and the overlay is enabled"""
    resolved = _resolved(root, doc)
    return applies(doc, resolved) and bool(
        effective_paths(resolved.application.item, _mode(doc)))


def flip_pending(root: str, doc: dict) -> bool:
    """Whether the last flip did not reach the folders' wanted state, on
    a node that replicates files: the database watch follows again"""
    return os.path.exists(os.path.join(root, PENDING)) and \
        replicates_files(root, doc)


def follow_flip(root: str, doc: dict, pair, role: str | None, found,
                runner=None, here=None) -> None:
    """The folder direction with the database role's, in the same
    operation (0050's amendment, point 5): `role` None pauses the
    folders, of a node in doubt or not proven. Nothing on a node that
    replicates no path or has the overlay off. It never raises, so the
    database flip this rides on is never undone: a failure pauses the
    folders as far as it can and is a follow problem, which the
    database watch retries"""
    runner = runner or subprocess.run
    try:
        resolved = _resolved(root, doc)
        if not applies(doc, resolved):
            return
        application = resolved.application.item
        if not effective_paths(application, _mode(doc)) and \
                not rejected_paths(application, _mode(doc)):
            return
        if shutil.which("syncthing") is None:
            found.say("syncthing is not installed: keel-overlay-syncthing"
                      " is not there; the file replication flip is skipped")
            return
        _flip(root, doc, application, pair, role, found, runner, here)
    except Exception as e:  # noqa: BLE001 - see the docstring
        found.fail(f"the file replication flip failed: {e}")
        _pause_best_effort(root, doc, runner, found)


def _flip(root: str, doc: dict, application: dict, pair, role: str | None,
          found, runner, here) -> None:
    mode = _mode(doc)
    paths = effective_paths(application, mode)
    refused = rejected_paths(application, mode)
    io.write(root, PENDING, "1\n", SECRET_MODE, private_dir=True)
    if refused:
        found.fail("; ".join(refused))
        role = None
    want = role or io.PAUSED
    device = ensure_identity(root, runner)
    if device is None:
        raise FlipError("syncthing's identity could not be made")
    key = ensure_apikey(root)
    # the folders' state first: a failure further on leaves the state
    # the later apply renders from, never the one before this flip
    io.write(root, STATE_FILE, want + "\n", SECRET_MODE, private_dir=True)
    target = _Target(root, paths, device, key, _overlay_address(doc),
                     runner, found)
    peer = io.read(root, PEER_FILE)
    peer_address = pair.peer_address if pair else None
    target.settle(want, peer, peer_address)
    if role == io.PRIMARY:
        _restore_owner(root, paths, found)
    complete = True
    if role is not None and peer_address and here:
        asked = _ask_peer(here, pair.vip, peer_address, found)
        if asked == device:
            found.fail("the other member answered this node's own"
                       " device ID")
        elif asked and asked != peer:
            io.write(root, PEER_FILE, asked + "\n", PUBLIC_MODE,
                     private_dir=True)
            peer = asked
            target.settle(want, peer, peer_address)
    if role is not None and peer is None:
        # not a failure (the other member makes its identity at its own
        # first apply), but the watch asks again
        found.say("the other member's syncthing device ID is not known"
                  " yet: the folders wait for it")
        complete = False
    if role is not None:
        failed = roles.run(root, role, runner, found.say)
        if failed:
            found.fail(f"{len(failed)} role hook(s) failed: "
                       + ", ".join(failed))
            complete = False
    if complete:
        io.remove(root, PENDING)
    found.say(f"syncthing: {len(paths)} folder(s) "
              + (role if role else "paused"))


def _restore_owner(root: str, paths: tuple[str, ...], found) -> None:
    """The folders no longer receive: give the application owner back to
    the entries that a first batch left with the syncthing user (keel#225),
    before a role hook starts the application. An error is a follow
    problem, which the database watch retries"""
    uid = pwd.getpwnam(USER).pw_uid
    total = 0
    for path in paths:
        total += filesync_owner.repair(
            os.path.join(root, path.lstrip("/")), uid)
    if total:
        found.say(f"syncthing: the application owner restored on {total}"
                  " replicated entries")


def _pause_best_effort(root: str, doc: dict, runner, found) -> None:
    """After a failed flip: the state is paused, and the running folders
    are paused. Each step stands alone: a state file that cannot be
    written does not skip the pause through the API"""
    def attempt(what, step) -> bool:
        try:
            step()
            return True
        except Exception as e:  # noqa: BLE001 - best effort, said
            found.say(f"the folders could not be paused ({what}): {e}")
            return False

    attempt("pending mark", lambda: io.write(
        root, PENDING, "1\n", SECRET_MODE, private_dir=True))
    attempt("state", lambda: io.write(
        root, STATE_FILE, io.PAUSED + "\n", SECRET_MODE, private_dir=True))
    paths: list[tuple[str, ...]] = []

    def find():
        resolved = _resolved(root, doc)
        paths.append(effective_paths(resolved.application.item, _mode(doc)))
    if not attempt("manifest", find):
        return
    key, device = api.key_of(root), device_id(root)
    if not key:
        return

    def settle():
        if not device:
            raise FlipError("no device ID")
        _Target(root, paths[0], device, key, _overlay_address(doc), runner,
                found).settle(io.PAUSED, io.read(root, PEER_FILE), None)
    if not attempt("files", settle):
        attempt("API", lambda: api.apply_folders(
            key, paths[0], io.PAUSED, device or "", None, None))


class _Target:
    """One node's folders, set to a wanted state and read back"""

    def __init__(self, root: str, paths: tuple[str, ...], device: str,
                 key: str, address: str | None, runner, found):
        self.root = root
        self.paths = paths
        self.device = device
        self.key = key
        self.address = address
        self.runner = runner
        self.found = found

    def _run(self, argv: list[str]):
        return self.runner(argv, check=False, capture_output=True,
                           text=True, timeout=COMMAND_TIMEOUT)

    def settle(self, want: str, peer: str | None,
               peer_address: str | None) -> None:
        """Render the files for a cold start, then set the running
        syncthing through its API; a restart only where the API gives
        no answer or the unit's drop-in changed"""
        root = self.root
        role = None if want == io.PAUSED else want
        config = config_xml(self.device, peer, peer_address, self.address,
                            self.key, self.paths, role)
        digest = render_digest(config)
        tree = Tree(root)
        if _read(tree, RECORD) != digest or not tree.exists(CONFIG):
            io.write(root, CONFIG, config, CONFIG_MODE, owner=USER)
            io.write(root, RECORD, digest + "\n", PUBLIC_MODE,
                     private_dir=True)
        wanted = drop_in(self.paths)
        moved = tree.read(DROP_IN).text != wanted
        if moved:
            io.write(root, DROP_IN, wanted, PUBLIC_MODE)
            done = self._run(["systemctl", "daemon-reload"])
            if done.returncode != 0:
                raise FlipError("systemctl daemon-reload failed:"
                                f" {_tail(done)}")
        if self._run(["systemctl", "is-active", "--quiet",
                      UNIT]).returncode != 0:
            return
        if not moved:
            try:
                api.apply_folders(self.key, self.paths, want, self.device,
                                  peer, peer_address)
                return
            except api.ApiError as e:
                self.found.say(f"syncthing's API did not take it ({e}):"
                               " restarting syncthing")
        self._restart(want, peer)

    def _restart(self, want: str, peer: str | None) -> None:
        done = self._run(["systemctl", "restart", UNIT])
        if done.returncode != 0:
            raise FlipError(f"systemctl restart {UNIT} failed:"
                            f" {_tail(done)}")
        error = "no answer"
        for attempt in range(VERIFY_TRIES):
            try:
                api.verify(self.key, self.paths, want, peer)
                return
            except api.ApiError as e:
                error = str(e)
            if attempt + 1 < VERIFY_TRIES:
                time.sleep(VERIFY_PAUSE)
        raise FlipError(f"after the restart the folders are not as asked:"
                        f" {error}")


def _tail(done) -> str:
    return " ".join((done.stderr or done.stdout or "").split())[-200:] \
        or f"exit {done.returncode}"


def _ask_peer(here, vip: str, at: str, found) -> str | None:
    """The other member's device ID over the members' channel; a miss
    is said and the folders keep the peer they know"""
    from keel.mesh import vipmsg
    from keel.mesh.memberlink import LinkError
    from keel.mesh.protocol import ProtocolError
    from keel.mesh.signing import SigningError
    from keel.mesh.vipnode import VipError
    try:
        answer = here.say(vipmsg.DEVICE, at, {"vip": vip})
        body = json.loads(answer.decode())
        value = body.get("id") if isinstance(body, dict) else None
    except LinkError as e:
        if "holds no" in str(e):
            found.say("the other member holds no syncthing identity yet")
            return None
        found.say(f"the other member at {at} did not answer the device"
                  f" message: {e}")
        return None
    except (SigningError, ProtocolError, ValueError, VipError,
            OSError) as e:
        found.say(f"the other member at {at} answered no device ID: {e}")
        return None
    if not isinstance(value, str) or not DEVICE_ID_RE.match(value):
        found.say(f"the other member at {at} answered no device ID")
        return None
    return value
