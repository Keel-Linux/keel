# Copyright (c) 2026 KeelLinux maintainers
"""The files keel keeps for the file replication, and how it writes them
(0050's amendment, keel.system.filesync)

Everything keel keeps for syncthing is in /var/lib/keel/filesync, a
directory for root alone (0700). A file is written whole to a new name
that is made 0600, then moved over the old one, so a reader never sees
half a file and a secret is never readable, not for one moment.
"""

import hashlib
import os
import pwd
import secrets

HOME = "var/lib/syncthing"
DIR = "var/lib/keel/filesync"
DEVICE_FILE = f"{DIR}/device"
PEER_FILE = f"{DIR}/peer.device"
APIKEY = f"{DIR}/apikey"
RECORD = f"{DIR}/render.sha256"
# paused, primary or replica: the direction the folders have now, kept
# at every flip; apply renders from it and from nothing else. It is in
# /run, so a boot starts with no state, which is paused: a node that was
# primary at shutdown never starts sending before a follow proved it.
STATE_FILE = "run/keel/filesync/state"
# present while the last flip did not reach the folders' wanted state:
# the database watch follows again until it is gone
PENDING = f"{DIR}/pending"
WATCH_STATE = f"{DIR}/counts"
PAUSED = "paused"
PRIMARY = "primary"
REPLICA = "replica"
STATES = (PAUSED, PRIMARY, REPLICA)
PUBLIC_MODE = 0o644
SECRET_MODE = 0o600
DIR_MODE = 0o700
# one folder per replicated path, whatever the path is
FOLDER_PREFIX = "keel-"


def folder_id(path: str) -> str:
    """The syncthing folder ID for a replicated path: stable, whatever
    the path is"""
    return FOLDER_PREFIX + hashlib.sha256(path.encode()).hexdigest()[:12]


def read(root: str, path: str) -> str | None:
    """The text of a file under root, stripped; None where there is none"""
    try:
        with open(os.path.join(root, path)) as fob:
            return fob.read().strip() or None
    except OSError:
        return None


def folder_state(root: str) -> str:
    """The direction the folders have now; paused where nothing says"""
    found = read(root, STATE_FILE)
    return found if found in (PRIMARY, REPLICA) else PAUSED


def narrow(directory: str, mode: int) -> None:
    """A directory made before keel kept anything in it may be wider"""
    os.chmod(directory, mode)


def write(root: str, path: str, text: str, mode: int,
          owner: str | None = None, private_dir: bool = False) -> None:
    """Atomic, and never readable before it has its mode"""
    full = os.path.join(root, path)
    directory = os.path.dirname(full)
    os.makedirs(directory, mode=DIR_MODE if private_dir else 0o755,
                exist_ok=True)
    if private_dir:
        narrow(directory, DIR_MODE)
    tmp = f"{full}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 SECRET_MODE)
    try:
        if owner is not None:
            entry = pwd.getpwnam(owner)
            os.fchown(fd, entry.pw_uid, entry.pw_gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as fob:
            fd = -1
            fob.write(text)
            fob.flush()
            os.fsync(fob.fileno())
        os.rename(tmp, full)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def remove(root: str, path: str) -> None:
    try:
        os.unlink(os.path.join(root, path))
    except FileNotFoundError:
        pass
