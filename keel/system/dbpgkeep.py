# Copyright (c) 2026 KeelLinux maintainers
"""The old data directory that a reseed keeps, and its pruning

Handbook decision 0054, second amendment of 2026-10-18. A reseed does not
delete the data directory of the old primary. It renames the directory to
`<datadir>.keel-kept-<UTC stamp>` and keeps it. keel keeps at least the
newest copy. It deletes the others when they are older than MAX_AGE_S, or
oldest first while the free space of the file system is below the floor,
the larger of 1 GiB and 5 % of the file system. When there is no room to
keep a copy (the free space after the new copy would be below the floor),
the reseed that keel picks by itself does not run, and the operator's flag
is required.
"""

import glob
import os
import shutil
import time

SUFFIX = ".keel-kept-"
MAX_AGE_S = 7 * 86400
FLOOR_MIN = 1024 ** 3
FLOOR_PERCENT = 5


def kept_name(datadir: str, now: float | None = None) -> str:
    stamp = time.strftime("%Y%m%dT%H%M%SZ",
                          time.gmtime(time.time() if now is None else now))
    return f"{datadir}{SUFFIX}{stamp}"


def kept_dirs(datadir: str) -> list[str]:
    """The kept copies, the oldest first (the stamp sorts as time)"""
    return sorted(one for one in glob.glob(glob.escape(datadir)
                                           + SUFFIX + "*")
                  if os.path.isdir(one))


def free_bytes(path: str) -> int:
    found = os.statvfs(os.path.dirname(path) or "/")
    return found.f_bavail * found.f_frsize


def total_bytes(path: str) -> int:
    found = os.statvfs(os.path.dirname(path) or "/")
    return found.f_blocks * found.f_frsize


def floor_bytes(datadir: str) -> int:
    return max(FLOOR_MIN, total_bytes(datadir) * FLOOR_PERCENT // 100)


def can_keep(datadir: str, copy_bytes: int) -> bool:
    """Whether the file system holds the new copy and the old data, with
    the floor still free"""
    try:
        return free_bytes(datadir) >= copy_bytes + floor_bytes(datadir)
    except OSError:
        return False


def prune(datadir: str, now: float | None = None) -> list[str]:
    """Delete the kept copies that age or space asks for; the paths gone.
    The newest copy always stays"""
    now = time.time() if now is None else now
    copies = kept_dirs(datadir)
    gone: list[str] = []
    for path in copies[:-1]:
        try:
            old = now - os.path.getmtime(path) > MAX_AGE_S
        except OSError:
            continue
        if old and _remove(path):
            gone.append(path)
    left = [one for one in copies[:-1] if one not in gone]
    for path in left:
        try:
            if free_bytes(datadir) >= floor_bytes(datadir):
                break
        except OSError:
            break
        if _remove(path):
            gone.append(path)
    return gone


def _remove(path: str) -> bool:
    try:
        shutil.rmtree(path)
    except OSError:
        return False
    return True
