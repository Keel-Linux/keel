# Copyright (c) 2026 KeelLinux maintainers
"""keel's record of the firewall state it last wrote (decision 0097)

/var/lib/keel/firewall/state holds `enforce` or `report`, apart from the
ruleset file: an empty or cut file loses its policy line, and a node in
enforce must stay in enforce (only the spec moves it out). The fourth
real test broke the first form of it, so:

- it is read with O_NOFOLLOW, and trusted only as a regular file that
  root owns and that no group or other may write, in a directory of the
  same kind; anything else is no record, said with a plain warning;
- it is written by a rename of a new file beside it, so a link at its
  path is replaced and never followed, and a wrong mode is put right.

Only root can write a record keel trusts, which is the power the spec
has: a record that says enforce on a fresh node gives enforce at once
(closed, the safe side). No more mechanism guards against that.
`apt purge` removes it (debian/keel.postrm); `remove` keeps it.
"""

import contextlib
import os
import stat
import tempfile

from keel.inspect.tree import Tree

RECORD = "var/lib/keel/firewall/state"
STATES = ("enforce", "report")
ROOT_UID = 0
MODE = 0o644
DIR_MODE = 0o755
UNSAFE = stat.S_IWGRP | stat.S_IWOTH


def read(tree: Tree) -> tuple[str | None, str]:
    """The recorded state, and a warning when a record is there and is
    not trusted; (None, "") when there is none"""
    path = tree.path(RECORD)
    problem = unsafe_dir(os.path.dirname(path))
    if problem == "absent":
        return None, ""
    if problem:
        return None, untrusted(f"its directory {problem}")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, ""
    except OSError:
        return None, untrusted("it is not a regular file")
    with os.fdopen(fd, "rb") as fob:
        problem = unsafe(os.fstat(fob.fileno()), "it")
        if problem:
            return None, untrusted(problem)
        value = fob.read(64).decode("ascii", "replace").strip()
    if value not in STATES:
        return None, untrusted("it is not a state keel writes")
    return value, ""


def unsafe(found: os.stat_result, what: str,
           regular: bool = True) -> str | None:
    if regular and not stat.S_ISREG(found.st_mode):
        return "it is not a regular file"
    if found.st_uid != ROOT_UID:
        return f"root does not own {what}"
    if found.st_mode & UNSAFE:
        return f"group or others may write {what}"
    return None


def unsafe_dir(path: str) -> str | None:
    try:
        found = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if not stat.S_ISDIR(found.st_mode):
        return "is not a directory"
    problem = unsafe(found, "it", regular=False)
    return f"is not trusted: {problem}" if problem else None


def untrusted(why: str) -> str:
    return (f"/{RECORD} is not trusted ({why}): it counts as no record;"
            " the next apply writes it again")


def write(root: str, state: str) -> str | None:
    """Write the record by a rename; None, or why it failed"""
    path = os.path.join(root, RECORD)
    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, mode=DIR_MODE, exist_ok=True)
        if os.path.islink(directory):
            return f"{directory} is a link: the record is not written"
        os.chmod(directory, DIR_MODE)
        fd, copy = tempfile.mkstemp(dir=directory, prefix=".state.")
        with os.fdopen(fd, "w") as fob:
            fob.write(f"{state}\n")
            fob.flush()
            os.fchmod(fob.fileno(), MODE)
            os.fsync(fob.fileno())
        os.replace(copy, path)
    except OSError as e:
        with contextlib.suppress(NameError, OSError):
            os.remove(copy)
        return f"the record cannot be written: {e.strerror or e}"
    return None
