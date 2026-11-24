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
import hashlib
import os
import re
import stat
import tempfile

from keel.inspect.tree import Tree

RECORD = "var/lib/keel/firewall/state"
# off too: the watch's shell then reads one file of keel's to know that
# the spec says off, and never matches text in the spec
STATES = ("enforce", "report", "off")
# the ruleset as keel last loaded it, restored first by keel firewall
# repair: it does not need the spec, and keeps the declared ports open
COPY = "var/lib/keel/firewall/last-good.nft"
COPY_LIMIT = 1 << 20
HASH_RE = re.compile(r"[0-9a-f]{64}")
ROOT_UID = 0
# root's alone: only keel, as root, reads it
MODE = 0o600
DIR_MODE = 0o700
UNSAFE = stat.S_IWGRP | stat.S_IWOTH


def read(tree: Tree) -> tuple[str | None, str]:
    """The recorded state, and a warning when a record is there and is
    not trusted; (None, "") when there is none"""
    state, _, warning = read_full(tree)
    return state, warning


def read_full(tree: Tree) -> tuple[str | None, str | None, str]:
    """The recorded state, the sha256 of the ruleset the last apply
    loaded (None when the record has none), and a warning"""
    text, problem = read_file(tree, RECORD, 160)
    if problem:
        return None, None, untrusted(RECORD, problem)
    if text is None:
        return None, None, ""
    words = text.split()
    state = words[0] if words else ""
    digest = words[1] if len(words) == 2 else None
    if state not in STATES or len(words) > 2 or (
            digest is not None and not HASH_RE.fullmatch(digest)):
        return None, None, untrusted(RECORD, "it is not a state keel writes")
    return state, digest, ""


def ruleset_hash(text: str) -> str:
    """The sha256 of a ruleset as keel wrote it, state line included:
    the record holds the one of the last apply, and the last good copy
    is restored only when it has it (the sixth real test)"""
    return hashlib.sha256(text.encode()).hexdigest()


def read_copy(tree: Tree) -> tuple[str | None, str]:
    """keel's last good copy of the ruleset, and a warning when it is
    there and is not trusted"""
    text, problem = read_file(tree, COPY, COPY_LIMIT)
    if problem:
        return None, untrusted(COPY, problem)
    return text, ""


def read_file(tree: Tree, relative: str,
              limit: int) -> tuple[str | None, str | None]:
    """A file of keel's directory, read with no symlink followed: its
    text, or the reason it is not trusted; (None, None) when absent"""
    path = tree.path(relative)
    problem = unsafe_dir(os.path.dirname(path))
    if problem == "absent":
        return None, None
    if problem:
        return None, f"its directory {problem}"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, "it is not a regular file"
    with os.fdopen(fd, "rb") as fob:
        problem = unsafe(os.fstat(fob.fileno()), "it")
        if problem:
            return None, problem
        return fob.read(limit).decode("utf-8", "replace"), None


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


def untrusted(relative: str, why: str) -> str:
    return (f"/{relative} is not trusted ({why}): it counts as none;"
            " the next apply writes it again, root's alone")


def write(root: str, state: str, digest: str = "") -> str | None:
    """Write the record by a rename: the state, and the sha256 of the
    ruleset the apply loaded; None, or why it failed"""
    line = f"{state} {digest}" if digest else state
    return write_file(root, RECORD, f"{line}\n", "the record")


def write_copy(root: str, text: str) -> str | None:
    """keel's last good copy of the ruleset, by a rename"""
    return write_file(root, COPY, text, "the last good copy")


def write_file(root: str, relative: str, content: str,
               what: str) -> str | None:
    """A file of keel's directory, written by a rename of a new file
    beside it, the directory put right first (root's, 0700; opened with
    no symlink followed); None, or why it failed"""
    path = os.path.join(root, relative)
    directory = os.path.dirname(path)
    try:
        problem = own_directory(directory)
        if problem:
            return f"{problem}: {what} is not written"
        fd, copy = tempfile.mkstemp(dir=directory, prefix=".keel.")
        with os.fdopen(fd, "w") as fob:
            fob.write(content)
            fob.flush()
            os.fchmod(fob.fileno(), MODE)
            os.fsync(fob.fileno())
        os.replace(copy, path)
    except OSError as e:
        with contextlib.suppress(NameError, OSError):
            os.remove(copy)
        return f"{what} cannot be written: {e.strerror or e}"
    return None


def own_directory(directory: str) -> str | None:
    """Make keel's directory root's and 0700, by fd: the fifth real test
    found one owned by another user, never put right, so the record was
    never trusted again; None, or why it cannot be"""
    os.makedirs(directory, mode=DIR_MODE, exist_ok=True)
    try:
        held = os.open(directory, os.O_RDONLY | os.O_DIRECTORY
                       | os.O_NOFOLLOW)
    except OSError:
        return f"{directory} is a link"
    try:
        os.fchown(held, ROOT_UID, -1)
        os.fchmod(held, DIR_MODE)
    finally:
        os.close(held)
    return None
