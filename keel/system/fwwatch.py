# Copyright (c) 2026 KeelLinux maintainers
"""keel firewall check --restore: what keel-firewall-watch.timer runs

Decision 0097, section 4. A lost or altered table beside a sound file is
loaded again (keel.system.fwcheck). Two things keep it cheap and quiet
(the second review of the change):

- Cost. Every 30 s the timer runs /usr/lib/keel/firewall-watch, a few
  lines of shell: when the hash of `nft -s list table inet keel` and the
  inode, size and time of keel's file are the ones this module wrote at
  the last good check (MARK, under /run), it exits at once; Python runs
  only on a difference. So the 30 s bound holds, and a run costs one nft
  listing.
- Noise. While the file is broken, one line per change of the problem
  and one an hour (STATE), not one every 30 s; the run that says it
  exits non-zero, the quiet repeats exit 0. The recovery is said once.
"""

import hashlib
import os
import time

from keel import exits
from keel.manifest.firewall import PATH
from keel.system import fwcheck

MARK = "run/keel/firewall-watch.ok"
STATE = "run/keel/firewall-watch.state"
REMIND = 3600
RECOVERED = "recovered: table inet keel is the one keel's file says again"


def watch(root: str, run=None, clock=time.time) -> tuple[int, list[str]]:
    """The exit code and the lines to say"""
    found = fwcheck.check(root, run)
    if found.code == exits.OK:
        return settle(root, run, [])
    message = found.message
    if found.restorable:
        problem = fwcheck.restore(root, run)
        if problem is None:
            again = fwcheck.check(root, run)
            if again.code == exits.OK:
                return settle(root, run, [f"{found.message}: loaded again"])
            message = again.message
        else:
            message = f"{found.message}; nft -f failed: {problem}"
    return failing(root, clock, message)


def settle(root: str, run, lines: list[str]) -> tuple[int, list[str]]:
    write_mark(root, run)
    if read_state(root)[0] is not None:
        lines.append(RECOVERED)
    remove(os.path.join(root, STATE))
    return exits.OK, lines


def failing(root: str, clock, message: str) -> tuple[int, list[str]]:
    remove(os.path.join(root, MARK))
    said, when = read_state(root)
    now = clock()
    if said == message and now - when < REMIND:
        return exits.OK, []
    write(os.path.join(root, STATE), f"{now:.0f}\n{message}\n")
    return exits.DRIFT_FOUND, [message]


def mark_of(listing: str, path: str) -> str:
    """What the shell compares: the sha256 of the listing as nft prints
    it, and the file's inode, size and time in seconds (`stat -c '%i %s
    %Y'`)"""
    found = os.stat(path)
    digest = hashlib.sha256(listing.encode()).hexdigest()
    return f"{digest} {found.st_ino} {found.st_size} {int(found.st_mtime)}"


def write_mark(root: str, run) -> None:
    path = os.path.join(root, PATH)
    listing = fwcheck.table_listing(run or fwcheck.subprocess.run)
    if listing is None or not os.path.exists(path):
        remove(os.path.join(root, MARK))
        return
    write(os.path.join(root, MARK), mark_of(listing, path) + "\n")


def read_state(root: str) -> tuple[str | None, float]:
    try:
        with open(os.path.join(root, STATE)) as fob:
            when, _, message = fob.read().partition("\n")
        return message.rstrip("\n"), float(when)
    except (OSError, ValueError):
        return None, 0.0


def write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    with open(path, "w") as fob:
        fob.write(text)


def remove(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
