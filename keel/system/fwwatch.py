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
  and one an hour (STATE), not one every 30 s. Every run exits non-zero
  while the problem lasts, so the unit stays failed and monitoring by
  failed units sees it all along; only the line is rate-limited. The
  table's state is part of a broken file's problem, so a table lost
  beside it is said at once. The recovery is said once.

The mark is the listing the check accepted, and the file's inode, size,
mtime and ctime as stat gave them before the check; a file that changed
during the check gets no mark (the third review of decision 0097).
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
    run = run or fwcheck.subprocess.run
    before = file_stat(root)
    found = fwcheck.check(root, run)
    if found.code == exits.OK:
        return settle(root, before, found, cleared(root, run))
    message = found.message
    if found.restorable:
        problem = fwcheck.restore(root, run)
        if problem is None:
            again = fwcheck.check(root, run)
            if again.code == exits.OK:
                return settle(root, before, again,
                              [f"{found.message}: loaded again"]
                              + cleared(root, run))
            message = again.message
        else:
            message = f"{found.message}; nft -f failed: {problem}"
    else:
        code, lines = repaired(root, run)
        if code == exits.OK:
            again = fwcheck.check(root, run)
            if again.code == exits.OK:
                return settle(root, file_stat(root), again,
                              lines + cleared(root, run))
        message = "; ".join([message, *lines, table_state(run)])
    return failing(root, clock, message)


def repaired(root: str, run) -> tuple[int, list[str]]:
    """keel firewall repair for a broken or missing file: the apply's
    firewall step, else the closed fallback (keel.system.fwrepair)"""
    from keel.system import fwrepair
    live = os.path.abspath(root) == "/"
    return fwrepair.repair(root, live, run)


def table_state(run) -> str:
    """The loaded table beside a broken file, so that its loss is a new
    problem"""
    listing = fwcheck.table_listing(run)
    if listing is None:
        return "table inet keel is not loaded"
    return f"table inet keel holds {fwcheck.loaded_digest(listing)}"


LIVE_ROOT = "/"


def cleared(root: str, run) -> list[str]:
    """keel#310: a keel-firewall.service that failed at boot (a broken
    spec, a fallback) stays failed after the spec is put back, until an
    apply. On a good run on the live system the watch restarts it: it
    loads the same sound file, and the node is not degraded any more"""
    from keel.system.fwstate import BOOT_UNIT, unit_failed
    if os.path.abspath(root) != LIVE_ROOT or not unit_failed(BOOT_UNIT):
        return []
    try:
        run(["systemctl", "restart", "--no-block", BOOT_UNIT],
            capture_output=True, text=True, check=False)
    except OSError:
        return []
    return [f"{BOOT_UNIT} restarted: it failed at boot, and the ruleset is"
            " sound now"]


def settle(root: str, before: str | None, found: fwcheck.Checked,
           lines: list[str]) -> tuple[int, list[str]]:
    write_mark(root, before, found.listing)
    if read_state(root)[0] is not None:
        lines.append(RECOVERED)
    remove(os.path.join(root, STATE))
    return exits.OK, lines


def failing(root: str, clock, message: str) -> tuple[int, list[str]]:
    remove(os.path.join(root, MARK))
    said, when = read_state(root)
    now = clock()
    if said == message and now - when < REMIND:
        return exits.DRIFT_FOUND, []
    write(os.path.join(root, STATE), f"{now:.0f}\n{message}\n")
    return exits.DRIFT_FOUND, [message]


def file_stat(root: str) -> str | None:
    """What the shell compares of keel's file: `stat -c '%i %s %Y %Z'`"""
    try:
        found = os.stat(os.path.join(root, PATH))
    except OSError:
        return None
    return (f"{found.st_ino} {found.st_size} {int(found.st_mtime)}"
            f" {int(found.st_ctime)}")


def mark_of(listing: str, stat: str) -> str:
    """The sha256 of the listing as nft printed it, and the file's stat"""
    return f"{hashlib.sha256(listing.encode()).hexdigest()} {stat}"


def write_mark(root: str, before: str | None,
               listing: str | None) -> None:
    """The listing the check accepted; none when the file changed during
    the check, or when there is no listing or no file"""
    if listing is None or before is None or file_stat(root) != before:
        remove(os.path.join(root, MARK))
        return
    write(os.path.join(root, MARK), mark_of(listing, before) + "\n")


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
