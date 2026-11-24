# Copyright (c) 2026 KeelLinux maintainers
"""One lock for the apply and the firewall's repair (decision 0097)

/run/keel/firewall.lock, flock: a person's apply (or keel mesh's) and
keel firewall repair (the boot unit, the watch) never write and load the
ruleset at the same moment. The sixth real test saw an apply fail while
the watch repaired. The apply waits for the lock (a repair holds it a few
seconds); the repair waits a short time and then skips its run, so it
never makes an apply fail. The kernel frees the lock when its holder
dies.
"""

import fcntl
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager

LOCK = "run/keel/firewall.lock"
POLL = 0.1


@contextmanager
def held(root: str, wait: float,
         clock=time.monotonic) -> Iterator[bool]:
    """Whether this process holds the lock after at most `wait` seconds"""
    path = os.path.join(root, LOCK)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        deadline = clock() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if clock() >= deadline:
                    yield False
                    return
                time.sleep(POLL)
        yield True
    finally:
        os.close(fd)
