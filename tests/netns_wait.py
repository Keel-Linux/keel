# Copyright (c) 2026 KeelLinux maintainers
"""What the netns harnesses share to set up a child namespace"""

import os
import time


def entered(pid: int, wait: float = 10.0) -> None:
    """Wait until process `pid` is in a network namespace of its own

    `unshare -n` has not always unshared yet when Popen returns. A veth
    end moved to its pid then stays in this namespace, and the next step
    in the child finds no device: "Cannot find device uplink" (the
    postgres job, CI 2026-11-06, under load)"""
    own = os.readlink("/proc/self/ns/net")
    deadline = time.monotonic() + wait
    while True:
        try:
            if os.readlink(f"/proc/{pid}/ns/net") != own:
                return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError(f"process {pid} entered no network namespace"
                               f" of its own within {wait:g} s")
        time.sleep(0.01)
