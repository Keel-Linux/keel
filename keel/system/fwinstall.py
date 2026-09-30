# Copyright (c) 2026 KeelLinux maintainers
"""Put a ruleset in place only once nft accepts it (decision 0041)

Carried out for keel.system.effects, its only caller. The copy sits
beside the target, so the rename is atomic, and it is made with mode
0600 from the start. A copy nft refuses is removed and the file already
in place, if any, is left as it was: keel-firewall.service loads that
file at boot, and a file nft refuses would leave the machine at boot
with no table of keel's at all.
"""

import contextlib
import os
import subprocess

from keel.system.actions import InstallRuleset

SUFFIX = ".keel-check"
MODE = 0o600


def install(root: str, action: InstallRuleset) -> str | None:
    target = os.path.join(root, action.path)
    copy = target + SUFFIX
    os.makedirs(os.path.dirname(target), exist_ok=True)
    fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                 | os.O_NOFOLLOW, MODE)
    os.fchmod(fd, MODE)
    with os.fdopen(fd, "w") as fob:
        fob.write(action.content)
    try:
        out = subprocess.run(["nft", "-c", "-f", copy], capture_output=True,
                             text=True, check=False)
    except OSError as e:
        os.remove(copy)
        return f"cannot run nft: {e.strerror}"
    if out.returncode != 0:
        with contextlib.suppress(FileNotFoundError):
            os.remove(copy)
        detail = out.stderr.strip() or out.stdout.strip()
        return ("nft -c refused the ruleset, which is not put in place:"
                f" {detail}")
    os.replace(copy, target)
    return None
