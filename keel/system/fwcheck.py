# Copyright (c) 2026 KeelLinux maintainers
"""keel firewall check: is the table the kernel holds the file's?

Decision 0097, section 4. Run by keel-firewall-watch.timer (with
--restore) and by Monit's check where the spec enables the monitor.
Nothing in the file is trusted for itself (the real test of PR 307: a
broken file whose digest comment was intact passed):

- the rules in the file must be the ones its digest names
  (keel.manifest.firewall.digest_of), else it was edited by hand;
- `nft -c` must accept the file;
- the table `inet keel` the kernel holds must carry that digest and the
  file's policy.

Exit 0 when they agree or when there is no file of keel's; DRIFT_FOUND
otherwise. A table that is absent or another, beside a sound file, is
`restorable`: --restore loads the file again with `nft -f`, one
transaction that replaces keel's table only. A broken file is never
loaded: that is for keel spec apply --system.
"""

import os
import subprocess
from dataclasses import dataclass

from keel import exits
from keel.manifest.firewall import (
    PATH,
    POLICY,
    POLICY_RE,
    TABLE,
    digest_of,
    file_state,
    loaded_digest,
)

APPLY = "keel spec apply --system writes it again"


@dataclass(frozen=True)
class Checked:
    code: int
    message: str
    restorable: bool = False


def check(root: str, run=None) -> Checked:
    run = run or subprocess.run
    path = os.path.join(root, PATH)
    try:
        with open(path) as fob:
            text = fob.read()
    except FileNotFoundError:
        text = None
    except OSError as e:
        return Checked(exits.DRIFT_FOUND,
                       f"{path} cannot be read: {e.strerror}")
    state = file_state(text)
    if state is None:
        return Checked(exits.OK,
                       f"{path}: no ruleset of keel's, nothing to compare")
    return compare(path, text or "", state, run)


def compare(path: str, text: str, state: str, run) -> Checked:
    wanted = loaded_digest(text)
    if digest_of(text) != wanted:
        return Checked(exits.DRIFT_FOUND, (
            f"the rules in the file are not the ones its digest names"
            f" ({path}, a change by hand): {APPLY}"))
    refused = nft_refuses(path, run)
    if refused is not None:
        return Checked(exits.DRIFT_FOUND,
                       f"nft -c refuses {path}: {refused}; {APPLY}")
    listing = table_listing(run)
    if listing is None:
        return Checked(exits.DRIFT_FOUND, (
            f"table inet keel is not loaded; {path} says {wanted}"), True)
    held = loaded_digest(listing)
    if held != wanted:
        return Checked(exits.DRIFT_FOUND, (
            f"table inet keel holds {held}; {path} says {wanted}"), True)
    policy = POLICY_RE.search(listing)
    found = policy.group(1) if policy else "none"
    if found != POLICY[state]:
        return Checked(exits.DRIFT_FOUND, (
            f"table inet keel has policy {found}, and the file says"
            f" {POLICY[state]}"), True)
    return Checked(exits.OK,
                   f"table inet keel is the one {path} says ({wanted})")


def nft_refuses(path: str, run) -> str | None:
    try:
        out = run(["nft", "-c", "-f", path], capture_output=True, text=True,
                  check=False)
    except OSError as e:
        return f"nft cannot run: {e.strerror}"
    if out.returncode == 0:
        return None
    return (out.stderr or out.stdout or "").strip() or "refused"


def table_listing(run) -> str | None:
    try:
        out = run(["nft", "list", "table", *TABLE], capture_output=True,
                  text=True, check=False)
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None


def restore(root: str, run=None) -> str | None:
    """Load keel's file again; None, or why it failed"""
    run = run or subprocess.run
    path = os.path.join(root, PATH)
    try:
        out = run(["nft", "-f", path], capture_output=True, text=True,
                  check=False)
    except OSError as e:
        return f"nft cannot run: {e.strerror}"
    if out.returncode == 0:
        return None
    return (out.stderr or out.stdout or "").strip() or "refused"
