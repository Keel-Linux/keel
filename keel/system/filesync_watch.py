# Copyright (c) 2026 KeelLinux maintainers
"""The alert of the file replication (0050's amendment, point 8)

The database watch calls watch_counts on each run. What counts is the
set of (path, counter) that are not zero, with a folder in error and a
folder paused while the node is proven. receiveOnlyChangedFiles counts at
once; needFiles only when it is not zero in NEED_RUNS runs in a row,
because a folder that is catching up wants files for a while and that is
no fault. One alert goes out when a member joins the set, one when the set
is empty again, and the state is kept only after the alert was taken, so
an alert that no channel took is sent again at the next run.
"""

import json
import os
from collections.abc import Callable

from keel.manifest.facts import gather
from keel.system import filesync_api as api
from keel.system import filesync_io as io
from keel.system.filesync import OVERLAY, _mode, effective_paths

NEED_RUNS = 3
CHANGED = "a replicated folder holds local changes or is not in sync"
CHANGED_TEXT = (
    "{host}: file replication of {paths}: {what}. On a replica a local"
    " change is what the primary replaced (kept as versions) or did not"
    " send yet; on a primary a receive count says a folder took local"
    " writes, which the pair's one-writer rule forbids (0050). keel diff"
    " reports the counts per folder."
)
BACK = "file replication is clean again"
BACK_TEXT = ("{host}: every replicated folder is in sync and holds no"
             " local change.")
Deliver = Callable[[str, str, str, str], bool]


def problems(found: dict[str, dict], state: str, runs: dict[str, int]
             ) -> tuple[dict[str, str], dict[str, int]]:
    """The members of the set now, each with its text, and the runs of
    needFiles in a row per path"""
    members: dict[str, str] = {}
    need_runs: dict[str, int] = {}
    for path, row in found.items():
        if row.get("error") or row.get("state") == "error":
            members[f"{path}\terror"] = (
                f"{path}: {row.get('error') or 'error'}")
        elif row.get("paused") and state != io.PAUSED:
            members[f"{path}\tpaused"] = (f"{path}: paused while this node"
                                          f" is the {state}")
        if row.get("receiveOnlyChangedFiles"):
            members[f"{path}\treceiveOnlyChangedFiles"] = (
                f"{path}: receiveOnlyChangedFiles"
                f" {row['receiveOnlyChangedFiles']}")
        if row.get("needFiles"):
            need_runs[path] = int(runs.get(path) or 0) + 1
            if need_runs[path] >= NEED_RUNS:
                members[f"{path}\tneedFiles"] = (
                    f"{path}: needFiles {row['needFiles']}")
    return members, need_runs


def watch_counts(root: str, doc: dict, out: Callable[[str], None],
                 deliver: Deliver) -> None:
    """Alert on the change of the set; `deliver(title, text, check,
    level)` says whether a channel took the alert"""
    if (doc.get("overlays") or {}).get(OVERLAY) != "enabled":
        return
    appliance = doc.get("appliance")
    if not isinstance(appliance, dict):
        return
    facts = gather(root, str(appliance.get("name") or ""))
    if facts.resolved is None or facts.resolved.application is None:
        return
    paths = effective_paths(facts.resolved.application.item, _mode(doc))
    if not paths:
        return
    found = api.counts(root, paths)
    if found is None:
        out("file replication: the counters are not readable: syncthing"
            " gives no answer on the loopback")
        return
    before = _load(root)
    members, need_runs = problems(found, io.folder_state(root),
                                  before.get("need_runs") or {})
    alerted = set(before.get("alerted") or ())
    keys = set(members)
    host = os.uname().nodename
    taken = True
    if keys - alerted:
        taken = deliver(CHANGED, CHANGED_TEXT.format(
            host=host, paths=", ".join(sorted({one.split("\t")[0]
                                               for one in keys})),
            what="; ".join(members[one] for one in sorted(keys))),
            "filesync-counts", "critical")
    elif not keys and alerted:
        taken = deliver(BACK, BACK_TEXT.format(host=host),
                        "filesync-counts", "recovery")
    _save(root, {"alerted": sorted(keys) if taken else sorted(alerted),
                 "need_runs": need_runs})


def _load(root: str) -> dict:
    try:
        with open(os.path.join(root, io.WATCH_STATE)) as fob:
            found = json.load(fob)
        return found if isinstance(found, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(root: str, state: dict) -> None:
    io.write(root, io.WATCH_STATE, json.dumps(state) + "\n",
             io.SECRET_MODE, private_dir=True)
