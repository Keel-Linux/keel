# Copyright (c) 2026 KeelLinux maintainers
"""Drift of the file replication (0050's amendment, point 8)

keel diff reports, per replicated path, the two counters the amendment
names: receiveOnlyChangedFiles (local changes a receive-only folder
holds: what the primary replaced, kept as versions, or did not send
yet) and needFiles (files the folder wants). Both wanted 0. On a
primary a receive count says a folder took local writes, which the
pair's one-writer rule forbids; the drift line says so. The counters
are read from syncthing's REST API on the loopback (keel.system.filesync),
on the live system only; when it gives no answer the rows are UNKNOWN,
as a peer's handshake is (keel.diff.handshakes).
"""

from keel.diff.report import DRIFT, SAME, UNKNOWN, FieldDiff
from keel.manifest.facts import gather
from keel.system import filesync, filesync_api, filesync_io

WANTED = "0"
NO_ANSWER = ("syncthing gives no answer on the loopback: is the service"
             " running, and the API key there?")
PEER_NOTE = ("peer unknown or not connected: the other member's device ID"
             " is asked at each flip of the role, and the link is the"
             " overlay's")
NOTE = ("on a replica these are the primary's replaced files (kept as"
        " versions) or what it did not send yet; on a primary they say"
        " a folder took local writes, which the pair's one-writer rule"
        " forbids (0050)")


def filesync_fields(declared: dict, root: str, live: bool) -> list[FieldDiff]:
    """Three rows per replicated path and one for the peer, on the live
    system"""
    if (declared.get("overlays") or {}).get(filesync.OVERLAY) != "enabled":
        return []
    appliance = declared.get("appliance")
    if not isinstance(appliance, dict):
        return []
    facts = gather(root, str(appliance.get("name")))
    if facts.resolved is None or facts.resolved.application is None:
        return []
    mode = str(((declared.get("installation") or {}).get("mode"))
               or "simple")
    paths = filesync.effective_paths(facts.resolved.application.item, mode)
    if not paths or not live:
        return []
    found = filesync_api.counts(root, paths)
    state = filesync_io.folder_state(root)
    fields = []
    for path in paths:
        fields.append(_folder_row(path, state, found))
        for counter in ("receiveOnlyChangedFiles", "needFiles"):
            name = f"filesync.{path}.{counter}"
            if found is None:
                fields.append(FieldDiff(name, UNKNOWN, reason=NO_ANSWER))
                continue
            value = found[path][counter]
            fields.append(FieldDiff(
                name, SAME if value == 0 else DRIFT, declared=WANTED,
                observed=str(value),
                note="" if value == 0 else NOTE))
    fields.append(_peer_row(root, found))
    return fields


DIRECTION = {filesync_io.PRIMARY: filesync.SEND,
             filesync_io.REPLICA: filesync.RECEIVE,
             filesync_io.PAUSED: filesync_io.PAUSED}
PAUSED_NOTE = ("the folder is paused: this node is in doubt or its role is"
               " not proven, so it sends and receives nothing (0050)")


def _folder_row(path: str, state: str, found) -> FieldDiff:
    """The direction the last flip set, and what syncthing runs; a
    folder in error or paused is a problem"""
    name = f"filesync.{path}.folder"
    declared = DIRECTION[state]
    if found is None:
        return FieldDiff(name, UNKNOWN, declared=declared,
                         reason=NO_ANSWER)
    row = found[path]
    if row.get("error") or row.get("state") == "error":
        return FieldDiff(name, DRIFT, declared=declared,
                         observed=f"error: {row.get('error') or 'error'}")
    if row.get("paused"):
        return FieldDiff(name, DRIFT, declared=declared,
                         observed=filesync_io.PAUSED, note=PAUSED_NOTE)
    observed = str(row.get("type") or "")
    return FieldDiff(name, SAME if observed == declared else DRIFT,
                     declared=declared, observed=observed)


def _peer_row(root: str, found) -> FieldDiff:
    peer = filesync_io.read(root, filesync_io.PEER_FILE)
    if found is None:
        return FieldDiff("filesync.peer", UNKNOWN, reason=NO_ANSWER)
    connected = filesync_api.peer_connected(root, peer) if peer else False
    if connected:
        return FieldDiff("filesync.peer", SAME, declared="connected",
                         observed="connected")
    return FieldDiff("filesync.peer", DRIFT, declared="connected",
                     observed="unknown" if peer is None else
                     "not connected", note=PEER_NOTE)
