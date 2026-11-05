# Copyright (c) 2026 KeelLinux maintainers
"""A pair of files only: the folders follow the VIP (decision 0076)

Keel Web in a cloud mode replicates its site files with syncthing and
has no database (0076, point 4). Its two nodes declare the same
`appliance.vip`, and the direction of the folders comes from the VIP,
as a database's role does (0049): the node that holds the VIP sends,
the other receives. keel.system.dbfollow calls this where a node
declares no `database.server`; the flip itself is
keel.system.filesync.follow_flip, in dbfollow's `finally`, so every
exit that proves no role pauses the folders.

| the VIP here | the folders |
| --- | --- |
| held by this node's newest claim, not in doubt, and on wg0 | send (primary) |
| held by this node's claim, but in doubt or not on wg0 | paused: not proven (keel#104) |
| held by the other member, or released or fenced here | receive (replica) |
| no claim yet | paused, until a node holds it (keel vip promote) |

A node qualifies when it is in cloud simple or cloud advanced, declares
`appliance.vip` and no `database.server`, and its appliance replicates
a path for its mode with the syncthing overlay enabled
(filesync.replicates_files). Any other node without a database keeps
dbfollow's refusal, or its "nothing to follow" on a witness.
"""

import os
from collections.abc import Callable

from keel.mesh import vip as vipstate
from keel.mesh import vipnet
from keel.network import live, wireguard
from keel.system import dbpair
from keel.system.dbstate import declared_server

CLOUD_MODES = ("cloud_simple", "cloud_advanced")
NO_CLAIM = (
    "no node holds {vip} yet: the folders stay paused. Run keel vip promote"
    " on the node that is to send the files"
)
NOT_PROVEN = (
    "this node's claim of {vip} is not proven (in doubt, or the VIP is not"
    " on wg0): the folders stay paused until it is"
)
DIRECTION = {
    dbpair.PRIMARY: "this node holds {vip}: its folders send the files",
    dbpair.REPLICA: "the other member holds {vip}: this node's folders"
                    " receive the files",
}


def applies(root: str, doc: dict) -> bool:
    """Whether this node is one of a pair of files only"""
    from keel.system import filesync
    mode = (doc.get("installation") or {}).get("mode")
    try:
        vip = vipstate.declared(doc)
    except ValueError:
        return False
    return mode in CLOUD_MODES and vip is not None and \
        not declared_server(doc) and filesync.replicates_files(root, doc)


def follow(root: str, doc: dict, found,
           proven: Callable[[], bool]) -> tuple[object, str | None]:
    """The pair, and the role the folders take (None pauses them); the
    role file written for a role proven. `proven` is whether the VIP is
    on wg0 now (dbfollow's proof, which waits for a promote)"""
    pair = dbpair.observe_pair(root, doc)
    if pair.problem or pair.peer_address is None:
        found.fail(pair.problem or "the other member of the pair is not"
                   " known (keel vip pair)")
        return pair, None
    role = pair.role
    if role is None:
        found.say(NO_CLAIM.format(vip=pair.vip))
        return pair, None
    if role == dbpair.PRIMARY and (vipstate.unconfirmed(root, pair.vip)
                                   or not proven()):
        found.say(NOT_PROVEN.format(vip=pair.vip))
        return pair, None
    write_role(root, role, pair.vip)
    found.say(DIRECTION[role].format(vip=pair.vip))
    return pair, role


def write_role(root: str, role: str, vip: str) -> None:
    """/var/lib/keel/role, with `replicates=files`"""
    from keel.system import dbfollow
    dbfollow.write_public(root, dbpair.ROLE_FILE,
                          dbpair.role_text(role, vip, database=False,
                                           files=True))


def recorded(root: str) -> str:
    try:
        with open(os.path.join(root, dbpair.ROLE_FILE)) as fob:
            return fob.read()
    except OSError:
        return ""


def mismatch(root: str, doc: dict, pair, output=live.output) -> bool:
    """For keel database watch: whether the folders' recorded role is
    not the VIP's, or the holder no longer carries the VIP on wg0 (its
    valid_lft ran out), so follow runs again"""
    if pair is None or pair.role is None or not applies(root, doc):
        return False
    if f"role={pair.role}\n" not in recorded(root):
        return True
    if pair.role != dbpair.PRIMARY:
        return False
    overlay = ((doc.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    return vipnet.carried(wireguard.interface(overlay), pair.vip,
                          output) is False
