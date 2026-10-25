# Copyright (c) 2026 KeelLinux maintainers
"""The application owner over a replicated tree (keel#225, 0050)

Each folder sets copyOwnershipFromParent, so a received entry takes the
owner of its parent. In the first batch of a replication a directory can
be made before its parent got the application owner: it and all below it
stay owned by the syncthing user, and the application, once this node is
primary, cannot write there.

The flip to primary calls `repair` for each replicated path. The owner
of the replicated root is the model (the application image makes it).
Only an entry that the syncthing user owns is changed, so an owner that
someone set on purpose is kept. A link is never followed, and another
file system is never entered. A node that is a replica needs no repair:
no application writes there.
"""

import os


def repair(top: str, syncthing_uid: int) -> int:
    """Give the owner of `top` to each entry under it that the syncthing
    user owns; the number of entries changed. A path that is not there,
    or a root that the syncthing user owns, changes nothing; an entry
    that vanishes during the walk is skipped"""
    try:
        model = os.lstat(top)
    except FileNotFoundError:
        return 0
    if model.st_uid == syncthing_uid:
        return 0
    changed = 0
    for here, directories, files in os.walk(top, followlinks=False):
        for name in directories + files:
            path = os.path.join(here, name)
            try:
                found = os.lstat(path)
                if found.st_uid != syncthing_uid or \
                        found.st_dev != model.st_dev:
                    continue
                os.lchown(path, model.st_uid, model.st_gid)
            except FileNotFoundError:
                continue
            changed += 1
    return changed
