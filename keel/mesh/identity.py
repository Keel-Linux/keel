# Copyright (c) 2026 KeelLinux maintainers
"""The mesh's identity: random, made once, carried by every token

Sixteen random bytes that name the mesh: every invite carries them, so
the nodes a join adds know which mesh they are in, and etcd takes them
as its cluster token when it forms at the third node (decision 0048).
The node that creates the mesh makes them; a mesh built by hand before
`keel mesh` existed gets them from its first invite. A joining node
keeps the identity its token carries.
"""

import secrets

from keel.mesh import DIR
from keel.mesh.invites import locked
from keel.mesh.token import MESH_ID_BYTES
from keel.network.marker import path, write_private

IDENTITY = f"{DIR}/identity"


def ensure(root: str) -> bytes:
    """The identity, made under the mesh's lock when there is none

    A file that does not hold one is an error, not replaced: another
    identity would be another mesh to every node that has the first.
    """
    with locked(root):
        found = read(root)
        if found is None:
            found = secrets.token_bytes(MESH_ID_BYTES)
            write_private(root, IDENTITY, found.hex() + "\n")
    return found


def read(root: str) -> bytes | None:
    """The identity, None when not made yet; ValueError when damaged"""
    try:
        with open(path(root, IDENTITY)) as fob:
            text = fob.read().strip()
    except FileNotFoundError:
        return None
    try:
        found = bytes.fromhex(text)
    except ValueError:
        found = b""
    if len(found) != MESH_ID_BYTES:
        raise ValueError(f"/{IDENTITY} does not hold a mesh identity"
                         f" ({MESH_ID_BYTES} bytes in hex); keel does not"
                         " replace it, since the mesh's other nodes know it")
    return found
