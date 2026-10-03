# Copyright (c) 2026 KeelLinux maintainers
"""The mesh's identity: random, made once, carried by every token

Sixteen random bytes that name the mesh: every invite carries them, so
the nodes a join adds know which mesh they are in, and etcd takes them
as its cluster token when it forms at the third node (decision 0048).
The node that creates the mesh makes them; a mesh built by hand before
`keel mesh` existed gets them from `keel mesh create --adopt` on one of
its nodes, and the others from it through `keel mesh sync`. A joining
node keeps the identity its token carries, and a node that holds
another than its members' takes theirs with `keel mesh sync --adopt`
(keel.mesh.sync).
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


def adopt(root: str, found: bytes) -> None:
    """Keep the identity a token carries, on the node that joins

    Raises ValueError when this node already keeps another one: it is
    in another mesh, and a node is in one.
    """
    with locked(root):
        current = read(root)
        if current is None:
            write_private(root, IDENTITY, found.hex() + "\n")
        elif current != found:
            raise ValueError(f"this node is in another mesh: /{IDENTITY}"
                             " names another one than the token's")


def replace(root: str, found: bytes) -> bytes | None:
    """Take `found` in place of the identity this node keeps, which is
    returned (None when it kept none)

    The repair of a split (keel mesh sync --adopt): a node that made an
    identity of its own in a mesh whose members keep another takes
    theirs. A damaged file is replaced too: the members' identity is
    the one to keep.
    """
    with locked(root):
        try:
            before = read(root)
        except ValueError:
            before = None
        write_private(root, IDENTITY, found.hex() + "\n")
    return before


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
