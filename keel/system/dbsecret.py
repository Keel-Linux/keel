# Copyright (c) 2026 KeelLinux maintainers
"""The replication credential a pair shares, never typed (0028, 0041)

0028 has the primary generate what the replica uses. On a paired node
(appliance.vip), the node that is primary at the pair's first apply
makes the credential (`generate`), keeps it root only under
/var/lib/keel/database, and the other member asks for it over the
members' channel (`ask`: a `secret` message on `POST /v1/vip`, signed
with its mesh key, answered only to the other member of the pair record,
keel.mesh.vipserve.shared), through the channel's TLS inside WireGuard.
It is the first use of 0041's `shared` secret policy. A
`replication.secret` declared in the spec stays what it was: a file the
operator put on both nodes, and it wins (keel.system.dbstate).
"""

import json
import os
import secrets

from keel.network.marker import path, write_private

# the mesh's modules are imported where they are used: keel.mesh.node
# imports keel.commands, which imports keel.system, which imports this

DIR = "var/lib/keel/database"
SECRET = f"{DIR}/replication.secret"
NAME = "database/replication"
BYTES = 32
# what the asker says when the holder has none yet
NOT_YET = ("the other node of the pair holds no replication credential yet:"
           " keel spec apply --system on the primary makes it")


def read(root: str) -> str | None:
    """The credential this node holds, or None"""
    try:
        with open(path(root, SECRET)) as fob:
            return fob.read().rstrip("\n") or None
    except FileNotFoundError:
        return None


def generate(root: str) -> str:
    """A fresh credential, kept root only; the one held when one is"""
    found = read(root)
    if found is not None:
        return found
    made = secrets.token_urlsafe(BYTES)
    write_private(root, SECRET, made + "\n")
    return made


def keep(root: str, value: str) -> None:
    write_private(root, SECRET, value + "\n")


def ask(here, vip: str, at: str) -> str:
    """The credential from the other member of the pair at `at` (`here`
    is this node, keel.mesh.vipnode.Here); raises VipError with why not"""
    from keel.mesh import vipmsg
    from keel.mesh.memberlink import LinkError
    from keel.mesh.protocol import ProtocolError
    from keel.mesh.signing import SigningError
    from keel.mesh.vipnode import VipError
    try:
        answer = here.say(vipmsg.SECRET, at, {"vip": vip, "name": NAME})
        value = json.loads(answer.decode()).get("value")
    except LinkError as e:
        if "holds no" in str(e):
            raise VipError(NOT_YET) from None
        raise VipError(f"the other node at {at} did not answer: {e}") \
            from None
    except (SigningError, ProtocolError, ValueError) as e:
        raise VipError(f"the other node at {at} answered no credential:"
                       f" {e}") from None
    if not isinstance(value, str) or not value or \
            len(value) > vipmsg.MAX_SECRET:
        raise VipError(f"the other node at {at} answered no credential")
    keep(here.root, value)
    return value


def shared(here, vip: str, primary: bool, at: str | None) -> str:
    """The pair's credential on this node: held, made here when this
    node is the primary, else asked of the other member; VipError"""
    from keel.mesh.vipnode import VipError
    found = read(here.root)
    if found is not None:
        return found
    if primary:
        return generate(here.root)
    if not at:
        raise VipError("this node is not the primary and knows no other"
                       " member to ask the credential of")
    return ask(here, vip, at)


def exists(root: str) -> bool:
    return os.path.exists(path(root, SECRET))
