# Copyright (c) 2026 KeelLinux maintainers
"""Anubis's signing key on a pair, asked of the other member (0041)

The overlay manifest of Anubis declares the secret `anubis_signing_key`
as `shared: true`: every node of a replicated set must hold the
primary's key, so a visitor who solved the challenge on one node is not
challenged again on the other. keel-overlay-anubis-key.service makes the
key on the primary at the first start of anubis@keel, and makes none on
a database replica (Keel-Linux/common, packages/anubis/signing-key).
Nothing copied it (Keel-Linux/common#56), so Anubis did not start on
the replica.

A paired node whose spec makes it a database replica, with Anubis
enabled, no key file and no `secrets.anubis_signing_key` declared, asks
the other member of its pair for the key: a `secret` message on the
members' channel, as keel.system.dbsecret asks for the replication
credential, answered only to the other member of the pair record
(keel.mesh.vipserve.shared). The plan writes it, mode 0600, before the
overlay's units start. A key that is there is never replaced, as the
key unit never replaces one.
"""

import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone

from keel.network.marker import path

KEY = "etc/anubis/keel.key"
NAME = "anubis/signing_key"
OVERLAY = "anubis"
SECRET = "anubis_signing_key"
MODE = 0o600
HEX = re.compile(r"[0-9a-f]{64}")
WAIT_PAIR = (
    "the Anubis key of a database replica is the primary's (decision"
    " 0041): it is asked of the other member once the pair is made (keel"
    " vip pair), and Anubis starts then"
)
WAIT_RUN = (
    "the Anubis key is the primary's and is not held here yet; a run that"
    " may change the machine asks the other member of the pair for it"
)
NOT_YET = "the other node of the pair holds no Anubis key yet"
LATER = "; Anubis starts once a later apply gets the key"


@dataclass(frozen=True)
class AnubisKey:
    """The key asked of the other member, or why there is none yet:
    `waiting` starts nothing and is no failure, `problem` refuses"""

    value: str | None = None
    problem: str = ""
    waiting: str = ""
    # /etc/anubis/keel.key is a link whose target is gone: removed before
    # the key is written, so the write cannot follow it
    dangling: bool = False


class Later(Exception):
    """The other member cannot give the key now: it made none yet, or it
    does not answer. Not a failure: a later run asks again."""


def valid(value: object) -> bool:
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def read(root: str) -> str | None:
    """The key this node holds, through a link too, or None"""
    try:
        with open(path(root, KEY)) as fob:
            found = fob.read().strip()
    except OSError:
        return None
    return found if valid(found) else None


def ask(here, vip: str, at: str) -> str:
    """The key from the other member of the pair at `at`; raises Later
    when it cannot give one now, VipError when its answer is no key.
    Nothing is written here: the plan does."""
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
            raise Later(f"{NOT_YET}: its first start of Anubis makes"
                        " it") from None
        raise Later(f"the other node at {at} did not answer: {e}") \
            from None
    except (SigningError, ProtocolError, ValueError, AttributeError) as e:
        raise VipError(f"the other node at {at} answered no Anubis key:"
                       f" {e}") from None
    if not valid(value):
        raise VipError(f"the other node at {at} answered no Anubis key")
    return value


def from_the_primary(doc: dict) -> bool:
    """What the spec says, as spec-key of keel-overlay-anubis reads it:
    no file declared for the key, and this node a database replica"""
    secret = (doc.get("secrets") or {}).get(SECRET)
    if isinstance(secret, dict) and secret.get("file"):
        return False
    server = (doc.get("database") or {}).get("server") or {}
    return server.get("role") == "replica"


def here_of(root: str, spec: str):
    """This node as the members' channel speaks for it"""
    from keel.mesh.node import Node
    from keel.mesh.vipnode import Here
    return Here(Node(root, spec), lambda: datetime.now(timezone.utc),
                lambda line: print(line, file=sys.stderr))


def observe(root: str, doc: dict, ask_peer: bool,
            spec: str) -> AnubisKey | None:
    """None when this node has nothing to ask: Anubis not enabled, a key
    already there, or the key not the primary's by the spec"""
    if (doc.get("overlays") or {}).get(OVERLAY) != "enabled":
        return None
    where = path(root, KEY)
    if os.path.exists(where):
        return None
    dangling = os.path.islink(where)
    if not from_the_primary(doc):
        return None
    from keel.system import dbpair
    pair = dbpair.observe_pair(root, doc)
    if pair is None or not pair.peer_address:
        return AnubisKey(waiting=WAIT_PAIR)
    if not ask_peer:
        return AnubisKey(waiting=WAIT_RUN)
    from keel.mesh.vipnode import VipError
    try:
        return AnubisKey(value=ask(here_of(root, spec), pair.vip,
                                   pair.peer_address), dangling=dangling)
    except Later as e:
        return AnubisKey(waiting=f"{e}{LATER}")
    except (VipError, OSError) as e:
        return AnubisKey(problem=str(e))
