# Copyright (c) 2026 KeelLinux maintainers
"""keel access list and remove (decision 0098, section 7)

`list` reads the spec's network.access and, on the live system, the
last handshake of each computer from `wg show <iface>
latest-handshakes` (never `dump`, which holds the node's private key).
`remove` writes the spec without the computer and applies it, as keel
mesh changes the spec (keel.mesh.node): validated whole, written through
a rename, under the sync lock. The apply removes the peer from the live
interface at once (`wg set ... remove`), so WireGuard drops each packet
of that key. A removal on one node does not remove the computer on
another; in a pair, the administrator removes it on each node (answer
7, A).
"""

import json
import os
import sys
from collections.abc import Callable
from datetime import datetime, timezone

from keel import exits, spec
from keel.inspect import ROOT_DEFAULT
from keel.network import access as acc

Reader = Callable[[tuple[str, ...]], str | None]


def out(line: str) -> None:
    print(line)


def error(line: str) -> None:
    print(f"keel access: {line}", file=sys.stderr)


def read_spec(path: str) -> tuple[dict | None, int]:
    try:
        return spec.canonical(spec.load(path)), exits.OK
    except spec.SpecError as e:
        error(str(e))
        return None, exits.SPEC_UNREADABLE


def handshakes(iface: str, output: Reader) -> dict[str, int]:
    """Each peer's last handshake, seconds since the epoch; 0 for none"""
    found = {}
    for line in (output(("wg", "show", iface, "latest-handshakes"))
                 or "").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit():
            found[fields[0]] = int(fields[1])
    return found


def rows(access: dict, seen: dict[str, int] | None) -> list[dict]:
    found = []
    for peer in acc.peers(access):
        at = None if seen is None else seen.get(str(peer["public_key"]), 0)
        found.append({
            "name": peer.get("name"),
            "address": acc.host(peer),
            "enrolled": peer.get("enrolled"),
            "public_key": peer.get("public_key"),
            "last_handshake": None if not at else datetime.fromtimestamp(
                at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        })
    return found


def access_list(args, output: Reader | None = None) -> int:
    doc, code = read_spec(args.spec)
    if doc is None:
        return code
    access = acc.section(doc)
    if access is None:
        if args.json:
            out(json.dumps({"interface": None, "computers": []}))
        else:
            out("no access network: the spec declares no network.access"
                " (keel access invite makes it)")
        return exits.OK
    iface = acc.interface(access)
    seen = None
    if os.path.abspath(args.root) == ROOT_DEFAULT:
        if output is None:
            from keel.network import live
            output = live.output
        seen = handshakes(iface, output)
    found = rows(access, seen)
    if args.json:
        out(json.dumps({"interface": iface,
                        "address": str(acc.address(access)),
                        "port": acc.port(access), "computers": found}))
        return exits.OK
    out(f"{iface}: {acc.address(access)}, UDP {acc.port(access)}")
    for row in found:
        out(f"{row['name']}\t{row['address']}\tenrolled {row['enrolled']}"
            f"\tlast handshake {row['last_handshake'] or 'none'}")
    if not found:
        out("no computer")
    return exits.OK


def without(doc: dict, name: str) -> dict | None:
    """The spec without the computer `name`; None when it has none"""
    access = acc.section(doc)
    if access is None:
        return None
    kept = [peer for peer in access.get("peers") or []
            if not (isinstance(peer, dict) and peer.get("name") == name)]
    if len(kept) == len(access.get("peers") or []):
        return None
    network = {**doc["network"], "access": {**access, "peers": kept}}
    return {**doc, "network": network}


def access_remove(args, node=None) -> int:
    from keel.mesh.commands import as_root, live_node
    from keel.mesh.node import NodeError
    code = as_root(args, "keel access remove")
    if code != exits.OK:
        return code
    node = node or live_node(args)
    try:
        doc = node.document()
    except NodeError as e:
        error(str(e))
        return exits.SPEC_UNREADABLE
    changed = without(doc, args.name)
    if changed is None:
        error(f"no computer {args.name!r} in network.access.peers;"
              " keel access list names them")
        return exits.USAGE
    try:
        done = node.change(changed)
    except NodeError as e:
        error(str(e))
        return exits.SPEC_INVALID
    if done.code != exits.OK:
        done.shown(error)
        error(f"{args.name} is out of the spec, and the apply failed"
              f" (exit {done.code}); keel spec apply --system again")
        return done.code
    out(f"removed {args.name}: its packets get no answer from now on")
    return exits.OK


def inviter(args):
    from keel.access import inviting
    return inviting.live(args, out, error)


def rooted(args, verb: str) -> int:
    from keel.mesh.commands import as_root
    return as_root(args, verb)


def access_invite(args) -> int:
    """Print the command that enrols a computer (decision 0098)"""
    from keel.access import inviting
    code = rooted(args, "keel access invite")
    if code != exits.OK:
        return code
    return inviting.invite(inviter(args), args.name, args.endpoint)


def access_serve(args) -> int:
    """What keel-access-invite@<id> runs"""
    import signal

    from keel.access import inviting
    from keel.mesh.inviting import terminated
    code = rooted(args, "keel access serve")
    if code != exits.OK:
        return code
    signal.signal(signal.SIGTERM, terminated)
    return inviting.serve(inviter(args), args.invite)


def access_invites(args) -> int:
    from keel.access import inviting
    code = rooted(args, "keel access invites")
    if code != exits.OK:
        return code
    found = inviter(args)
    for line in inviting.waiting(found.root, found.clock()) or [
            "no enrolment waits"]:
        out(line)
    return exits.OK


def access_cancel(args) -> int:
    from keel.access import inviting
    code = rooted(args, "keel access cancel")
    if code != exits.OK:
        return code
    return inviting.cancel(inviter(args), args.invite)
