# Copyright (c) 2026 KeelLinux maintainers
"""keel vip: promote, check, tend, status (decision 0049, docs/mesh.md)

The service VIP of a replicated appliance pair, on the WireGuard mesh.
`promote` is the operator's; `check` is what keel-vip-check.timer runs,
`tend` what keel-vip.service runs (keel-overlay-vip), and `status` reads
only. Like every command, nothing here prompts.
"""

import os
import signal
import sys
import threading
from datetime import datetime, timezone

from keel import exits, system
from keel.commands import error
from keel.inspect import ROOT_DEFAULT
from keel.mesh import vipetcd, vippromote
from keel.mesh.node import Node
from keel.mesh.vipnode import Here


def add(subparsers, options) -> None:
    """keel vip, with keel.mesh.parser's shared options"""
    vip_parser = subparsers.add_parser(
        "vip",
        help="the service VIP of a replicated appliance pair on the"
        " WireGuard mesh: promote this node to hold it, and the units'"
        " check and controller (decision 0049, docs/mesh.md)",
    )
    actions = vip_parser.add_subparsers(dest="action", metavar="ACTION")
    promote_parser = actions.add_parser(
        "promote",
        help="make this node the primary of its pair: the old primary"
        " releases the VIP, this node takes it at the next epoch and tells"
        " every peer; no network confirmation (root)",
    )
    options.common(promote_parser)
    promote_parser.add_argument(
        "--old-primary-gone", action="store_true",
        help="the old primary does not answer and you know it is gone:"
        " take the VIP without its release (with etcd, once its lease"
        " expired; never revoked)",
    )
    options.root(promote_parser, "promote the VIP of")
    promote_parser.set_defaults(handler=vip_promote)
    check_parser = actions.add_parser(
        "check",
        help="ask every peer its epoch, take a newer claim, drop the VIP"
        " where it is not held and route it to its holder; what"
        " keel-vip-check.timer runs (root)",
    )
    options.common(check_parser)
    options.root(check_parser, "check the VIPs of")
    check_parser.set_defaults(handler=vip_check)
    tend_parser = actions.add_parser(
        "tend",
        help="the controller with etcd: renew the holder's lease, drop the"
        " VIP 10 s after the last renewal, follow and fail over; what"
        " keel-vip.service runs (root)",
    )
    options.common(tend_parser)
    tend_parser.add_argument(
        "--stopped", action="store_true",
        help="drop every VIP this node carries; what the unit runs once"
        " the controller stopped, however it stopped",
    )
    options.root(tend_parser, "tend the VIPs of")
    tend_parser.set_defaults(handler=vip_tend)
    status_parser = actions.add_parser(
        "status",
        help="each VIP: the role, the epoch and holder, whether this node"
        " carries it and which peer it is routed to; never a secret",
    )
    options.common(status_parser)
    options.root(status_parser, "read the VIPs of")
    status_parser.set_defaults(handler=vip_status)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def out(line: str) -> None:
    print(line, flush=True)


def err(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def here_of(args) -> Here:
    return Here(Node(os.path.abspath(args.root), args.spec), utcnow, err)


def as_root(args, verb: str) -> int:
    refusal = system.needs_root(os.path.abspath(args.root), verb)
    if refusal:
        error(refusal)
        return exits.APPLY_NEEDS_ROOT
    return exits.OK


def vip_promote(args) -> int:
    code = as_root(args, "keel vip promote")
    if code != exits.OK:
        return code
    return vippromote.promote(here_of(args), args.old_primary_gone, out)


def vip_check(args) -> int:
    code = as_root(args, "keel vip check")
    if code != exits.OK:
        return code
    return vippromote.check(here_of(args), out)


def vip_tend(args) -> int:
    code = as_root(args, "keel vip tend")
    if code != exits.OK:
        return code
    here = here_of(args)
    if args.stopped:
        for vip in vipetcd.stopped(here):
            out(f"vip {vip}: dropped, the controller stopped")
        return exits.OK
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
    vipetcd.Controller(here, stop).run()
    return exits.OK


def vip_status(args) -> int:
    for line in vippromote.lines(here_of(args),
                                 os.path.abspath(args.root) == ROOT_DEFAULT):
        print(line)
    return exits.OK
