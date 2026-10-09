# Copyright (c) 2026 KeelLinux maintainers
"""keel vip: promote, pair, unpair, check, tend, status (decision 0049)

The service VIP of a replicated appliance pair, on the WireGuard mesh.
`promote`, `pair` and `unpair` are the operator's (docs/vip.md); `check`
is what keel-vip-check.timer runs, `tend` what keel-vip.service runs
(keel-overlay-vip), and `status` reads only. Like every command, nothing here prompts.
"""

import os
import signal
import sys
import threading
from datetime import datetime, timezone

from keel import exits, system
from keel.commands import error
from keel.inspect import ROOT_DEFAULT
from keel.mesh import vipbridge, vipetcd, vippromote, vipunit
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
        " expired; never revoked). Without etcd, an old primary that is"
        " alive but cannot be reached stays writable until it learns the"
        " newer claim",
    )
    options.root(promote_parser, "promote the VIP of")
    promote_parser.set_defaults(handler=vip_promote)
    pair_parser = actions.add_parser(
        "pair",
        help="record this node's appliance.vip as the pair's with the peer"
        " at ADDRESS, which declares the same VIP: both sign the record"
        " every claim carries (root)",
    )
    options.common(pair_parser)
    pair_parser.add_argument("address", metavar="ADDRESS",
                             help="the other node's overlay address")
    options.root(pair_parser, "pair the VIP of")
    pair_parser.set_defaults(handler=vip_pair)
    unpair_parser = actions.add_parser(
        "unpair",
        help="release this pair's reservation of VIP in etcd, once no"
        " member declares it, so another pair may reserve it (root)",
    )
    options.common(unpair_parser)
    unpair_parser.add_argument("vip", metavar="VIP",
                               help="the VIP the pair no longer uses")
    options.root(unpair_parser, "release the VIP of")
    unpair_parser.set_defaults(handler=vip_unpair)
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
        help="the VIP's root helper with etcd, which starts the"
        " unprivileged controller (renew the holder's lease, drop the VIP"
        " 10 s after the last renewal the majority confirmed, follow and"
        " fail over) and alone changes wg0; what keel-vip.service runs"
        " (root)",
    )
    options.common(tend_parser)
    tend_parser.add_argument(
        "--stopped", action="store_true",
        help="drop every VIP this node carries, but keep one bounded by"
        " its lifetime while the unit restarts (an upgrade, a crash); what"
        " the unit runs once the controller stopped",
    )
    options.root(tend_parser, "tend the VIPs of")
    tend_parser.set_defaults(handler=vip_tend)
    control_parser = actions.add_parser(
        "control",
        help="the unprivileged controller keel vip tend starts as the unit"
        " keel-vip-control; not run by hand",
    )
    control_parser.add_argument("socket", metavar="SOCKET",
                                help="the root helper's unix socket")
    control_parser.set_defaults(handler=vip_control)
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


def vip_pair(args) -> int:
    code = as_root(args, "keel vip pair")
    if code != exits.OK:
        return code
    return vippromote.pair(here_of(args), args.address, out)


def vip_unpair(args) -> int:
    code = as_root(args, "keel vip unpair")
    if code != exits.OK:
        return code
    return vippromote.unpair(here_of(args), args.vip, out)


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
    vipbridge.no_new_privileges(err)
    if args.stopped:
        dropped, kept = vipetcd.stopped(here, vipunit.restarting(
            os.environ, here.node.output))
        for vip in dropped:
            out(f"vip {vip}: dropped, the controller stopped")
        for vip in kept:
            out(f"vip {vip}: kept while the unit restarts; the kernel"
                " removes it at the release time unless the next"
                " controller renews its lease")
        return exits.OK
    stop = threading.Event()

    def stopped(signum, frame):
        stop.set()
        # out of the bridge's read, through serve's cleanup
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stopped)
    return vipbridge.serve(here, stop)


def vip_control(args) -> int:
    """What keel-vip-control runs: the unprivileged controller"""
    return vipbridge.control(args.socket, err)


def vip_status(args) -> int:
    for line in vippromote.lines(here_of(args),
                                 os.path.abspath(args.root) == ROOT_DEFAULT):
        print(line)
    return exits.OK
