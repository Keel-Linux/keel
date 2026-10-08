# Copyright (c) 2026 KeelLinux maintainers
"""The keel mesh subcommands' arguments (decision 0048, docs/mesh.md)

Apart from keel.cli for length; the options every subcommand shares
are keel.cli's own, handed in, so they are defined once.
"""

import argparse
from collections.abc import Callable
from dataclasses import dataclass

from keel.mesh import commands
from keel.network.wireguard import DEFAULT_PORT as WIREGUARD_PORT
from keel.system import DEFAULT_WINDOW


@dataclass(frozen=True)
class Options:
    """keel.cli's shared helpers: --spec and friends, --root, and the
    types of a port and of a window"""

    common: Callable[[argparse.ArgumentParser], None]
    root: Callable[[argparse.ArgumentParser, str], None]
    port: Callable[[str], int]
    window: Callable[[str], int]


def add(subparsers, options: Options) -> None:
    """keel mesh: joining the WireGuard mesh with one command (0048)"""
    mesh_parser = subparsers.add_parser(
        "mesh",
        help="invite a node into this node's WireGuard mesh, or join one"
        " with the line an invite printed (decision 0048, docs/mesh.md)",
    )
    mesh_actions = mesh_parser.add_subparsers(
        dest="action", metavar="ACTION"
    )
    invite_parser = mesh_actions.add_parser(
        "invite",
        help="print the keel mesh join line for a new node, valid one hour"
        " and once, and reserve its overlay address (root)",
    )
    options.common(invite_parser)
    invite_parser.add_argument(
        "--endpoint", action="append", default=None, metavar="ADDRESS",
        help="an address the new node reaches this one at, one per family;"
        " may be repeated (default: the static addresses"
        " network.interfaces declares)",
    )
    invite_parser.add_argument(
        "--port", type=options.port, default=WIREGUARD_PORT,
        metavar="PORT",
        help="the TCP port the join request goes to (default: %(default)s,"
        " the number of WireGuard's UDP port)",
    )
    options.root(invite_parser, "read the overlay of and keep the invite in")
    invite_parser.set_defaults(handler=commands.mesh_invite)
    join_parser = mesh_actions.add_parser(
        "join",
        help="join the mesh of the node that printed TOKEN (root); with"
        " --dry-run, print the change of this node's spec it makes",
    )
    options.common(join_parser)
    join_parser.add_argument(
        "token", metavar="TOKEN",
        help="the keel1: token keel mesh invite printed, or - to read it"
        " from standard input, which keeps it out of the process list",
    )
    join_parser.add_argument(
        "--dry-run", action="store_true",
        help="print the address and the peer the join would write into the"
        " spec, and change nothing",
    )
    join_parser.add_argument(
        "--endpoint", default=None, metavar="ADDRESS",
        help="the address the inviter reaches this node at (default: a"
        " static address network.interfaces declares, else a global one"
        " this node holds; none behind NAT)",
    )
    window(options, join_parser)
    options.root(join_parser, "read the appliance manifests of")
    join_parser.set_defaults(handler=commands.mesh_join)
    actions(mesh_actions, options)


def window(options: Options, parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--network-window", type=options.window,
        default=DEFAULT_WINDOW, metavar="SECONDS",
        help="how long this node's overlay change waits for its"
        " confirmation before it reverts (default: %(default)s)",
    )


def actions(mesh_actions, options: Options) -> None:
    """keel mesh create, accept, status, and the listener's serve"""
    create_parser = mesh_actions.add_parser(
        "create",
        help="make the mesh on its first node: a random overlay prefix,"
        " this node at ::1, confirmed by itself (root)",
    )
    options.common(create_parser)
    create_parser.add_argument(
        "--adopt", action="store_true",
        help="on one node of a mesh built by hand: give the mesh its"
        " identity (this node's, else its peers', else a new one), which"
        " the others take with keel mesh sync",
    )
    window(options, create_parser)
    options.root(create_parser, "create the mesh in")
    create_parser.set_defaults(handler=commands.mesh_create)
    sync_parser = mesh_actions.add_parser(
        "sync",
        help="add the members this node's peers know and it does not, over"
        " the overlay, confirmed by a WireGuard handshake (root); run at"
        " boot and by keel-mesh-sync.timer",
    )
    options.common(sync_parser)
    sync_parser.add_argument(
        "--from", dest="source", action="append", default=None,
        metavar="ADDRESS",
        help="ask the member at this overlay address alone; may be"
        " repeated (default: every peer)",
    )
    sync_parser.add_argument(
        "--adopt", default=None, metavar="ADDRESS",
        help="first take the mesh identity of the member at this overlay"
        " address in place of this node's: the repair of a split",
    )
    window(options, sync_parser)
    options.root(sync_parser, "sync the mesh of")
    sync_parser.set_defaults(handler=commands.mesh_sync)
    members_parser = mesh_actions.add_parser(
        "members",
        help="the members' channel on the overlay, which keel-mesh-members"
        " runs: rosters for keel mesh sync, announcements of new nodes;"
        " not run by hand",
    )
    options.common(members_parser)
    window(options, members_parser)
    options.root(members_parser, "serve the mesh of")
    members_parser.set_defaults(handler=commands.mesh_members)
    members_listen = mesh_actions.add_parser(
        "members-listen",
        help="the unprivileged listener keel mesh members starts as the"
        " unit keel-mesh-members-listen; not run by hand",
    )
    members_listen.add_argument("socket", metavar="SOCKET",
                                help="the root helper's unix socket")
    members_listen.set_defaults(handler=commands.mesh_members_listen)
    remove_parser = mesh_actions.add_parser(
        "remove",
        help="remove a peer from this node's spec, applied under the window"
        " for keel network confirm, and keep its tombstone so no keel mesh"
        " sync adds it again (root)",
    )
    options.common(remove_parser)
    remove_parser.add_argument(
        "member", metavar="KEY|ADDRESS",
        help="the peer's WireGuard public key or its overlay address")
    window(options, remove_parser)
    options.root(remove_parser, "remove the peer in")
    remove_parser.set_defaults(handler=commands.mesh_remove)
    accept_parser = mesh_actions.add_parser(
        "accept",
        help="on the inviter, the keel mesh accept line a join printed when"
        " it could not reach this node's port (root)",
    )
    options.common(accept_parser)
    accept_parser.add_argument(
        "line", metavar="LINE",
        help="the keel1a: line, or - to read it from standard input",
    )
    window(options, accept_parser)
    options.root(accept_parser, "accept the new node in")
    accept_parser.set_defaults(handler=commands.mesh_accept)
    status_parser = mesh_actions.add_parser(
        "status",
        help="this node's peers, their last handshakes, and the pending"
        " invites; never a secret",
    )
    options.common(status_parser)
    options.root(status_parser, "read the mesh of")
    status_parser.set_defaults(handler=commands.mesh_status)
    serve_parser = mesh_actions.add_parser(
        "serve",
        help="the invite's root helper, which keel mesh invite starts as"
        " the unit keel-mesh-invite@ID; not run by hand",
    )
    options.common(serve_parser)
    serve_parser.add_argument("invite", metavar="ID",
                              help="the invite to answer")
    options.root(serve_parser, "serve the invite of")
    serve_parser.set_defaults(handler=commands.mesh_serve)
    listen_parser = mesh_actions.add_parser(
        "listen",
        help="the unprivileged listener keel mesh serve starts as the unit"
        " keel-mesh-listen@ID; not run by hand",
    )
    listen_parser.add_argument("socket", metavar="SOCKET",
                               help="the root helper's unix socket")
    listen_parser.set_defaults(handler=commands.mesh_listen)
    check_parser = mesh_actions.add_parser(
        "upgrade-check",
        help="whether this node may be upgraded now: every other etcd"
        " member healthy and none restarting, and whether it holds a VIP;"
        " changes nothing (docs/vip.md, \"Upgrading a pair without"
        " downtime\")",
    )
    options.common(check_parser)
    options.root(check_parser, "check the upgrade of")
    check_parser.set_defaults(handler=commands.mesh_upgrade_check)
    etcd_actions(mesh_actions, options)


def seconds(text: str) -> int:
    """A whole number of seconds, zero or more"""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"not a number of seconds: {text}") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"not a number of seconds: {text}")
    return value


def etcd_actions(mesh_actions, options: Options) -> None:
    """keel mesh etcd form, tend and reissue (0025, 0048, keel#83)"""
    etcd_parser = mesh_actions.add_parser(
        "etcd",
        help="etcd, the mesh's registry: form it on a mesh that never saw"
        " a third join, and tend its learners and certificates",
    )
    etcd_subs = etcd_parser.add_subparsers(dest="etcd_action",
                                           metavar="ACTION")
    form_parser = etcd_subs.add_parser(
        "form",
        help="ask every member, make the mesh's etcd CA if it has none,"
        " enroll the cloud advanced members and form the cluster at three;"
        " on a formed cluster, bring in what it lacks (root)",
    )
    options.common(form_parser)
    form_parser.add_argument(
        "--dry-run", action="store_true",
        help="ask the members and print what it would do; change nothing"
        " on any member",
    )
    window(options, form_parser)
    options.root(form_parser, "form etcd in")
    form_parser.set_defaults(handler=commands.mesh_etcd_form)
    tend_parser = etcd_subs.add_parser(
        "tend",
        help="promote learners in sync, remove those that never started"
        " within an hour, renew this member's certificates; what"
        " keel-mesh-etcd.timer runs (root)",
    )
    options.common(tend_parser)
    window(options, tend_parser)
    options.root(tend_parser, "tend etcd in")
    tend_parser.set_defaults(handler=commands.mesh_etcd_tend)
    gate_parser = etcd_subs.add_parser(
        "gate",
        help="restart etcd one member at a time: `stop` waits until every"
        " other member is healthy and none restarts, and takes the restart"
        " lock; `started` waits until this member is back and releases it;"
        " what keel-overlay-etcd's drop-in of etcd.service runs (root)",
    )
    options.common(gate_parser)
    gate_parser.add_argument("step", choices=("stop", "started"),
                             help="before etcd stops, or once it started")
    gate_parser.add_argument(
        "--wait", type=seconds, default=None, metavar="SECONDS",
        help="how long to wait (stop: 300, then it stops anyway; started:"
        " 120)",
    )
    options.root(gate_parser, "gate etcd in")
    gate_parser.set_defaults(handler=commands.mesh_etcd_gate)
    reissue_parser = etcd_subs.add_parser(
        "reissue",
        help="on the root CA's holder: move every member to a certificate"
        " the root signs, one at a time, revoke the members' intermediate"
        " CAs and enable etcd's auth (keel#83); safe to run again (root)",
    )
    options.common(reissue_parser)
    which = reissue_parser.add_mutually_exclusive_group()
    which.add_argument(
        "--dry-run", action="store_true",
        help="ask the members and print what it would do; change nothing"
        " on any member",
    )
    which.add_argument(
        "--rollback", action="store_true",
        help="disable etcd's auth again; the certificates stay the root's",
    )
    window(options, reissue_parser)
    options.root(reissue_parser, "reissue etcd's certificates in")
    reissue_parser.set_defaults(handler=commands.mesh_etcd_reissue)
