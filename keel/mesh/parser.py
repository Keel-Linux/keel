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
    window(options, create_parser)
    options.root(create_parser, "create the mesh in")
    create_parser.set_defaults(handler=commands.mesh_create)
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
