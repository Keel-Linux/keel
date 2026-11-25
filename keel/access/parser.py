# Copyright (c) 2026 KeelLinux maintainers
"""The keel access subcommands' arguments (decision 0098)

Apart from keel.cli for length, and light: it imports nothing of the
library (decision 0070). keel.cli hands in its shared options.
"""


def add(subparsers, options) -> None:
    """keel access: the administrators' computers (decision 0098)"""
    access_parser = subparsers.add_parser(
        "access",
        help="the computers of the administrators on this node's access"
        " network: enrol, list or remove them (decision 0098)",
    )
    actions = access_parser.add_subparsers(dest="action", metavar="ACTION")
    list_parser = actions.add_parser(
        "list",
        help="each computer: its name, address, day of enrolment and last"
        " handshake",
    )
    options.common(list_parser)
    list_parser.add_argument(
        "--json", action="store_true",
        help="one JSON document, for confconsole")
    options.root(list_parser, "read the access network of")
    list_parser.set_defaults(handler="keel.access.commands.access_list")
    remove_parser = actions.add_parser(
        "remove",
        help="remove a computer from the spec and apply: its packets get no"
        " answer from then on (root)",
    )
    options.common(remove_parser)
    remove_parser.add_argument("name", metavar="NAME",
                               help="the computer's name, as list shows it")
    options.root(remove_parser, "remove the computer in")
    remove_parser.set_defaults(handler="keel.access.commands.access_remove")
    invite_parser = actions.add_parser(
        "invite",
        help="print the one command that enrols a computer, valid once and"
        " for network.access.token_minutes (default 15); makes"
        " network.access at the first enrolment (root)",
    )
    options.common(invite_parser)
    invite_parser.add_argument("--name", required=True, metavar="NAME",
                               help="the computer's name: 1 to 32 of a-z"
                               " 0-9 and -")
    invite_parser.add_argument(
        "--endpoint", default=None, metavar="ADDRESS",
        help="the IPv6 address the computer reaches this node at (default:"
        " its global IPv6 address)")
    options.root(invite_parser, "enrol the computer on")
    invite_parser.set_defaults(handler="keel.access.commands.access_invite")
    serve_parser = actions.add_parser(
        "serve", help="what keel-access-invite@ID runs (root)")
    options.common(serve_parser)
    serve_parser.add_argument("invite", metavar="ID")
    options.root(serve_parser, "serve the enrolment of")
    serve_parser.set_defaults(handler="keel.access.commands.access_serve")
    invites_parser = actions.add_parser(
        "invites", help="the enrolments that wait: id, name, address,"
        " expiry, port (root)")
    options.common(invites_parser)
    options.root(invites_parser, "list the enrolments of")
    invites_parser.set_defaults(handler="keel.access.commands.access_invites")
    cancel_parser = actions.add_parser(
        "cancel", help="cancel an enrolment that waits (root)")
    options.common(cancel_parser)
    cancel_parser.add_argument("invite", metavar="ID")
    options.root(cancel_parser, "cancel the enrolment on")
    cancel_parser.set_defaults(handler="keel.access.commands.access_cancel")
