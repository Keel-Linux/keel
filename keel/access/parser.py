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
        " network: list or remove them (decision 0098)",
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
