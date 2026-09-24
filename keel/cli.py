# Copyright (c) 2026 KeelLinux maintainers
"""Command line interface for Keel

The CLI holds no logic of its own: it parses arguments and calls
keel.commands, which confconsole calls directly. Every command runs
without a terminal and without prompting.

Exit codes are defined in keel.exits and documented in README.md.
"""

import argparse
import os
import signal
import sys

from keel import __version__, commands, exits
from keel.spec import CONF_DEFAULT, CONF_ENV, SPEC_DEFAULT, SPEC_ENV


class Parser(argparse.ArgumentParser):
    """argparse exits 2 on a usage error; Keel reserves 2 for the spec"""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        print(f"Error: {message}", file=sys.stderr)
        raise SystemExit(exits.USAGE)


def spec_default() -> str:
    return os.environ.get(SPEC_ENV, SPEC_DEFAULT)


def conf_default() -> str:
    return os.environ.get(CONF_ENV, CONF_DEFAULT)


def add_common_options(parser: argparse.ArgumentParser) -> None:
    """Options every command accepts, so callers never have to branch"""
    parser.add_argument(
        "--spec",
        default=spec_default(),
        metavar="FILE",
        help=f"instance spec to read (default: ${SPEC_ENV} or {SPEC_DEFAULT})",
    )
    parser.add_argument(
        "--conf",
        default=conf_default(),
        metavar="FILE",
        help=f"conf file to write (default: ${CONF_ENV} or {CONF_DEFAULT})",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="never prompt (the default, accepted for callers that pass it)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="keel",
        description="Declarative management of one appliance instance",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    spec_parser = subparsers.add_parser(
        "spec", help="work with the instance spec"
    )
    spec_actions = spec_parser.add_subparsers(
        dest="action", metavar="ACTION"
    )
    _add_spec_action(
        spec_actions, "validate", "check the spec and report every error",
        commands.spec_validate,
    )
    _add_spec_action(
        spec_actions, "render",
        "print the conf that apply would write, secrets masked",
        commands.spec_render,
    )
    _add_spec_action(
        spec_actions, "apply",
        "write the conf, leaving an existing non empty conf alone",
        commands.spec_apply,
    )

    _add_command(
        subparsers, "inspect",
        "write a spec from the running machine (not implemented yet)",
        commands.inspect,
    )
    _add_command(
        subparsers, "diff",
        "report drift between declared and running (not implemented yet)",
        commands.diff,
    )
    _add_command(
        subparsers, "verify",
        "check layers and packages against the manifest (not implemented"
        " yet)",
        commands.verify,
    )
    return parser


def _add_spec_action(subparsers, name: str, help_text: str, handler) -> None:
    parser = subparsers.add_parser(name, help=help_text)
    add_common_options(parser)
    parser.set_defaults(handler=handler)


def _add_command(subparsers, name: str, help_text: str, handler) -> None:
    parser = subparsers.add_parser(name, help=help_text)
    add_common_options(parser)
    parser.set_defaults(handler=handler)


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help(sys.stderr)
        return exits.USAGE
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
