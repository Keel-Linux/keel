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
from keel.layers import (
    CACHE_DEFAULT,
    CACHE_ENV,
    LAYERS_DEFAULT,
    LAYERS_ENV,
)
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


def layers_default() -> str:
    return os.environ.get(LAYERS_ENV, LAYERS_DEFAULT)


def cache_default() -> str:
    return os.environ.get(CACHE_ENV, CACHE_DEFAULT)


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
    verify_parser = _add_command(
        subparsers, "verify",
        "check the installed layers against their manifests (packages not"
        " implemented yet)",
        commands.verify,
    )
    add_layer_options(verify_parser)

    pull_parser = _add_command(
        subparsers, "pull",
        "fetch the layers of an appliance that the cache does not have",
        commands.pull,
    )
    add_pull_options(pull_parser)
    assemble_parser = _add_command(
        subparsers, "assemble",
        "extract cached layers into a rootfs and pack a Proxmox template"
        " (root only)",
        commands.assemble,
    )
    add_assemble_options(assemble_parser)
    return parser


def add_layer_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--layers-dir",
        default=layers_default(),
        metavar="DIR",
        help=f"directory of layer manifests (default: ${LAYERS_ENV} or"
        f" {LAYERS_DEFAULT})",
    )
    parser.add_argument(
        "--tarballs-dir",
        default=None,
        metavar="DIR",
        help="directory of layer tarballs and hash files (default: the"
        " layers directory)",
    )


def add_cache_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--cache-dir",
        default=cache_default(),
        metavar="DIR",
        help=f"layer cache (default: ${CACHE_ENV} or {CACHE_DEFAULT})",
    )


def add_pull_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "layer",
        metavar="LAYER",
        help="layer name to look up at the source, or the path of its"
        " manifest file",
    )
    parser.add_argument(
        "--source",
        required=True,
        metavar="URL-or-DIR",
        help="where manifests and tarballs are served: an http(s) URL such"
        " as http://[2001:db8::1]/layers, or a directory",
    )
    add_cache_option(parser)


def add_assemble_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "layer", metavar="LAYER", help="layer name, as pulled into the cache"
    )
    parser.add_argument(
        "--rootfs",
        required=True,
        metavar="DIR",
        help="directory to extract into; created, must be empty",
    )
    parser.add_argument(
        "--template",
        default=None,
        metavar="FILE",
        help="also pack the rootfs into this .tar.zst, with FILE.sha512"
        " next to it",
    )
    parser.add_argument(
        "--sha256",
        default=None,
        metavar="HEX",
        help="which cached version of LAYER, when more than one is cached",
    )
    add_cache_option(parser)


def _add_spec_action(subparsers, name: str, help_text: str, handler) -> None:
    parser = subparsers.add_parser(name, help=help_text)
    add_common_options(parser)
    parser.set_defaults(handler=handler)


def _add_command(
    subparsers, name: str, help_text: str, handler
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(name, help=help_text)
    add_common_options(parser)
    parser.set_defaults(handler=handler)
    return parser


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
