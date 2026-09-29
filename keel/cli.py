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
from keel.inspect import ROOT_DEFAULT, SECRETS_DIR_DEFAULT
from keel.layers import (
    CACHE_DEFAULT,
    CACHE_ENV,
    CHANNELS,
    KEYRING_DEFAULT,
    KEYRING_ENV,
    LAYERS_DEFAULT,
    LAYERS_ENV,
    SIGNER_ENV,
    STATE_DEFAULT,
    STATE_ENV,
)
from keel.spec import CONF_DEFAULT, CONF_ENV, SPEC_DEFAULT, SPEC_ENV


DIFF_FORMATS = ("text", "json")


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


def keyring_default() -> str:
    return os.environ.get(KEYRING_ENV, KEYRING_DEFAULT)


def state_default() -> str:
    return os.environ.get(STATE_ENV, STATE_DEFAULT)



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
    validate_parser = _add_spec_action(
        spec_actions, "validate", "check the spec and report every error",
        commands.spec_validate,
    )
    validate_parser.add_argument(
        "--no-secret-files",
        action="store_true",
        help="check the structure of each secret reference but not that"
        " the file exists with the right owner and mode; for a machine"
        " that does not hold the secrets (default: check the files)",
    )
    _add_spec_action(
        spec_actions, "render",
        "print the conf that apply would write, secrets masked",
        commands.spec_render,
    )
    apply_parser = _add_spec_action(
        spec_actions, "apply",
        "write the conf, leaving an existing non empty conf alone; with"
        " --system also converge the system state, with --system-only that"
        " state alone",
        commands.spec_apply,
    )
    add_apply_options(apply_parser)

    database_parser = subparsers.add_parser(
        "database", help="operations on the database server of this node"
    )
    database_actions = database_parser.add_subparsers(
        dest="action", metavar="ACTION"
    )
    promote_parser = database_actions.add_parser(
        "promote",
        help="make this replica a primary: stop replicating and forget"
        " the primary it was following. Never something apply decides,"
        " and there is no failover in Keel, so only the operator knows"
        " the old primary should stop being one",
    )
    add_common_options(promote_parser)
    promote_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print what would be done and change nothing; needs no root",
    )
    add_root_option(promote_parser, "promote")
    promote_parser.set_defaults(handler=commands.database_promote)

    inspect_parser = _add_command(
        subparsers, "inspect",
        "write a spec from the running machine, or from an offline root,"
        " reporting what could not be inferred",
        commands.inspect,
    )
    add_inspect_options(inspect_parser)
    diff_parser = _add_command(
        subparsers, "diff",
        "report drift between the spec and the running machine, or an"
        " offline root",
        commands.diff,
    )
    add_diff_options(diff_parser)
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
    parser.add_argument(
        "--channel",
        default=None,
        choices=CHANNELS,
        help="follow this channel pointer at the source; its signature and"
        " its expiry are checked and an expired pointer is an error"
        " (default: the flat layout, which follows no pointer)",
    )
    add_channel_options(parser)
    parser.add_argument(
        "--channel-state",
        default=state_default(),
        metavar="FILE",
        help="where the channel and revision this instance follows is"
        f" recorded (default: ${STATE_ENV} or {STATE_DEFAULT})",
    )
    parser.add_argument(
        "--release",
        default=None,
        metavar="YYYY-MM-DD",
        help="an immutable release revision instead of a channel; with"
        " --rev. This is how a rollback is asked for: the blobs of every"
        " release are kept, so an earlier revision can always be pulled",
    )
    parser.add_argument(
        "--rev",
        default=None,
        type=int,
        metavar="N",
        help="which revision of --release; revisions never overwrite each"
        " other, so this names one set of bytes for good",
    )
    parser.add_argument(
        "--allow-rollback",
        action="store_true",
        help="accept a channel pointer that names an earlier revision than"
        " the one this instance is on. Without it such a pointer is an"
        " error, because a mirror does not move an appliance backwards",
    )


def add_channel_options(parser: argparse.ArgumentParser) -> None:
    """What a pointer is verified against, for the commands that read one

    That is `pull` and `inspect --check-channel`. Not `verify`: it reads
    manifests and tarballs in a directory, where no pointer lives, and
    giving it a keyring would suggest it checks a signature it does not.
    What it says about a `.hash` signature names the check it did not make.
    """
    parser.add_argument(
        "--channel-keyring",
        default=keyring_default(),
        metavar="FILE",
        help="the OpenPGP keyring a channel pointer is verified against,"
        f" armored or binary (default: ${KEYRING_ENV} or"
        f" {KEYRING_DEFAULT})",
    )
    parser.add_argument(
        "--channel-signer",
        action="append",
        default=None,
        dest="channel_signers",
        metavar="FINGERPRINT",
        help="only this key may move a channel, given as a full"
        " fingerprint of the signing key or of its primary key; may be"
        f" repeated (default: ${SIGNER_ENV}, else any key in the keyring,"
        " so a keyring holding the channel key alone gets the same"
        " separation)",
    )


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


def add_root_option(parser: argparse.ArgumentParser, verb: str) -> None:
    parser.add_argument(
        "--root",
        default=ROOT_DEFAULT,
        metavar="DIR",
        help=f"filesystem to {verb}: the live system, a mounted container"
        f" rootfs or a tree keel assemble produced (default: {ROOT_DEFAULT})",
    )


def add_apply_options(parser: argparse.ArgumentParser) -> None:
    phase = parser.add_mutually_exclusive_group()
    phase.add_argument(
        "--system",
        action="store_true",
        help="after the conf, converge the system state the spec declares"
        " (the fully qualified name in /etc/hosts, users with their"
        " authorized keys, locale, timezone); root on the live system"
        " (default: the conf only)",
    )
    phase.add_argument(
        "--system-only",
        action="store_true",
        help="the system state and nothing else: the conf is neither read"
        " nor written and no secret is resolved, so a generated password"
        " the hooks already applied is never regenerated; for a machine"
        " whose conf phase has already run (docs/apply.md)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="with --system or --system-only: print the plan and change"
        " nothing, not even the conf",
    )
    parser.add_argument(
        "--destroy-local-database",
        action="store_true",
        help="confirm, for this run only, that making this node a replica"
        " of the declared primary may drop the databases it holds; a"
        " replica is a copy of its primary, so there is no other way."
        " Without it apply refuses and changes nothing, which is what a"
        " first boot gets (docs/apply.md)",
    )
    parser.add_argument(
        "--defer-certificate",
        action="store_true",
        help="with --system or --system-only: write tls.acme but ask no"
        " certificate authority for a certificate in this run; the first"
        " boot hook passes it, since DNS rarely points at a machine that is"
        " still booting (docs/apply.md)",
    )
    add_root_option(parser, "converge with --system")


def add_diff_options(parser: argparse.ArgumentParser) -> None:
    add_root_option(parser, "compare with the spec")
    parser.add_argument(
        "--format",
        choices=DIFF_FORMATS,
        default=DIFF_FORMATS[0],
        help="one line per field, or one JSON document for a calling"
        " program (default: %(default)s)",
    )


def add_inspect_options(parser: argparse.ArgumentParser) -> None:
    add_root_option(parser, "inspect")
    parser.add_argument(
        "--check-channel",
        action="store_true",
        help="also ask the mirror this instance pulled from what its"
        " channel now holds, and report whether newer revisions exist."
        " Off by default: every other probe reads files only",
    )
    add_channel_options(parser)
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="write the spec here, mode 0600 (default: stdout)",
    )
    parser.add_argument(
        "--report",
        default=None,
        metavar="FILE",
        help="write the field by field report here (default: stderr)",
    )
    parser.add_argument(
        "--secrets-dir",
        default=SECRETS_DIR_DEFAULT,
        metavar="DIR",
        help="where the secret placeholders point; the values are never"
        f" read or written (default: {SECRETS_DIR_DEFAULT})",
    )


def _add_spec_action(
    subparsers, name: str, help_text: str, handler
) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(name, help=help_text)
    add_common_options(parser)
    parser.set_defaults(handler=handler)
    return parser


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
    system = getattr(args, "system", False) or getattr(
        args, "system_only", False
    ) or args.command == "database"
    if getattr(args, "dry_run", False) and not system:
        parser.error("--dry-run requires --system or --system-only")
    if getattr(args, "defer_certificate", False) and not system:
        parser.error(
            "--defer-certificate requires --system or --system-only:"
            " the certificate is requested there"
        )
    if getattr(args, "destroy_local_database", False) and not system:
        parser.error(
            "--destroy-local-database requires --system or --system-only:"
            " the database phase runs there"
        )
    if args.command == "pull":
        # Asked here so a combination that cannot resolve is a usage
        # error before the mirror is touched, rather than a 404 for a
        # path that was never going to exist.
        try:
            commands.resolution(args)
        except ValueError as e:
            parser.error(str(e))
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
