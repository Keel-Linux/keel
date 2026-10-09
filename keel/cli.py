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
from keel.manifest import KINDS as MANIFEST_KINDS
from keel.mesh import parser as mesh_parser
from keel.mesh import vipcli
from keel.monitor.channelfile import PATH as NOTIFY_SETTINGS
from keel.monitor.notify import CHECKS as NOTIFY_CHECKS
from keel.monitor.notify import DIRECTIONS as NOTIFY_DIRECTIONS
from keel.monitor.notify import LEVELS as NOTIFY_LEVELS
from keel.spec import CONF_DEFAULT, CONF_ENV, SPEC_DEFAULT, SPEC_ENV
from keel.system import DEFAULT_WINDOW


DIFF_FORMATS = ("text", "json")
MIN_WINDOW = 30


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
    add_root_option(validate_parser, "read the appliance manifests of")
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
    promote_parser.add_argument(
        "--old-primary-gone",
        action="store_true",
        help="with appliance.vip: the old primary does not answer and you"
        " know it is gone; the VIP moves without its release (keel vip"
        " promote --old-primary-gone). Without etcd, an old primary that"
        " is alive but cannot be reached stays writable until it learns"
        " the newer claim",
    )
    add_root_option(promote_parser, "promote")
    promote_parser.set_defaults(handler=commands.database_promote)
    follow_parser = database_actions.add_parser(
        "follow",
        help="make the server follow the pair's VIP (decisions 0020, 0049):"
        " the holder writable, the other node read only and replicating"
        " from the holder, an old primary rejoined by GTID when it holds"
        " nothing the holder lacks; what keel-database-follow.service runs"
        " when the VIP moves (root)",
    )
    add_common_options(follow_parser)
    follow_parser.add_argument(
        "--destroy-local-database",
        action="store_true",
        help="confirm, for this run only, that a diverged old primary may"
        " be reseeded from the holder, its errant transactions discarded"
        " (a dump is kept first under /var/backups/keel/mariadb)",
    )
    add_root_option(follow_parser, "follow the VIP of")
    follow_parser.set_defaults(handler=commands.database_follow)
    watch_parser = database_actions.add_parser(
        "watch",
        help="report the semi-synchronous fallback and its recovery through"
        " the monitor's channels, and renew the database certificate; what"
        " keel-database-watch.timer runs (root)",
    )
    add_common_options(watch_parser)
    add_root_option(watch_parser, "watch the database of")
    watch_parser.set_defaults(handler=commands.database_watch)
    status_parser = database_actions.add_parser(
        "status",
        help="the role from the VIP and from the server, semi-synchronous"
        " status, the replica's lag, GTID positions, the certificate, a"
        " divergence; never a secret",
    )
    add_common_options(status_parser)
    add_root_option(status_parser, "read the database of")
    status_parser.set_defaults(handler=commands.database_status)

    network_parser = subparsers.add_parser(
        "network", help="a network change apply made, waiting to be kept;"
        " this node's WireGuard key"
    )
    network_actions = network_parser.add_subparsers(
        dest="action", metavar="ACTION"
    )
    confirm_parser = network_actions.add_parser(
        "confirm",
        help="keep the network change apply made; refused unless run from a"
        " session opened after the change over the new configuration, or"
        " from a console (decision 0018)",
    )
    add_root_option(confirm_parser, "confirm the change of")
    confirm_parser.set_defaults(handler=commands.network_confirm)
    revert_parser = network_actions.add_parser(
        "revert",
        help="put back the interfaces file a pending change replaced; what"
        " the revert timer runs, and a way to give up without waiting",
    )
    revert_parser.add_argument(
        "--boot",
        action="store_true",
        help="restore the file only, without restarting the interface; for"
        " the boot unit, which runs before networking",
    )
    add_root_option(revert_parser, "revert the change of")
    revert_parser.set_defaults(handler=commands.network_revert)
    add_wireguard_parser(network_actions)
    mesh_options = mesh_parser.Options(
        add_common_options, add_root_option, port_number, window_seconds)
    mesh_parser.add(subparsers, mesh_options)
    vipcli.add(subparsers, mesh_options)

    # no --spec: notify reads the settings apply wrote, never the spec
    notify_parser = subparsers.add_parser(
        "notify",
        help="tell the operator about a monit alert on every channel the"
        " monitor section declares, with what to do; what the file keel"
        " writes for monit runs (decision 0021)",
    )
    add_notify_options(notify_parser)
    notify_parser.set_defaults(handler=commands.notify)

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
    add_manifest_parser(subparsers)
    return parser


def add_manifest_parser(subparsers) -> None:
    """keel manifest: the appliance and overlay manifests (decision 0041)"""
    manifest_parser = subparsers.add_parser(
        "manifest",
        help="check and print the appliance and overlay manifests under"
        " /usr/share/keel (decision 0041); not the layer manifests",
    )
    manifest_actions = manifest_parser.add_subparsers(
        dest="action", metavar="ACTION"
    )
    validate_parser = manifest_actions.add_parser(
        "validate",
        help="check one manifest, the manifests of a name, or with no"
        " argument every installed one, and resolve each appliance along"
        " its chain; every error at once",
    )
    validate_parser.add_argument(
        "target", nargs="?", default=None, metavar="PATH|NAME",
        help="a manifest file (a PATH has a / or ends in .yaml), or a NAME"
        " looked up under --root (default: every installed manifest)",
    )
    add_manifest_options(validate_parser)
    validate_parser.set_defaults(handler=commands.manifest_validate)
    show_parser = manifest_actions.add_parser(
        "show",
        help="print a manifest as its file says it, or with --resolved its"
        " appliance resolved along its chain, as tables",
    )
    show_parser.add_argument("name", metavar="NAME",
                             help="the manifest to print")
    show_parser.add_argument(
        "--resolved", action="store_true",
        help="print the overlays with their state in each mode, the ports"
        " with their exposure, the processes, checks, secrets, options and"
        " hooks the chain resolves to (appliances only)",
    )
    add_manifest_options(show_parser)
    show_parser.set_defaults(handler=commands.manifest_show)


def add_manifest_options(parser: argparse.ArgumentParser) -> None:
    add_common_options(parser)
    parser.add_argument(
        "--kind", choices=MANIFEST_KINDS, default=None,
        help="which kind a NAME is, when an overlay and an appliance share"
        " it (default: either)",
    )
    add_root_option(parser, "read /usr/share/keel/{overlays,appliances}"
                    " and the unit files and hooks the manifests name in")


def add_wireguard_parser(network_actions) -> None:
    """keel network wireguard: this node's side of the overlay (0020)"""
    wireguard_parser = network_actions.add_parser(
        "wireguard",
        help="this node's WireGuard key and a first overlay address; the"
        " overlay itself is network.overlay.wireguard, converged by apply",
    )
    wireguard_actions = wireguard_parser.add_subparsers(
        dest="wireguard_action", metavar="ACTION"
    )
    key_parser = wireguard_actions.add_parser(
        "key",
        help="print this node's public key, making the key pair first when"
        " there is none (root, live system only); the private key is never"
        " printed",
    )
    key_parser.add_argument(
        "--spec",
        default=spec_default(),
        metavar="FILE",
        help="where the overlay's key file is declared (default:"
        f" ${SPEC_ENV} or {SPEC_DEFAULT}; without it, wg0's default)",
    )
    add_root_option(key_parser, "read the key of")
    key_parser.set_defaults(handler=commands.network_wireguard_key)
    suggest_parser = wireguard_actions.add_parser(
        "suggest-address",
        help="print a fresh unique local IPv6 address (RFC 4193) with its"
        " /64, for the first node of a set; the others take ::2, ::3",
    )
    suggest_parser.set_defaults(handler=commands.network_wireguard_suggest)


def port_number(text: str) -> int:
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise argparse.ArgumentTypeError(f"not a port number: {text}")
    return int(text)


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
    parser.add_argument(
        "--network-window",
        type=window_seconds,
        default=DEFAULT_WINDOW,
        metavar="SECONDS",
        help="with --system or --system-only: how long a network change"
        " waits for keel network confirm before it reverts (default:"
        " %(default)s)",
    )
    parser.add_argument(
        "--skip-network",
        action="store_true",
        help="with --system or --system-only: leave the network alone in"
        " this run; the first boot hook passes it, since 01ipconfig has"
        " already written the file and nobody is there to confirm",
    )
    parser.add_argument(
        "--skip-uplink",
        action="store_true",
        help="with --system or --system-only: leave network.interfaces"
        " alone in this run and converge the overlay only; the console's"
        " overlay screen passes it",
    )
    add_root_option(parser, "converge with --system")


def window_seconds(text: str) -> int:
    """A confirmation window long enough to open a new session in"""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number of seconds: {text}")
    if value < MIN_WINDOW:
        raise argparse.ArgumentTypeError(
            f"at least {MIN_WINDOW} seconds, to open a new session in"
        )
    return value


def add_notify_options(parser: argparse.ArgumentParser) -> None:
    """What monit's exec line says; the event itself is in the environment

    No token or URL is ever an option: they are read from the settings
    apply wrote and the secret files those name, so none reaches an
    argument vector.
    """
    parser.add_argument(
        "--settings", default=NOTIFY_SETTINGS, metavar="FILE",
        help="the channels apply --system wrote; root owned, and writable"
        " by nobody else (default: %(default)s)",
    )
    parser.add_argument(
        "--level", required=True, choices=NOTIFY_LEVELS,
        help="warn or critical when a test fails and while it lasts,"
        " recovery when it succeeds again",
    )
    parser.add_argument(
        "--check", required=True, choices=NOTIFY_CHECKS,
        help="which test of the monitor section this is about",
    )
    parser.add_argument(
        "--path", default="", metavar="DIR",
        help="the mount point, for disk and inodes",
    )
    parser.add_argument(
        "--iface", default="", metavar="NAME",
        help="the interface, for link and throughput",
    )
    parser.add_argument(
        "--name", default="", metavar="NAME",
        help="the process or check of the appliance manifests, for service"
        " and restarts",
    )
    parser.add_argument(
        "--unit", default="", metavar="UNIT",
        help="the systemd unit that process or check belongs to",
    )
    parser.add_argument(
        "--threshold", default="", metavar="N",
        help="the threshold the test holds, as the spec declares it",
    )
    parser.add_argument(
        "--direction", default="", choices=("",) + NOTIFY_DIRECTIONS,
        help="upload or download, for throughput",
    )


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
    ) or args.command in ("database", "mesh", "vip")
    if getattr(args, "dry_run", False) and not system:
        parser.error("--dry-run requires --system or --system-only")
    if getattr(args, "defer_certificate", False) and not system:
        parser.error(
            "--defer-certificate requires --system or --system-only:"
            " the certificate is requested there"
        )
    for flag in ("skip_network", "skip_uplink"):
        if getattr(args, flag, False) and not system:
            parser.error(
                f"--{flag.replace('_', '-')} requires --system or"
                " --system-only: the network is converged there"
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
