# Copyright (c) 2026 KeelLinux maintainers
"""Read a root filesystem and hand the files to the probes

This is the thin layer with side effects: it reads files under the root
and, on the live system, runs the two commands the probes need
(`hostname -f` and `ip -6 addr show`). Everything it learns is passed to
pure probe functions.
"""

import os
import subprocess
from datetime import datetime, timezone

from keel.inspect import constants as paths
from keel.inspect.app import probe_app, probe_appliance
from keel.inspect.channel import probe_channel
from keel.inspect.database import Installed, probe_database
from keel.inspect.dbclient import READERS, Reader
from keel.inspect.dbengines import ENGINES
from keel.inspect.hostname import probe_hostname
from keel.inspect.ipv6 import Runtime
from keel.inspect.locale import probe_locale
from keel.inspect.monitor import monit_cycle, probe_monitor
from keel.inspect.network import probe_network
from keel.inspect.overlays import probe_appliance_sections
from keel.inspect.report import Finding, Inspection
from keel.inspect.secrets import probe_hub, probe_secrets
from keel.inspect.security import probe_security
from keel.inspect.tls import probe_tls
from keel.inspect.tree import File, Tree
from keel.inspect.users import probe_users
from keel.inspect.wireguard import Module, probe_overlay
from keel.mesh import vip, vipnet
from keel.network import live as live_system
from keel.network import wgkeys
from keel.network import wireguard
from keel.network.wireguard import CONF_DIR, MODULE
from keel.spec import SCHEMA_VERSION

OFFLINE = "not run: the root is not the live system"
OVERLAY_FILES = f"{CONF_DIR}/*.conf"


def inspect_root(
    root: str = paths.ROOT_DEFAULT,
    secrets_dir: str = paths.SECRETS_DIR_DEFAULT,
) -> Inspection:
    """Inspect the filesystem under `root` and build a spec from it"""
    tree = Tree(root)
    findings: list[Finding] = []
    spec: dict = {"version": SCHEMA_VERSION}

    appliance, finding = probe_appliance(tree.read(paths.TURNKEY_VERSION))
    findings.append(finding)

    instance, found = probe_hostname(
        tree.read(paths.HOSTNAME), tree.read(paths.HOSTS), hostname_f(tree)
    )
    findings += found
    _add(spec, "instance", instance)

    network, found = probe_network(
        [tree.read(paths.INTERFACES)] + tree.read_dir(paths.INTERFACES_D),
        tree.read(paths.RESOLV_CONF),
        tree.exists(paths.LXC_MARKER),
        Runtime(run_command(tree, paths.IP_ADDR_COMMAND), leases(tree),
                links(tree)),
    )
    findings += found
    overlay, found = overlay_section(tree)
    findings += found
    if overlay:
        network = {**(network or {}), "overlay": overlay}
    _add(spec, "network", network)

    tls, found = probe_tls(
        tree.read(paths.DEHYDRATED_CONFIG),
        [tree.read(paths.DEHYDRATED_DOMAINS),
         tree.read(paths.DEHYDRATED_DOMAINS_PLAIN)],
        tree.exists(paths.DEHYDRATED_DIR),
        tree.read(paths.TLS_CERT),
        datetime.now(timezone.utc),
    )
    findings += found
    _add(spec, "tls", tls)

    conf = tree.read(paths.INITHOOKS_CONF)
    database = any(tree.exists(path) for path in paths.DATABASE_DIRS)
    secrets, found = probe_secrets(conf, secrets_dir, database)
    findings += found
    _add(spec, "secrets", secrets)

    app, found = probe_app(conf, (instance or {}).get("fqdn"))
    findings += found
    _add(spec, "app", app)

    security, found = probe_security(
        conf,
        tree.read(paths.ALIASES),
        tree.read(paths.CRON_APT_CONFIG),
        tree.read(paths.CRON_APT_INSTALL),
        tree.read(paths.AUTO_UPGRADES),
        tree.read(paths.SEC_UPDATES_RECORD),
    )
    findings += found
    _add(spec, "security", security)

    hub, found = probe_hub(tree.present(paths.TKLBAM_HUB_REGISTRATION),
                           tree.present(paths.CLOUD_API_KEY), secrets_dir)
    findings += found
    _add(spec, "hub", hub)

    users, found = probe_users(
        key_files(tree), tree.read(paths.PASSWD), tree.read(paths.GROUP)
    )
    findings += found
    _add(spec, "users", users)

    database, found = probe_database(
        database_servers(tree), client_configs(tree)
    )
    findings += found
    _add(spec, "database", database)

    locale, found = probe_locale(
        tree.read(paths.TIMEZONE),
        tree.readlink(paths.LOCALTIME),
        tree.read(paths.DEFAULT_LOCALE),
    )
    findings += found
    _add(spec, "locale", locale)

    monitor, found = probe_monitor(tree.read(paths.MONIT_CONF),
                                   monit_cycle(tree),
                                   tree.read(paths.MONITOR_SETTINGS))
    findings += found
    _add(spec, "monitor", monitor)

    sections, found = probe_appliance_sections(tree)
    findings += found
    for key, section in sections.items():
        _add(spec, key, section)

    # The channel this instance follows is not part of the spec: it is
    # not something an operator declares, it is what the machine was
    # last pulled to. An appliance that follows none produces no line.
    channel, found = probe_channel(tree.read(paths.CHANNEL_STATE))
    findings += found

    return Inspection(
        tree.root, str(appliance or "unknown appliance"), spec,
        tuple(findings), channel, vip_lines(tree, spec),
    )


def vip_lines(tree: Tree, spec: dict) -> tuple[str, ...]:
    """The VIPs this node knows, as machine state beside the spec
    (decision 0049): the holder and epoch, whether this node is fenced,
    and on the live system whether wg0 carries it and which peer the
    table routes it to"""
    overlay = ((spec.get("network") or {}).get("overlay") or {}).get(
        "wireguard") or {}
    iface = overlay.get("interface") or "wg0"
    is_live = tree.root == paths.ROOT_DEFAULT
    own_key = wgkeys.public(tree.path(
        wireguard.key_path(overlay).lstrip("/")))[0] if overlay else None
    declared = (spec.get("appliance") or {}).get("vip")
    found = []
    for held in vip.held_all(tree.root):
        line = f"vip {held.vip}: "
        if held.vip == declared:
            line += f"role {vip.role(spec, held, own_key)}; "
        line += (f"epoch {held.epoch}, held by {held.holder} at"
                 f" {held.claim.address}" if held.claim
                 else "no holder known")
        if held.fenced:
            line += "; fenced here"
        if is_live:
            carried = vipnet.carried(iface, held.vip, live_system.output)
            to = vipnet.routed_to(iface, held.vip, live_system.output)
            line += (f"; carried here: {'yes' if carried else 'no'}; routed"
                     f" to {to or 'no peer'}")
        found.append(line)
    return tuple(found)


def _add(spec: dict, key: str, section: dict | None) -> None:
    if section is not None:
        spec[key] = section


def overlay_section(tree: Tree) -> tuple[dict | None, list[Finding]]:
    """The WireGuard files, the public key of the key file they name, and
    on the live system whether the kernel module is loaded"""
    live = tree.root == paths.ROOT_DEFAULT
    overlay, found = probe_overlay(
        [tree.read(name) for name in tree.glob(OVERLAY_FILES)],
        lambda key: wgkeys.public(tree.path(key.lstrip("/"))),
        Module(tree.exists(MODULE) if live else None,
               tree.exists(paths.LXC_MARKER)),
    )
    # a VIP is routed at runtime, never declared: the peers read back
    # are the spec's (decision 0049), so a VIP move is never drift
    if overlay is not None:
        overlay = {"wireguard": vip.unrouted(overlay["wireguard"],
                                             vip.known(tree.root))}
    return overlay, found


def run_command(tree: Tree, argv: tuple[str, ...]) -> File:
    """Keep a command's output as a File, only on the live system

    An offline root answers questions about another machine, so a
    command run here would describe the wrong one; the reason is
    recorded and the probes report the field as not inferred.
    """
    command = " ".join(argv)
    if tree.root != paths.ROOT_DEFAULT:
        return File(command, problem=OFFLINE)
    try:
        out = subprocess.run(
            list(argv), capture_output=True, text=True, check=False,
        )
    except OSError as e:
        return File(command, problem=f"failed: {e.strerror}")
    if out.returncode != 0:
        return File(command, problem=f"exited {out.returncode}")
    return File(command, out.stdout)


def hostname_f(tree: Tree) -> File:
    """Run `hostname -f`, only when inspecting the live system"""
    return run_command(tree, paths.HOSTNAME_COMMAND)


def leases(tree: Tree) -> tuple[File, ...]:
    """Every DHCPv6 lease file under the root, in path order

    A lease file is on disk, so an offline root carries it too; it is
    the one piece of IPv6 evidence that survives without the machine.
    """
    return tuple(
        tree.read(name)
        for pattern in paths.DHCP6_LEASES
        for name in tree.glob(pattern)
    )


def links(tree: Tree) -> frozenset[str] | None:
    """The network interfaces the live machine has; None offline

    An offline root carries no /sys of the machine it describes, so
    which cards that machine has is unknown there, and said so by None.
    """
    if tree.root != paths.ROOT_DEFAULT:
        return None
    try:
        return frozenset(os.listdir(paths.SYS_CLASS_NET))
    except OSError:
        return None


def database_servers(tree: Tree) -> tuple[Installed, ...]:
    """Every database server installed under the root, with its answers

    An engine is present when its server binary is, not when its
    configuration directory is: mysql-common puts /etc/mysql on a machine
    that only holds the client. Each server is then asked what it is; on an
    offline root the questions are not run and every field of the reading
    reports why.
    """
    sockets = run_command(tree, paths.LISTENING_COMMAND)
    found = []
    for engine in ENGINES:
        binary = engine.installed(tree.glob)
        if binary is None:
            continue
        answers = {
            name: run_command(tree, argv)
            for name, argv in engine.questions.items()
        }
        found.append(
            Installed(engine, tree.path(binary), answers, sockets)
        )
    return tuple(found)


def client_configs(tree: Tree) -> tuple[tuple[Reader, File], ...]:
    """The application configuration of every reader that finds its file"""
    found = []
    for reader in READERS:
        for pattern in reader.patterns:
            matches = tree.glob(pattern)
            if matches:
                found.append((reader, tree.read(matches[0])))
                break
    return tuple(found)


def key_files(tree: Tree) -> list[tuple[str, File]]:
    """root's authorized_keys, then one per home directory"""
    found = [("root", tree.read(paths.ROOT_KEYS))]
    for relative in tree.glob(paths.HOME_KEYS):
        name = relative.split(os.sep)[1]
        found.append((name, tree.read(relative)))
    return found
