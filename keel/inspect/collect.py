# Copyright (c) 2026 KeelLinux maintainers
"""Read a root filesystem and hand the files to the probes

This is the thin layer with side effects: it reads files under the root
and, on the live system, runs the two commands the probes need
(`hostname -f` and `ip -6 addr show`). Everything it learns is passed to
pure probe functions.
"""

import os
import subprocess

from keel.inspect import constants as paths
from keel.inspect.app import probe_app, probe_appliance
from keel.inspect.channel import probe_channel
from keel.inspect.database import Installed, probe_database
from keel.inspect.dbclient import READERS, Reader
from keel.inspect.dbengines import ENGINES
from keel.inspect.hostname import probe_hostname
from keel.inspect.ipv6 import Runtime
from keel.inspect.locale import probe_locale
from keel.inspect.network import probe_network
from keel.inspect.report import Finding, Inspection
from keel.inspect.secrets import probe_hub, probe_secrets
from keel.inspect.security import probe_security
from keel.inspect.tls import probe_tls
from keel.inspect.tree import File, Tree
from keel.inspect.users import probe_users
from keel.spec import SCHEMA_VERSION

OFFLINE = "not run: the root is not the live system"


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
        Runtime(run_command(tree, paths.IP_ADDR_COMMAND), leases(tree)),
    )
    findings += found
    _add(spec, "network", network)

    tls, found = probe_tls(
        tree.read(paths.DEHYDRATED_CONFIG),
        [tree.read(paths.DEHYDRATED_DOMAINS),
         tree.read(paths.DEHYDRATED_DOMAINS_PLAIN)],
        tree.exists(paths.DEHYDRATED_DIR),
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
    )
    findings += found
    _add(spec, "security", security)

    hub, found = probe_hub()
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

    # The channel this instance follows is not part of the spec: it is
    # not something an operator declares, it is what the machine was
    # last pulled to. An appliance that follows none produces no line.
    channel, found = probe_channel(tree.read(paths.CHANNEL_STATE))
    findings += found

    return Inspection(
        tree.root, str(appliance or "unknown appliance"), spec,
        tuple(findings), channel,
    )


def _add(spec: dict, key: str, section: dict | None) -> None:
    if section is not None:
        spec[key] = section


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
