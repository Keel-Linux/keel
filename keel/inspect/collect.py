# Copyright (c) 2026 KeelLinux maintainers
"""Read a root filesystem and hand the files to the probes

This is the thin layer with side effects: it reads files under the root
and runs `hostname -f` when the root is the live system. Everything it
learns is passed to pure probe functions.
"""

import os
import subprocess

from keel.inspect import constants as paths
from keel.inspect.app import probe_app, probe_appliance
from keel.inspect.hostname import probe_hostname
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

    users, found = probe_users(key_files(tree))
    findings += found
    _add(spec, "users", users)

    locale, found = probe_locale(
        tree.read(paths.TIMEZONE),
        tree.readlink(paths.LOCALTIME),
        tree.read(paths.DEFAULT_LOCALE),
    )
    findings += found
    _add(spec, "locale", locale)

    return Inspection(
        tree.root, str(appliance or "unknown appliance"), spec,
        tuple(findings),
    )


def _add(spec: dict, key: str, section: dict | None) -> None:
    if section is not None:
        spec[key] = section


def hostname_f(tree: Tree) -> File:
    """Run `hostname -f`, only when inspecting the live system"""
    command = " ".join(paths.HOSTNAME_COMMAND)
    if tree.root != paths.ROOT_DEFAULT:
        return File(command, problem=OFFLINE)
    try:
        out = subprocess.run(
            list(paths.HOSTNAME_COMMAND), capture_output=True, text=True,
            check=False,
        )
    except OSError as e:
        return File(command, problem=f"failed: {e.strerror}")
    if out.returncode != 0:
        return File(command, problem=f"exited {out.returncode}")
    return File(command, out.stdout)


def key_files(tree: Tree) -> list[tuple[str, File]]:
    """root's authorized_keys, then one per home directory"""
    found = [("root", tree.read(paths.ROOT_KEYS))]
    for relative in tree.glob(paths.HOME_KEYS):
        name = relative.split(os.sep)[1]
        found.append((name, tree.read(relative)))
    return found
