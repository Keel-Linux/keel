# Copyright (c) 2026 KeelLinux maintainers
"""What the planners look at, read once from the root

The only reads of apply --system happen here, through keel.inspect.tree,
so the planners are pure functions of a SystemState. Commands are looked
up and `locale -a` is run only when the root is the live system: a
scratch tree has no locale archive of its own to ask.
"""

import shutil
import subprocess
from dataclasses import dataclass

from keel.inspect import constants as paths
from keel.inspect.accounts import home_of, passwd_entries
from keel.inspect.tree import File, Tree
from keel.system.dbstate import DatabaseState, observe_database

LOCALE_GEN = "etc/locale.gen"
MAILNAME = "etc/mailname"
POSTFIX_MAIN = "etc/postfix/main.cf"
KEYS_UNDER_HOME = ".ssh/authorized_keys"
LOCALE_LIST = ("locale", "-a")
COMMANDS = (
    "useradd", "usermod", "timedatectl", "locale-gen", "localedef", "newaliases",
    "hostnamectl", "hostname", "systemctl",
)


@dataclass(frozen=True)
class SystemState:
    root: str
    live: bool
    passwd: File
    group: File
    hosts: File
    key_files: dict[str, File]
    timezone: File
    localtime_target: str | None
    default_locale: File
    locale_gen: File
    generated: tuple[str, ...] | None
    available: frozenset[str]
    database: DatabaseState | None = None
    aliases: File | None = None
    cron_apt_config: File | None = None
    hostname: File | None = None
    mailname: File | None = None
    postfix_main: File | None = None


def observe(root: str, doc: dict) -> SystemState:
    """Read everything the plan for `doc` depends on under `root`"""
    tree = Tree(root)
    live = tree.root == paths.ROOT_DEFAULT
    passwd = tree.read(paths.PASSWD)
    entries = passwd_entries(passwd)
    key_files = {
        str(name): tree.read(keys_path(str(name), entries))
        for name in (doc.get("users") or {})
    }
    return SystemState(
        root=tree.root,
        live=live,
        passwd=passwd,
        group=tree.read(paths.GROUP),
        hosts=tree.read(paths.HOSTS),
        key_files=key_files,
        timezone=tree.read(paths.TIMEZONE),
        localtime_target=tree.readlink(paths.LOCALTIME),
        default_locale=tree.read(paths.DEFAULT_LOCALE),
        locale_gen=tree.read(LOCALE_GEN),
        generated=generated_locales() if live else None,
        available=frozenset(
            name for name in COMMANDS if shutil.which(name)
        ) if live else frozenset(),
        database=observe_database(root, doc),
        aliases=tree.read(paths.ALIASES),
        cron_apt_config=tree.read(paths.CRON_APT_CONFIG),
        hostname=tree.read(paths.HOSTNAME),
        mailname=tree.read(MAILNAME),
        postfix_main=tree.read(POSTFIX_MAIN),
    )


def keys_path(name: str, entries: dict) -> str:
    """The authorized_keys path of a user, relative to the root"""
    home = home_of(name, entries).strip("/")
    return f"{home}/{KEYS_UNDER_HOME}"


def generated_locales() -> tuple[str, ...] | None:
    """What `locale -a` lists, or None when it cannot be asked"""
    try:
        out = subprocess.run(
            list(LOCALE_LIST), capture_output=True, text=True, check=False,
        )
    except OSError:
        return None
    if out.returncode != 0:
        return None
    return tuple(out.stdout.split())
