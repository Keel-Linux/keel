# Copyright (c) 2026 KeelLinux maintainers
"""What the planners look at, read once from the root

The only reads of apply --system happen here, through keel.inspect.tree,
so the planners are pure functions of a SystemState. Commands are looked
up and `locale -a` is run only when the root is the live system: a
scratch tree has no locale archive of its own to ask.
"""

import base64
import shutil
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

from keel.inspect import constants as paths
from keel.inspect.accounts import home_of, passwd_entries
from keel.inspect.tree import File, Tree
from keel.system.dbstate import DatabaseState, observe_database
from keel.system.monstate import MonitorState, observe_monitor
from keel.system.netstate import NetworkState, observe_network

LOCALE_GEN = "etc/locale.gen"
MAILNAME = "etc/mailname"
POSTFIX_MAIN = "etc/postfix/main.cf"
ACME_WRAPPER = "usr/lib/confconsole/plugins.d/Lets_Encrypt/dehydrated-wrapper"
# dehydrated 0.7.2's names for its CAs, and the one it uses when none is set
ACME_CAS = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt-test":
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    "zerossl": "https://acme.zerossl.com/v2/DV90",
    "buypass": "https://api.buypass.com/acme/directory",
    "buypass-test": "https://api.test4.buypass.no/acme/directory",
    "google": "https://dv.acme-v02.api.pki.goog/directory",
    "google-test": "https://dv.acme-v02.test-api.pki.goog/directory",
}
ACME_DEFAULT_CA = "letsencrypt"
# the account dehydrated moves to the v02 directory for Let's Encrypt
ACME_OLD_CAS = {
    ACME_CAS["letsencrypt"]: "https://acme-v01.api.letsencrypt.org/directory",
}
ACME_BASEDIR = "/var/lib/dehydrated"
# the units tls.acme restarts when it gives a certificate back, where present
SERVICE_UNIT_DIRS = ("etc/systemd/system", "usr/lib/systemd/system",
                     "lib/systemd/system")
TLS_SERVICES = ("nginx.service", "apache2.service", "lighttpd.service",
                "tomcat10.service", "tomcat11.service", "webmin.service")
KEYS_UNDER_HOME = ".ssh/authorized_keys"
LOCALE_LIST = ("locale", "-a")
COMMANDS = (
    "useradd", "usermod", "timedatectl", "locale-gen", "localedef", "newaliases",
    "hostnamectl", "hostname", "systemctl", "ifup", "ifdown", "ip",
    "systemd-run", "monit",
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
    kernel_hostname: str | None = None
    tls_cert: File | None = None
    acme_domains: File | None = None
    acme_account: bool = False
    acme_wrapper: bool = False
    now: datetime | None = None
    service_units: frozenset[str] = frozenset()
    network: NetworkState | None = None
    monitor: MonitorState | None = None


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
        kernel_hostname=socket.gethostname() if live else None,
        tls_cert=tree.read(paths.TLS_CERT),
        acme_domains=tree.read(paths.DEHYDRATED_DOMAINS),
        acme_account=acme_account(tree),
        acme_wrapper=tree.exists(ACME_WRAPPER),
        now=datetime.now(timezone.utc),
        service_units=frozenset(
            unit for unit in TLS_SERVICES
            if any(tree.exists(f"{d}/{unit}") for d in SERVICE_UNIT_DIRS)
        ),
        network=observe_network(root, doc),
        monitor=observe_monitor(root, doc),
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


def account_hash(ca_url: str) -> str:
    """dehydrated's name for a CA's account: `echo "$CA" | urlbase64`"""
    encoded = base64.b64encode(f"{ca_url}\n".encode()).decode()
    return encoded.rstrip("=").replace("+", "-").replace("/", "_")


def acme_account(tree: Tree) -> bool:
    """Whether an account is registered with the CA the config names

    An account for another CA (staging, or one the machine used before) is
    not consent for this one. The account key is never read, only whether
    dehydrated's registration record exists.
    """
    config = tree.read(paths.DEHYDRATED_CONFIG).assignments()
    ca = config.get("CA", ACME_DEFAULT_CA)
    url = ACME_CAS.get(ca, ca)
    basedir = config.get("BASEDIR", ACME_BASEDIR).strip("/")
    candidates = [url] + ([ACME_OLD_CAS[url]] if url in ACME_OLD_CAS else [])
    return any(
        tree.exists(f"{basedir}/accounts/{account_hash(one)}"
                    "/registration_info.json")
        for one in candidates
    )
