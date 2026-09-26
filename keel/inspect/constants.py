# Copyright (c) 2026 KeelLinux maintainers
"""Paths inspect reads, relative to the root it is given, and its defaults"""

ROOT_DEFAULT = "/"
SECRETS_DIR_DEFAULT = "/etc/keel/secrets"

HOSTNAME = "etc/hostname"
HOSTS = "etc/hosts"
INTERFACES = "etc/network/interfaces"
INTERFACES_D = "etc/network/interfaces.d"
RESOLV_CONF = "etc/resolv.conf"
LXC_MARKER = "var/lib/turnkey-info/inithooks.service/lxc"
DEHYDRATED_DIR = "etc/dehydrated"
DEHYDRATED_CONFIG = "etc/dehydrated/confconsole.config"
DEHYDRATED_DOMAINS = "etc/dehydrated/confconsole.domains.txt"
DEHYDRATED_DOMAINS_PLAIN = "etc/dehydrated/domains.txt"
TURNKEY_VERSION = "etc/turnkey_version"
INITHOOKS_CONF = "etc/inithooks.conf"
ALIASES = "etc/aliases"
CRON_APT_CONFIG = "etc/cron-apt/config"
CRON_APT_INSTALL = "etc/cron-apt/action.d/5-install"
AUTO_UPGRADES = "etc/apt/apt.conf.d/20auto-upgrades"
ROOT_KEYS = "root/.ssh/authorized_keys"
HOME_KEYS = "home/*/.ssh/authorized_keys"
TIMEZONE = "etc/timezone"
LOCALTIME = "etc/localtime"
DEFAULT_LOCALE = "etc/default/locale"
PASSWD = "etc/passwd"
GROUP = "etc/group"
DATABASE_DIRS = ("etc/mysql", "etc/postgresql")

HOSTNAME_COMMAND = ("hostname", "-f")

# A spec missing any of these cannot be applied headless: the hook behind
# each one prompts when its variable is unset.
REQUIRED = (
    "instance.hostname",
    "instance.fqdn",
    "network.interfaces",
    "security.alerts",
    "security.updates",
)
