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
TLS_CERT = "etc/ssl/private/cert.pem"
# tklbam's record of a Hub registration; only its presence is asked, and
# at the default registry, not one TKLBAM_REGISTRY moved for a test
TKLBAM_HUB_REGISTRATION = "var/lib/tklbam/sub_apikey"
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
# The record keel pull leaves of the channel and release revision this
# instance follows; absent on an appliance that follows the flat layout.
CHANNEL_STATE = "var/lib/keel/channel"
# Where a DHCPv6 client writes its lease down, dhcpcd first, dhclient
# second: the trace that tells a DHCPv6 address from a SLAAC one.
DHCP6_LEASES = ("var/lib/dhcpcd/*.lease6", "var/lib/dhcp/dhclient6*.leases")

HOSTNAME_COMMAND = ("hostname", "-f")
IP_ADDR_COMMAND = ("ip", "-6", "addr", "show")
# What a server is bound to, asked of the kernel rather than of the
# server's own setting: docs/traps.md, "Asserting the configuration is not
# asserting the behaviour".
LISTENING_COMMAND = ("ss", "-lntH")

# A spec missing any of these cannot be applied headless: the hook behind
# each one prompts when its variable is unset.
REQUIRED = (
    "instance.hostname",
    "instance.fqdn",
    "network.interfaces",
    "security.alerts",
    "security.updates_at_first_boot",
)
