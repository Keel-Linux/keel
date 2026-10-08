# Copyright (c) 2026 KeelLinux maintainers
"""Paths inspect reads, relative to the root it is given, and its defaults"""

import os

# The live system is /. KEEL_LIVE_ROOT names a tree that stands for it:
# the multi-node tests run several nodes in one container, each on a
# scratch root in a network namespace of its own, and keel there asks
# the servers, runs systemctl and writes under that root as it does on
# a machine (tests/mariadb_netns.py). Never set on a machine.
ROOT_DEFAULT = os.path.abspath(os.environ.get("KEEL_LIVE_ROOT") or "/")
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
# where the first boot keeps a Keel Cloud API key (confconsole's
# keelfirstboot.py); only its presence is asked, as for the Hub's
CLOUD_API_KEY = "etc/keel/secrets/cloud_api_key"
CLOUD_API_KEY_NAME = "cloud_api_key"
# the line inithooks' 95secupdates leaves of the first boot's answer,
# skip or force, which nothing else on the machine records
SEC_UPDATES_RECORD = "var/lib/inithooks/sec-updates"
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
# The one monit file keel writes (decision 0021), and where the mounts a
# check per filesystem is written for are listed.
MONIT_CONF = "etc/monit/conf.d/keel.conf"
MONITRC = "etc/monit/monitrc"
MOUNTINFO = "proc/self/mountinfo"
# What keel notify reads when monit runs it: the channels, resolved from
# the spec at apply, with token files by path and never by value.
MONITOR_SETTINGS = "etc/keel/monitor.json"
# The record keel pull leaves of the channel and release revision this
# instance follows; absent on an appliance that follows the flat layout.
CHANNEL_STATE = "var/lib/keel/channel"
# Where a DHCPv6 client writes its lease down, dhcpcd first, dhclient
# second: the trace that tells a DHCPv6 address from a SLAAC one.
DHCP6_LEASES = ("var/lib/dhcpcd/*.lease6", "var/lib/dhcp/dhclient6*.leases")

# the kernel's list of the network interfaces, read on the live system
# only, so an allow-hotplug stanza for a card the machine does not have
# is told from one it has
SYS_CLASS_NET = "/sys/class/net"

HOSTNAME_COMMAND = ("hostname", "-f")
IP_ADDR_COMMAND = ("ip", "-6", "addr", "show")
# What a server is bound to, asked of the kernel rather than of the
# server's own setting: docs/traps.md, "Asserting the configuration is not
# asserting the behaviour".
LISTENING_COMMAND = ("ss", "-lntH")

# A spec missing any of these cannot be applied headless: the hook behind
# each one prompts when its variable is unset. instance.fqdn is not one:
# no hook asks for it (00declarative exports FQDN and nothing reads it),
# apply leaves /etc/hosts alone without it, and an appliance out of the
# box has none, so requiring it made inspect exit 13 on every new one.
REQUIRED = (
    "instance.hostname",
    "network.interfaces",
    "security.alerts",
    "security.updates_at_first_boot",
)
