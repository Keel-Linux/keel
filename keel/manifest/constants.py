# Copyright (c) 2026 KeelLinux maintainers
"""The vocabulary of the appliance manifest, version 1

Every word a field may take is listed here once, in the order the
format (docs/manifest.md, and docs/manifest-v1.md in the handbook) lists
it, since the messages name the choices in that order.
"""

import re

MANIFEST_VERSION = 1

OVERLAY = "overlay"
APPLIANCE = "appliance"
KINDS = (OVERLAY, APPLIANCE)
DIRS = {OVERLAY: "overlays", APPLIANCE: "appliances"}
SHARE_DIR = "usr/share/keel"
SUFFIX = ".yaml"

CORE = "core"
NO_BASE = "none"

MODES = ("simple", "cloud_simple", "cloud_advanced")
MODE_TITLES = {
    "simple": "simple",
    "cloud_simple": "cloud simple",
    "cloud_advanced": "cloud advanced",
}
ENABLED = "enabled"
DISABLED = "disabled"
ASK = "ask"
STATES = (ENABLED, DISABLED, ASK)

ENGINES = ("mariadb", "postgresql", "redis", "opensearch", "elasticsearch",
           "s3")
# "dump (the engine's own dump ...)": the engines whose own tool writes
# one, mariadb-dump and pg_dump. The conservative reading: a new engine
# joins this list by a keel release, not by an overlay's say-so.
DUMP_ENGINES = ("mariadb", "postgresql")
REPLICATION = ("native", "none")
BACKUP = ("dump", "files", "none")

EXPOSE = ("loopback", "mesh", "public")
LOOPBACK = "loopback"
PROTOCOLS = ("tcp", "udp")
LOOPBACK_LITERALS = ("::1", "127.0.0.1")

CHECK_TYPES = ("http", "tcp", "protocol", "command")
CHECK_ADDRESSES = ("loopback", "mesh")
MONIT_PROTOCOLS = ("mysql", "pgsql", "redis", "ssh", "smtp")
ON_FAILURE = ("restart", "alert")
RESTART = "restart"
NEVER = "never"
DEFAULT_RESTART = {"attempts": 3, "within_cycles": 5}
DEFAULT_EVERY = 1
MIN_STATUS = 100
MAX_STATUS = 599

GENERATE = ("allowed", "required", "never")
SHARED_GENERATE = ("allowed", "required")
OPTION_TYPES = ("string", "integer", "boolean", "enum")
PLACEMENTS = ("embedded", "discovered", "none")
EMBEDDED = "embedded"
PHP = "php"

HOOK_DIR = "/usr/lib/inithooks/firstboot.d/"
UNIT_DIRS = ("/usr/lib/systemd/system", "/lib/systemd/system",
             "/etc/systemd/system")
# systemd's sysv generator makes a unit of an init script at boot, which
# is all shellinabox, Core's web shell, ships in trixie
INIT_DIR = "/etc/init.d"
UNIT_SUFFIX = ".service"
NEVER_REPLICATED = ("/etc", "/usr", "/tmp", "/var/tmp", "/var/cache",
                    "/var/log", "/run")

MAX_NAME = 32
NAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")
NAME_TEXT = "[a-z][a-z0-9-]*"
ITEM_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
ITEM_TEXT = "[a-z][a-z0-9_-]*"
VAR_RE = re.compile(r"^[a-z][a-z0-9_]*$")
VAR_TEXT = "[a-z][a-z0-9_]*"
# Debian's relations, then a version as dpkg --compare-versions reads it
CONSTRAINT_RE = re.compile(
    r"^(<<|<=|=|>=|>>) ?([0-9]+:)?[0-9][A-Za-z0-9.+~-]*$")
TIMESPAN_RE = re.compile(r"^[1-9][0-9]*(s|min|h|d|w)$")
SIZE_RE = re.compile(r"^[1-9][0-9]*[kKmMgG]?$")

COMMON_KEYS = ("manifest_version", "kind", "name", "title", "summary")
OVERLAY_KEYS = ("requires", "provides", "processes", "checks", "data",
                "secrets", "hooks", "screen")
APP_SECTIONS = ("services", "state", "workers", "web")
APPLIANCE_KEYS = ("base", "overlays", "processes", "checks", "secrets",
                  "options", "hooks") + APP_SECTIONS
KIND_KEYS = {OVERLAY: OVERLAY_KEYS, APPLIANCE: APPLIANCE_KEYS}
HOOK_KEYS = {OVERLAY: ("first_boot",), APPLIANCE: ("first_boot", "migrate")}
MIGRATE = "migrate"
