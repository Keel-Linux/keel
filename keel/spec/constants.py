# Copyright (c) 2026 KeelLinux maintainers
"""Names, paths and key tables of the instance spec

Kept apart from the code that uses them so that the format can be read
without reading the parser.
"""

SPEC_DEFAULT = "/etc/keel/instance.yaml"
CONF_DEFAULT = "/etc/inithooks.conf"
SPEC_ENV = "KEEL_SPEC"
CONF_ENV = "KEEL_CONF"
LXC_MARKER = "/var/lib/turnkey-info/inithooks.service/lxc"

SCHEMA_VERSION = 1
GENERATED_BYTES = 12
MASK = "[masked]"

TOP_LEVEL_KEYS = (
    "version",
    "instance",
    "network",
    "tls",
    "secrets",
    "app",
    "hub",
    "security",
    "first_login_wizard",
    "preseed",
    "users",
    "locale",
    "database",
    "monitor",
    "appliance",
    "installation",
    "overlays",
)
SECRET_VARS = {
    "root_password": "ROOT_PASS",
    "db_password": "DB_PASS",
    "app_password": "APP_PASS",
}
MASKED_VARS = tuple(SECRET_VARS.values()) + ("HUB_APIKEY",)
KEYWORDS = ("SKIP", "FORCE", "TRUE", "FALSE")
WIZARD_ONLY_GENERATE = ("root_password", "app_password")
SECRET_BACKENDS = ("file", "generate")
MANAGED_BY = ("host", "file")
IPV4_METHODS = ("static", "dhcp", "manual", "none")
IPV6_METHODS = ("static", "dhcp", "auto", "manual", "none")

# The two subjects of the database section, which one field cannot serve: a
# machine that runs a server has a role, a machine that uses one names the
# endpoints it uses. A machine can have both, or either alone.
DATABASE_SUBJECTS = ("server", "client")
DATABASE_ENGINES = ("mariadb", "postgresql", "redis")
# Roles a server can be in. Multi-primary (Galera, Redis Cluster) and the
# shard roles are not here: a machine in one of those is reported as a role
# the spec has no value for, which is why nothing here has to be renamed
# when they arrive (decision 0013).
SERVER_ROLES = ("standalone", "primary", "replica")
# The port each engine listens on when the description names none.
DEFAULT_PORTS = {"mariadb": 3306, "postgresql": 5432, "redis": 6379}
MAX_PORT = 65535

# What the appliance manifests make of the spec (decision 0041): the
# installation modes of 0028 and the two states an overlay takes on a
# machine. `ask` is the manifest's and never reaches a spec.
INSTALLATION_MODES = ("simple", "cloud_simple", "cloud_advanced")
OVERLAY_STATES = ("enabled", "disabled")
# A secret a manifest declares, beyond SECRET_VARS, renders as this
# prefix and its name upper cased (docs/manifest-v1.md, "Secrets")
MANIFEST_SECRET_PREFIX = "KEEL_SECRET_"
