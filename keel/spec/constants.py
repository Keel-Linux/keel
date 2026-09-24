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
