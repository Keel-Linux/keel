# Copyright (c) 2026 KeelLinux maintainers
"""Where the application on this machine keeps its data

The second subject of the database section, and the one place where the
configuration *is* the fact. A server can be asked what it is; an
application cannot be asked where it will connect next, and watching its
open sockets would report a connection rather than a declaration. So this
reads the application's own configuration, which is where that fact lives
and the only place it lives.

One reader per application, in a table that grows as appliances arrive.
A machine with none of these files has no client section at all, which is
what "with no application, nothing for the second" means. A file that is
there and cannot be read or parsed is reported as not inferred, naming it,
so `keel diff` calls it unknown and never drift.

No password is ever read out of any of these files.
"""

import json
import re
from collections.abc import Callable
from dataclasses import dataclass

from keel.inspect.tree import File

# define('DB_HOST', '[::1]:3306'); with any spacing and either quote.
WP_DEFINE = re.compile(
    r"""define\s*\(\s*['"](DB_NAME|DB_USER|DB_HOST)['"]\s*,"""
    r"""\s*['"]([^'"]*)['"]""",
)
# NodeBB names its engine in "database" and keeps that engine's settings
# under a key of the same name. Mongo is not an engine the spec knows.
NODEBB_ENGINES = {"redis": "redis", "postgres": "postgresql"}
# No application configuration this table reads expresses a read endpoint,
# so the field is reported as one inspect cannot infer rather than left to
# be read as drift against a description that declares one.
NO_READ_ENDPOINTS = (
    "no application configuration inspect reads expresses read endpoints;"
    " {path} names one place to connect and nothing about reads going"
    " elsewhere"
)


@dataclass(frozen=True)
class Endpoint:
    """One place an application reaches a database, and what it knows"""

    engine: str
    host: str
    port: int | None = None
    name: str = ""
    user: str = ""


def split_host(text: str) -> tuple[str, int | None]:
    """`[::1]:3306`, `::1`, `192.0.2.10:3306` or a bare name and a port

    A bracketed address keeps its own colons; an unbracketed one with more
    than one colon is an IPv6 address and carries no port, because that is
    the only reading that cannot corrupt an address.
    """
    value = text.strip()
    if value.startswith("["):
        address, _, rest = value.partition("]")
        port = rest.lstrip(":")
        return address[1:], int(port) if port.isdigit() else None
    host, sep, port = value.rpartition(":")
    if not sep or value.count(":") > 1:
        return value, None
    return host, int(port) if port.isdigit() else None


def read_wordpress(config: File) -> tuple[Endpoint | None, str]:
    """WordPress keeps DB_HOST, DB_NAME and DB_USER in wp-config.php"""
    values = dict(WP_DEFINE.findall(config.text or ""))
    if "DB_HOST" not in values:
        return None, f"{config.path} defines no DB_HOST"
    host, port = split_host(values["DB_HOST"])
    if not host:
        return None, f"{config.path} defines an empty DB_HOST"
    return Endpoint(
        engine="mariadb",
        host=host,
        port=port,
        name=values.get("DB_NAME", ""),
        user=values.get("DB_USER", ""),
    ), config.path


def read_nodebb(config: File) -> tuple[Endpoint | None, str]:
    """NodeBB names its engine in config.json and its settings under it"""
    try:
        document = json.loads(config.text or "")
    except ValueError as e:
        return None, f"{config.path} is not valid JSON: {e}"
    if not isinstance(document, dict):
        return None, f"{config.path} does not hold a JSON object"

    named = str(document.get("database", ""))
    engine = NODEBB_ENGINES.get(named)
    if engine is None:
        return None, (
            f'{config.path} names database "{named}", which is not one of'
            f" {', '.join(sorted(NODEBB_ENGINES))}"
        )
    settings = document.get(named)
    if not isinstance(settings, dict) or not settings.get("host"):
        return None, f"{config.path} gives no host for {named}"
    host, port = split_host(str(settings["host"]))
    declared = settings.get("port")
    if str(declared or "").isdigit():
        port = int(declared)
    return Endpoint(
        engine=engine,
        host=host,
        port=port,
        name=str(settings.get("database", "")),
        user=str(settings.get("username", "")),
    ), config.path


@dataclass(frozen=True)
class Reader:
    """One application: where its configuration is and how to read it"""

    application: str
    patterns: tuple[str, ...]
    read: Callable[[File], tuple[Endpoint | None, str]]


READERS = (
    Reader(
        application="wordpress",
        patterns=("var/www/*/wp-config.php", "var/www/wp-config.php"),
        read=read_wordpress,
    ),
    Reader(
        application="nodebb",
        patterns=("var/www/nodebb/config.json", "opt/nodebb/config.json"),
        read=read_nodebb,
    ),
)


def client_section(endpoint: Endpoint) -> dict:
    """The database.client section one endpoint describes"""
    primary: dict = {"host": endpoint.host}
    if endpoint.port is not None:
        primary["port"] = endpoint.port
    if endpoint.name:
        primary["name"] = endpoint.name
    if endpoint.user:
        primary["user"] = endpoint.user
    return {"engine": endpoint.engine, "primary": primary}
