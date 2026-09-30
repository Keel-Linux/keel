# Copyright (c) 2026 KeelLinux maintainers
"""Validation of the database section: two subjects, never one field

A machine that **runs** a database server has a role: standalone, primary
or replica. A machine that **uses** a database names the endpoints it uses:
a primary for writes and optionally replicas for reads. A machine can have
both, and neither subject implies the other, so `server` and `client` are
separate mappings and each is optional (decision 0013).

Three rules this file enforces that come from defects, not from taste:

- every address is a literal, never a name, because Debian maps `::1` to
  `ip6-localhost` and never to `localhost` (docs/traps.md), which is how
  the PostgreSQL appliance shipped listening on IPv4 only;
- every credential is a file reference, never a value in the description;
- a replica names the primary it replicates from, the way a static
  interface names its address, because a replica without one declares
  nothing. A primary's authorization list is *not* refused on a replica:
  an operator prepares a promotion before making it, exactly as with a
  certificate configuration behind `tls.acme.enabled` (decision 0009).
"""

from typing import Any

from keel.spec.constants import (
    DATABASE_ENGINES,
    DATABASE_SUBJECTS,
    SERVER_ROLES,
)
from keel.spec.fields import (
    list_error,
    literal_address_error,
    mapping_error,
    origin_error,
    port_error,
)
from keel.spec.origins import mariadb_problem
from keel.spec.validate_secret import validate_secret

SERVER_KEYS = ("engine", "role", "listen", "replication")
REPLICATION_KEYS = ("primary", "allowed_from", "secret")
CLIENT_KEYS = ("engine", "primary", "replicas")
ENDPOINT_KEYS = ("host", "port")
CLIENT_PRIMARY_KEYS = ("host", "port", "name", "user", "secret")
REPLICA_ROLE = "replica"


def validate_database(
    database: Any, check_secret_files: bool = True
) -> list[str]:
    """Every error in the database section, empty when it is valid"""
    error = mapping_error("database", database)
    if error or not database:
        return [error] if error else []

    errors = [
        f"database.{key}: unknown key"
        for key in database
        if key not in DATABASE_SUBJECTS
    ]
    errors.extend(
        _validate_server(database.get("server"), check_secret_files)
    )
    errors.extend(
        _validate_client(database.get("client"), check_secret_files)
    )
    return errors


def _validate_server(server: Any, check_secret_files: bool) -> list[str]:
    error = mapping_error("database.server", server)
    if error or not server:
        return [error] if error else []

    errors = [
        f"database.server.{key}: unknown key"
        for key in server
        if key not in SERVER_KEYS
    ]
    errors.extend(_engine("database.server", server))

    role = server.get("role")
    if role is None or str(role) not in SERVER_ROLES:
        errors.append(
            f"database.server.role: must be one of {SERVER_ROLES}"
        )
    errors.extend(_listen(server.get("listen")))
    errors.extend(
        _replication(
            server.get("replication"), str(role), check_secret_files,
            str(server.get("engine")),
        )
    )
    return errors


def _engine(key: str, section: dict) -> list[str]:
    engine = section.get("engine")
    if engine is None or str(engine) not in DATABASE_ENGINES:
        return [f"{key}.engine: must be one of {DATABASE_ENGINES}"]
    return []


def _listen(listen: Any) -> list[str]:
    key = "database.server.listen"
    error = list_error(key, listen)
    if error:
        return [error]
    if listen is not None and not listen:
        return [f"{key}: must name at least one address"]
    return [
        error
        for address in listen or []
        if (error := literal_address_error(key, address)) is not None
    ]


def _replication(
    replication: Any, role: str, check_secret_files: bool, engine: str,
) -> list[str]:
    key = "database.server.replication"
    error = mapping_error(key, replication)
    if error:
        return [error]
    replication = replication or {}

    errors = [
        f"{key}.{name}: unknown key"
        for name in replication
        if name not in REPLICATION_KEYS
    ]
    primary = replication.get("primary")
    if role == REPLICA_ROLE and not isinstance(primary, dict):
        errors.append(
            f"{key}.primary: required when the role is {REPLICA_ROLE},"
            " because a replica replicates from somewhere"
        )
    elif primary is not None:
        errors.extend(_endpoint(f"{key}.primary", primary, ENDPOINT_KEYS))

    errors.extend(_allowed_from(replication.get("allowed_from"), engine))
    errors.extend(
        _secret(f"{key}.secret", replication.get("secret"),
                check_secret_files)
    )
    return errors


def _allowed_from(allowed: Any, engine: str) -> list[str]:
    key = "database.server.replication.allowed_from"
    error = list_error(key, allowed)
    if error:
        return [error]
    errors = []
    for origin in allowed or []:
        error = origin_error(key, origin) or _grantable(key, origin, engine)
        if error:
            errors.append(error)
    return errors


def _grantable(key: str, origin: str, engine: str) -> str | None:
    """A MariaDB grant holds an origin exactly, or the description is wrong

    Refused here and not only in the plan: by then apply has written the
    primary's configuration and restarted it, and the refusal skips the
    grants of the other origins in the list too.
    """
    if engine != "mariadb":
        return None
    problem = mariadb_problem(origin)
    return f"{key}: {problem}" if problem else None


def _validate_client(client: Any, check_secret_files: bool) -> list[str]:
    error = mapping_error("database.client", client)
    if error or not client:
        return [error] if error else []

    errors = [
        f"database.client.{key}: unknown key"
        for key in client
        if key not in CLIENT_KEYS
    ]
    errors.extend(_engine("database.client", client))

    primary = client.get("primary")
    if not isinstance(primary, dict):
        errors.append(
            "database.client.primary: required, and a mapping: a machine"
            " that uses a database writes somewhere"
        )
    else:
        errors.extend(
            _endpoint("database.client.primary", primary,
                      CLIENT_PRIMARY_KEYS, check_secret_files)
        )
    errors.extend(_replicas(client.get("replicas")))
    return errors


def _replicas(replicas: Any) -> list[str]:
    key = "database.client.replicas"
    error = list_error(key, replicas)
    if error:
        return [error]
    errors = []
    for index, endpoint in enumerate(replicas or []):
        errors.extend(_endpoint(f"{key}[{index}]", endpoint, ENDPOINT_KEYS))
    return errors


def _endpoint(
    key: str, endpoint: Any, allowed: tuple[str, ...],
    check_secret_files: bool = True,
) -> list[str]:
    """One place a database is reached: a literal address and a port"""
    error = mapping_error(key, endpoint)
    if error:
        return [error]

    errors = [
        f"{key}.{name}: unknown key"
        for name in endpoint
        if name not in allowed
    ]
    if "host" not in endpoint:
        errors.append(f"{key}.host: required")
    else:
        error = literal_address_error(f"{key}.host", endpoint["host"])
        if error:
            errors.append(error)
    if "port" in endpoint:
        error = port_error(f"{key}.port", endpoint["port"])
        if error:
            errors.append(error)
    for name in ("name", "user"):
        if name in allowed and name in endpoint:
            errors.extend(_word(f"{key}.{name}", endpoint[name]))
    if "secret" in allowed:
        errors.extend(
            _secret(f"{key}.secret", endpoint.get("secret"),
                    check_secret_files)
        )
    return errors


def _word(key: str, value: Any) -> list[str]:
    if not isinstance(value, str | int) or not str(value).strip():
        return [f"{key}: must be a name"]
    if len(str(value).split()) != 1:
        return [f"{key}: must be a single word"]
    return []


def _secret(key: str, secret: Any, check_secret_files: bool) -> list[str]:
    """A credential is a reference; what it unlocks differs per engine"""
    if secret is None:
        return []
    return validate_secret(key, secret, check_secret_files)
