# Copyright (c) 2026 KeelLinux maintainers
"""The database section: what this machine is, and where its data is

Two subjects and two independent readings. The server side asks the server
running here what it is; the client side reads what the application here is
pointed at. A machine with no server reports nothing for the first, a
machine with no application nothing for the second, and a machine with both
reports both (issue 25).

Nothing here reads the filesystem or runs a command: keel.inspect.collect
gathers the answers and hands them over, so every branch below is a pure
function of what came back.
"""

from dataclasses import dataclass, field

from keel.inspect.dbclient import NO_READ_ENDPOINTS, Reader, client_section
from keel.inspect.dbengines import Engine
from keel.inspect.dbreading import Reading, Value
from keel.inspect.report import Finding, inferred, missing
from keel.inspect.tree import File
from keel.spec.origins import mariadb_problem

SERVER = "database.server"
CLIENT = "database.client"
REPLICA = "replica"
PRIMARY = "primary"
# A field that describes nothing unless the server is in one of these
# roles, and what the report says when it is not. The field is reported as
# one that could not be inferred rather than left out silently: a
# description that declares it against a machine in another role is then
# unknown to keel diff, with the role named, instead of a second drift line
# repeating what the role line already said.
ROLE_FIELDS = {
    "replication.primary": (
        (REPLICA,),
        "the server is a {role}: it replicates from nowhere, so there is no"
        " primary on the machine to read",
    ),
    "replication.allowed_from": (
        (PRIMARY,),
        "the server is a {role}: nothing replicates from it, so the"
        " authorizations it would hold as a primary are not read",
    ),
}
# A server that is installed and cannot say what it is. The whole section
# is reported as not inferred, the way an unreadable interfaces file reports
# network.interfaces, so every field under it is unknown to diff and none of
# them is drift. The engine, which the binary does settle, is named in the
# reason: writing a section with an engine and no role would be a
# description that does not validate, and inspect writes a description an
# operator can apply after editing.
NOT_ASKED = (
    "the {engine} server is installed ({binary}) and could not be asked what"
    " it is: {problem}"
)
UNHELD = (
    "the server holds a grant no description may declare, so none is"
    " written: {problems}. keel spec apply drops it once the description"
    " names the origins it should hold"
)
SEVERAL_ENGINES = (
    "this machine runs {count} database servers ({engines}); the description"
    " has one database.server, so the role of each cannot be written down"
    " separately yet"
)


@dataclass(frozen=True)
class Installed:
    """One database server found on the machine, and what it answered"""

    engine: Engine
    binary: str
    answers: dict[str, File] = field(default_factory=dict)
    sockets: File = field(default_factory=lambda: File(""))

    def reading(self) -> Reading:
        return self.engine.read(self.answers, self.sockets)


def probe_database(
    servers: tuple[Installed, ...],
    client_files: tuple[tuple[Reader, File], ...],
) -> tuple[dict | None, list[Finding]]:
    """Build the database section from both readings, each on its own"""
    findings: list[Finding] = []
    section: dict = {}

    server, found = probe_server(servers)
    findings += found
    if server is not None:
        section["server"] = server

    client, found = probe_client(client_files)
    findings += found
    if client is not None:
        section["client"] = client

    return (section or None), findings


def probe_server(
    servers: tuple[Installed, ...],
) -> tuple[dict | None, list[Finding]]:
    """What the server running here says it is, or nothing at all

    No server installed is not a gap: there is nothing to report and
    nothing is reported, so a description that declares one drifts against
    this machine rather than being excused.
    """
    if not servers:
        return None, []
    if len(servers) > 1:
        names = ", ".join(one.engine.name for one in servers)
        return None, [
            missing(
                SERVER,
                SEVERAL_ENGINES.format(count=len(servers), engines=names),
            )
        ]

    installed = servers[0]
    engine = installed.engine
    reading = installed.reading()
    if not reading.role.known:
        return None, [missing(
            SERVER,
            NOT_ASKED.format(
                engine=engine.name, binary=installed.binary,
                problem=reading.role.problem,
            ),
        )]

    section: dict = {"engine": engine.name}
    findings = [
        inferred(f"{SERVER}.engine", engine.name, installed.binary)
    ]
    role = _add(section, findings, f"{SERVER}.role", "role", reading.role)
    _add(section, findings, f"{SERVER}.listen", "listen", reading.listen)

    replication: dict = {}
    for name, value in (
        ("primary", reading.primary),
        ("allowed_from", reading.allowed_from),
    ):
        path = f"{SERVER}.replication.{name}"
        reason = _other_role(f"replication.{name}", role) or _unheld(
            engine.name, name, value
        )
        if reason:
            findings.append(missing(path, reason))
            continue
        _add(replication, findings, path, name, value)
    if replication:
        section["replication"] = replication
    return section, findings


def _unheld(engine: str, name: str, value: Value) -> str:
    """Why the grants a MariaDB primary holds are not written, if so

    keel 0.11.0 granted the overlay /64 as fd3d:80b2:d0d7:0:%, which
    refuses fd3d:80b2:d0d7::2. Written into the description, that grant
    would not validate, and a description inspect writes must, so the
    field is reported with the reason instead.
    """
    if engine != "mariadb" or name != "allowed_from" or not value.known:
        return ""
    problems = [
        problem for one in value.value or []
        if (problem := mariadb_problem(str(one)))
    ]
    return UNHELD.format(problems="; ".join(problems)) if problems else ""


def _other_role(path: str, role: object) -> str:
    """Why this field says nothing in the role that was observed, if so"""
    roles, reason = ROLE_FIELDS[path]
    if str(role) in roles:
        return ""
    return reason.format(role=role)


def _add(
    section: dict, findings: list[Finding], path: str, key: str, value: Value,
) -> object:
    """Record one field of a reading, as a value or as a reason"""
    if not value.known:
        findings.append(missing(path, value.problem))
        return None
    section[key] = value.value
    findings.append(inferred(path, _shown(value.value), value.source))
    return value.value


def _shown(value: object) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{name} {item}" for name, item in value.items())
    return str(value)


def probe_client(
    client_files: tuple[tuple[Reader, File], ...],
) -> tuple[dict | None, list[Finding]]:
    """Where the application here is pointed, from its own configuration"""
    if not client_files:
        return None, []

    findings: list[Finding] = []
    for reader, config in client_files:
        if not config.readable:
            findings.append(
                missing(f"{CLIENT}.primary", f"{config.path} {config.problem}")
            )
            continue
        endpoint, source = reader.read(config)
        if endpoint is None:
            findings.append(missing(f"{CLIENT}.primary", source))
            continue
        section = client_section(endpoint)
        findings.append(
            inferred(f"{CLIENT}.engine", endpoint.engine, source)
        )
        findings.append(
            inferred(
                f"{CLIENT}.primary",
                _shown(section["primary"]),
                source,
            )
        )
        findings.append(
            missing(
                f"{CLIENT}.replicas",
                NO_READ_ENDPOINTS.format(path=source),
            )
        )
        return section, findings
    return None, findings
