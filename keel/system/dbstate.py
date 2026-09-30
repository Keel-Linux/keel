# Copyright (c) 2026 KeelLinux maintainers
"""What the database planner looks at, read once from the machine

The same shape as keel.system.state: every read and every command run for
the database phase happens here, so keel.system.database is a pure
function of a DatabaseState and can be tested against fixtures with no
server anywhere.

The server is asked what it is with the questions keel.inspect.dbengines
already puts to it, rather than with a second set of its own. A phase that
decides whether to reconfigure a machine must not disagree with the phase
that reports what the machine is, and the way to be sure of that is to ask
the same questions.
"""

from dataclasses import dataclass, field

from keel.inspect import constants as paths
from keel.inspect.collect import run_command
from keel.inspect.dbengines import (
    ENGINES,
    PRIMARY_HOST_KEYS,
    PRIMARY_PORT_KEYS,
    Engine,
)
from keel.inspect.dbreading import Reading, field_lines
from keel.inspect.tree import File, Tree
from keel.spec.constants import DEFAULT_PORTS
from keel.spec.errors import SpecError
from keel.spec.origins import canonical
from keel.spec.secretstore import resolve_secret
from keel.system import dbseed
from keel.system.dbmariadb import (
    DROPIN,
    SCHEMAS_QUESTION,
    unquotable,
)

MACHINE_ID = "etc/machine-id"
NO_SECRET = (
    "database.server.replication.secret is not declared, and a replication"
    " account without a credential authenticates nothing"
)
GENERATED = (
    "a replication credential cannot be generated on the machine: both ends"
    " of a pair must hold the same value, so declare it as a file the"
    " operator puts on each node"
)


@dataclass(frozen=True)
class Credential:
    """The replication password, or why it could not be had"""

    value: str = ""
    problem: str = ""

    @property
    def known(self) -> bool:
        return not self.problem


@dataclass(frozen=True)
class DatabaseState:
    """One machine's database, as the planner needs to see it"""

    engine: str
    live: bool
    binary: str = ""
    reading: Reading = field(default_factory=Reading)
    schemas: File = field(default_factory=lambda: File(""))
    machine_id: File = field(default_factory=lambda: File(MACHINE_ID))
    dropin: File = field(default_factory=lambda: File(""))
    credential: Credential = field(default_factory=Credential)
    # SHOW REPLICA STATUS as the server printed it, for the one thing the
    # reading does not keep: whether the SQL thread still runs.
    status: File = field(default_factory=lambda: File(""))
    # Why the declared primary cannot be copied from, asked only when a
    # copy would be made (needs_copy); empty when it can, or was not asked.
    reach: str = ""
    # The primary's accounts this server holds too, which keep this
    # server's authentication when it is seeded (keel.system.dbaccounts).
    shared: tuple[str, ...] = ()

    @property
    def installed(self) -> bool:
        return bool(self.binary)


def endpoint(server: dict) -> tuple[str, int]:
    """The declared primary of a replica, as a host and a port"""
    primary = (server.get("replication") or {}).get("primary") or {}
    host = str(primary.get("host") or "")
    return host, int(primary.get("port") or DEFAULT_PORTS["mariadb"])


def sql_stopped(status: File) -> str | None:
    """The reason the SQL thread stopped, or None while it runs

    None too when the status does not say: only an explicit `No` counts,
    because a replica is never rebuilt on a guess.
    """
    values = field_lines(status)
    if values.get("Slave_SQL_Running", "").lower() != "no":
        return None
    return values.get("Last_SQL_Error") or "no error was recorded"


def replicates_from(status: File, host: str, port: int) -> bool:
    """Whether the status names this endpoint as the primary"""
    values = field_lines(status)
    was_host = next((values[k] for k in PRIMARY_HOST_KEYS if k in values), "")
    was_port = next((values[k] for k in PRIMARY_PORT_KEYS if k in values), "")
    return canonical(was_host) == canonical(host) and was_port == str(port)


def needs_copy(server: dict, status: File) -> bool:
    """Whether apply would seed this node from its primary

    A declared replica that replicates from nowhere, from another
    endpoint, or with its SQL thread stopped. A healthy replica of the
    declared primary is never dialled, let alone copied again.
    """
    if str(server.get("role") or "") != "replica":
        return False
    host, port = endpoint(server)
    if not host:
        return False
    if not replicates_from(status, host, port):
        return True
    return sql_stopped(status) is not None


def declared_server(doc: dict) -> dict:
    """The database.server mapping of a description, or an empty one"""
    return ((doc.get("database") or {}).get("server")) or {}


def observe_database(root: str, doc: dict) -> DatabaseState | None:
    """Read everything the database plan for `doc` depends on

    None when the description declares no server: there is nothing to
    converge and nothing is asked of the machine, so a description without
    the section costs no command at all.
    """
    server = declared_server(doc)
    if not server:
        return None
    tree = Tree(root)
    name = str(server.get("engine") or "")
    engine = _engine(name)
    live = tree.root == paths.ROOT_DEFAULT
    if engine is None:
        return DatabaseState(engine=name, live=live)

    binary = engine.installed(tree.glob)
    answers = {} if binary is None else {
        key: run_command(tree, argv)
        for key, argv in engine.questions.items()
    }
    sockets = File("") if binary is None else run_command(
        tree, paths.LISTENING_COMMAND
    )
    status = answers.get("status", File(""))
    secret = credential(server)
    found = _reach(
        tree, server, status, secret,
        live and bool(binary) and name == "mariadb",
    )
    return DatabaseState(
        engine=name,
        live=live,
        binary="" if binary is None else tree.path(binary),
        reading=Reading() if binary is None else engine.read(answers, sockets),
        schemas=File("") if binary is None else run_command(
            tree, SCHEMAS_QUESTION
        ),
        machine_id=tree.read(MACHINE_ID),
        dropin=tree.read(DROPIN),
        credential=secret,
        status=status,
        reach=found.problem,
        shared=found.shared,
    )


def _reach(
    tree: Tree, server: dict, status: File, secret: Credential, asks: bool,
) -> dbseed.Reach:
    """Ask the declared primary whether it can be copied from, if it would be

    Only on the live system with a server installed, with a credential,
    and only when a copy would follow: dialling another machine at every
    boot of a healthy replica would be a question nobody needs answered.
    """
    if not (asks and secret.known and needs_copy(server, status)):
        return dbseed.Reach()
    host, port = endpoint(server)
    return dbseed.reach(tree.root, host, port, secret.value)


def _engine(name: str) -> Engine | None:
    for engine in ENGINES:
        if engine.name == name:
            return engine
    return None


def credential(server: dict) -> Credential:
    """Read the replication password, or say why there is none

    The one secret the database phase resolves. `apply --system-only`
    resolves none of the others on purpose, so that a password the first
    boot hooks already set is never regenerated behind them; this one is
    read here, and only here, because a grant and a CHANGE MASTER cannot
    be written without it.
    """
    reference = (server.get("replication") or {}).get("secret")
    if not isinstance(reference, dict):
        return Credential(problem=NO_SECRET)
    if reference.get("generate"):
        return Credential(problem=GENERATED)
    try:
        value = resolve_secret(reference)
    except (SpecError, OSError, KeyError) as e:
        return Credential(problem=str(e))
    problem = unquotable(value)
    if problem:
        return Credential(problem=f"{reference.get('file')}: {problem}")
    return Credential(value=value)
