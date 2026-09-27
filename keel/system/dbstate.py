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
from keel.inspect.dbengines import ENGINES, Engine
from keel.inspect.dbreading import Reading
from keel.inspect.tree import File, Tree
from keel.spec.errors import SpecError
from keel.spec.secretstore import resolve_secret
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

    @property
    def installed(self) -> bool:
        return bool(self.binary)


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
        credential=credential(server),
    )


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
