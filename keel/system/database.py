# Copyright (c) 2026 KeelLinux maintainers
"""Configure this node in the role the description declares; pure

Phase 3 of decision 0013 for MariaDB. `keel inspect` reads what the server
is and `keel diff` reports the difference; this is the acting half, and
the four properties below are what make acting safe. None of them is
optional and each is a branch in the plan this module builds.

**Becoming a replica destroys the local database.** A standby is a copy of
its primary, so a machine that holds data cannot become one without losing
that data. The plan refuses unless the server holds no database of
anybody's but its own, or the operator confirmed the destruction in this
invocation (`--destroy-local-database`). The refusal is the default, it is
what a first boot gets, and a server that cannot be asked what it holds is
refused too: not knowing is not permission.

**A primary holds authorizations, not replicas.** Each entry of
`allowed_from` becomes a grant of replication from that origin, and an
origin the description no longer names has its grant withdrawn, because
`inspect` reads the authorizations off the server and one left behind
would drift for ever.

**Promotion is a separate act.** Nothing here promotes a replica or demotes
a primary. Where the observed role differs from the declared one in a way
that would need either, the plan refuses and names `keel database promote`.

**No automatic failover exists here.** This module configures the machine
it runs on and never looks at another one, which is the line decision 0013
drew and the reason the console screen says what it says.

Nothing here reads a file or runs a command: keel.system.dbstate observes
and keel.system.effects acts.
"""

from keel.spec.origins import canonical, is_name, mariadb_problem
from keel.system import dbmariadb as mariadb
from keel.system.actions import (
    Action,
    LockReplica,
    Note,
    PromoteReplica,
    Refuse,
    Run,
    RunSql,
    SeedReplica,
    Step,
    UnlockAccounts,
    WriteFile,
)
from keel.system.dbreadonly import STOPPED as UNDRAINABLE
from keel.system.dbstate import (
    DatabaseState,
    declared_server,
    endpoint,
    sql_stopped,
)

FIELD = "database.server"
AUTHORIZATIONS = f"{FIELD}.replication.allowed_from"
REPLICATION = f"{FIELD}.replication.primary"
STANDALONE = "standalone"
PRIMARY = "primary"
REPLICA = "replica"
DROPIN_MODE = 0o644

OTHER_ENGINE = (
    "{engine} is read by keel inspect and compared by keel diff, and its"
    " roles are not configured by this version; decision 0013 takes the"
    " engines one at a time and MariaDB is the first"
)
OFFLINE = (
    "the root is not the live system, so the server cannot be asked what"
    " it is and no statement may be sent to another machine's database"
)
NOT_INSTALLED = (
    "the description declares a {engine} server and none is installed here"
    " ({role}); keel does not install packages, so nothing was configured"
)
# Only `disabled`: a masked unit cannot be started either, so it never
# gets here (DOWN), and static, indirect or generated units are started
# by something else on purpose.
ENABLE = (
    "enable the server, so the server the description declares starts at"
    " boot and not only when apply starts it"
)
DOWN = (
    "the server is not answering ({problem}), so what it is cannot be"
    " read; its configuration was not written and nothing was restarted,"
    " and the field is left for the next keel spec apply --system"
)
NOT_ASKED = (
    "the server could not be asked what it is ({problem}), and a role is"
    " never changed on a guess"
)
NO_IDENTITY = (
    "{path} is empty or unreadable and database.server.listen names no"
    " address, so this machine has nothing of its own to derive a server"
    " id from; two nodes with the same server id stop replicating, so"
    " none is invented here"
)
PROMOTION = (
    "this machine is a replica and the description says {declared}."
    " Promotion is an operator action, never something apply decides:"
    " run `keel database promote` on this node, then change the"
    " description. Nothing was configured"
)
DEMOTION = (
    "this machine is a primary and the description says {declared}."
    " Demoting a primary destroys everything written to it since a replica"
    " last agreed, so apply never does it. Nothing was configured"
)
REPOINT = (
    "this machine already replicates from [{observed}] and the description"
    " says [{declared}]. A replica is a copy of its primary, so pointing it"
    " at a different one replaces the local data"
)
DESTRUCTION = (
    "becoming a replica replaces the local database with a copy of the"
    " primary, and this server holds {count} database(s) that are not its"
    " own ({schemas})"
)
# What to do instead, said only when apply is declining. The confirmed
# line repeats the reason and not the remedy: a run that went ahead
# telling the operator that the server was left alone would be a lie.
# Declining comes before the configuration is written (plan_database),
# which is what makes the first sentence true.
REMEDY = (
    ". The server was left as it was: its configuration was not rewritten"
    " and it was not restarted. Move the data elsewhere, or run the same"
    " command again with --destroy-local-database to drop them and build"
    " the replica"
)
CONFIRMED = "confirmed with --destroy-local-database: {reason}"
UNKNOWN_CONTENT = (
    "the server could not be asked which databases it holds ({problem}),"
    " and becoming a replica replaces them; not knowing is not permission"
)
NAME_ORIGIN = (
    "an origin is a name ({names}), so the server must keep resolving"
    " client addresses and skip_name_resolve stays off. docs/spec.md calls"
    " a name fragile for this reason: it fails quietly when DNS does"
)
ALREADY = "unchanged (already replicating from [{host}]:{port})"
STOPPED = (
    "this machine replicates from [{host}]:{port} and its SQL thread"
    " stopped ({error}). A replica that stopped on a row it does not hold"
    " diverged from its primary, and rebuilding it replaces the local"
    " data with a fresh copy of the primary"
)
SHARED = (
    "{accounts} exist on both nodes and keep this node's own password;"
    " only their grants are made the primary's. An ALTER USER of them on"
    " the primary will replicate and replace this node's password, and"
    " the application on this node (wp-config.php and its DB_PASS for"
    " WordPress) must then be given the new one"
)
READ_ONLY_FIELD = f"{FIELD}.read_only"
# How long a promotion waits for the SQL thread to apply what the I/O
# thread received. A WordPress replica holds seconds of backlog; one that
# needs longer is refused and replicates on.
DRAIN_TIMEOUT = 600
LOCKED = (
    "unchanged (no account but root, mysql and mariadb.sys at this machine"
    " holds READ_ONLY ADMIN)"
)
UNLISTED = (
    "the accounts that write through read_only could not be listed"
    " ({problem}), so none had READ_ONLY ADMIN taken"
)
UNREAD = (
    "the server names no read_only ({problem}), so it was not set on a"
    " guess; the configuration file carries it into the next restart"
)
UNREACHABLE = (
    "{problem}. The replica cannot be seeded, so nothing was dropped, its"
    " configuration was not rewritten and the server was not restarted"
)
NOT_DECLARED = (
    "not declared, so the authorizations the server holds are left alone"
)
NO_SERVER = (
    "the description declares no database.server, so there is no role to"
    " promote and nothing says what this machine should become"
)


def plan_database(
    doc: dict, state: DatabaseState | None, confirmed: bool = False
) -> list[Step]:
    """The steps that put this node in the role the description declares"""
    if state is None:
        return []
    server = declared_server(doc)
    role = str(server.get("role") or "")
    refusal = _cannot_act(state, role)
    if refusal:
        return [Step(FIELD, (refusal,))]
    overlay = mariadb.overlay_addresses(doc)

    observed = str(state.reading.role.value)
    stop = _wrong_way_round(role, observed)
    if stop:
        return [Step(FIELD, (Refuse(stop),))]

    if role == REPLICA:
        # Asked before anything is written: a replica apply declines to
        # build keeps the server it had, configuration and restart
        # included, so the refusal can say nothing was touched.
        replication = _replication(server, state, observed, confirmed)
        if any(isinstance(one, Refuse) for one in replication.actions):
            return [replication]
        seeds = any(isinstance(one, SeedReplica)
                    for one in replication.actions)
        return [_configuration(server, state, role, overlay), replication,
                _lock(state, seeds)]
    steps = [_configuration(server, state, role, overlay)]
    if role == PRIMARY:
        steps.append(_authorizations(server, state))
    if state.revoked.readable:
        steps.append(Step(READ_ONLY_FIELD, (UnlockAccounts(),)))
    return steps


def _lock(state: DatabaseState, seeds: bool) -> Step:
    """Take READ_ONLY ADMIN from the accounts that write through read_only

    After the seed, which copies the primary's grants and with them the
    privilege this takes away; and whenever a seed runs, since what it
    brings was not observed. Asked of the server when it runs.
    """
    accounts = state.reading.bypass
    if seeds or accounts.value:
        return Step(READ_ONLY_FIELD, (
            LockReplica(tuple(accounts.value or ())),
        ))
    if not accounts.known:
        return Step(READ_ONLY_FIELD, (
            Note(UNLISTED.format(problem=accounts.problem)),
        ))
    return Step(READ_ONLY_FIELD, (Note(LOCKED),))


PROMOTE_FIELD = "database.server.role"
NOT_A_REPLICA = (
    "this machine is {observed} and only a replica can be promoted."
    " Nothing was changed"
)
AFTER = (
    "this node is a primary now and the description still says replica,"
    " which keel diff reports as drift and must not be corrected"
    " automatically. Change the description to primary and run"
    " `keel spec apply --system-only` to give it a binary log of its own"
)
OLD_PRIMARY = (
    "nothing here stopped the old primary or told anybody else about"
    " this. There is no failover in Keel: two writable servers on one"
    " dataset is what this command can cause, and only the operator"
    " knows the old primary is gone"
)


def plan_promote(doc: dict, state: DatabaseState | None) -> list[Step]:
    """Make this replica a primary, which apply is never allowed to do

    Its own operation because it is its own decision. Replication in Keel
    has no automatic failover, so the fact that the old primary should
    stop being one is knowledge no machine here has and only the operator
    does. Afterwards the description still says replica and the machine
    says primary, which is drift by design (docs/diff.md).
    """
    if state is None:
        return [Step(PROMOTE_FIELD, (Refuse(NO_SERVER),))]
    refusal = _cannot_act(state, REPLICA)
    if refusal:
        return [Step(PROMOTE_FIELD, (refusal,))]
    observed = str(state.reading.role.value)
    if observed != REPLICA:
        return [Step(PROMOTE_FIELD, (
            Refuse(NOT_A_REPLICA.format(observed=observed)),
        ))]
    error = sql_stopped(state.status)
    if error is not None:
        return [Step(PROMOTE_FIELD, (
            Refuse(UNDRAINABLE.format(error=error)),
        ))]
    return [Step(PROMOTE_FIELD, (
        PromoteReplica(DRAIN_TIMEOUT),
    ) + _writable_file(state) + _give_back(state) + (
        Note(AFTER),
        Note(OLD_PRIMARY),
    ))]


def _give_back(state: DatabaseState) -> tuple[Action, ...]:
    """READ_ONLY ADMIN back to what the replica took it from, if anything

    After the file is rewritten and never before: a GRANT that fails
    stops the step, and a file still saying read_only = ON would bring
    the new primary back read only at its next restart.
    """
    return (UnlockAccounts(),) if state.revoked.readable else ()


def _writable_file(state: DatabaseState) -> tuple[Action, ...]:
    """The configuration file without read_only, so a restart keeps the
    new primary writable before the description is changed

    Only the one line apply wrote for the replica goes; nothing restarts,
    because SET GLOBAL already turned it off. A file that does not hold
    the line, or no file at all, is left as it is.
    """
    text = state.dropin.text if state.dropin.readable else None
    if text is None or mariadb.READ_ONLY_LINE not in text:
        return ()
    return (WriteFile(
        mariadb.DROPIN, mariadb.writable(text), DROPIN_MODE, None,
        f"remove read_only from {state.dropin.path}",
    ),)


def _cannot_act(state: DatabaseState, role: str) -> Action | None:
    """Why this machine cannot be configured at all, if it cannot"""
    if state.engine != mariadb_name():
        return Note(OTHER_ENGINE.format(engine=state.engine))
    if not state.live:
        return Note(OFFLINE)
    if not state.installed:
        return Refuse(
            NOT_INSTALLED.format(engine=state.engine, role=role)
        )
    if state.down:
        return Refuse(DOWN.format(problem=state.down))
    if not state.reading.role.known:
        return Refuse(
            NOT_ASKED.format(problem=state.reading.role.problem)
        )
    return None


def mariadb_name() -> str:
    return "mariadb"


def _wrong_way_round(declared: str, observed: str) -> str:
    """Why this change of role is an operator's and not apply's"""
    if observed == declared:
        return ""
    if observed == REPLICA:
        return PROMOTION.format(declared=declared)
    if observed == PRIMARY:
        return DEMOTION.format(declared=declared)
    return ""


def _configuration(
    server: dict, state: DatabaseState, role: str, overlay: list[str],
) -> Step:
    """The server id, the addresses it answers on, and the binary log"""
    identity = mariadb.server_id(
        state.machine_id.text or "", server.get("listen"), overlay
    )
    if identity is None:
        return Step(FIELD, (
            Refuse(NO_IDENTITY.format(path=state.machine_id.path)),
        ))
    origins = [str(one) for one in _allowed_from(server) or []]
    names = [one for one in origins if is_name(one)]
    text = mariadb.dropin_text(
        identity, server.get("listen"), role, bool(names)
    )
    notes: list[Action] = []
    if names:
        notes.append(Note(NAME_ORIGIN.format(names=", ".join(names))))
    if state.enabled == "disabled":
        notes.append(Run(("systemctl", "enable", mariadb.SERVICE), ENABLE))
    if state.dropin.readable and state.dropin.text == text:
        return Step(FIELD, tuple(notes) + (
            Note(f"unchanged ({state.dropin.path}, server id {identity})"),
        ) + _read_only_now(state, role))
    return Step(FIELD, tuple(notes) + (
        WriteFile(
            mariadb.DROPIN, text, DROPIN_MODE, None,
            f"write {state.dropin.path}: {role}, server id {identity}",
        ),
        Run(
            ("systemctl", "restart", mariadb.SERVICE),
            "restart the server, which is the only way these take effect",
        ),
    ))


def _read_only_now(state: DatabaseState, role: str) -> tuple[Action, ...]:
    """Bring the running server's read_only to what the role needs

    Only when the file already says so, which is when no restart comes:
    `SET GLOBAL read_only = OFF` by hand on a replica, or a promoted
    replica returning to standalone, must not wait for the next restart.
    A server that names no read_only is sent nothing on a guess.
    """
    running = state.reading.read_only
    wanted = role == REPLICA
    if not running.known:
        return (Note(UNREAD.format(problem=running.problem)),)
    if running.value == wanted:
        return ()
    statements = mariadb.set_read_only(wanted)
    return (RunSql(mariadb.CLIENT, statements.text, statements.summary),)


def _allowed_from(server: dict) -> list | None:
    return (server.get("replication") or {}).get("allowed_from")


def _authorizations(server: dict, state: DatabaseState) -> Step:
    """Grant replication from each declared origin, withdraw the rest"""
    declared = _allowed_from(server)
    if declared is None:
        return Step(AUTHORIZATIONS, (Note(NOT_DECLARED),))
    if not state.credential.known:
        return Step(AUTHORIZATIONS, (Refuse(state.credential.problem),))

    actions: list[Action] = []
    hosts = []
    for origin in (str(one) for one in declared):
        host = mariadb.as_host(origin)
        if host is None:
            actions.append(Refuse(str(mariadb_problem(origin))))
            continue
        hosts.append(host)
    # By the text of the host and not by canonical(): an account 0.11.0
    # made at fd3d:80b2:d0d7:0:0:0:0:2 is the same origin as the
    # fd3d:80b2:d0d7::2 granted now, but an account MariaDB never matches,
    # so it is dropped. Case alone does not count: MariaDB ignores it.
    wanted = {host.lower() for host in hosts}
    extra = [
        str(one) for one in (state.reading.allowed_from.value or [])
        if str(one).lower() not in wanted
    ]
    for statements in (mariadb.revoke(extra),
                       mariadb.grants(hosts, state.credential.value)):
        if statements is not None:
            actions.append(
                RunSql(mariadb.CLIENT, statements.text, statements.summary)
            )
    if not actions:
        return Step(AUTHORIZATIONS, (
            Note("unchanged (no origin is declared and none is held)"),
        ))
    return Step(AUTHORIZATIONS, tuple(actions))


def _replication(
    server: dict, state: DatabaseState, observed: str, confirmed: bool,
) -> Step:
    """Make this node a replica of the declared primary, or refuse to"""
    host, port = endpoint(server)
    if observed == REPLICA:
        return _already_replicating(state, host, port, confirmed)
    return _become_replica(state, host, port, confirmed, "")


def _already_replicating(
    state: DatabaseState, host: str, port: int, confirmed: bool
) -> Step:
    """A replica of the declared primary is converged and left alone

    Idempotence matters more here than anywhere else in keel: apply runs
    at every boot, and restarting replication from the beginning of the
    primary's binary log on a machine that is already a replica would
    throw away everything it had caught up on.
    """
    current = state.reading.primary.value or {}
    was_host = str(current.get("host") or "")
    was_port = int(current.get("port") or port)
    if canonical(was_host) == canonical(host) and was_port == port:
        error = sql_stopped(state.status)
        if error is None:
            return Step(REPLICATION, (
                Note(ALREADY.format(host=host, port=port)),
            ))
        return _become_replica(
            state, host, port, confirmed,
            STOPPED.format(host=host, port=port, error=error),
        )
    return _become_replica(
        state, host, port, confirmed,
        REPOINT.format(
            observed=f"{was_host or 'nowhere'}]:{was_port}",
            declared=f"{host}]:{port}",
        ),
    )


def _become_replica(
    state: DatabaseState, host: str, port: int, confirmed: bool, why: str,
) -> Step:
    """The one step of this feature that can lose data

    A replica is a copy of its primary, so it is seeded with one before it
    replicates (keel.system.dbseed): replicating from an empty position
    carries only what the primary writes afterwards. The primary was
    asked whether it can be copied from while the machine was observed,
    so an unreachable one is refused here, before anything is written.
    """
    if not state.credential.known:
        return Step(REPLICATION, (Refuse(state.credential.problem),))
    if not state.schemas.readable:
        return Step(REPLICATION, (
            Refuse(UNKNOWN_CONTENT.format(problem=state.schemas.problem)),
        ))
    if state.reach:
        return Step(REPLICATION, (
            Refuse(UNREACHABLE.format(problem=state.reach)),
        ))
    held = mariadb.user_schemas((state.schemas.text or "").splitlines())
    actions: list[Action] = []
    if held or why:
        reason = _reason(held, why)
        if not confirmed:
            return Step(REPLICATION, (Refuse(reason + REMEDY),))
        actions.append(Note(CONFIRMED.format(reason=reason)))
    if state.shared:
        actions.append(Note(SHARED.format(accounts=", ".join(state.shared))))
    actions.append(
        SeedReplica(host, port, state.credential.value, tuple(held))
    )
    return Step(REPLICATION, tuple(actions))


def _reason(held: list[str], why: str) -> str:
    """Why this is the step that loses data, without the remedy"""
    if why:
        return why
    return DESTRUCTION.format(count=len(held), schemas=", ".join(held))
