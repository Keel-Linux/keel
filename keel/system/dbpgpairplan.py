# Copyright (c) 2026 KeelLinux maintainers
"""The plan for a paired PostgreSQL node (appliance.vip); pure

The twin of keel.system.dbpairplan, one engine at a time the way
handbook decision 0054 has it. Both nodes of a pair get the same
configuration, whatever the VIP's role: the drop-in of a
primary-capable node (its listen addresses, the hba file, the TLS
files of the leaf keel.system.dbtls made for this engine), the pair's
drop-in (synchronous commit waits for the standby of application_name
`keel`, with no timeout, and wal_log_hints and wal_keep_size are what
pg_rewind needs), the whole of pg_hba.conf with a replication line and a
postgres-database line per declared origin, and the user name map
pg_ident.conf the replication lines' cert method consults: a
replication connection's certificate CN is `<member> postgresql`,
never the database user `repl`, so the map is what pins the peer's
certificate, the twin of MariaDB's REQUIRE SUBJECT. The VIP is bound
beside the
node's own addresses through net.ipv6.ip_nonlocal_bind, so the primary
answers on it the moment it carries the address and no role change
restarts the server. What the role decides, a seed or a rejoin, is one
action, `FollowVip`, carried out by keel.system.dbfollow from the
VIP's state.

The order: the certificate first, in the same step as the drop-in and
its restart, since the drop-in names the certificate's files and the
server would not start without them (a step's failed action skips the
rest of it); the sysctl before the restart, since the bind needs it;
the authorizations; then the role. A changed drop-in or pair drop-in
restarts the server, the only way their settings take effect; a
changed hba or ident file alone is reloaded, which is enough for both.
"""

import os

from keel.inspect import constants as paths
from keel.system import dbpair, dbpgrewind, dbpostgres, dbtls
from keel.system.actions import (
    Action,
    EnsureDatabaseTls,
    FollowVip,
    Note,
    Refuse,
    Run,
    RunSql,
    Step,
    WriteFile,
)
from keel.system.dbpairplan import (
    DAMAGED,
    NO_PEER,
    NO_RECORD,
    ROLE_NOTE,
    UNCLAIMED,
)
from keel.system.dbstate import DatabaseState, declared_server

FIELD = "database.server"
TLS_FIELD = f"{FIELD}.tls"
AUTHORIZATIONS = f"{FIELD}.replication.allowed_from"
ROLE_FIELD = f"{FIELD}.role"
DROPIN_MODE = 0o644
NO_CLUSTER = (
    "no PostgreSQL cluster is installed under {glob}, so there is nothing"
    " to configure. The database was left as it was"
)
NO_IDENTITY = (
    "{path} is empty or unreadable and this node declares no overlay"
    " address, so there is nothing of its own to name the certificate"
    " with. The database was left as it was"
)
NAME_NOTE = (
    "an origin is a name or a network ({names}), so its hba line pins no"
    " certificate: the line authorizes the connection, the map cannot"
    " name its subject, and docs/spec.md calls a name fragile for this"
    " reason: it fails quietly when DNS does"
)
UNUSABLE_NOTE = (
    "the copy of this node is unusable (pg_rewind failed halfway) and its"
    " server does not answer: --destroy-local-database replaces it with a"
    " copy of the holder"
)
UNCHANGED = (
    "unchanged ({path}, a paired node, primary-capable; the hba, ident"
    " and pair drop-in beside it are unchanged too)"
)


def plan_pair(doc: dict, state: DatabaseState, confirmed: bool,
              spec: str, cannot_act) -> list[Step]:
    """The steps for a paired node; `cannot_act` is the common gate of
    keel.system.database"""
    server = declared_server(doc)
    declared = str(server.get("role") or "")
    pair = state.pair
    if state.down and confirmed and dbpgrewind.broken(paths.ROOT_DEFAULT):
        # pg_rewind failed halfway and the copy does not start: only the
        # confirmed reseed replaces it, and it needs no answer from the
        # server (0054, amendment of 2026-10-18)
        return [Step(ROLE_FIELD, (Note(UNUSABLE_NOTE), FollowVip(
            spec, confirmed)))]
    refusal = cannot_act(state, declared)
    if refusal:
        return [Step(FIELD, (refusal,))]
    if pair.problem:
        return [Step(FIELD, (Refuse(DAMAGED.format(problem=pair.problem)),))]
    if pair.peer_key is None:
        return [Step(FIELD, (Refuse(NO_RECORD.format(vip=pair.vip)),))]
    if pair.peer_address is None:
        return [Step(FIELD, (Refuse(NO_PEER.format(key=pair.peer_key)),))]
    own = dbpostgres.overlay_addresses(doc)
    address = own[0] if own else None
    if address is None:
        return [Step(FIELD, (Refuse(NO_IDENTITY.format(
            path=state.machine_id.path)),))]
    tls = EnsureDatabaseTls(address, pair.vip, pair.peer_address, spec)
    return [
        _configuration(server, state, own, tls),
        _authorizations(server, state),
        _role(server, state, confirmed, spec),
    ]


def _configuration(server: dict, state: DatabaseState,
                   overlay: list[str], tls: EnsureDatabaseTls) -> Step:
    """The certificate, the sysctl, the four files and the one restart

    The drop-in and the pair drop-in cannot change while the server
    runs, so either changing restarts it; the hba and ident files the
    two point at are reloaded when they alone change. An origin that is
    not a host address (a name, a network) still gets its hba line,
    with a note that the line pins no certificate.
    """
    pair = state.pair
    if not state.hba.path:
        return Step(FIELD, (Refuse(NO_CLUSTER.format(
            glob=dbpostgres.CONF_GLOB)),))
    allowed = dbpair.allowed_hosts(pair, server) or []
    cns = _certificate_names(allowed)
    loose = [str(one) for one in allowed if etcd_name(str(one)) is None]
    hba_path = os.path.join(paths.ROOT_DEFAULT, state.hba.path)
    ident_path = os.path.join(paths.ROOT_DEFAULT, state.ident.path)
    bind = dbpair.bind_addresses(server.get("listen"), overlay, pair.vip)
    dropin_wanted = dbpostgres.dropin_text(
        bind, "primary", hba_path) + dbtls.dropin_lines(
        paths.ROOT_DEFAULT, "postgresql")
    pair_wanted = dbpostgres.pair_dropin_text(ident_path)
    password = state.credential.value if state.credential.known else ""
    hba_wanted = dbpostgres.hba_text(allowed, password, verify=True)
    ident_wanted = dbpostgres.ident_text(cns)
    dropin_kept = state.dropin.readable and \
        state.dropin.text == dropin_wanted
    # a primary that commits alone after keel database promote
    # --old-primary-gone is follow's runtime state, not drift: follow
    # writes the synchronous line back once a standby streams (0054)
    pair_kept = state.pair_dropin.readable and \
        state.pair_dropin.text in (pair_wanted,
                                   dbpostgres.alone_text(pair_wanted))
    # the text of keel before 0.23.44 lacks wal_keep_size, which the
    # server takes on a reload: written, never a restart (a primary
    # that serves clients is not restarted for it), and a primary that
    # commits alone keeps committing alone
    pair_older = dbpostgres.pair_dropin_text(ident_path, legacy=True)
    pair_reload = state.pair_dropin.readable and \
        state.pair_dropin.text in (pair_older,
                                   dbpostgres.alone_text(pair_older))
    if pair_reload and dbpostgres.commits_alone(state.pair_dropin.text):
        pair_wanted = dbpostgres.alone_text(pair_wanted)
    hba_kept = state.hba.readable and state.hba.text == hba_wanted
    ident_kept = state.ident.readable and \
        state.ident.text == ident_wanted

    actions: list[Action] = [tls]
    if (state.nonlocal_bind.text or "").strip() != "1":
        actions += [
            WriteFile(dbpostgres.SYSCTL, dbpostgres.sysctl_text(),
                      DROPIN_MODE, None,
                      f"write /{dbpostgres.SYSCTL}: both nodes bind the"
                      " VIP"),
            Run(("sysctl", "-q", "-w", f"{dbpostgres.NONLOCAL_BIND}=1"),
                "let the server bind the VIP before it carries it"),
        ]
    if state.enabled == "disabled":
        actions.append(Run(("systemctl", "enable", dbpostgres.boot_unit()),
                           "enable the server, so it starts at boot"))
    if loose:
        actions.append(Note(NAME_NOTE.format(names=", ".join(loose))))
    if dropin_kept and pair_kept and hba_kept and ident_kept:
        actions.append(Note(UNCHANGED.format(path=state.dropin.path)))
        return Step(FIELD, tuple(actions))
    if not dropin_kept:
        actions.append(WriteFile(
            state.dropin.path, dropin_wanted, DROPIN_MODE, None,
            f"write {state.dropin.path}: a paired node, primary-capable,"
            f" the pair's hba and TLS, the VIP {pair.vip} bound"))
    if not pair_kept:
        actions.append(WriteFile(
            state.pair_dropin.path, pair_wanted, DROPIN_MODE, None,
            f"write {state.pair_dropin.path}: the pair's synchronous"
            " commit and the ident map it points at"))
    if not hba_kept:
        actions.append(WriteFile(
            state.hba.path, hba_wanted, DROPIN_MODE, None,
            f"write {state.hba.path}: the pair's authorizations, the"
            " peer's certificate pinned"))
    if not ident_kept:
        actions.append(WriteFile(
            state.ident.path, ident_wanted, DROPIN_MODE, None,
            f"write {state.ident.path}: the peer's certificate CN mapped"
            " to the replication role"))
    if not (dropin_kept and (pair_kept or pair_reload)):
        actions.append(Run(
            ("systemctl", "restart", dbpostgres.boot_unit()),
            "restart the server, which is the only way these take"
            " effect"))
    else:
        actions.append(Run(
            ("systemctl", "reload", dbpostgres.boot_unit()),
            "reload the server, which is how hba and ident rules take"
            " effect"))
    return Step(FIELD, tuple(actions))


def etcd_name(origin: str) -> str | None:
    """The origin as a certificate name, or None when it is not a host
    address (a name or a network pins nothing, NAME_NOTE)"""
    from keel.mesh import etcdstate
    try:
        return etcdstate.database_name(origin, "postgresql")
    except ValueError:
        return None


def _certificate_names(allowed: list[str]) -> list[str]:
    """The CNs the ident map pins: one per origin that is a host address"""
    return [cn for cn in (etcd_name(str(one)) for one in allowed) if cn]


def _authorizations(server: dict, state: DatabaseState) -> Step:
    """The replication role, the pair's slot and the grants that the
    rewind of an old primary reads through, as declared

    Both statements are idempotent, so they are sent on every apply;
    the hba file's rewrite is what withdraws an origin (its line goes
    with the file), and the slot's guards refuse on a standby, where
    slots cannot be made, and when the slot exists.
    """
    if not state.credential.known:
        return Step(AUTHORIZATIONS, (Refuse(state.credential.problem),))
    slot = dbpostgres.slot_statements()
    role = dbpostgres.role_statements(state.credential.value)
    rewind = dbpostgres.rewind_statements()
    return Step(AUTHORIZATIONS, (
        RunSql(dbpostgres.CLIENT, slot.text, slot.summary),
        RunSql(dbpostgres.CLIENT, role.text, role.summary),
        RunSql(dbpostgres.CLIENT, rewind.text, rewind.summary),
    ))


def _role(server: dict, state: DatabaseState, confirmed: bool,
          spec: str) -> Step:
    pair = state.pair
    declared = str(server.get("role") or "")
    notes: list[Action] = []
    if pair.claimed:
        notes.append(Note(ROLE_NOTE.format(role=pair.role,
                                           holder=pair.holder_address,
                                           declared=declared)))
    else:
        notes.append(Note(UNCLAIMED.format(vip=pair.vip, declared=declared)))
    return Step(ROLE_FIELD, tuple(notes) + (FollowVip(spec, confirmed),))
