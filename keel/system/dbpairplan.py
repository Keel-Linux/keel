# Copyright (c) 2026 KeelLinux maintainers
"""The plan for a paired MariaDB node (appliance.vip); pure

Both nodes of a pair get the same configuration, whatever their role
(keel.system.dbpair, keel.system.dbmariadb.pair_dropin_text): the
binary log, GTIDs kept as they came, strict mode, semi-synchronous
replication both ways, the server's TLS, and the VIP bound beside the
node's own addresses through `net.ipv6.ip_nonlocal_bind`, so the primary
answers on it the moment it carries the address and no role change
restarts the server. Each node authorizes the other member to replicate
from it, over TLS with a certificate of the mesh's root. What the role
decides, read_only, the root lock, replication's direction, a seed or a
rejoin, is one action, `FollowVip`, carried out by keel.system.dbfollow
from the VIP's state, as keel-database-follow.service carries it out
when the VIP moves.

The order: the certificate first, in the same step as the drop-in and
its restart, since the drop-in names the certificate's files and the
server would not start without them (a step's failed action skips the
rest of it); the sysctl before the restart, since the bind needs it;
the authorizations; then the role.
"""

from keel.system import dbmariadb as mariadb
from keel.system import dbpair, dbtls
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
from keel.system.dbstate import DatabaseState, declared_server

FIELD = "database.server"
TLS_FIELD = f"{FIELD}.tls"
AUTHORIZATIONS = f"{FIELD}.replication.allowed_from"
ROLE_FIELD = f"{FIELD}.role"
DROPIN_MODE = 0o644
NO_RECORD = (
    "this node declares appliance.vip {vip} and holds no pair record: run"
    " keel vip pair with the other node's overlay address on one node of"
    " the pair, then apply again. The database was left as it was"
)
NO_PEER = (
    "the pair record names {key}, and the spec routes no /128 to that peer,"
    " so the other node's address is not known. The database was left as"
    " it was"
)
NO_IDENTITY = (
    "{path} is empty or unreadable and this node has no overlay address, so"
    " there is nothing of its own to derive a server id from"
)
DAMAGED = "the VIP's state cannot be read ({problem}); nothing was changed"
ROLE_NOTE = (
    "the role is the VIP's: {role} here (epoch known, held at"
    " {holder}); the declared {declared} is the installation's (0020)"
)
UNCLAIMED = (
    "no claim of {vip} is known yet, so the declared role, {declared},"
    " stands until keel vip promote on the primary claims it"
)


def plan_pair(doc: dict, state: DatabaseState, confirmed: bool,
              spec: str, cannot_act) -> list[Step]:
    """The steps for a paired node; `cannot_act` is the common gate of
    keel.system.database"""
    server = declared_server(doc)
    declared = str(server.get("role") or "")
    pair = state.pair
    refusal = cannot_act(state, declared)
    if refusal:
        return [Step(FIELD, (refusal,))]
    if pair.problem:
        return [Step(FIELD, (Refuse(DAMAGED.format(problem=pair.problem)),))]
    if pair.peer_key is None:
        return [Step(FIELD, (Refuse(NO_RECORD.format(vip=pair.vip)),))]
    if pair.peer_address is None:
        return [Step(FIELD, (Refuse(NO_PEER.format(key=pair.peer_key)),))]
    own = mariadb.overlay_addresses(doc)
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
    """The certificate, the sysctl, the drop-in and its one restart, when
    they changed; a certificate that cannot be had stops the step before
    the drop-in names it"""
    pair = state.pair
    identity = mariadb.server_id(state.machine_id.text or "",
                                 server.get("listen"), overlay)
    if identity is None:
        return Step(FIELD, (Refuse(NO_IDENTITY.format(
            path=state.machine_id.path)),))
    allowed = dbpair.allowed_hosts(pair, server) or []
    from keel.spec.origins import is_name
    names = any(is_name(str(one)) for one in allowed)
    text = mariadb.pair_dropin_text(
        identity, dbpair.bind_addresses(server.get("listen"), overlay,
                                        pair.vip),
        names, dbtls.dropin_lines(state_root(state)))
    actions: list[Action] = [tls]
    if (state.nonlocal_bind.text or "").strip() != "1":
        actions += [
            WriteFile(mariadb.SYSCTL, mariadb.sysctl_text(), DROPIN_MODE,
                      None, f"write /{mariadb.SYSCTL}: both nodes bind the"
                      " VIP"),
            Run(("sysctl", "-q", "-w", f"{mariadb.NONLOCAL_BIND}=1"),
                "let the server bind the VIP before it carries it"),
        ]
    if state.enabled == "disabled":
        actions.append(Run(("systemctl", "enable", mariadb.service()),
                           "enable the server, so it starts at boot"))
    if state.dropin.readable and state.dropin.text == text:
        actions.append(Note(f"unchanged ({state.dropin.path}, server id"
                            f" {identity}, a paired node)"))
        return Step(FIELD, tuple(actions))
    actions += [
        WriteFile(mariadb.DROPIN, text, DROPIN_MODE, None,
                  f"write {state.dropin.path}: a paired node, server id"
                  f" {identity}, binary log, GTID strict, semi-synchronous"
                  f" replication, TLS, the VIP {pair.vip} bound"),
        Run(("systemctl", "restart", mariadb.service()),
            "restart the server, which is the only way these take effect"),
    ]
    return Step(FIELD, tuple(actions))


def state_root(state: DatabaseState) -> str:
    """The root the drop-in's TLS paths are written for: the live one"""
    from keel.inspect import constants as paths
    return paths.ROOT_DEFAULT


def _authorizations(server: dict, state: DatabaseState) -> Step:
    """The other member may replicate from this node, with a certificate
    of the mesh's root; an origin the spec no longer names is withdrawn"""
    pair = state.pair
    hosts = dbpair.allowed_hosts(pair, server) or []
    if not state.credential.known:
        return Step(AUTHORIZATIONS, (Refuse(state.credential.problem),))
    actions: list[Action] = []
    granted = []
    for origin in hosts:
        host = mariadb.as_host(origin)
        if host is None:
            from keel.spec.origins import mariadb_problem
            actions.append(Refuse(str(mariadb_problem(origin))))
            continue
        granted.append(host)
    wanted = {host.lower() for host in granted}
    extra = [str(one) for one in (state.reading.allowed_from.value or [])
             if str(one).lower() not in wanted]
    # the other member's database certificate alone: its subject and
    # the root's name (an etcd member's leaf of the same root is refused)
    subject = dbtls.peer_subject(pair.peer_address)
    if not state.tls_issuer:
        return Step(AUTHORIZATIONS, (Refuse(
            "the mesh root's name is not known here (no mesh identity), so"
            " the replication account cannot be bound to the other member's"
            " certificate"),))
    for statements in (mariadb.revoke(extra),
                       mariadb.grants(granted, state.credential.value,
                                      subject=subject,
                                      issuer=state.tls_issuer)):
        if statements is not None:
            actions.append(RunSql(mariadb.CLIENT, statements.text,
                                  statements.summary))
    if not actions:
        return Step(AUTHORIZATIONS, (Note("unchanged (nothing to grant)"),))
    return Step(AUTHORIZATIONS, tuple(actions))


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
