# Copyright (c) 2026 KeelLinux maintainers
"""keel database status of a PostgreSQL server (0054, keel#155)

The lines that keel.system.dbstatus prints after the server's role: the
timeline, the synchronous commit, each standby that streams from here,
each replication slot, and what a standby receives and how far its
replay is behind. One question, asked as the postgres account over the
socket. Reads only; never a secret: the receiver's host and port are
asked, not its connection string.
"""

import subprocess
from collections.abc import Callable

from keel.system import dbpostgres

# One row for each thing, the kind first and 6 text columns in all, so
# that one psql call answers everything (UNION ALL wants the same columns
# in each part). The timeline is the one of the last checkpoint, which a
# standby has too.
STATUS_SQL = (
    "SELECT 'state', pg_is_in_recovery()::text,"
    " (SELECT timeline_id FROM pg_control_checkpoint())::text,"
    " current_setting('synchronous_commit'),"
    " current_setting('synchronous_standby_names'),"
    " coalesce((now() - pg_last_xact_replay_timestamp())::text, '')"
    " UNION ALL"
    " SELECT 'standby', application_name,"
    " coalesce(client_addr::text, 'local'), state, sync_state,"
    " coalesce(replay_lag::text, '')"
    " FROM pg_stat_replication"
    " UNION ALL"
    " SELECT 'slot', slot_name,"
    " CASE WHEN active THEN 'active' ELSE 'inactive' END,"
    " coalesce(restart_lsn::text, ''), coalesce(wal_status, ''), ''"
    " FROM pg_replication_slots"
    " UNION ALL"
    " SELECT 'receiver', status, coalesce(sender_host, ''),"
    " coalesce(sender_port::text, ''), coalesce(received_tli::text, ''), ''"
    " FROM pg_stat_wal_receiver"
)
WIDTH = 6


def status_lines(runner: Callable | None = None) -> list[str]:
    """The status lines, or 1 line that says why there are none"""
    runner = runner or subprocess.run
    try:
        done = runner(list(dbpostgres.CLIENT + ("--command", STATUS_SQL)),
                      capture_output=True, text=True, check=False)
    except OSError as e:
        return [f"  status: not readable ({e})"]
    if done.returncode != 0:
        problem = (done.stderr or "").strip()[-200:] or "no answer"
        return [f"  status: not readable ({problem})"]
    rows: dict[str, list[list[str]]] = {}
    for line in (done.stdout or "").splitlines():
        cells = line.split("\t")
        if len(cells) == WIDTH:
            rows.setdefault(cells[0], []).append(cells[1:])
    return described(rows)


def described(rows: dict[str, list[list[str]]]) -> list[str]:
    """The lines for the rows of STATUS_SQL, by kind"""
    found: list[str] = []
    state = (rows.get("state") or [["", "", "", "", ""]])[0]
    _, timeline, commit, names, replay = state
    found.append(f"  timeline: {timeline or 'unknown'}")
    found.append(f"  synchronous commit: {commit or 'unknown'},"
                 f" synchronous_standby_names '{names}'")
    standbys = rows.get("standby") or []
    for name, client, streams, sync, lag in standbys:
        found.append(f"  standby: {name} from [{client}], {streams},"
                     f" {sync}, replay lag {lag or 'none'}")
    if not standbys:
        found.append("  standby: none streams from here")
    slots = rows.get("slot") or []
    for name, active, restart, wal, _ in slots:
        found.append(f"  slot: {name}, {active}, restart_lsn"
                     f" {restart or 'none'}, wal_status {wal or 'none'}")
    if not slots:
        found.append("  slot: none")
    receivers = rows.get("receiver") or []
    for streams, host, port, received, _ in receivers:
        found.append(f"  receiving from: [{host}]:{port}, {streams},"
                     f" timeline {received or 'unknown'}")
    if not receivers:
        found.append("  receiving from: nobody")
    if replay:
        found.append(f"  replay lag: {replay}")
    return found
