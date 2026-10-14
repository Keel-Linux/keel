# Copyright (c) 2026 KeelLinux maintainers
"""The PostgreSQL flow of the database phase, one test per branch

The twin of test_system_database.py for decision 0054: a standby is made
with a base backup, so the destroy-local-database refusal and confirmation
read the same; a standby refuses writes while it recovers, so there is no
read_only lock step and no unlock on promotion; the hba file is the whole
authorization surface, and it is owned by the configuration step.
"""

import os
import unittest
from dataclasses import replace

from helpers_database import postgresql_reading
from test_inspect_database import PG_STANDALONE, SOCKETS

from keel.inspect.tree import File
from keel.system import dbpostgres
from keel.system.actions import (
    Note,
    PromoteReplica,
    Refuse,
    Run,
    RunSql,
    SeedReplica,
    UnlockAccounts,
    WriteFile,
)
from keel.system.database import (
    DRAIN_TIMEOUT,
    plan_database,
    plan_promote,
)
from keel.system.dbstate import Credential, DatabaseState

MACHINE_ID = "0123456789abcdef0123456789abcdef\n"
PASSWORD = "a-replication-password"
PREFIX = "2804:710:d0:5::/64"
PRIMARY_HOST = "2001:db8:1::10"
PRIMARY_PORT = 5432
BINARY = "/usr/lib/postgresql/17/bin/postgres"
PG_DROPIN = "etc/postgresql/17/main/conf.d/99-keel-database.conf"
PG_HBA = "etc/postgresql/17/main/conf.d/99-keel-pg_hba.conf"
PG_STREAMING = {
    "state": "t\t0\t5432\n",
    "receiver": "user=repl host=2001:db8:1::10 port=5432"
                " password=******** sslmode=prefer\n",
    "standby": "pid\t1234\n",
    "hba": "local\t\t\n",
}


def state(
    answered: dict | None = None,
    schemas: str | None = "postgres\n",
    dropin: str | None = None,
    hba: str | None = None,
    credential: Credential | None = None,
    live: bool = True,
    binary: str = BINARY,
    problem: str = "",
    reach: str = "",
    down: str = "",
    revoked: str | None = None,
    enabled: str = "enabled",
) -> DatabaseState:
    """One machine's PostgreSQL, as the planner is given it"""
    answered = answered or PG_STANDALONE
    if down:
        problem = problem or down
    return DatabaseState(
        engine="postgresql",
        live=live,
        binary=binary,
        reading=postgresql_reading(answered, SOCKETS, problem),
        schemas=_file("schemas", schemas),
        machine_id=_file("/etc/machine-id", MACHINE_ID),
        dropin=_file(PG_DROPIN, dropin),
        hba=_file(PG_HBA, hba),
        credential=credential or Credential(value=PASSWORD),
        reach=reach,
        down=down,
        revoked=_file("var/lib/keel/readonly.accounts", revoked),
        enabled=enabled,
    )


def _file(path: str, text: str | None) -> File:
    if text is None:
        return File(path, problem="not present")
    return File(path, text)


def declaring(**server) -> dict:
    return {"database": {"server": {"engine": "postgresql", **server}}}


def steps(doc: dict, observed: DatabaseState, confirmed: bool = False):
    return {
        step.field: step.actions
        for step in plan_database(doc, observed, confirmed)
    }


def only(actions, kind):
    return [one for one in actions if isinstance(one, kind)]


def writes(actions) -> dict:
    return {one.path: one.content for one in only(actions, WriteFile)}


def refusals(plan: dict) -> str:
    return "\n".join(
        one.summary
        for actions in plan.values() for one in only(actions, Refuse)
    )


def replication_of(primary: str, port: int = PRIMARY_PORT) -> dict:
    return {"primary": {"host": primary, "port": port}}


def declared_primary(**server) -> dict:
    return declaring(role="replica",
                     replication=replication_of(PRIMARY_HOST), **server)


class TestTheMachineIsNotAskedOnAGuess(unittest.TestCase):
    def test_an_offline_root_configures_nothing(self):
        plan = steps(declaring(role="standalone"), state(live=False))
        self.assertIn("not the live system",
                      only(plan["database.server"], Note)[0].summary)

    def test_a_description_without_an_installed_cluster_is_refused(self):
        plan = steps(declaring(role="standalone"), state(binary=""))
        self.assertIn("none is installed here", refusals(plan))

    def test_a_server_that_never_came_up_is_left_alone(self):
        plan = steps(declaring(role="standalone"),
                     state(down="not answering within 90 s"))
        self.assertIn("not answering", refusals(plan))

    def test_a_role_is_never_changed_on_a_guess(self):
        plan = steps(declaring(role="standalone"),
                     state(problem="the socket refused"))
        self.assertIn("a role is", refusals(plan))

    def test_a_clusterless_root_is_refused_before_any_file_write(self):
        observed = replace(
            state(), dropin=File("", problem="not present"),
            hba=File("", problem="not present"))
        plan = steps(declaring(role="standalone"), observed)
        self.assertIn("no PostgreSQL cluster is installed", refusals(plan))
        self.assertFalse(writes(plan["database.server"]))

    def test_a_replica_declared_of_a_primary_is_a_promotion_refusal(self):
        plan = steps(declaring(role="primary"), state(answered=PG_STREAMING))
        self.assertIn("Promotion is an operator action", refusals(plan))


class TestConfiguration(unittest.TestCase):
    """The drop-in and the hba file: one step owns both"""

    def test_a_first_apply_writes_both_files_and_restarts(self):
        plan = steps(declaring(role="standalone"), state())
        files = writes(plan["database.server"])
        self.assertEqual(files[PG_DROPIN], dbpostgres.dropin_text(
            None, "standalone", os.path.join("/", PG_HBA)))
        self.assertEqual(files[PG_HBA], dbpostgres.hba_text([], PASSWORD))
        commands = [one.argv for one in only(plan["database.server"], Run)]
        self.assertIn(("systemctl", "restart", dbpostgres.boot_unit()),
                      commands)

    def test_a_primary_holds_one_replication_line_per_origin(self):
        plan = steps(
            declaring(role="primary",
                      replication={"allowed_from": [PREFIX]}), state())
        hba = writes(plan["database.server"])[PG_HBA]
        self.assertIn(f"hostssl replication repl {PREFIX} scram-sha-256\n",
                      hba)

    def test_a_replica_authorizes_nobody(self):
        doc = declared_primary()
        doc["database"]["server"]["replication"]["allowed_from"] = [PREFIX]
        plan = steps(doc, state(answered=PG_STREAMING))
        hba = writes(plan["database.server"])[PG_HBA]
        self.assertNotIn("hostssl replication", hba)

    def test_matching_files_are_left_alone(self):
        observed = state(
            dropin=dbpostgres.dropin_text(
                None, "standalone", os.path.join("/", PG_HBA)),
            hba=dbpostgres.hba_text([], PASSWORD),
        )
        plan = steps(declaring(role="standalone"), observed)
        notes = "\n".join(one.summary
                          for one in only(plan["database.server"], Note))
        self.assertIn("unchanged", notes)
        self.assertFalse(writes(plan["database.server"]))
        self.assertFalse(only(plan["database.server"], Run))

    def test_a_changed_hba_alone_is_reloaded_not_restarted(self):
        observed = state(
            dropin=dbpostgres.dropin_text(
                None, "primary", os.path.join("/", PG_HBA)),
            hba=dbpostgres.hba_text([], PASSWORD),
        )
        plan = steps(declaring(role="primary",
                               replication={"allowed_from": [PREFIX]}),
                     observed)
        files = writes(plan["database.server"])
        self.assertNotIn(PG_DROPIN, files)
        self.assertIn(PG_HBA, files)
        commands = [one.argv for one in only(plan["database.server"], Run)]
        self.assertIn(("systemctl", "reload", dbpostgres.boot_unit()),
                      commands)
        self.assertNotIn(("systemctl", "restart", dbpostgres.boot_unit()),
                         commands)

    def test_a_changed_drop_in_restarts_the_server(self):
        observed = state(
            dropin=dbpostgres.dropin_text(
                ["2001:db8:1::10"], "standalone",
                os.path.join("/", PG_HBA)),
            hba=dbpostgres.hba_text([], PASSWORD),
        )
        plan = steps(declaring(role="standalone"), observed)
        self.assertIn(PG_DROPIN, writes(plan["database.server"]))
        commands = [one.argv for one in only(plan["database.server"], Run)]
        self.assertIn(("systemctl", "restart", dbpostgres.boot_unit()),
                      commands)

    def test_a_disabled_unit_is_enabled(self):
        plan = steps(declaring(role="standalone"),
                     state(enabled="disabled"))
        commands = [one.argv for one in only(plan["database.server"], Run)]
        self.assertIn(("systemctl", "enable", dbpostgres.boot_unit()),
                      commands)


class TestAuthorizations(unittest.TestCase):
    """The replication role, kept true when the origins drift"""

    def _step(self, doc: dict, observed: DatabaseState):
        return steps(doc, observed)["database.server.replication.allowed_from"]

    def test_no_declaration_leaves_the_server_alone(self):
        actions = self._step(declaring(role="primary"), state())
        self.assertIn("not declared",
                      only(actions, Note)[0].summary)

    def test_the_declared_origins_as_the_held_ones_change_nothing(self):
        answered = dict(PG_STANDALONE, hba=f"host\t{PREFIX}\t\n")
        actions = self._step(
            declaring(role="primary",
                      replication={"allowed_from": [PREFIX]}),
            state(answered=answered))
        self.assertIn("unchanged", only(actions, Note)[0].summary)
        self.assertFalse(only(actions, RunSql))

    def test_a_drift_sends_the_idempotent_role_statement(self):
        actions = self._step(
            declaring(role="primary",
                      replication={"allowed_from": [PREFIX]}), state())
        statements = "\n".join(one.statements for one in only(actions, RunSql))
        self.assertIn("CREATE ROLE repl", statements)
        self.assertIn(dbpostgres.literal(PASSWORD), statements)
        self.assertFalse(only(actions, Refuse))

    def test_a_role_without_a_credential_is_refused(self):
        plan = steps(
            declaring(role="primary",
                      replication={"allowed_from": [PREFIX]}),
            state(credential=Credential(problem="no secret was declared")))
        self.assertIn("no secret was declared", refusals(plan))


class TestReplication(unittest.TestCase):
    """A standby is a base backup of its primary, never rebuilt healthy"""

    def test_a_standby_of_the_declared_primary_is_left_alone(self):
        plan = steps(declared_primary(), state(answered=PG_STREAMING))
        actions = plan["database.server.replication.primary"]
        self.assertIn(f"already replicating from [{PRIMARY_HOST}]",
                      only(actions, Note)[0].summary)
        self.assertFalse(only(actions, SeedReplica))
        self.assertFalse(only(actions, Refuse))

    def test_a_standalone_with_user_data_is_refused_until_confirmed(self):
        plan = steps(declared_primary(), state(schemas="wordpress\n"))
        self.assertIn("replaces the local database", refusals(plan))
        self.assertIn("--destroy-local-database", refusals(plan))

    def test_a_confirmation_names_what_goes_and_seeds(self):
        plan = steps(declared_primary(), state(schemas="wordpress\n"),
                     confirmed=True)
        actions = plan["database.server.replication.primary"]
        self.assertIn("wordpress",
                      only(actions, Note)[0].summary)
        seed = only(actions, SeedReplica)
        self.assertEqual(len(seed), 1)
        self.assertEqual(seed[0].engine, "postgresql")
        self.assertEqual((seed[0].host, seed[0].port, seed[0].password),
                         (PRIMARY_HOST, PRIMARY_PORT, PASSWORD))

    def test_an_empty_server_seeds_without_a_confirmation(self):
        plan = steps(declared_primary(), state())
        actions = plan["database.server.replication.primary"]
        self.assertFalse(only(actions, Refuse))
        self.assertEqual(len(only(actions, SeedReplica)), 1)

    def test_a_standby_of_another_primary_is_a_repoint_refusal(self):
        other = dict(PG_STREAMING,
                     receiver="user=repl host=2001:db8:1::20 port=5432"
                              " password=******** sslmode=prefer\n")
        plan = steps(declared_primary(), state(answered=other))
        self.assertIn("pointing it", refusals(plan))

    def test_a_confirmed_repoint_seeds_again(self):
        other = dict(PG_STREAMING,
                     receiver="user=repl host=2001:db8:1::20 port=5432"
                              " password=******** sslmode=prefer\n")
        plan = steps(declared_primary(), state(answered=other),
                     confirmed=True)
        actions = plan["database.server.replication.primary"]
        seed = only(actions, SeedReplica)
        self.assertEqual(len(seed), 1)
        self.assertEqual(seed[0].host, PRIMARY_HOST)

    def test_an_unreachable_primary_is_refused_before_any_write(self):
        plan = steps(declared_primary(), state(reach="the primary did"
                                               " not answer"))
        self.assertIn("cannot be seeded", refusals(plan))

    def test_an_unreadable_schema_list_is_refused(self):
        plan = steps(declared_primary(), state(schemas=None))
        self.assertIn("could not be asked which databases",
                      refusals(plan))

    def test_a_replica_flow_has_no_lock_step(self):
        plan = steps(declared_primary(), state(schemas="wordpress\n"),
                     confirmed=True)
        self.assertNotIn("database.server.read_only", plan)


class TestPromotion(unittest.TestCase):
    """The drain-then-promote act, with nothing read_only to undo"""

    def test_only_a_replica_is_promoted(self):
        plan = plan_promote(declaring(role="replica"), state())
        self.assertIn("only a replica can be promoted",
                      only(plan[0].actions, Refuse)[0].summary)

    def test_a_standby_is_drained_and_promoted_with_nothing_unlocked(self):
        plan = plan_promote(declaring(role="replica"),
                            state(answered=PG_STREAMING))
        promote = only(plan[0].actions, PromoteReplica)
        self.assertEqual(len(promote), 1)
        self.assertEqual(promote[0].timeout, DRAIN_TIMEOUT)
        self.assertEqual(promote[0].engine, "postgresql")
        self.assertFalse(only(plan[0].actions, UnlockAccounts))
        notes = "\n".join(one.summary for one in only(plan[0].actions, Note))
        self.assertIn("WAL settings of a", notes)

    def test_a_revoked_list_is_given_back_after_the_promotion(self):
        observed = state(answered=PG_STREAMING,
                         revoked="wpuser\n")
        plan = plan_promote(declaring(role="replica"), observed)
        promoted = plan[0].actions
        self.assertIsInstance(promoted[0], PromoteReplica)
        self.assertIsInstance(promoted[1], UnlockAccounts)


if __name__ == "__main__":
    unittest.main()
