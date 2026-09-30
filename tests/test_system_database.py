# Copyright (c) 2026 KeelLinux maintainers
"""The database phase of apply, one test per branch of the plan

The four properties of decision 0013 are each a class here: becoming a
replica destroys the local database, a primary holds authorizations,
promotion is a separate act, and no role is ever changed on a guess.
Every test builds a DatabaseState by hand, so nothing needs a server, a
container or root.
"""

import unittest

from helpers_database import mariadb_reading
from test_inspect_database import (
    MARIADB_REPLICA_STATUS,
    MARIADB_STANDALONE,
    SOCKETS,
)

from keel.inspect.tree import File
from keel.system import dbmariadb as mariadb
from keel.system.actions import Note, Refuse, Run, RunSql, WriteFile
from keel.system.database import plan_database, plan_promote
from keel.system.dbstate import Credential, DatabaseState

MACHINE_ID = "0123456789abcdef0123456789abcdef\n"
PASSWORD = "a-replication-password"
PREFIX = "2804:710:d0:5::/64"
PATTERN = "2804:710:d0:5:%"
PRIMARY_HOST = "2804:710:d0:5:bc:24ff:fe25:b2"
SYSTEM_SCHEMAS = "information_schema\nmysql\nperformance_schema\nsys\n"


def state(
    answered: dict | None = None,
    schemas: str | None = SYSTEM_SCHEMAS,
    machine_id: str | None = MACHINE_ID,
    dropin: str | None = None,
    credential: Credential | None = None,
    engine: str = "mariadb",
    live: bool = True,
    binary: str = "/usr/sbin/mariadbd",
    problem: str = "",
) -> DatabaseState:
    """One machine's database, as the planner is given it"""
    return DatabaseState(
        engine=engine,
        live=live,
        binary=binary,
        reading=mariadb_reading(
            answered or MARIADB_STANDALONE, SOCKETS, problem
        ),
        schemas=_file("schemas", schemas),
        machine_id=_file("/etc/machine-id", machine_id),
        dropin=_file(mariadb.DROPIN, dropin),
        credential=credential or Credential(value=PASSWORD),
    )


def _file(path: str, text: str | None) -> File:
    if text is None:
        return File(path, problem="not present")
    return File(path, text)


def declaring(**server) -> dict:
    return {"database": {"server": {"engine": "mariadb", **server}}}


def steps(doc: dict, observed: DatabaseState, confirmed: bool = False):
    return {
        step.field: step.actions
        for step in plan_database(doc, observed, confirmed)
    }


def only(actions, kind):
    return [one for one in actions if isinstance(one, kind)]


def written(actions) -> str:
    return only(actions, WriteFile)[0].content


def sql(actions) -> str:
    return "\n".join(one.statements for one in only(actions, RunSql))


def refusals(plan: dict) -> str:
    return "\n".join(
        one.summary
        for actions in plan.values() for one in only(actions, Refuse)
    )


class TestNothingDeclared(unittest.TestCase):
    def test_a_description_with_no_server_plans_nothing(self):
        self.assertEqual(plan_database({}, None), [])


class TestTheServerIsNotAskedOnAGuess(unittest.TestCase):
    """No role is changed from something the machine did not say"""

    def test_another_engine_is_read_and_compared_and_not_configured(self):
        plan = steps(
            {"database": {"server": {"engine": "redis", "role": "primary"}}},
            state(engine="redis"),
        )
        self.assertIn("not configured by this version",
                      only(plan["database.server"], Note)[0].summary)

    def test_an_offline_root_configures_nothing(self):
        plan = steps(declaring(role="primary"), state(live=False))
        self.assertIn("not the live system",
                      only(plan["database.server"], Note)[0].summary)

    def test_a_declared_server_that_is_not_installed_is_a_refusal(self):
        plan = steps(declaring(role="primary"), state(binary=""))
        self.assertIn("none is installed here", refusals(plan))

    def test_a_server_that_cannot_be_asked_is_a_refusal(self):
        plan = steps(
            declaring(role="primary"),
            state(problem="exited 1"),
        )
        self.assertIn("never changed on a guess", refusals(plan))

    def test_a_machine_with_no_identity_gets_no_invented_server_id(self):
        plan = steps(declaring(role="standalone"), state(machine_id=""))
        self.assertIn("nothing of its own to derive a server id from",
                      refusals(plan))

    def test_two_machine_ids_give_two_server_ids(self):
        first = mariadb.server_id("0123456789abcdef0123456789abcdef")
        second = mariadb.server_id("fedcba9876543210fedcba9876543210")
        self.assertNotEqual(first, second)
        self.assertGreater(first, 0)

    def test_one_machine_id_and_two_addresses_still_give_two(self):
        """The published core layer ships one machine-id for every machine

        Measured on the build host: the `core` layer's rootfs carries a
        populated /etc/machine-id, so both nodes of the gate and both live
        appliances hold the same value. A server id derived from it alone
        was the same on both nodes, which is the one thing that stops
        replication outright.
        """
        shared = "f0e97605ab594989b4d78f4a126b5b37"

        first = mariadb.server_id(shared, ["::1", "2804:710:d0:5::20"])
        second = mariadb.server_id(shared, ["::1", "2804:710:d0:5::21"])

        self.assertNotEqual(first, second)

    def test_the_addresses_alone_are_enough(self):
        found = mariadb.server_id("", ["2804:710:d0:5::20"])

        self.assertIsNotNone(found)
        self.assertGreater(found, 0)

    def test_the_order_the_addresses_were_written_in_does_not_change_it(self):
        one = mariadb.server_id("abc", ["::1", "127.0.0.1"])
        other = mariadb.server_id("abc", ["127.0.0.1", "::1"])

        self.assertEqual(one, other)

    def test_a_declared_listen_of_blanks_is_no_identity_either(self):
        self.assertIsNone(mariadb.server_id("  ", ["  "]))


class TestTheConfiguration(unittest.TestCase):
    """What every role writes: the server id, the addresses, the log"""

    def test_a_standalone_writes_a_server_id_and_restarts_once(self):
        plan = steps(
            declaring(role="standalone", listen=["::1", "127.0.0.1"]),
            state(),
        )
        actions = plan["database.server"]
        self.assertIn("bind-address = ::1,127.0.0.1", written(actions))
        self.assertIn("server_id = ", written(actions))
        self.assertNotIn("log_bin", written(actions))
        self.assertEqual(
            only(actions, Run)[0].argv,
            ("systemctl", "restart", "mariadb"),
        )

    def test_a_primary_writes_the_binary_log_a_replica_reads(self):
        plan = steps(declaring(role="primary"), state())
        self.assertIn(
            "log_bin = mariadb-bin", written(plan["database.server"])
        )

    def test_a_replica_needs_no_binary_log_of_its_own(self):
        plan = steps(
            declaring(
                role="replica",
                replication={"primary": {"host": PRIMARY_HOST}},
            ),
            state(),
        )
        self.assertNotIn("log_bin", written(plan["database.server"]))

    def test_listen_is_left_alone_when_the_description_names_none(self):
        plan = steps(declaring(role="standalone"), state())
        self.assertNotIn("bind-address", written(plan["database.server"]))

    def test_an_unchanged_file_is_not_rewritten_and_nothing_restarts(self):
        first = steps(declaring(role="standalone", listen=["::1"]), state())
        text = written(first["database.server"])

        again = steps(
            declaring(role="standalone", listen=["::1"]), state(dropin=text)
        )

        self.assertEqual(only(again["database.server"], WriteFile), [])
        self.assertEqual(only(again["database.server"], Run), [])
        self.assertIn("unchanged",
                      only(again["database.server"], Note)[0].summary)

    def test_name_resolution_stays_on_when_an_origin_is_a_name(self):
        plan = steps(
            declaring(
                role="primary",
                replication={"allowed_from": ["replica.example.org"]},
            ),
            state(),
        )
        actions = plan["database.server"]
        self.assertNotIn("skip_name_resolve", written(actions))
        self.assertIn("docs/spec.md calls", only(actions, Note)[0].summary)

    def test_name_resolution_is_off_when_every_origin_is_an_address(self):
        plan = steps(
            declaring(
                role="primary", replication={"allowed_from": [PREFIX]}
            ),
            state(),
        )
        self.assertIn("skip_name_resolve = ON",
                      written(plan["database.server"]))


class TestAPrimaryHoldsAuthorizations(unittest.TestCase):
    """Each entry of allowed_from becomes a grant, and nothing else"""

    def test_a_prefix_is_granted_in_the_spelling_mariadb_holds(self):
        plan = steps(
            declaring(
                role="primary", replication={"allowed_from": [PREFIX]}
            ),
            state(),
        )
        text = sql(plan["database.server.replication.allowed_from"])
        self.assertIn(f"'repl'@'{PATTERN}'", text)
        self.assertIn("GRANT REPLICATION SLAVE ON *.*", text)

    def test_the_credential_never_reaches_an_argument_vector(self):
        plan = steps(
            declaring(
                role="primary", replication={"allowed_from": [PREFIX]}
            ),
            state(),
        )
        action = only(
            plan["database.server.replication.allowed_from"], RunSql
        )[0]
        self.assertIn(PASSWORD, action.statements)
        self.assertNotIn(PASSWORD, " ".join(action.argv))
        self.assertNotIn(PASSWORD, action.describe())

    def test_an_origin_the_description_dropped_is_withdrawn(self):
        plan = steps(
            declaring(
                role="primary", replication={"allowed_from": [PREFIX]}
            ),
            state(answered=dict(
                MARIADB_STANDALONE,
                grants=f"{PATTERN}\n2001:db8:9:%\nlocalhost\n",
            )),
        )
        text = sql(plan["database.server.replication.allowed_from"])
        self.assertIn("DROP USER IF EXISTS 'repl'@'2001:db8:9:%'", text)
        self.assertNotIn(f"DROP USER IF EXISTS 'repl'@'{PATTERN}'", text)

    def test_an_empty_list_withdraws_every_authorization(self):
        plan = steps(
            declaring(role="primary", replication={"allowed_from": []}),
            state(answered=dict(MARIADB_STANDALONE, grants=f"{PATTERN}\n")),
        )
        self.assertIn(
            "DROP USER", sql(plan["database.server.replication.allowed_from"])
        )

    def test_a_field_that_is_not_declared_leaves_the_server_alone(self):
        plan = steps(
            declaring(role="primary", replication={}),
            state(answered=dict(MARIADB_STANDALONE, grants=f"{PATTERN}\n")),
        )
        actions = plan["database.server.replication.allowed_from"]
        self.assertEqual(only(actions, RunSql), [])
        self.assertIn("not declared", only(actions, Note)[0].summary)

    def test_a_prefix_with_no_spelling_is_refused_and_not_widened(self):
        plan = steps(
            declaring(
                role="primary",
                replication={"allowed_from": ["2804:710:d0::/56"]},
            ),
            state(),
        )
        self.assertIn("names no whole group of the address", refusals(plan))

    def test_the_overlay_prefix_is_refused_and_the_address_named(self):
        # The Template B smoke test of 2026-09-30: suggest-address gave
        # fd3d:80b2:d0d7::/64, keel granted fd3d:80b2:d0d7:0:% and MariaDB
        # refused the replica at fd3d:80b2:d0d7::2.
        plan = steps(
            declaring(
                role="primary",
                replication={"allowed_from": ["fd3d:80b2:d0d7::/64"]},
            ),
            state(),
        )
        actions = plan["database.server.replication.allowed_from"]
        self.assertEqual(only(actions, RunSql), [])
        refused = refusals(plan)
        self.assertIn("fd3d:80b2:d0d7::/64", refused)
        self.assertIn("fd3d:80b2:d0d7::1,", refused)
        self.assertIn("each replica's address", refused)
        self.assertNotIn("fd3d:80b2:d0d7:0:%'", refused)

    def test_an_address_is_granted_in_its_compressed_text(self):
        plan = steps(
            declaring(
                role="primary",
                replication={"allowed_from": ["FD3D:80B2:D0D7:0:0:0:0:2"]},
            ),
            state(),
        )
        text = sql(plan["database.server.replication.allowed_from"])
        self.assertIn("'repl'@'fd3d:80b2:d0d7::2'", text)

    def test_a_missing_credential_grants_nothing(self):
        plan = steps(
            declaring(
                role="primary", replication={"allowed_from": [PREFIX]}
            ),
            state(credential=Credential(problem="no secret file")),
        )
        self.assertIn("no secret file", refusals(plan))

    def test_nothing_declared_and_nothing_held_is_unchanged(self):
        plan = steps(
            declaring(role="primary", replication={"allowed_from": []}),
            state(),
        )
        actions = plan["database.server.replication.allowed_from"]
        self.assertIn("unchanged", only(actions, Note)[0].summary)


class TestBecomingAReplicaDestroysTheLocalDatabase(unittest.TestCase):
    """The one step of the feature that loses data, and its refusal"""

    def replica(self, **kwargs):
        return steps(
            declaring(
                role="replica",
                replication={"primary": {"host": PRIMARY_HOST}},
            ),
            state(**{k: v for k, v in kwargs.items() if k != "confirmed"}),
            kwargs.get("confirmed", False),
        )

    def test_an_empty_server_becomes_a_replica_with_gtid(self):
        text = sql(self.replica()["database.server.replication.primary"])
        self.assertIn(f"MASTER_HOST='{PRIMARY_HOST}'", text)
        self.assertIn("MASTER_USE_GTID=slave_pos", text)
        self.assertIn("START SLAVE", text)
        self.assertNotIn("DROP DATABASE", text)

    def test_a_server_holding_data_is_refused_by_default(self):
        plan = self.replica(schemas=SYSTEM_SCHEMAS + "wordpress\nkeeltest\n")
        self.assertIn("--destroy-local-database", refusals(plan))
        self.assertIn("wordpress, keeltest", refusals(plan))
        self.assertEqual(
            only(plan["database.server.replication.primary"], RunSql), []
        )

    def test_a_refused_replica_leaves_the_server_as_it_was(self):
        # The Template B smoke test of 2026-09-30: the refusal said
        # nothing was changed after the configuration had been rewritten
        # and the server restarted. The check comes first now.
        plan = self.replica(schemas=SYSTEM_SCHEMAS + "wordpress\n")
        self.assertNotIn("database.server", plan)
        self.assertIn("left as it was", refusals(plan))

    def test_every_refusal_of_the_replica_comes_before_any_change(self):
        for plan in (
            self.replica(schemas=None),
            self.replica(credential=Credential(problem="no secret file")),
        ):
            self.assertEqual(
                list(plan), ["database.server.replication.primary"]
            )
            self.assertTrue(refusals(plan))

    def test_a_confirmed_replica_is_configured_and_then_replicates(self):
        plan = self.replica(
            schemas=SYSTEM_SCHEMAS + "wordpress\n", confirmed=True
        )
        self.assertEqual(
            list(plan),
            ["database.server", "database.server.replication.primary"],
        )
        self.assertTrue(only(plan["database.server"], WriteFile))

    def test_the_confirmation_drops_what_it_named_and_then_replicates(self):
        plan = self.replica(
            schemas=SYSTEM_SCHEMAS + "wordpress\n", confirmed=True
        )
        text = sql(plan["database.server.replication.primary"])
        self.assertIn("DROP DATABASE IF EXISTS `wordpress`", text)
        self.assertIn("CHANGE MASTER TO", text)
        note = only(
            plan["database.server.replication.primary"], Note
        )[0].summary
        self.assertIn("confirmed with --destroy-local-database", note)
        self.assertIn("wordpress", note)
        # A run that went ahead must not also say nothing was changed.
        self.assertNotIn("Nothing was changed", note)

    def test_a_server_that_cannot_say_what_it_holds_is_refused(self):
        plan = self.replica(schemas=None)
        self.assertIn("not knowing is not permission", refusals(plan))

    def test_not_knowing_is_refused_even_with_the_confirmation(self):
        # The confirmation says "drop what this server holds", and a
        # server that will not say what it holds cannot be dropped from.
        plan = self.replica(schemas=None, confirmed=True)
        self.assertIn("not knowing is not permission", refusals(plan))

    def test_a_replica_of_the_declared_primary_is_left_alone(self):
        plan = steps(
            declaring(
                role="replica",
                replication={"primary": {"host": "2001:db8:1::10"}},
            ),
            state(answered=dict(
                MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS
            )),
        )
        actions = plan["database.server.replication.primary"]
        self.assertEqual(only(actions, RunSql), [])
        self.assertIn("already replicating", only(actions, Note)[0].summary)

    def test_pointing_a_replica_at_another_primary_is_refused(self):
        plan = steps(
            declaring(
                role="replica",
                replication={"primary": {"host": "2001:db8:2::10"}},
            ),
            state(answered=dict(
                MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS
            )),
        )
        self.assertIn("replaces the local data", refusals(plan))

    def test_pointing_it_elsewhere_is_allowed_once_confirmed(self):
        plan = steps(
            declaring(
                role="replica",
                replication={"primary": {"host": "2001:db8:2::10"}},
            ),
            state(answered=dict(
                MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS
            )),
            True,
        )
        self.assertIn(
            "MASTER_HOST='2001:db8:2::10'",
            sql(plan["database.server.replication.primary"]),
        )

    def test_a_replica_with_no_credential_replicates_from_nowhere(self):
        plan = self.replica(credential=Credential(problem="no secret file"))
        self.assertIn("no secret file", refusals(plan))

    def test_the_declared_port_is_used_and_the_default_when_absent(self):
        with_port = steps(
            declaring(
                role="replica",
                replication={
                    "primary": {"host": PRIMARY_HOST, "port": 3307}
                },
            ),
            state(),
        )
        self.assertIn(
            "MASTER_PORT=3307",
            sql(with_port["database.server.replication.primary"]),
        )
        self.assertIn(
            "MASTER_PORT=3306",
            sql(self.replica()["database.server.replication.primary"]),
        )


class TestPromotionIsASeparateAct(unittest.TestCase):
    """apply never promotes and never demotes"""

    def observed_replica(self, declared: str):
        return steps(
            declaring(role=declared, replication={"allowed_from": [PREFIX]}),
            state(answered=dict(
                MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS
            )),
        )

    def observed_primary(self, declared: str, **replication):
        return steps(
            declaring(role=declared, replication=replication or {}),
            state(answered=dict(MARIADB_STANDALONE, grants=f"{PATTERN}\n")),
        )

    def test_a_declared_primary_on_a_replica_names_the_command(self):
        plan = self.observed_replica("primary")
        self.assertIn("keel database promote", refusals(plan))
        self.assertEqual(list(plan), ["database.server"])

    def test_a_declared_standalone_on_a_replica_is_refused_too(self):
        self.assertIn(
            "keel database promote", refusals(self.observed_replica(
                "standalone"
            ))
        )

    def test_a_declared_replica_on_a_primary_is_never_demoted(self):
        plan = self.observed_primary(
            "replica", primary={"host": PRIMARY_HOST}
        )
        self.assertIn("Demoting a primary destroys", refusals(plan))
        self.assertEqual(
            only(plan["database.server"], WriteFile), []
        )

    def test_a_declared_standalone_on_a_primary_is_never_demoted(self):
        self.assertIn(
            "Demoting a primary destroys",
            refusals(self.observed_primary("standalone")),
        )

    def test_a_primary_that_is_already_one_is_configured_normally(self):
        plan = self.observed_primary("primary", allowed_from=[PREFIX])
        self.assertIn("log_bin", written(plan["database.server"]))


class TestPromotion(unittest.TestCase):
    """Its own operation, and the one keel makes the operator type"""

    DOC = declaring(
        role="replica", replication={"primary": {"host": PRIMARY_HOST}},
    )

    def promote(self, observed, doc=None):
        return {
            step.field: step.actions
            for step in plan_promote(doc or self.DOC, observed)
        }

    def replicating(self, **kwargs):
        return state(
            answered=dict(MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS),
            **kwargs,
        )

    def test_a_replica_stops_replicating_and_forgets_the_primary(self):
        plan = self.promote(self.replicating())
        text = sql(plan["database.server.role"])
        self.assertIn("STOP SLAVE", text)
        self.assertIn("RESET SLAVE ALL", text)

    def test_it_says_what_the_description_now_disagrees_with(self):
        plan = self.promote(self.replicating())
        notes = " ".join(
            one.summary for one in only(plan["database.server.role"], Note)
        )
        self.assertIn("keel diff reports as drift", notes)
        self.assertIn("Change the description to primary", notes)

    def test_it_says_that_nothing_stopped_the_old_primary(self):
        plan = self.promote(self.replicating())
        notes = " ".join(
            one.summary for one in only(plan["database.server.role"], Note)
        )
        self.assertIn("There is no failover in Keel", notes)

    def test_a_standalone_is_not_promoted(self):
        plan = self.promote(state())
        self.assertIn("only a replica can be promoted", refusals(plan))
        self.assertEqual(only(plan["database.server.role"], RunSql), [])

    def test_a_primary_is_not_promoted_again(self):
        plan = self.promote(state(
            answered=dict(MARIADB_STANDALONE, grants=f"{PATTERN}\n")
        ))
        self.assertIn("only a replica can be promoted", refusals(plan))

    def test_a_description_with_no_server_has_no_role_to_promote(self):
        plan = self.promote(None, doc={})
        self.assertIn("declares no database.server", refusals(plan))

    def test_a_server_that_cannot_be_asked_is_not_promoted(self):
        plan = self.promote(state(problem="exited 1"))
        self.assertIn("never changed on a guess", refusals(plan))

    def test_an_offline_root_promotes_nothing(self):
        plan = self.promote(self.replicating(live=False))
        self.assertEqual(only(plan["database.server.role"], RunSql), [])
        self.assertIn(
            "not the live system",
            only(plan["database.server.role"], Note)[0].summary,
        )
