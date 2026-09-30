# Copyright (c) 2026 KeelLinux maintainers
"""The database phase of apply, one test per branch of the plan

The four properties of decision 0013 are each a class here: becoming a
replica destroys the local database, a primary holds authorizations,
promotion is a separate act, and no role is ever changed on a guess.
Every test builds a DatabaseState by hand, so nothing needs a server, a
container or root.
"""

import unittest
from dataclasses import replace

from helpers_database import mariadb_reading
from test_inspect_database import (
    MARIADB_REPLICA_STATUS,
    MARIADB_STANDALONE,
    SOCKETS,
)

from keel.inspect.dbreading import Value
from keel.inspect.tree import File
from keel.system import dbmariadb as mariadb
from keel.system import dbreadonly
from keel.system.actions import (
    LockReplica,
    Note,
    PromoteReplica,
    Refuse,
    Run,
    RunSql,
    SeedReplica,
    UnlockAccounts,
    WriteFile,
)
from keel.system.database import DRAIN_TIMEOUT, plan_database, plan_promote
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
    reach: str = "",
    shared: tuple = (),
    revoked: str | None = None,
) -> DatabaseState:
    """One machine's database, as the planner is given it"""
    answered = answered or MARIADB_STANDALONE
    return DatabaseState(
        engine=engine,
        live=live,
        binary=binary,
        reading=mariadb_reading(answered, SOCKETS, problem),
        schemas=_file("schemas", schemas),
        machine_id=_file("/etc/machine-id", machine_id),
        dropin=_file(mariadb.DROPIN, dropin),
        credential=credential or Credential(value=PASSWORD),
        status=File("SHOW REPLICA STATUS", answered.get("status", "")),
        reach=reach,
        shared=shared,
        revoked=_file(dbreadonly.RECORD, revoked),
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


def seeding(actions) -> SeedReplica:
    """The one seed of a replica step, which a test expects to be there"""
    found = only(actions, SeedReplica)
    if len(found) != 1:
        raise AssertionError(f"expected one seed, found {actions}")
    return found[0]


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


SHARED_ID = "0123456789abcdef0123456789abcdef"


def with_overlay(doc: dict, address: str, ipv4: str | None = None) -> dict:
    wireguard = {"address": address}
    if ipv4:
        wireguard["ipv4_address"] = ipv4
    return dict(doc, network={"overlay": {"wireguard": wireguard}})


class TestTheOverlayGivesTheServerIdItsIdentity(unittest.TestCase):
    """listen is "::" on every node, so it told two nodes apart only when
    a description named real addresses; the overlay address is unique to
    each node and stable, so it is what a server id is made from"""

    def test_a_node_without_an_overlay_keeps_the_server_id_it_had(self):
        # The values keel 0.11.3 derived; a change would restart every
        # server and give it a new identity for nothing.
        self.assertEqual(mariadb.server_id(SHARED_ID, ["::", "::1"]),
                         823627360)
        self.assertEqual(mariadb.server_id(SHARED_ID, None, ()),
                         380331519)

    def test_two_nodes_listening_on_the_wildcard_differ_by_overlay(self):
        first = mariadb.server_id(SHARED_ID, ["::"], ["fd3d:80b2:d0d7::1"])
        second = mariadb.server_id(SHARED_ID, ["::"], ["fd3d:80b2:d0d7::2"])
        self.assertNotEqual(first, second)

    def test_wildcard_and_loopback_entries_are_left_out(self):
        overlay = ["fd3d:80b2:d0d7::1"]
        bare = mariadb.server_id(SHARED_ID, None, overlay)
        for listen in (["::"], ["0.0.0.0", "*"], ["::1", "127.0.0.1"],
                       ["localhost", "127.0.1.1"]):
            self.assertEqual(
                mariadb.server_id(SHARED_ID, listen, overlay), bare, listen
            )

    def test_a_real_listen_address_still_counts(self):
        overlay = ["fd3d:80b2:d0d7::1"]
        for listen in (["2001:db8::5"], ["db.example.org"]):
            self.assertNotEqual(
                mariadb.server_id(SHARED_ID, listen, overlay),
                mariadb.server_id(SHARED_ID, None, overlay),
            )

    def test_the_plan_mixes_in_the_declared_overlay_address(self):
        doc = with_overlay(
            declaring(role="primary", listen=["::"]),
            "fd3d:80b2:d0d7::1/64", "10.77.0.1/24",
        )
        text = written(steps(doc, state())["database.server"])
        expected = mariadb.server_id(
            MACHINE_ID, ["::"], ["fd3d:80b2:d0d7::1", "10.77.0.1"]
        )
        self.assertIn(f"server_id = {expected}\n", text)

    def test_the_prefix_length_is_not_part_of_the_identity(self):
        self.assertEqual(
            mariadb.overlay_addresses(with_overlay({}, "fd3d::1/64")),
            ["fd3d::1"],
        )
        self.assertEqual(
            mariadb.overlay_addresses(with_overlay({}, "FD3D:0::1/48")),
            ["fd3d::1"],
        )

    def test_a_description_without_an_overlay_has_no_addresses(self):
        self.assertEqual(mariadb.overlay_addresses({}), [])
        self.assertEqual(
            mariadb.overlay_addresses({"network": {"overlay": None}}), []
        )
        self.assertEqual(
            mariadb.overlay_addresses(with_overlay({}, "not an address")),
            [],
        )


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


# The primary MARIADB_REPLICA_STATUS names, so a replicating state is a
# healthy replica of the declared primary.
REPLICA_DOC = declaring(
    role="replica", replication={"primary": {"host": "2001:db8:1::10"}},
)


def answering(read_only: str | None = None, replicating: bool = False,
              bypass: str = "") -> dict:
    """What the server answers, with read_only and the replica row"""
    variables = MARIADB_STANDALONE["variables"]
    if read_only is not None:
        variables += f"read_only\t{read_only}\n"
    answered = dict(MARIADB_STANDALONE, variables=variables, bypass=bypass)
    if replicating:
        answered["status"] = MARIADB_REPLICA_STATUS
    return answered


class TestAReplicaIsReadOnly(unittest.TestCase):
    """tracker#26: a writable replica took a WordPress write of its own,
    the primary's next write reused the id, and the SQL thread stopped
    with error 1062. The replication thread and root write through
    read_only; the application's account does not."""

    def test_a_replica_writes_read_only_into_its_configuration(self):
        plan = steps(REPLICA_DOC, state())
        self.assertIn("read_only = ON", written(plan["database.server"]))

    def test_read_only_is_on_before_the_copy_is_loaded(self):
        """The load runs as root, which holds READ_ONLY ADMIN, and the
        restart that turns read_only on comes before it: nothing the
        application does between the two can land in the copy"""
        plan = plan_database(REPLICA_DOC, state())
        fields = [step.field for step in plan]
        self.assertEqual(
            fields,
            ["database.server", "database.server.replication.primary",
             "database.server.read_only"],
        )
        self.assertIn("read_only = ON", written(plan[0].actions))
        seeding(plan[1].actions)

    def test_a_standalone_and_a_primary_are_writable(self):
        for role in ("standalone", "primary"):
            with self.subTest(role=role):
                plan = steps(declaring(role=role), state())
                self.assertNotIn("read_only", written(plan["database.server"]))

    def test_a_replica_turned_writable_by_hand_is_turned_back(self):
        text = written(steps(REPLICA_DOC, state())["database.server"])
        plan = steps(REPLICA_DOC, state(
            answered=answering("OFF", replicating=True), dropin=text,
        ))
        actions = plan["database.server"]
        self.assertEqual(only(actions, WriteFile), [])
        self.assertEqual(only(actions, Run), [])
        self.assertIn("SET GLOBAL read_only = ON", sql(actions))

    def test_a_read_only_standalone_is_made_writable_without_a_restart(self):
        """The way back to standalone after a promotion by hand"""
        doc = declaring(role="standalone")
        text = written(steps(doc, state())["database.server"])
        plan = steps(doc, state(answered=answering("ON"), dropin=text))
        self.assertIn("SET GLOBAL read_only = OFF",
                      sql(plan["database.server"]))

    def test_a_server_that_already_agrees_is_sent_nothing(self):
        text = written(steps(REPLICA_DOC, state())["database.server"])
        plan = steps(REPLICA_DOC, state(
            answered=answering("ON", replicating=True), dropin=text,
        ))
        self.assertEqual(only(plan["database.server"], RunSql), [])

    def test_a_server_that_names_no_read_only_is_not_sent_a_guess(self):
        text = written(steps(REPLICA_DOC, state())["database.server"])
        plan = steps(REPLICA_DOC, state(
            answered=answering(None, replicating=True), dropin=text,
        ))
        self.assertEqual(only(plan["database.server"], RunSql), [])

    def test_a_read_only_that_cannot_be_read_is_said(self):
        text = written(steps(REPLICA_DOC, state())["database.server"])
        plan = steps(REPLICA_DOC, state(
            answered=answering(None, replicating=True), dropin=text,
        ))
        notes = " ".join(
            one.summary for one in only(plan["database.server"], Note)
        )
        self.assertIn("names no read_only", notes)
        self.assertIn("was not set", notes)


READ_ONLY_STEP = "database.server.read_only"


class TestNoApplicationWritesThroughIt(unittest.TestCase):
    """READ_ONLY ADMIN is taken from the accounts that hold it on a
    replica, `admin` and Adminer's `adminer` among them, and given back
    when the node is no longer one"""

    def test_a_replica_with_accounts_that_bypass_it_takes_it_away(self):
        plan = steps(REPLICA_DOC, state(answered=answering(
            "ON", replicating=True,
            bypass="'root'@'localhost'\n'admin'@'localhost'\n",
        )))
        lock = only(plan[READ_ONLY_STEP], LockReplica)[0]
        self.assertEqual(lock.accounts, ("'admin'@'localhost'",))

    def test_it_comes_after_the_seed_which_copies_the_primarys_grants(self):
        plan = plan_database(REPLICA_DOC, state(answered=answering(
            "OFF", bypass="'admin'@'localhost'\n",
        )))
        self.assertEqual([step.field for step in plan][-1], READ_ONLY_STEP)
        seeding(plan[1].actions)
        self.assertTrue(only(plan[2].actions, LockReplica))

    def test_a_seed_is_always_followed_by_it(self):
        """The copy brings the primary's grants, READ_ONLY ADMIN too"""
        plan = steps(REPLICA_DOC, state())
        self.assertTrue(only(plan[READ_ONLY_STEP], LockReplica))

    def test_a_replica_where_nobody_bypasses_it_is_unchanged(self):
        plan = steps(REPLICA_DOC, state(answered=answering(
            "ON", replicating=True, bypass="'root'@'localhost'\n",
        )))
        self.assertEqual(only(plan[READ_ONLY_STEP], LockReplica), [])
        self.assertIn("unchanged",
                      only(plan[READ_ONLY_STEP], Note)[0].summary)

    def test_accounts_that_cannot_be_listed_are_said(self):
        observed = state(answered=answering("ON", replicating=True))
        observed = replace(observed, reading=replace(
            observed.reading, bypass=Value(problem="bypass exited 1"),
        ))
        plan = steps(REPLICA_DOC, observed)
        self.assertIn("could not be listed",
                      only(plan[READ_ONLY_STEP], Note)[0].summary)

    def test_a_standalone_gives_back_what_a_replica_took(self):
        plan = steps(declaring(role="standalone"), state(
            revoked="admin\tlocalhost\n",
        ))
        self.assertTrue(only(plan[READ_ONLY_STEP], UnlockAccounts))

    def test_a_primary_gives_it_back_as_well(self):
        plan = steps(declaring(role="primary"), state(
            revoked="admin\tlocalhost\n",
        ))
        self.assertTrue(only(plan[READ_ONLY_STEP], UnlockAccounts))

    def test_nothing_taken_is_nothing_given_back(self):
        plan = steps(declaring(role="standalone"), state())
        self.assertNotIn(READ_ONLY_STEP, plan)


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
        self.assertIn("GRANT REPLICATION SLAVE", text)

    def test_the_grant_lets_a_new_replica_copy_what_is_already_here(self):
        # A replica is seeded with mariadb-dump over the network, as the
        # same account: without these it copies nothing and says so.
        plan = steps(
            declaring(
                role="primary", replication={"allowed_from": [PREFIX]}
            ),
            state(),
        )
        text = sql(plan["database.server.replication.allowed_from"])
        self.assertIn(
            "GRANT REPLICATION SLAVE, SELECT, SHOW VIEW, TRIGGER, EVENT"
            f" ON *.* TO 'repl'@'{PATTERN}'",
            text,
        )

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

    def test_an_account_at_an_expanded_address_is_replaced(self):
        # keel 0.11.0 granted an address as written. canonical() makes the
        # expanded and the compressed spelling one origin, so comparing on
        # it kept the dead account beside the new one; the text decides.
        plan = steps(
            declaring(
                role="primary",
                replication={"allowed_from": ["fd3d:80b2:d0d7::2"]},
            ),
            state(answered=dict(
                MARIADB_STANDALONE,
                grants=f"fd3d:80b2:d0d7:0:0:0:0:2\n{PATTERN}\n",
            )),
        )
        text = sql(plan["database.server.replication.allowed_from"])
        self.assertIn(
            "DROP USER IF EXISTS 'repl'@'fd3d:80b2:d0d7:0:0:0:0:2'", text
        )
        self.assertIn(f"DROP USER IF EXISTS 'repl'@'{PATTERN}'", text)
        self.assertIn("'repl'@'fd3d:80b2:d0d7::2'", text)

    def test_an_account_held_in_another_case_is_kept(self):
        plan = steps(
            declaring(
                role="primary",
                replication={"allowed_from": ["fd3d:80b2:d0d7::2", PREFIX]},
            ),
            state(answered=dict(
                MARIADB_STANDALONE,
                grants=f"FD3D:80B2:D0D7::2\n{PATTERN}\n",
            )),
        )
        text = sql(plan["database.server.replication.allowed_from"])
        self.assertNotIn("DROP USER", text)

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

    def test_an_empty_server_is_seeded_from_its_primary(self):
        # Replicating from an empty gtid_slave_pos copied only what the
        # primary wrote afterwards, and the first UPDATE of an older
        # WordPress row stopped the SQL thread. The copy comes first now.
        actions = self.replica()["database.server.replication.primary"]
        seed = seeding(actions)
        self.assertEqual((seed.host, seed.port), (PRIMARY_HOST, 3306))
        self.assertEqual(seed.drop, ())
        self.assertEqual(seed.password, PASSWORD)
        self.assertEqual(only(actions, RunSql), [])

    def test_a_server_holding_data_is_refused_by_default(self):
        plan = self.replica(schemas=SYSTEM_SCHEMAS + "wordpress\nkeeltest\n")
        self.assertIn("--destroy-local-database", refusals(plan))
        self.assertIn("wordpress, keeltest", refusals(plan))
        self.assertEqual(
            only(plan["database.server.replication.primary"], SeedReplica),
            [],
        )

    def test_the_accounts_both_nodes_hold_are_named_before_the_seed(self):
        plan = self.replica(shared=("'wordpress'@'localhost'",))
        actions = plan["database.server.replication.primary"]
        note = only(actions, Note)[0].summary
        self.assertIn("'wordpress'@'localhost'", note)
        self.assertIn("ALTER USER", note)
        self.assertIn("application", note)
        self.assertLess(actions.index(only(actions, Note)[0]),
                        actions.index(seeding(actions)))

    def test_no_shared_account_needs_no_note(self):
        actions = self.replica()["database.server.replication.primary"]
        self.assertEqual(only(actions, Note), [])

    def test_an_unreachable_primary_is_refused_before_any_change(self):
        for confirmed in (False, True):
            plan = self.replica(
                schemas=SYSTEM_SCHEMAS + "wordpress\n",
                reach="the primary did not answer",
                confirmed=confirmed,
            )
            self.assertEqual(
                list(plan), ["database.server.replication.primary"]
            )
            self.assertIn("the primary did not answer", refusals(plan))
            self.assertIn("nothing was dropped", refusals(plan))
            self.assertEqual(
                only(plan["database.server.replication.primary"],
                     SeedReplica),
                [],
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
            ["database.server", "database.server.replication.primary",
             "database.server.read_only"],
        )
        self.assertTrue(only(plan["database.server"], WriteFile))

    def test_the_confirmation_drops_what_it_named_and_then_replicates(self):
        plan = self.replica(
            schemas=SYSTEM_SCHEMAS + "wordpress\n", confirmed=True
        )
        seed = seeding(plan["database.server.replication.primary"])
        self.assertEqual(seed.drop, ("wordpress",))
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
        self.assertEqual(
            seeding(plan["database.server.replication.primary"]).host,
            "2001:db8:2::10",
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
        self.assertEqual(
            seeding(with_port["database.server.replication.primary"]).port,
            3307,
        )
        self.assertEqual(
            seeding(self.replica()["database.server.replication.primary"])
            .port,
            3306,
        )


STOPPED_STATUS = MARIADB_REPLICA_STATUS.replace(
    "Slave_SQL_Running: Yes",
    "Slave_SQL_Running: No\n"
    "                Last_SQL_Error: Could not execute Update_rows_v1"
    " event on table wordpress.wp_posts; Can't find record in 'wp_posts'",
)


class TestAReplicaThatStoppedIsReseededOnlyOnRequest(unittest.TestCase):
    """A replica built empty by 0.11.1 halts on its first UPDATE"""

    def plan(self, status: str, confirmed: bool = False):
        return steps(
            declaring(
                role="replica",
                replication={"primary": {"host": "2001:db8:1::10"}},
            ),
            state(
                answered=dict(MARIADB_STANDALONE, status=status),
                schemas=SYSTEM_SCHEMAS + "wordpress\n",
            ),
            confirmed,
        )

    def test_a_healthy_replica_is_never_seeded_again(self):
        for confirmed in (False, True):
            actions = self.plan(MARIADB_REPLICA_STATUS, confirmed)[
                "database.server.replication.primary"
            ]
            self.assertEqual(only(actions, SeedReplica), [])
            self.assertIn("already replicating",
                          only(actions, Note)[0].summary)

    def test_a_stopped_sql_thread_is_refused_with_its_error(self):
        plan = self.plan(STOPPED_STATUS)
        refused = refusals(plan)
        self.assertIn("Can't find record in 'wp_posts'", refused)
        self.assertIn("--destroy-local-database", refused)
        self.assertEqual(
            only(plan["database.server.replication.primary"], SeedReplica),
            [],
        )

    def test_a_stopped_sql_thread_is_reseeded_once_confirmed(self):
        plan = self.plan(STOPPED_STATUS, confirmed=True)
        seed = seeding(plan["database.server.replication.primary"])
        self.assertEqual(seed.host, "2001:db8:1::10")
        self.assertEqual(seed.drop, ("wordpress",))

    def test_a_status_that_does_not_say_is_left_alone(self):
        status = MARIADB_REPLICA_STATUS.replace(
            "            Slave_SQL_Running: Yes\n", ""
        )
        actions = self.plan(status)["database.server.replication.primary"]
        self.assertIn("already replicating", only(actions, Note)[0].summary)


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

    def test_a_replica_drains_then_is_promoted(self):
        """keel.system.dbreadonly stops the I/O thread, waits for the
        SQL thread, then forgets the primary and turns read_only off"""
        plan = self.promote(self.replicating())
        promotion = only(plan["database.server.role"], PromoteReplica)
        self.assertEqual(len(promotion), 1)
        self.assertEqual(promotion[0].timeout, DRAIN_TIMEOUT)
        self.assertEqual(only(plan["database.server.role"], RunSql), [])

    def test_a_stopped_sql_thread_is_refused_and_says_what_to_do(self):
        stopped = MARIADB_REPLICA_STATUS.replace(
            "Slave_SQL_Running: Yes",
            "Slave_SQL_Running: No\n  Last_SQL_Error: Error 1062",
        )
        plan = self.promote(state(
            answered=dict(MARIADB_STANDALONE, status=stopped),
        ))
        text = refusals(plan)
        self.assertIn("Error 1062", text)
        self.assertIn("START SLAVE", text)
        self.assertIn("--destroy-local-database", text)
        self.assertEqual(only(plan["database.server.role"], PromoteReplica),
                         [])

    def test_it_keeps_the_primary_writable_across_a_restart(self):
        """The file apply wrote for the replica says read_only = ON, and
        a restart before the description is changed must not bring it
        back: the file loses that line, and nothing restarts now"""
        dropin = written(steps(self.DOC, state())["database.server"])
        plan = self.promote(self.replicating(dropin=dropin))
        actions = plan["database.server.role"]
        rewritten = written(actions)
        self.assertNotIn("read_only", rewritten)
        self.assertIn("server_id = ", rewritten)
        self.assertEqual(only(actions, Run), [])

    def test_a_file_without_the_line_is_not_rewritten(self):
        plan = self.promote(self.replicating(dropin="[mysqld]\n"))
        self.assertEqual(only(plan["database.server.role"], WriteFile), [])

    def test_no_file_is_not_created(self):
        plan = self.promote(self.replicating(dropin=None))
        self.assertEqual(only(plan["database.server.role"], WriteFile), [])

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
