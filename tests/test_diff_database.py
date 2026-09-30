# Copyright (c) 2026 KeelLinux maintainers
"""What diff does with each field of the database section

The section is compared like every other observed section, with three rules
of its own: a field only the declared role has any use for is not compared,
origins and listen addresses compare as sets and never resolve a name, and
the one drift that can destroy data if it is acted on the wrong way round
carries the warning saying so.
"""

import unittest

from helpers_database import answers

from keel.diff import DRIFT, NOT_COMPARED, SAME, UNKNOWN, compare  # noqa
from keel.diff.compare import ROLE_FIELD  # noqa: E402
from keel.inspect.database import probe_database  # noqa: E402
from keel.inspect.dbengines import ENGINES  # noqa: E402
from keel.inspect.database import Installed  # noqa: E402
from keel.inspect.report import Inspection  # noqa: E402
from keel.inspect.tree import File  # noqa: E402
from test_inspect_database import (  # noqa: E402
    MARIADB_REPLICA_STATUS,
    MARIADB_STANDALONE,
    SOCKETS,
)


def observe(answered: dict, engine_name: str = "mariadb") -> Inspection:
    """An Inspection holding nothing but one machine's database section"""
    engine = next(one for one in ENGINES if one.name == engine_name)
    installed = Installed(
        engine, f"/usr/sbin/{engine_name}d",
        answers(engine, answered), File("ss -lntH", SOCKETS),
    )
    section, findings = probe_database((installed,), ())
    return Inspection("/", "test", {"database": section}, tuple(findings))


def verdicts(declared: dict, inspection: Inspection) -> dict[str, str]:
    return {
        field.field: field.status
        for field in compare(declared, inspection).fields
    }


def line(declared: dict, inspection: Inspection, path: str) -> str:
    return next(
        field.line() for field in compare(declared, inspection).fields
        if field.field == path
    )


def declaring(**server) -> dict:
    return {"database": {"server": {"engine": "mariadb", **server}}}


class TestRole(unittest.TestCase):
    def test_a_standalone_that_is_one_is_the_same(self):
        found = verdicts(declaring(role="standalone"), observe(
            MARIADB_STANDALONE
        ))
        self.assertEqual(found[ROLE_FIELD], SAME)

    def test_a_declared_replica_on_a_standalone_is_drift(self):
        found = verdicts(
            declaring(
                role="replica",
                replication={"primary": {"host": "2001:db8:1::10"}},
            ),
            observe(MARIADB_STANDALONE),
        )
        self.assertEqual(found[ROLE_FIELD], DRIFT)

    def test_a_role_that_could_not_be_read_is_unknown_and_never_drift(self):
        answered = dict(MARIADB_STANDALONE, variables="wsrep_on\tON\n")
        found = verdicts(declaring(role="primary"), observe(answered))
        self.assertEqual(found[ROLE_FIELD], UNKNOWN)
        self.assertEqual(found["database.server.engine"], UNKNOWN)

    def test_the_engine_is_compared(self):
        found = verdicts(
            {"database": {"server": {
                "engine": "postgresql", "role": "standalone",
            }}},
            observe(MARIADB_STANDALONE),
        )
        self.assertEqual(found["database.server.engine"], DRIFT)


class TestNeverCorrected(unittest.TestCase):
    """Demoting a primary destroys data, so the line says not to"""

    def primary(self) -> Inspection:
        return observe(dict(MARIADB_STANDALONE, grants="2001:db8:1::/64\n"))

    def test_a_declared_replica_against_an_observed_primary_warns(self):
        declared = declaring(
            role="replica",
            replication={"primary": {"host": "2001:db8:1::10"}},
        )
        text = line(declared, self.primary(), ROLE_FIELD)
        self.assertIn("drift (declared replica, observed primary", text)
        self.assertIn("never correct this automatically", text)
        self.assertIn("demoting one destroys the data", text)

    def test_a_declared_primary_against_an_observed_replica_warns(self):
        answered = dict(MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS)
        declared = declaring(
            role="primary",
            replication={"allowed_from": ["2001:db8:1::/64"]},
        )
        text = line(declared, observe(answered), ROLE_FIELD)
        self.assertIn("never correct this automatically", text)
        self.assertIn("Promotion is an operator action", text)

    def test_the_warning_reaches_a_calling_program(self):
        declared = declaring(
            role="replica",
            replication={"primary": {"host": "2001:db8:1::10"}},
        )
        field = next(
            one for one in compare(declared, self.primary()).fields
            if one.field == ROLE_FIELD
        )
        self.assertIn("demoting one destroys", field.note)

    def test_ordinary_drift_carries_no_warning(self):
        declared = declaring(role="standalone", listen=["2001:db8::1"])
        field = next(
            one for one in compare(declared, observe(MARIADB_STANDALONE))
            .fields if one.field == "database.server.listen"
        )
        self.assertEqual(field.status, DRIFT)
        self.assertEqual(field.note, "")


class TestFieldsOfAnotherRole(unittest.TestCase):
    def test_a_standalone_may_carry_the_authorizations_of_a_promotion(self):
        declared = declaring(
            role="standalone",
            replication={"allowed_from": ["2001:db8:1::/64"]},
        )
        found = verdicts(declared, observe(MARIADB_STANDALONE))
        self.assertEqual(
            found["database.server.replication.allowed_from"], NOT_COMPARED
        )
        self.assertEqual(found[ROLE_FIELD], SAME)

    def test_the_reason_names_the_role_that_would_compare_it(self):
        declared = declaring(
            role="standalone",
            replication={"allowed_from": ["2001:db8:1::/64"]},
        )
        text = line(
            declared, observe(MARIADB_STANDALONE),
            "database.server.replication.allowed_from",
        )
        self.assertIn("the declared role is standalone", text)
        self.assertIn("compared when the role is primary", text)

    def test_a_primary_may_carry_the_endpoint_of_a_demotion(self):
        declared = declaring(
            role="primary",
            replication={
                "allowed_from": ["2001:db8:1:5::/64"],
                "primary": {"host": "2001:db8:1::10"},
            },
        )
        found = verdicts(
            declared,
            observe(dict(MARIADB_STANDALONE, grants="2001:db8:1:5:%\n")),
        )
        self.assertEqual(
            found["database.server.replication.primary.host"], NOT_COMPARED
        )
        self.assertEqual(
            found["database.server.replication.allowed_from"], SAME
        )

    def test_a_field_of_the_declared_role_on_a_machine_in_another_is_unknown(
        self,
    ):
        """The role line is the drift; the field it governs is not read"""
        declared = declaring(
            role="primary",
            replication={"allowed_from": ["2001:db8:1::/64"]},
        )
        answered = dict(MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS)
        found = verdicts(declared, observe(answered))
        self.assertEqual(found[ROLE_FIELD], DRIFT)
        self.assertEqual(
            found["database.server.replication.allowed_from"], UNKNOWN
        )

    def test_a_description_with_no_role_compares_nothing_of_the_role(self):
        declared = {"database": {"server": {"engine": "mariadb"}}}
        found = verdicts(declared, observe(MARIADB_STANDALONE))
        self.assertEqual(found["database.server.engine"], SAME)


class TestNormalisation(unittest.TestCase):
    def test_listen_addresses_compare_as_a_set_in_canonical_form(self):
        declared = declaring(
            role="standalone", listen=["0:0:0:0:0:0:0:1", "127.0.0.1"]
        )
        found = verdicts(declared, observe(MARIADB_STANDALONE))
        self.assertEqual(found["database.server.listen"], SAME)

    def test_a_missing_listen_address_is_drift(self):
        declared = declaring(role="standalone", listen=["::1"])
        found = verdicts(declared, observe(MARIADB_STANDALONE))
        self.assertEqual(found["database.server.listen"], DRIFT)

    def test_origins_compare_as_a_set_in_canonical_form(self):
        declared = declaring(
            role="primary",
            replication={"allowed_from": [
                "2001:0DB8:0002:0005::/64", "2001:db8:1:5::/64",
            ]},
        )
        # Grants MariaDB matches: a host written as a /64 matches nothing
        # there, and inspect reports it as not inferred (keel 0.11.1).
        observed = observe(dict(
            MARIADB_STANDALONE, grants="2001:db8:1:5:%\n2001:db8:2:5:%\n"
        ))
        found = verdicts(declared, observed)
        self.assertEqual(
            found["database.server.replication.allowed_from"], SAME
        )

    def test_the_prefix_and_the_pattern_mariadb_holds_are_one_origin(self):
        """The preferred form against the only spelling MariaDB has

        docs/spec.md tells an operator to write the prefix and says the
        server can only hold `2804:710:d0:5:%`. If the two were drift, the
        preferred form would report drift on every MariaDB primary, which
        would make it unusable.
        """
        declared = declaring(
            role="primary",
            replication={"allowed_from": ["2804:710:d0:5::/64"]},
        )
        observed = observe(
            dict(MARIADB_STANDALONE, grants="2804:710:d0:5:%\n")
        )
        found = verdicts(declared, observed)
        self.assertEqual(
            found["database.server.replication.allowed_from"], SAME
        )

    def test_a_pattern_for_a_wider_prefix_is_still_drift(self):
        declared = declaring(
            role="primary",
            replication={"allowed_from": ["2804:710:d0:5::/64"]},
        )
        observed = observe(
            dict(MARIADB_STANDALONE, grants="2804:710:d0:%\n")
        )
        found = verdicts(declared, observed)
        self.assertEqual(
            found["database.server.replication.allowed_from"], DRIFT
        )

    def test_a_name_is_never_resolved_and_an_address_is_not_that_name(self):
        declared = declaring(
            role="primary",
            replication={"allowed_from": ["replica.example.org"]},
        )
        observed = observe(
            dict(MARIADB_STANDALONE, grants="2001:db8:1::20\n")
        )
        found = verdicts(declared, observed)
        self.assertEqual(
            found["database.server.replication.allowed_from"], DRIFT
        )

    def test_a_name_that_the_server_still_holds_is_the_same(self):
        declared = declaring(
            role="primary",
            replication={"allowed_from": ["Replica.Example.org."]},
        )
        observed = observe(
            dict(MARIADB_STANDALONE, grants="replica.example.org\n")
        )
        found = verdicts(declared, observed)
        self.assertEqual(
            found["database.server.replication.allowed_from"], SAME
        )

    def test_a_primary_endpoint_compares_as_an_address(self):
        declared = declaring(
            role="replica",
            replication={"primary": {
                "host": "2001:0db8:0001:0000::10", "port": 3306,
            }},
        )
        answered = dict(MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS)
        found = verdicts(declared, observe(answered))
        self.assertEqual(
            found["database.server.replication.primary.host"], SAME
        )
        self.assertEqual(
            found["database.server.replication.primary.port"], SAME
        )


class TestClientSide(unittest.TestCase):
    def client(self, **primary) -> dict:
        return {"database": {"client": {
            "engine": "mariadb", "primary": primary,
        }}}

    def observed(self) -> Inspection:
        section = {"client": {
            "engine": "mariadb",
            "primary": {"host": "::1", "port": 3306, "name": "wordpress"},
        }}
        return Inspection("/", "test", {"database": section}, ())

    def test_the_endpoint_is_compared_field_by_field(self):
        found = verdicts(
            self.client(host="0:0:0:0:0:0:0:1", port=3306, name="wordpress"),
            self.observed(),
        )
        self.assertEqual(found["database.client.primary.host"], SAME)
        self.assertEqual(found["database.client.primary.port"], SAME)
        self.assertEqual(found["database.client.primary.name"], SAME)

    def test_an_endpoint_that_moved_is_drift(self):
        found = verdicts(
            self.client(host="2001:db8:1::10"), self.observed()
        )
        self.assertEqual(found["database.client.primary.host"], DRIFT)

    def test_the_client_credential_is_never_compared(self):
        declared = self.client(
            host="::1", secret={"file": "/etc/keel/secrets/db_password"}
        )
        found = verdicts(declared, self.observed())
        self.assertEqual(
            found["database.client.primary.secret.file"], NOT_COMPARED
        )


class TestSecretsAreNeverCompared(unittest.TestCase):
    def test_the_replication_credential_is_never_compared(self):
        declared = declaring(
            role="primary",
            replication={"secret": {"file": "/etc/keel/secrets/repl"}},
        )
        found = verdicts(
            declared,
            observe(dict(MARIADB_STANDALONE, grants="2001:db8:1::/64\n")),
        )
        self.assertEqual(
            found["database.server.replication.secret.file"], NOT_COMPARED
        )
