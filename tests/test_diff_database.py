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


READ_ONLY = "database.server.read_only"
REPLICA = declaring(
    role="replica", replication={"primary": {"host": "2001:db8:1::10"}},
)


def variables(read_only: str) -> str:
    return MARIADB_STANDALONE["variables"] + f"read_only\t{read_only}\n"


def replica(read_only: str) -> Inspection:
    return observe(dict(
        MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS,
        variables=variables(read_only),
    ))


def standalone(read_only: str) -> Inspection:
    return observe(dict(MARIADB_STANDALONE, variables=variables(read_only)))


class TestReadOnly(unittest.TestCase):
    """read_only follows the role the server has, never a field of its own

    Decision 0020: what depends on the role follows the role the machine
    holds. So a replica promoted by hand is compared as the primary it is,
    and the role line alone reports what the description disagrees with.
    """

    def test_a_read_only_replica_is_the_same(self):
        found = verdicts(REPLICA, replica("ON"))
        self.assertEqual(found[READ_ONLY], SAME)

    def test_a_writable_replica_is_drift_and_says_what_it_costs(self):
        text = line(REPLICA, replica("OFF"), READ_ONLY)
        self.assertIn("drift (declared true, observed false", text)
        self.assertIn("stops replication", text)
        self.assertIn("keel spec apply", text)

    def test_a_writable_standalone_is_the_same(self):
        found = verdicts(declaring(role="standalone"), standalone("OFF"))
        self.assertEqual(found[READ_ONLY], SAME)

    def test_a_read_only_standalone_is_drift(self):
        text = line(declaring(role="standalone"), standalone("ON"), READ_ONLY)
        self.assertIn("drift (declared false, observed true", text)
        self.assertIn("refuses the application's writes", text)

    def test_a_promoted_replica_is_compared_as_the_primary_it_is(self):
        found = verdicts(REPLICA, standalone("OFF"))
        self.assertEqual(found[ROLE_FIELD], DRIFT)
        self.assertEqual(found[READ_ONLY], SAME)

    def test_a_read_only_that_could_not_be_read_is_unknown(self):
        found = verdicts(REPLICA, observe(dict(
            MARIADB_STANDALONE, status=MARIADB_REPLICA_STATUS,
        )))
        self.assertEqual(found[READ_ONLY], UNKNOWN)

    def test_a_description_with_no_role_compares_nothing_of_it(self):
        found = verdicts({"database": {"server": {"engine": "mariadb"}}},
                         replica("OFF"))
        self.assertNotIn(READ_ONLY, found)

    def test_a_machine_reporting_nothing_about_it_compares_nothing(self):
        inspection = Inspection("/", "test", {}, ())
        found = verdicts(REPLICA, inspection)
        self.assertNotIn(READ_ONLY, found)

    def test_it_comes_right_after_the_database_section(self):
        fields = [one.field for one in compare(REPLICA, replica("ON")).fields]
        database = [n for n, one in enumerate(fields)
                    if one.startswith("database.")]
        self.assertEqual(fields.index(READ_ONLY), max(database))


SEMI_SYNC = "database.server.semi_sync"

# A primary on a pair with log_bin ON: semi_sync is compared only here
PAIRED_VARIABLES = (
    "log_bin\tON\nport\t3306\nserver_id\t7\nwsrep_on\tOFF\nread_only\tOFF\n"
)
PAIR_VIP = "fd00:6b65:1::ffff:100"
PAIRED_DECLARED = {
    "appliance": {"name": "core", "vip": PAIR_VIP},
    "database": {"server": {
        "engine": "mariadb", "role": "primary",
        "listen": ["::1", "127.0.0.1"],
        "replication": {"allowed_from": ["fd00:6b65:1::/64"]},
    }},
}


def semisync_answered(master: str, clients: str) -> dict:
    """MARIADB_STANDALONE with semi_sync status variables spliced in"""
    return dict(
        MARIADB_STANDALONE,
        variables=PAIRED_VARIABLES,
        grants="fd00:6b65:1:%\nlocalhost\n",
        semisync=(
            f"Rpl_semi_sync_master_status\t{master}\n"
            f"Rpl_semi_sync_slave_status\tOFF\n"
            f"Rpl_semi_sync_master_clients\t{clients}\n"
            f"Rpl_semi_sync_master_yes_tx\t100\n"
            f"Rpl_semi_sync_master_no_tx\t5\n"
        ),
    )


def paired_inspection(answered: dict, role: str = "primary") -> Inspection:
    engine = next(one for one in ENGINES if one.name == "mariadb")
    installed = Installed(
        engine, "/usr/sbin/mariadbd",
        answers(engine, answered), File("ss -lntH", SOCKETS),
    )
    section, findings = probe_database((installed,), ())
    return Inspection("/", "test", {"database": section}, tuple(findings),
                      role=role)


class TestSemiSync(unittest.TestCase):
    """keel#107: semi_sync must check whether a replica is connected,
    not just the setting"""

    def test_on_with_one_replica_is_same(self):
        inspection = paired_inspection(semisync_answered("ON", "1"))
        found = verdicts(PAIRED_DECLARED, inspection)
        self.assertEqual(found[SEMI_SYNC], SAME)

    def test_on_with_no_replica_is_drift(self):
        """The setting is on but no replica is connected: the primary
        commits without waiting, which is the bug keel#107 reports"""
        inspection = paired_inspection(semisync_answered("ON", "0"))
        found = verdicts(PAIRED_DECLARED, inspection)
        self.assertEqual(found[SEMI_SYNC], DRIFT)

    def test_on_with_no_replica_carries_a_note(self):
        inspection = paired_inspection(semisync_answered("ON", "0"))
        text = line(PAIRED_DECLARED, inspection, SEMI_SYNC)
        self.assertIn("no replica", text.lower())
        self.assertNotIn("fell back", text)

    def test_off_with_no_replica_is_drift_with_fallback_note(self):
        inspection = paired_inspection(semisync_answered("OFF", "0"))
        found = verdicts(PAIRED_DECLARED, inspection)
        self.assertEqual(found[SEMI_SYNC], DRIFT)
        text = line(PAIRED_DECLARED, inspection, SEMI_SYNC)
        self.assertIn("fell back", text)

    def test_on_with_two_replicas_is_same(self):
        inspection = paired_inspection(semisync_answered("ON", "2"))
        found = verdicts(PAIRED_DECLARED, inspection)
        self.assertEqual(found[SEMI_SYNC], SAME)

    def test_on_with_unknown_clients_is_not_same(self):
        """A clients count the probe could not read is not healthy"""
        answered = dict(
            MARIADB_STANDALONE,
            variables=PAIRED_VARIABLES,
            grants="fd00:6b65:1:%\nlocalhost\n",
            semisync=(
                "Rpl_semi_sync_master_status\tON\n"
                "Rpl_semi_sync_slave_status\tOFF\n"
                "Rpl_semi_sync_master_yes_tx\t100\n"
                "Rpl_semi_sync_master_no_tx\t5\n"
            ),
        )
        inspection = paired_inspection(answered)
        found = verdicts(PAIRED_DECLARED, inspection)
        self.assertNotEqual(found[SEMI_SYNC], SAME)

    def test_on_the_replica_semi_sync_is_not_compared(self):
        inspection = paired_inspection(
            semisync_answered("ON", "0"), role="replica")
        found = verdicts(PAIRED_DECLARED, inspection)
        self.assertEqual(found[SEMI_SYNC], NOT_COMPARED)


class TestPairListen(unittest.TestCase):
    """keel#233: the VIP and the overlay are implicitly bound, so they
    are never drift when the spec did not declare them in listen"""

    VIP = "fd00:6b65:1::ffff:100"
    OVERLAY = "fd00:6b65:1::1"
    LISTEN = "database.server.listen"

    def paired_declared(self, listen):
        return {
            "appliance": {"name": "core", "vip": self.VIP},
            "network": {"overlay": {"wireguard": {
                "address": f"{self.OVERLAY}/64"}}},
            "database": {"server": {
                "engine": "mariadb", "role": "primary",
                "listen": listen}},
        }

    def test_the_overlay_and_vip_are_not_drift(self):
        from keel.diff.compare import LISTEN_FIELD, pair_listen
        from keel.diff.report import DRIFT, SAME, FieldDiff
        declared = self.paired_declared(["::1", "127.0.0.1"])
        field = FieldDiff(
            LISTEN_FIELD, DRIFT,
            declared=["::1", "127.0.0.1"],
            observed=["::1", "127.0.0.1", self.OVERLAY, self.VIP])
        result = pair_listen([field], declared)
        self.assertEqual(result[0].status, SAME)

    def test_a_declared_overlay_stays_in_the_comparison(self):
        from keel.diff.compare import LISTEN_FIELD, pair_listen
        from keel.diff.report import SAME, FieldDiff
        declared = self.paired_declared([self.OVERLAY, "::1"])
        field = FieldDiff(
            LISTEN_FIELD, "drift",
            declared=[self.OVERLAY, "::1"],
            observed=[self.OVERLAY, "::1", self.VIP])
        result = pair_listen([field], declared)
        self.assertEqual(result[0].status, SAME)


# --- keel#110: socket annotation on listen drift -------------------------

class TestListenSocketNote(unittest.TestCase):
    """When database.server.listen drifts and a socket is active, the
    FieldDiff carries a note naming the socket and the remedy"""

    def _note(self, fields, declared, units_dict):
        from unittest.mock import patch
        from keel.diff.observe import _listen_socket_note
        with patch("keel.diff.observe.read_units", return_value=units_dict):
            return _listen_socket_note(fields, declared, "/not-live")

    @staticmethod
    def _unit(name, enabled="enabled", active="active"):
        from keel.inspect.units import UnitState
        return UnitState(unit=name, enabled=enabled, active=active)

    @staticmethod
    def _drift_field(field="database.server.listen", note=""):
        from keel.diff.compare import LISTEN_FIELD
        from keel.diff.report import DRIFT, FieldDiff
        return FieldDiff(LISTEN_FIELD, DRIFT,
                         declared=["::1"], observed=["::"],
                         note=note)

    def test_active_socket_annotates_drift(self):
        declared = {"database": {"server": {"engine": "mariadb"}}}
        drift = self._drift_field()
        unit = self._unit("mariadb.socket")
        result = self._note((drift,), declared, {"mariadb.socket": unit})
        self.assertIn("mariadb.socket", result[0].note)
        self.assertIn("socket activation", result[0].note)
        self.assertIn("keel spec apply --system", result[0].note)

    def test_masked_socket_does_not_annotate(self):
        declared = {"database": {"server": {"engine": "mariadb"}}}
        drift = self._drift_field()
        unit = self._unit("mariadb.socket", enabled="masked",
                          active="inactive")
        result = self._note((drift,), declared, {"mariadb.socket": unit})
        self.assertEqual(result[0].note, "")

    def test_no_drift_leaves_fields_unchanged(self):
        from keel.diff.compare import LISTEN_FIELD
        from keel.diff.report import SAME, FieldDiff
        declared = {"database": {"server": {"engine": "mariadb"}}}
        same = FieldDiff(LISTEN_FIELD, SAME,
                         declared=["::1"], observed=["::1"])
        result = self._note((same,), declared, {})
        self.assertEqual(result[0].status, SAME)
        self.assertEqual(result[0].note, "")

    def test_non_mariadb_engine_skips_annotation(self):
        declared = {"database": {"server": {"engine": "postgresql"}}}
        drift = self._drift_field()
        result = self._note((drift,), declared, {})
        self.assertEqual(result[0].note, "")

    def test_existing_note_is_preserved(self):
        declared = {"database": {"server": {"engine": "mariadb"}}}
        drift = self._drift_field(note="previous note")
        unit = self._unit("mariadb.socket")
        result = self._note((drift,), declared, {"mariadb.socket": unit})
        self.assertIn("previous note", result[0].note)
        self.assertIn("socket activation", result[0].note)
