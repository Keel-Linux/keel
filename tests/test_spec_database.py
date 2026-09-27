# Copyright (c) 2026 KeelLinux maintainers
"""Validation of the database section, both subjects

`server` is what a machine that runs a database server is; `client` is
where a machine that uses one reaches it. Neither implies the other, and
the checks that come from defects (a literal address, a secret by
reference, a replica that names its primary) each have their own test.
"""

import unittest

from helpers import doc, errors, spec

from keel.spec.constants import (  # noqa: E402
    DATABASE_ENGINES,
    MAX_PORT,
    SERVER_ROLES,
)

STANDALONE = """version: 1
database:
  server:
    engine: mariadb
    role: standalone
    listen:
      - "::1"
      - 127.0.0.1
"""

REPLICA = """version: 1
database:
  server:
    engine: postgresql
    role: replica
    replication:
      primary:
        host: 2001:db8:1::10
        port: 5432
      secret:
        file: /etc/keel/secrets/replication_password
"""

PRIMARY = """version: 1
database:
  server:
    engine: redis
    role: primary
    listen:
      - "::"
    replication:
      allowed_from:
        - 2001:db8:1::/64
        - 2001:db8:2::20
        - replica.example.org
      secret:
        file: /etc/keel/secrets/replication_password
"""

CLIENT = """version: 1
database:
  client:
    engine: mariadb
    primary:
      host: "::1"
      port: 3306
      name: wordpress
      user: wordpress
      secret:
        file: /etc/keel/secrets/db_password
    replicas:
      - host: 2001:db8:1::21
      - host: 2001:db8:1::22
        port: 3307
"""

BOTH = """version: 1
database:
  server:
    engine: mariadb
    role: primary
  client:
    engine: mariadb
    primary:
      host: "::1"
"""


def messages(text: str, *fragments: str) -> None:
    """Assert that every fragment appears in exactly one error message"""
    found = errors(text, check_secret_files=False)
    for fragment in fragments:
        matching = [error for error in found if fragment in error]
        if len(matching) != 1:
            raise AssertionError(
                f"expected one error mentioning {fragment!r}, got {found}"
            )


def valid(text: str) -> None:
    found = errors(text, check_secret_files=False)
    if found:
        raise AssertionError(f"expected no errors, got {found}")


class TestAccepted(unittest.TestCase):
    def test_a_standalone_server_is_valid(self):
        valid(STANDALONE)

    def test_a_replica_naming_its_primary_is_valid(self):
        valid(REPLICA)

    def test_a_primary_with_authorizations_is_valid(self):
        valid(PRIMARY)

    def test_a_client_with_a_primary_and_replicas_is_valid(self):
        valid(CLIENT)

    def test_a_machine_can_be_both_a_server_and_a_client(self):
        valid(BOTH)

    def test_an_absent_database_section_is_valid(self):
        valid("version: 1\n")

    def test_an_empty_database_section_is_valid(self):
        valid("version: 1\ndatabase: {}\n")

    def test_every_engine_is_accepted_for_both_subjects(self):
        for engine in DATABASE_ENGINES:
            with self.subTest(engine=engine):
                valid(
                    f"version: 1\ndatabase:\n  server:\n"
                    f"    engine: {engine}\n    role: standalone\n"
                    f"  client:\n    engine: {engine}\n"
                    f'    primary:\n      host: "::1"\n'
                )

    def test_every_role_is_accepted(self):
        for role in SERVER_ROLES:
            with self.subTest(role=role):
                text = (
                    "version: 1\ndatabase:\n  server:\n"
                    "    engine: redis\n"
                    f"    role: {role}\n"
                    "    replication:\n      primary:\n"
                    "        host: 2001:db8:1::10\n"
                )
                valid(text)


class TestShape(unittest.TestCase):
    def test_the_section_and_both_subjects_must_be_mappings(self):
        for key in ("database", "database:\n  server", "database:\n  client"):
            with self.subTest(key=key):
                messages(f"version: 1\n{key}: [one]\n", "must be a mapping")

    def test_an_unknown_subject_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  proxy: {}\n",
            "database.proxy: unknown key",
        )

    def test_an_unknown_key_of_either_subject_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: redis\n"
            "    role: standalone\n    topology: cloud\n",
            "database.server.topology: unknown key",
        )
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: redis\n"
            '    primary:\n      host: "::1"\n    pool: 10\n',
            "database.client.pool: unknown key",
        )


class TestEngineAndRole(unittest.TestCase):
    def test_a_declared_server_names_an_engine(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    role: standalone\n",
            "database.server.engine: must be one of",
        )

    def test_a_declared_client_names_an_engine(self):
        messages(
            'version: 1\ndatabase:\n  client:\n    primary:\n'
            '      host: "::1"\n',
            "database.client.engine: must be one of",
        )

    def test_an_unknown_engine_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mongodb\n"
            "    role: standalone\n",
            "database.server.engine: must be one of",
        )

    def test_a_declared_server_names_a_role(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n",
            "database.server.role: must be one of",
        )

    def test_a_role_the_spec_has_no_value_for_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: multi_primary\n",
            "database.server.role: must be one of",
        )


class TestListen(unittest.TestCase):
    def test_localhost_is_refused_and_the_reason_names_the_trap(self):
        found = errors(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: standalone\n    listen:\n      - localhost\n",
            check_secret_files=False,
        )
        self.assertEqual(len(found), 1)
        self.assertIn("database.server.listen", found[0])
        self.assertIn("ip6-localhost", found[0])
        self.assertIn("::1", found[0])

    def test_the_debian_ipv6_name_is_refused_as_well(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: standalone\n    listen:\n      - ip6-localhost\n",
            "is a name, not an address",
        )

    def test_any_other_name_is_refused(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: standalone\n    listen:\n      - db.example.org\n",
            "is not an address; addresses are literal",
        )

    def test_a_listen_entry_that_is_not_a_string_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: redis\n"
            "    role: standalone\n    listen:\n      - 1\n",
            "database.server.listen: must be an address",
        )

    def test_listen_must_be_a_list(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: redis\n"
            '    role: standalone\n    listen: "::1"\n',
            "database.server.listen: must be a list",
        )

    def test_an_empty_listen_list_declares_nothing(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: redis\n"
            "    role: standalone\n    listen: []\n",
            "must name at least one address",
        )


class TestReplication(unittest.TestCase):
    def test_a_replica_must_name_the_primary_it_replicates_from(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: replica\n",
            "required when the role is replica",
        )

    def test_a_replica_with_an_empty_replication_section_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: replica\n    replication:\n"
            "      allowed_from: [2001:db8::/64]\n",
            "required when the role is replica",
        )

    def test_a_primary_may_carry_the_authorizations_of_a_promotion(self):
        valid(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: standalone\n    replication:\n"
            "      allowed_from: [2001:db8::/64]\n"
        )

    def test_the_primary_endpoint_must_be_a_literal_address(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: replica\n    replication:\n      primary:\n"
            "        host: primary.example.org\n",
            "is not an address; addresses are literal",
        )

    def test_the_primary_endpoint_needs_a_host(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: replica\n    replication:\n      primary:\n"
            "        port: 3306\n",
            "database.server.replication.primary.host: required",
        )

    def test_the_primary_endpoint_takes_no_other_key(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: replica\n    replication:\n      primary:\n"
            "        host: 2001:db8::10\n        user: repl\n",
            "database.server.replication.primary.user: unknown key",
        )

    def test_replication_must_be_a_mapping(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: primary\n    replication: cloud\n",
            "database.server.replication: must be a mapping",
        )

    def test_an_unknown_replication_key_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: primary\n    replication:\n      replicas: []\n",
            "database.server.replication.replicas: unknown key",
        )

    def test_the_credential_is_a_reference_and_never_a_value(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: primary\n    replication:\n"
            "      secret: hunter2\n",
            "database.server.replication.secret: must be a mapping",
        )

    def test_the_credential_names_exactly_one_backend(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: primary\n    replication:\n      secret:\n"
            "        file: /etc/keel/secrets/repl\n        generate: true\n",
            "exactly one of file, generate is required",
        )


class TestAllowedFrom(unittest.TestCase):
    def test_a_prefix_an_address_and_a_name_are_all_accepted(self):
        valid(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: primary\n    replication:\n      allowed_from:\n"
            "        - 2001:db8:1::/64\n        - 192.0.2.0/24\n"
            "        - 2001:db8:1::20\n        - replica.example.org\n"
        )

    def test_a_mariadb_host_pattern_is_accepted(self):
        """The only spelling MariaDB has for an IPv6 prefix in a grant

        Measured on the bench: a MariaDB primary authorized from a /64
        holds `2804:710:d0:5:%`, and inspect reads that back, so a schema
        that refused it would break the round trip on every primary.
        """
        valid(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            "    role: primary\n    replication:\n      allowed_from:\n"
            "        - 2001:db8:1:%\n        - 192.0.2.%\n"
            "        - replica_.example.org\n"
        )

    def test_a_pattern_of_nothing_but_a_wildcard_is_accepted(self):
        valid(
            "version: 1\ndatabase:\n  server:\n    engine: mariadb\n"
            '    role: primary\n    replication:\n      allowed_from: ["%"]\n'
        )

    def test_allowed_from_must_be_a_list(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: primary\n    replication:\n"
            "      allowed_from: 2001:db8::/64\n",
            "allowed_from: must be a list",
        )

    def test_a_malformed_prefix_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: primary\n    replication:\n      allowed_from:\n"
            "        - 2001:db8::/200\n",
            "is not a prefix",
        )

    def test_a_host_bits_prefix_is_accepted_as_written(self):
        valid(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: primary\n    replication:\n      allowed_from:\n"
            "        - 2001:db8:1::20/64\n"
        )

    def test_neither_an_address_nor_a_prefix_nor_a_name_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: primary\n    replication:\n      allowed_from:\n"
            '        - "not a host"\n',
            "is not an address, a prefix, a host pattern or a name",
        )

    def test_localhost_is_refused_as_an_origin(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: primary\n    replication:\n      allowed_from:\n"
            "        - localhost\n",
            "is ambiguous",
        )

    def test_an_empty_origin_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  server:\n    engine: postgresql\n"
            "    role: primary\n    replication:\n      allowed_from:\n"
            '        - ""\n',
            "must be an address, a prefix, a host pattern or a name",
        )


class TestClient(unittest.TestCase):
    def test_a_client_names_where_it_writes(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n",
            "database.client.primary: required, and a mapping",
        )

    def test_the_write_endpoint_must_be_a_literal_address(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            "    primary:\n      host: localhost\n",
            "is a name, not an address",
        )

    def test_a_port_must_be_a_number_in_range(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n      port: "3306"\n',
            "database.client.primary.port: must be a port number",
        )
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            f'    primary:\n      host: "::1"\n      port: {MAX_PORT + 1}\n',
            f"between 1 and {MAX_PORT}",
        )

    def test_a_port_of_zero_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n      port: 0\n',
            "between 1 and",
        )

    def test_a_boolean_is_not_a_port(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n      port: true\n',
            "must be a port number",
        )

    def test_a_redis_numbered_database_is_accepted_as_the_name(self):
        valid(
            "version: 1\ndatabase:\n  client:\n    engine: redis\n"
            '    primary:\n      host: "::1"\n      name: 0\n'
        )

    def test_a_name_with_a_space_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n      name: two words\n',
            "database.client.primary.name: must be a single word",
        )

    def test_an_empty_user_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n      user: ""\n',
            "database.client.primary.user: must be a name",
        )

    def test_a_user_that_is_not_a_word_is_an_error(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n      user: [wordpress]\n',
            "database.client.primary.user: must be a name",
        )

    def test_the_read_endpoints_must_be_a_list_of_mappings(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n    replicas: 2001:db8::21\n',
            "database.client.replicas: must be a list",
        )
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n'
            "    replicas:\n      - 2001:db8::21\n",
            "database.client.replicas[0]: must be a mapping",
        )

    def test_each_read_endpoint_is_named_by_its_position(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n'
            "    replicas:\n      - host: 2001:db8::21\n"
            "      - host: replica.example.org\n",
            "database.client.replicas[1].host",
        )

    def test_a_read_endpoint_carries_no_credential_of_its_own(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n'
            "    replicas:\n      - host: 2001:db8::21\n"
            "        user: reader\n",
            "database.client.replicas[0].user: unknown key",
        )

    def test_the_client_credential_is_a_reference(self):
        messages(
            "version: 1\ndatabase:\n  client:\n    engine: mariadb\n"
            '    primary:\n      host: "::1"\n      secret: hunter2\n',
            "database.client.primary.secret: must be a mapping",
        )


class TestNotApplied(unittest.TestCase):
    """This phase is vocabulary, reading and comparison, never applying"""

    def test_apply_warns_that_the_section_is_left_alone(self):
        found = spec.unsupported(doc(STANDALONE))
        matching = [line for line in found if line.startswith("database:")]
        self.assertEqual(len(matching), 1)
        self.assertIn("no database configuration is written", matching[0])

    def test_the_warning_stands_with_the_system_flag_too(self):
        found = spec.unsupported(doc(REPLICA), system=True)
        self.assertEqual(
            len([line for line in found if line.startswith("database:")]), 1
        )

    def test_a_spec_without_the_section_says_nothing_about_it(self):
        found = spec.unsupported(doc("version: 1\n"))
        self.assertEqual(
            [line for line in found if line.startswith("database:")], []
        )
