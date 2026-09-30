# Copyright (c) 2026 KeelLinux maintainers
"""The primary's accounts, and what a new replica needs to match them

keel.system.dbaccounts is pure: it reads the answers of the clients, as
MariaDB 11.8 printed them on the bench (`--batch --raw
--skip-column-names`), and writes the statements that align the replica.
"""

import unittest

from helpers import spec  # noqa: F401

from keel.system import dbaccounts
from keel.system.dbaccounts import Account, Definition

WP = Account("wp", "%")
WORDPRESS = Account("wordpress", "localhost")
LISTING = (
    "mariadb.sys\tlocalhost\tN\nroot\tlocalhost\tN\nmysql\tlocalhost\tN\n"
    "debian-sys-maint\tlocalhost\tN\nrepl\tfd42:b2:0:1:%\tN\n"
    "wp\t%\tN\nwordpress\tlocalhost\tN\n\tlocalhost\tN\nbroken line\n"
)
PRIMARY = (
    "keel:account\n"
    "CREATE USER `wp`@`%` IDENTIFIED BY PASSWORD '*0A1B'\n"
    "GRANT USAGE ON *.* TO `wp`@`%` IDENTIFIED BY PASSWORD '*0A1B'\n"
    "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wp`@`%`\n"
    "keel:account\n"
    "CREATE USER `wordpress`@`localhost` IDENTIFIED BY PASSWORD '*P'\n"
    "GRANT USAGE ON *.* TO `wordpress`@`localhost` IDENTIFIED BY"
    " PASSWORD '*P'\n"
    "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wordpress`@`localhost`\n"
    "keel:account\n"
)
LOCAL = (
    "keel:account\n"
    "GRANT USAGE ON *.* TO `wordpress`@`localhost` IDENTIFIED BY"
    " PASSWORD '*R'\n"
    "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wordpress`@`localhost`\n"
)


def definitions(text: str = PRIMARY) -> dict:
    found, problem = dbaccounts.primary_definitions(text, [WP, WORDPRESS])
    if problem:
        raise AssertionError(problem)
    return found


class TestTheListing(unittest.TestCase):
    def test_the_server_and_keel_accounts_and_the_anonymous_are_left(self):
        accounts, roles = dbaccounts.listing(LISTING)
        self.assertEqual(accounts, [WP, WORDPRESS])
        self.assertEqual(roles, [])

    def test_roles_are_named(self):
        _, roles = dbaccounts.listing(LISTING + "editor\t\tY\n")
        self.assertEqual(roles, ["editor"])

    def test_the_questions_are_separated_by_a_marker(self):
        self.assertEqual(
            dbaccounts.primary_questions([WP]),
            "SELECT 'keel:account';\nSHOW CREATE USER 'wp'@'%';\n"
            "SHOW GRANTS FOR 'wp'@'%';\n"
            "SELECT 'keel:account';\nSHOW GRANTS FOR PUBLIC;\n",
        )
        self.assertEqual(
            dbaccounts.local_questions([WORDPRESS]),
            "SELECT 'keel:account';\n"
            "SHOW GRANTS FOR 'wordpress'@'localhost';\n",
        )


class TestTheDefinitions(unittest.TestCase):
    def test_each_account_gets_its_create_and_its_grants(self):
        found = definitions()
        self.assertEqual(
            found[WP].create,
            "CREATE USER `wp`@`%` IDENTIFIED BY PASSWORD '*0A1B'",
        )
        self.assertEqual(len(found[WP].grants), 2)

    def test_privileges_given_to_public_are_refused(self):
        _, problem = dbaccounts.primary_definitions(
            PRIMARY + "GRANT SELECT ON `wordpress`.* TO PUBLIC\n",
            [WP, WORDPRESS],
        )
        self.assertIn("PUBLIC", problem)

    def test_an_answer_that_does_not_match_the_questions_is_refused(self):
        _, problem = dbaccounts.primary_definitions(PRIMARY, [WP])
        self.assertIn("2 account(s)", problem)

    def test_a_block_without_its_create_user_is_refused(self):
        _, problem = dbaccounts.primary_definitions(
            "keel:account\nGRANT USAGE ON *.* TO `wp`@`%`\nkeel:account\n",
            [WP],
        )
        self.assertIn("GRANT USAGE ON *.* TO `wp`@`%`", problem)

    def test_a_statement_that_is_not_an_account_is_refused(self):
        for line in ("DROP DATABASE wordpress", "GRANT `editor` TO `wp`@`%`",
                     "SET DEFAULT ROLE `editor` FOR `wp`@`%`"):
            text = PRIMARY.replace(
                "keel:account\nCREATE USER `wordpress`",
                f"{line}\nkeel:account\nCREATE USER `wordpress`",
            )
            _, problem = dbaccounts.primary_definitions(text,
                                                        [WP, WORDPRESS])
            self.assertIn(line, problem)

    def test_what_comes_before_the_first_marker_is_not_an_answer(self):
        found = definitions("Warning: something\n" + PRIMARY)
        self.assertEqual(set(found), {WP, WORDPRESS})

    def test_the_local_grants_are_read_the_same_way(self):
        found, problem = dbaccounts.local_grants(LOCAL, [WORDPRESS])
        self.assertEqual(problem, "")
        self.assertEqual(len(found[WORDPRESS]), 2)
        _, problem = dbaccounts.local_grants(LOCAL, [WORDPRESS, WP])
        self.assertIn("1 account(s)", problem)
        _, problem = dbaccounts.local_grants(
            "keel:account\nDROP TABLE x\n", [WORDPRESS]
        )
        self.assertIn("DROP TABLE x", problem)


class TestTheAlignment(unittest.TestCase):
    def test_an_account_the_replica_lacks_is_created_off_the_log(self):
        text = dbaccounts.alignment(definitions(), {WORDPRESS.key()},
                                    {WORDPRESS: definitions()[WORDPRESS]
                                     .grants})
        self.assertTrue(text.startswith("SET SESSION sql_log_bin = 0;\n"))
        self.assertIn(
            "CREATE USER `wp`@`%` IDENTIFIED BY PASSWORD '*0A1B';\n", text
        )
        self.assertIn(
            "GRANT ALL PRIVILEGES ON `wordpress`.* TO `wp`@`%`;\n", text
        )
        self.assertNotIn("`wordpress`@`localhost`", text)

    def test_the_same_grants_under_another_password_are_left_alone(self):
        local, _ = dbaccounts.local_grants(LOCAL, [WORDPRESS])
        text = dbaccounts.alignment(
            {WORDPRESS: definitions()[WORDPRESS]}, {WORDPRESS.key()}, local
        )
        self.assertEqual(text, "")

    def test_other_grants_are_replaced_by_the_primarys(self):
        # The replica's own first boot gave it the account with other
        # grants, and a REVOKE on the primary stopped the replica.
        local, _ = dbaccounts.local_grants(
            LOCAL + "GRANT SELECT ON `other`.* TO `wordpress`@`localhost`\n",
            [WORDPRESS],
        )
        text = dbaccounts.alignment(
            {WORDPRESS: definitions()[WORDPRESS]}, {WORDPRESS.key()}, local
        )
        self.assertIn("DROP USER 'wordpress'@'localhost';\n", text)
        self.assertLess(text.index("DROP USER"), text.index("CREATE USER"))
        self.assertIn("GRANT ALL PRIVILEGES ON `wordpress`.*", text)

    def test_the_host_of_a_held_account_compares_without_case(self):
        self.assertEqual(Account("wp", "LOCALHOST").key(),
                         Account("wp", "localhost").key())
        self.assertNotEqual(Account("WP", "localhost").key(),
                            Account("wp", "localhost").key())

    def test_normalizing_drops_only_the_credential(self):
        self.assertEqual(
            dbaccounts.normalized(
                "GRANT ALL PRIVILEGES ON *.* TO `a`@`b` IDENTIFIED VIA"
                " mysql_native_password USING '*X' OR unix_socket"
                " WITH GRANT OPTION"
            ),
            "GRANT ALL PRIVILEGES ON *.* TO `a`@`b` WITH GRANT OPTION",
        )
        self.assertEqual(
            dbaccounts.normalized("GRANT USAGE ON *.* TO `a`@`b`"),
            "GRANT USAGE ON *.* TO `a`@`b`",
        )

    def test_a_definition_is_a_value(self):
        self.assertEqual(Definition("CREATE USER x", ("GRANT a",)),
                         Definition("CREATE USER x", ("GRANT a",)))


if __name__ == "__main__":
    unittest.main()
