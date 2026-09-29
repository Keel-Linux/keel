# Copyright (c) 2026 KeelLinux maintainers
"""Whether this machine has a Let's Encrypt account for the configured CA

dehydrated 0.7.2 keeps an account in BASEDIR/accounts/HASH, where HASH is
the url-safe base64 of the CA's URL and a newline (its `echo "${CA}" |
urlbase64`). An account for another CA, staging for instance, is not
consent for this one (review of #39).
"""

import os
import tempfile
import unittest
from os.path import join

from helpers import spec  # noqa: F401

from keel.inspect.tree import Tree
from keel.system.state import acme_account, account_hash

PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
OLD = "https://acme-v01.api.letsencrypt.org/directory"


def machine(config: str | None, *accounts: str) -> Tree:
    root = tempfile.mkdtemp()
    os.makedirs(join(root, "etc", "dehydrated"))
    if config is not None:
        with open(join(root, "etc/dehydrated/confconsole.config"), "w") as fob:
            fob.write(config)
    for url in accounts:
        folder = join(root, "var/lib/dehydrated/accounts", account_hash(url))
        os.makedirs(folder)
        with open(join(folder, "registration_info.json"), "w") as fob:
            fob.write("{}\n")
    return Tree(root)


class TestAccountHash(unittest.TestCase):
    def test_the_hash_dehydrated_computes(self):
        self.assertEqual(account_hash(PRODUCTION),
                         "aHR0cHM6Ly9hY21lLXYwMi5hcGkubGV0c2VuY3J5cHQub3Jn"
                         "L2RpcmVjdG9yeQo")


class TestAcmeAccount(unittest.TestCase):
    def test_the_default_ca_is_lets_encrypt_production(self):
        self.assertTrue(acme_account(machine(None, PRODUCTION)))
        self.assertTrue(acme_account(machine('CA="letsencrypt"\n',
                                             PRODUCTION)))

    def test_an_account_for_another_ca_is_not_one_for_this(self):
        self.assertFalse(acme_account(machine(None, STAGING)))
        self.assertFalse(acme_account(machine('CA="letsencrypt-test"\n',
                                              PRODUCTION)))
        self.assertTrue(acme_account(machine('CA="letsencrypt-test"\n',
                                             STAGING)))

    def test_a_ca_given_by_url_is_used_as_it_is(self):
        self.assertTrue(acme_account(machine(f"CA={STAGING}\n", STAGING)))

    def test_the_old_production_account_is_reused_as_dehydrated_does(self):
        self.assertTrue(acme_account(machine(None, OLD)))

    def test_basedir_from_the_config(self):
        tree = machine('BASEDIR=/srv/acme\n')
        folder = join(tree.root, "srv/acme/accounts", account_hash(PRODUCTION))
        os.makedirs(folder)
        with open(join(folder, "registration_info.json"), "w") as fob:
            fob.write("{}\n")
        self.assertTrue(acme_account(tree))

    def test_no_accounts_at_all(self):
        self.assertFalse(acme_account(machine(None)))


if __name__ == "__main__":
    unittest.main()
