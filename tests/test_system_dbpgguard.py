# Copyright (c) 2026 KeelLinux maintainers
"""keel database guard (keel.system.dbpgguard, keel#156): the ExecStartPre
of the PostgreSQL unit on a pair. The server starts as a primary only on
the proven holder; on the node whose newest claim is the other member's
it starts as a standby that follows nobody; the holder whose claim is
not proven (at boot) does not start until follow proves it. The pair,
the VIP's state and the spec are real (tests/vip_helpers.py)"""

import os
from unittest import mock

from test_system_dbpgfollow import (DATADIR, FOLLOW_DROPIN, STANDBY_SIGNAL,
                                    FollowTestCase)
from vip_helpers import VIP

from keel import exits
from keel.system import dbpgguard, dbpostgres


class TestTheGuard(FollowTestCase):
    def guard(self, index: int) -> tuple[int, list[str]]:
        said: list[str] = []
        here = self.all[index]
        with mock.patch.dict(os.environ, {dbpostgres.SERVICE_ENV: ""}):
            code = dbpgguard.guard(here.root, here.node.path, said.append,
                                   output=self.nets[index].output)
        return code, said

    def signal(self, index: int) -> bool:
        return os.path.exists(os.path.join(self.all[index].root,
                                           STANDBY_SIGNAL))

    def test_the_proven_holder_starts_as_a_primary(self):
        self.pair_nodes()
        self.nets[0].addresses.append(f"{VIP}/128")
        code, said = self.guard(0)
        self.assertEqual(code, exits.OK, said)
        self.assertFalse(self.signal(0))

    def test_the_holder_not_proven_does_not_start(self):
        """At boot the VIP is on no wg0: a start as a primary would take
        writes until the follow stops it (3 to 4 s on real nodes, and a
        client with synchronous_commit = local gets its write
        acknowledged)"""
        self.pair_nodes()
        self.nets[0].addresses.clear()
        code, said = self.guard(0)
        self.assertNotEqual(code, exits.OK, said)
        self.assertFalse(self.signal(0))
        self.assertIn("not proven", " ".join(said))

    def test_the_other_member_s_node_starts_as_a_standby(self):
        """An old primary that took the newer claim: fenced on disk
        before the start, so it never takes a write (the window after a
        heal, keel#156)"""
        self.pair_nodes()
        root = self.all[1].root
        with open(os.path.join(root, FOLLOW_DROPIN), "w") as fob:
            fob.write("primary_conninfo = 'host=elsewhere'\n")
        code, said = self.guard(1)
        self.assertEqual(code, exits.OK, said)
        self.assertTrue(self.signal(1))
        self.assertFalse(os.path.exists(os.path.join(root, FOLLOW_DROPIN)))
        self.assertIn("standby", " ".join(said))

    def test_a_standby_starts_as_it_is(self):
        self.pair_nodes()
        root = self.all[1].root
        open(os.path.join(root, STANDBY_SIGNAL), "w").close()
        with open(os.path.join(root, FOLLOW_DROPIN), "w") as fob:
            fob.write("primary_conninfo = 'host=holder'\n")
        code, said = self.guard(1)
        self.assertEqual(code, exits.OK, said)
        self.assertTrue(os.path.exists(os.path.join(root, FOLLOW_DROPIN)))

    def test_a_pair_with_no_claim_yet_starts(self):
        self.pair_nodes(claim=None)
        code, said = self.guard(0)
        self.assertEqual(code, exits.OK, said)
        self.assertFalse(self.signal(0))

    def test_a_node_in_no_pair_starts(self):
        self.pair_nodes()
        here = self.all[2]
        os.makedirs(os.path.join(here.root, DATADIR), exist_ok=True)
        code, said = self.guard(2)
        self.assertEqual(code, exits.OK, said)

    def test_a_spec_that_cannot_be_read_on_a_pair_refuses(self):
        self.pair_nodes()
        with open(self.all[0].node.path, "w") as fob:
            fob.write("{not yaml")
        with open(os.path.join(self.all[0].root,
                               "etc/postgresql/17/main/conf.d",
                               dbpostgres.PAIR_DROPIN_NAME), "w") as fob:
            fob.write(dbpostgres.pair_dropin_text())
        code, said = self.guard(0)
        self.assertNotEqual(code, exits.OK, said)

    def test_a_spec_that_cannot_be_read_off_a_pair_starts(self):
        self.pair_nodes()
        with open(self.all[0].node.path, "w") as fob:
            fob.write("{not yaml")
        code, said = self.guard(0)
        self.assertEqual(code, exits.OK, said)
