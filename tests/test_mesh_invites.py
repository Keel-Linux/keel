# Copyright (c) 2026 KeelLinux maintainers
"""The pending invites under /var/lib/keel/mesh (decision 0048)

Against a scratch root, at the store's seam: reserve, find, consume and
expire. What is on disk is checked where the decision says what must be
there and what must not: root's modes, one file per invite, no secret.
"""

import json
import os
import shutil
import stat
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from os.path import join

from keel.mesh import invites
from keel.mesh.invites import InviteError, Pending

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
KEY = bytes(range(32, 64))
TLS_KEY = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"


def pending(invite_id="0123456789abcdef", address="fd00:1::2/64",
            expires=NOW + HOUR) -> Pending:
    return Pending(invite_id=invite_id, address=address, expires=expires,
                   https_port=51820, certificate="CERT", hmac_key=KEY,
                   tls_key=TLS_KEY)


class Case(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def reserve(self, made=None, now=NOW):
        seen = []

        def make(others):
            seen.append(others)
            return made or pending()

        found = invites.reserve(self.root, now, make)
        return found, seen[0]

    def files(self):
        directory = join(self.root, invites.INVITES)
        return sorted(os.listdir(directory))


class TestReserve(Case):
    def test_written_root_only(self):
        self.reserve()
        for relative in (invites.DIR, invites.INVITES):
            with self.subTest(directory=relative):
                mode = os.stat(join(self.root, relative)).st_mode
                self.assertEqual(stat.S_IMODE(mode), 0o700)
        self.assertEqual(self.files(), ["0123456789abcdef.json"])
        mode = os.stat(join(self.root, invites.INVITES,
                            "0123456789abcdef.json")).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o600)

    def test_a_directory_left_open_is_closed_again(self):
        os.makedirs(join(self.root, invites.INVITES), mode=0o755)
        os.chmod(join(self.root, invites.DIR), 0o755)
        os.chmod(join(self.root, invites.INVITES), 0o755)
        self.reserve()
        for relative in (invites.DIR, invites.INVITES):
            mode = os.stat(join(self.root, relative)).st_mode
            self.assertEqual(stat.S_IMODE(mode), 0o700)

    def test_make_sees_the_other_pending_invites_not_the_expired(self):
        self.reserve(pending("1" * 16, "fd00:1::2/64"))
        self.reserve(pending("2" * 16, "fd00:1::3/64",
                             expires=NOW + timedelta(minutes=1)))
        _, seen = self.reserve(pending("3" * 16, "fd00:1::4/64"),
                               now=NOW + timedelta(minutes=2))
        self.assertEqual([one.address for one in seen], ["fd00:1::2/64"])
        self.assertNotIn("2" * 16 + ".json", self.files())

    def test_an_id_already_pending_is_refused(self):
        self.reserve()
        with self.assertRaises(InviteError):
            self.reserve()

    def test_what_make_refuses_writes_nothing(self):
        def make(_others):
            raise InviteError("prefix full")

        with self.assertRaises(InviteError):
            invites.reserve(self.root, NOW, make)
        self.assertEqual(self.files(), [])

    def test_the_file_holds_no_secret_and_no_token(self):
        made, _ = self.reserve()
        path = join(self.root, invites.INVITES, "0123456789abcdef.json")
        with open(path) as fob:
            data = json.load(fob)
        self.assertEqual(data["hmac_key"], KEY.hex())
        self.assertNotIn("secret", data)
        self.assertNotIn("keel1:", json.dumps(data))
        self.assertEqual(data["expires"], "2026-10-03T13:00:00Z")

    def test_repr_holds_neither_key(self):
        text = repr(pending())
        self.assertNotIn(KEY.hex(), text)
        self.assertNotIn("PRIVATE KEY", text)
        self.assertIn("0123456789abcdef", text)


class TestFind(Case):
    def test_found_as_written(self):
        self.reserve()
        self.assertEqual(invites.find(self.root, "0123456789abcdef", NOW),
                         pending())

    def test_unknown(self):
        self.assertIsNone(invites.find(self.root, "f" * 16, NOW))

    def test_expired_is_not_found(self):
        self.reserve()
        self.assertIsNone(invites.find(self.root, "0123456789abcdef",
                                       NOW + HOUR))

    def test_an_id_that_is_not_one_is_never_a_path(self):
        self.reserve()
        for bad in ("../../etc/passwd", "0123456789ABCDEF", "", "0" * 17):
            with self.subTest(bad=bad):
                self.assertIsNone(invites.find(self.root, bad, NOW))

    def test_a_damaged_file_is_no_invite(self):
        self.reserve()
        good = join(self.root, invites.INVITES, "0123456789abcdef.json")
        with open(good) as fob:
            data = json.load(fob)
        for name, text in (("a" * 16, "{not json"),
                           ("b" * 16, json.dumps({**data,
                                                  "address": "nonsense"}))):
            with open(join(self.root, invites.INVITES, f"{name}.json"),
                      "w") as fob:
                fob.write(text)
            with self.subTest(damage=name):
                self.assertIsNone(invites.find(self.root, name, NOW))


class TestConsume(Case):
    def test_once(self):
        self.reserve()
        spent = invites.consume(self.root, "0123456789abcdef", NOW)
        self.assertTrue(spent.consumed)
        with self.assertRaises(InviteError) as raised:
            invites.consume(self.root, "0123456789abcdef", NOW)
        self.assertIn("already used", str(raised.exception))

    def test_unknown(self):
        with self.assertRaises(InviteError) as raised:
            invites.consume(self.root, "f" * 16, NOW)
        self.assertIn("no pending invite", str(raised.exception))

    def test_a_consumed_invite_keeps_its_address_until_it_expires(self):
        self.reserve()
        invites.consume(self.root, "0123456789abcdef", NOW)
        _, seen = self.reserve(pending("1" * 16, "fd00:1::3/64"))
        self.assertEqual([(one.address, one.consumed) for one in seen],
                         [("fd00:1::2/64", True)])
        self.assertEqual(invites.expire(self.root, NOW + HOUR),
                         ("0123456789abcdef", "1" * 16))

    def test_a_consumed_mark_that_is_not_one_is_a_damaged_file(self):
        self.reserve()
        name = join(self.root, invites.INVITES, "0123456789abcdef.json")
        with open(name) as fob:
            data = json.load(fob)
        with open(name, "w") as fob:
            json.dump({**data, "consumed": "yes"}, fob)
        self.assertIsNone(invites.find(self.root, "0123456789abcdef", NOW))

    def test_expired(self):
        self.reserve()
        with self.assertRaises(InviteError) as raised:
            invites.consume(self.root, "0123456789abcdef", NOW + HOUR)
        self.assertIn("expired", str(raised.exception))
        self.assertEqual(self.files(), [])

    def test_a_request_verify_refuses_leaves_it_pending(self):
        # the listener checks the HMAC here, under the same lock
        self.reserve()
        checked = []

        def verify(found):
            checked.append(found)
            return False

        with self.assertRaises(InviteError) as raised:
            invites.consume(self.root, "0123456789abcdef", NOW, verify)
        self.assertIn("refused", str(raised.exception))
        self.assertEqual(checked, [pending()])
        self.assertEqual(self.files(), ["0123456789abcdef.json"])

    def test_a_request_verify_accepts_spends_it(self):
        self.reserve()
        invites.consume(self.root, "0123456789abcdef", NOW, lambda _: True)
        self.assertTrue(invites.find(self.root, "0123456789abcdef",
                                     NOW).consumed)


class TestTogether(Case):
    """The lock: two invites at once, two requests for one invite"""

    def test_two_reservations_at_once_get_two_addresses(self):
        def make_for(invite_id):
            def make(others):
                taken = {one.address for one in others}
                address = next(f"fd00:1::{n}/64" for n in range(2, 9)
                               if f"fd00:1::{n}/64" not in taken)
                time.sleep(0.2)  # the other thread tries meanwhile
                return pending(invite_id, address)
            return make

        threads = [threading.Thread(target=invites.reserve,
                                    args=(self.root, NOW, make_for(one)))
                   for one in ("1" * 16, "2" * 16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        found = {one.address for one in invites.pending(self.root, NOW)}
        self.assertEqual(found, {"fd00:1::2/64", "fd00:1::3/64"})

    def test_one_of_two_requests_spends_it(self):
        self.reserve()
        outcomes = []

        def request():
            try:
                invites.consume(self.root, "0123456789abcdef", NOW,
                                lambda _: time.sleep(0.2) or True)
                outcomes.append("spent")
            except InviteError:
                outcomes.append("refused")

        threads = [threading.Thread(target=request) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(outcomes), ["refused", "spent"])


class TestExpire(Case):
    def test_removes_the_expired_and_the_damaged_only(self):
        self.reserve(pending("1" * 16, expires=NOW + timedelta(minutes=5)))
        self.reserve(pending("2" * 16, "fd00:1::3/64"))
        with open(join(self.root, invites.INVITES, "3" * 16 + ".json"),
                  "w") as fob:
            fob.write("[]")
        with open(join(self.root, invites.INVITES, "notes.txt"), "w") as fob:
            fob.write("left alone")
        removed = invites.expire(self.root, NOW + timedelta(minutes=5))
        self.assertEqual(removed, ("1" * 16, "3" * 16))
        self.assertEqual(self.files(), ["2" * 16 + ".json", "notes.txt"])

    def test_nothing_pending(self):
        self.assertEqual(invites.expire(self.root, NOW), ())

    def test_a_write_that_never_reached_its_rename_is_removed(self):
        self.reserve()
        stale = join(self.root, invites.INVITES, "f" * 16 + ".json.new")
        with open(stale, "w") as fob:
            fob.write(TLS_KEY)
        invites.expire(self.root, NOW)
        self.assertEqual(self.files(), ["0123456789abcdef.json"])


class TestPending(Case):
    def test_the_ones_not_expired(self):
        self.reserve(pending("1" * 16, expires=NOW + timedelta(minutes=5)))
        self.reserve(pending("2" * 16, "fd00:1::3/64"))
        found = invites.pending(self.root, NOW + timedelta(minutes=5))
        self.assertEqual([one.invite_id for one in found], ["2" * 16])

    def test_a_node_that_never_invited(self):
        self.assertEqual(invites.pending(self.root, NOW), ())


if __name__ == "__main__":
    unittest.main()
