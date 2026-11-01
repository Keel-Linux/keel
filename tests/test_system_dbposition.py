# Copyright (c) 2026 KeelLinux maintainers
"""keel#271: a replica that lags does not become a writable primary by
itself. The holder leaves its position in etcd; the node that claims the
VIP compares it, by GTID, before it takes writes"""

import subprocess
import tempfile
import unittest
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel.mesh.etcdclient import EtcdError
from keel.system import dbposition

VIP = "fd00:6b65:f1b::ffff:100"


def record(position="0-1-100", alone=False) -> dbposition.Record:
    return dbposition.Record(position, alone, "holder-key")


def no_answer() -> None:
    return None


class TestWhyNot(unittest.TestCase):
    def test_a_replica_at_the_position_passes(self):
        self.assertIsNone(dbposition.why_not("0-1-100", record(), no_answer))
        self.assertIsNone(dbposition.why_not("0-1-101", record(), no_answer))

    def test_the_case_of_the_evidence_is_refused_with_the_true_distance(self):
        """K1: 14614 against 27978, and Seconds_Behind_Master said 0"""
        why = dbposition.why_not("0-1-14614", record("0-1-27978"), no_answer)
        self.assertIn("13364", why)
        self.assertIn("0-1-14614", why)
        self.assertIn("0-1-27978", why)
        self.assertIn("--accept-lost-writes", why)

    def test_a_holder_that_had_no_replica_is_refused_at_the_same_position(
            self):
        """F2: the two nodes had the same GTID when the replica was cut,
        then the holder acknowledged 60 writes the record may not show"""
        why = dbposition.why_not("0-1-100", record(alone=True), no_answer)
        self.assertIn("no replica", why)
        self.assertIn("--accept-lost-writes", why)

    def test_an_old_primary_that_answers_decides(self):
        """Fresher than any record: it came back, or the promote is
        planned, and what it logged is the truth"""
        self.assertIsNone(dbposition.why_not(
            "0-1-100", record(alone=True), lambda: "0-1-100"))
        self.assertIsNone(dbposition.why_not(
            "0-1-100", record("0-1-200"), lambda: "0-1-90"))
        why = dbposition.why_not(
            "0-1-100", record(alone=True), lambda: "0-1-160")
        self.assertIn("60", why)
        self.assertIn("catches up", why)

    def test_the_old_primary_is_asked_only_when_the_record_refuses(self):
        """A dead primary costs the connect timeout: a failover with a
        record that passes does not pay it"""
        asked = mock.Mock(return_value=None)
        self.assertIsNone(dbposition.why_not("0-1-100", record(), asked))
        asked.assert_not_called()

    def test_no_record_passes(self):
        """A holder of an older keel leaves none: the behaviour of that
        keel, flagged in the PR for the maintainer"""
        self.assertIsNone(dbposition.why_not("0-1-1", None, no_answer))

    def test_a_record_or_a_position_that_cannot_be_read_refuses(self):
        self.assertIn("could not", dbposition.why_not(
            "0-1-1", dbposition.UNREADABLE, no_answer))
        self.assertIsNone(dbposition.why_not(
            "0-1-1", dbposition.UNREADABLE, lambda: "0-1-1"))
        self.assertIn("could not", dbposition.why_not(
            "nonsense", record(), no_answer))


class TestRecord(unittest.TestCase):
    def test_it_goes_there_and_back(self):
        one = record("0-1-5,1-1-2", True)
        self.assertEqual(dbposition.parsed(one.text()), one)

    def test_a_value_that_is_no_record_is_unreadable(self):
        for bad in ("nonsense", "[]", '{"position": 1}',
                    '{"position": "x", "alone": false, "holder": "k"}'):
            with self.subTest(bad=bad):
                self.assertIs(dbposition.parsed(bad), dbposition.UNREADABLE)

    def test_the_key_is_one_every_member_may_write_and_no_claim_s(self):
        """Not under /vip/<vip>/: keel.mesh.vipetcd.seen reads each key
        there as a claim, and says so at each tick, on older keels too"""
        key = dbposition.key("mesh", VIP)
        self.assertTrue(key.startswith("/keel/mesh/etcd/"), key)
        self.assertNotIn("/vip/", key)


def sample(position="0-1-1", clients="1", status="ON", read_only="0") -> str:
    return f"{position}\t{read_only}\t{clients}\t{status}\n"


class TestPublisher(unittest.TestCase):
    def setUp(self):
        self.answers: list[str] = []
        self.put: list[tuple[str, str]] = []
        self.publisher = dbposition.Publisher(
            self.answer, lambda value: self.put.append(value), "own-key")

    def answer(self, argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, self.answers.pop(0), "")

    def turns(self, *answers):
        self.answers = list(answers)
        for _ in answers:
            self.publisher.turn()

    def last(self) -> dbposition.Record:
        return dbposition.parsed(self.put[-1])

    def test_the_position_published_is_an_older_sample(self):
        """AFTER_SYNC: a commit is in the binary log before the replica
        has it, so the newest position is ahead of a healthy replica for
        one round trip. An older one is not, so a crash under load does
        not read as a lag"""
        self.turns(*(sample(f"0-1-{n}") for n in range(1, 2 +
                                                       dbposition.DELAY)))
        self.assertEqual(self.last().position, "0-1-1")
        self.assertFalse(self.last().alone)

    def test_nothing_is_published_before_a_sample_is_old_enough(self):
        self.turns(sample("0-1-1"))
        self.assertEqual(self.put, [])

    def test_a_primary_with_no_replica_is_published_at_once(self):
        for clients, status in (("0", "ON"), ("1", "OFF")):
            with self.subTest(clients=clients):
                self.setUp()
                self.turns(sample("0-1-7", clients, status))
                self.assertTrue(self.last().alone)

    def test_a_read_only_server_publishes_nothing(self):
        """A lagging holder that follow keeps read only must not write
        its own low position over the record that refused it"""
        self.turns(*[sample("0-1-5", read_only="1")] * (dbposition.DELAY + 3))
        self.assertEqual(self.put, [])

    def test_the_same_value_is_not_written_again(self):
        self.turns(*[sample("0-1-5")] * (dbposition.DELAY + 5))
        self.assertEqual(len(self.put), 1)

    def test_a_server_that_does_not_answer_publishes_nothing(self):
        publisher = dbposition.Publisher(
            lambda argv, **kwargs: subprocess.CompletedProcess(
                argv, 1, "", "no"), self.put.append, "own-key")
        publisher.turn()
        self.assertEqual(self.put, [])


class TestRefusal(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def refuse(self, taken=True):
        said: list[str] = []
        with mock.patch("keel.monitor.alerting.alert",
                        return_value=taken) as alerted:
            dbposition.refused(self.root, VIP, "why it is refused", said.append)
        return alerted

    def test_it_is_alerted_once_and_shown(self):
        self.assertEqual(self.refuse().call_count, 1)
        self.refuse().assert_not_called()
        self.assertIn("why it is refused",
                      " ".join(dbposition.status_lines(self.root)))

    def test_an_alert_no_channel_took_is_tried_again(self):
        self.refuse(taken=False).assert_called_once()
        self.refuse().assert_called_once()

    def test_a_passed_gate_forgets_it(self):
        self.refuse()
        dbposition.forget(self.root)
        self.assertEqual(dbposition.status_lines(self.root), [])
        self.refuse().assert_called_once()

    def test_the_operator_s_act_is_a_mark_that_goes_after_the_command(self):
        self.assertFalse(dbposition.accepted(self.root))
        with dbposition.accepting(self.root):
            self.assertTrue(dbposition.accepted(self.root))
        self.assertFalse(dbposition.accepted(self.root))
        with self.assertRaises(RuntimeError), dbposition.accepting(self.root):
            raise RuntimeError("the promote failed")
        self.assertFalse(dbposition.accepted(self.root))


class FakeHere:
    def __init__(self, values=(), error=None):
        self.values, self.error = values, error
        self.root = "/"

    def mesh_id(self):
        return "mesh"

    def local(self):
        client = mock.Mock()
        if self.error:
            client.prefix.side_effect = self.error
        else:
            client.prefix.return_value = list(self.values)
        return client


class TestReading(unittest.TestCase):
    def test_no_key_is_no_record(self):
        self.assertIsNone(dbposition.read_record(FakeHere(), VIP))

    def test_the_key_read(self):
        value = mock.Mock(key=dbposition.key("mesh", VIP),
                          value=record().text().encode())
        self.assertEqual(dbposition.read_record(FakeHere([value]), VIP),
                         record())

    def test_an_etcd_that_does_not_answer_is_unreadable(self):
        self.assertIs(
            dbposition.read_record(FakeHere(error=EtcdError("down")), VIP),
            dbposition.UNREADABLE)


if __name__ == "__main__":
    unittest.main()
