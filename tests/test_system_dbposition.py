# Copyright (c) 2026 KeelLinux maintainers
"""keel#271: a replica that lags does not become a writable primary by
itself. The holder leaves its position in etcd; the node that claims the
VIP compares it, by GTID, before it takes writes"""

import contextlib
import io
import os
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel import exits
from keel.mesh.etcdclient import EtcdError
from keel.mesh.vipnode import VipError
from keel.system import dbfollow, dbposition, dbpositionunit
from vip_helpers import VIP as PAIR_VIP
from vip_helpers import Pair

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


NO_KEY = ("this node's WireGuard key: /etc/wireguard/wg0.key: secret file"
          " not found")


class KeylessHere(FakeHere):
    """A node with no WireGuard key file, as a one-node node is"""

    def __init__(self):
        super().__init__()
        self.asked_key = 0

    def own_key(self):
        self.asked_key += 1
        raise VipError(NO_KEY)


class KeyedHere(FakeHere):
    """A node of a pair, with its key"""

    def __init__(self):
        super().__init__()
        self.asked_key = 0
        self.client = mock.Mock()

    def own_key(self):
        self.asked_key += 1
        return "holder-key"

    def local(self):
        return self.client


def serving(here, answers):
    """serve with pair_of giving `answers` in turn, the last one again;
    what it said, on each stream, and how many times pair_of was asked"""
    said = {"out": [], "err": []}
    asked = []

    def pair_of():
        asked.append(1)
        found = answers[min(len(asked), len(answers)) - 1]
        if isinstance(found, Exception):
            raise found
        return found

    stop = threading.Event()
    with mock.patch.object(dbposition, "POLL", 0):
        timer = threading.Timer(5, stop.set)
        timer.start()
        try:
            dbposition.serve(here, pair_of, stop, said["err"].append,
                             runner=mock.Mock(side_effect=OSError),
                             out=said["out"].append)
        finally:
            timer.cancel()
    return said, len(asked), stop.is_set()


class TestServe(unittest.TestCase):
    """keel#313: a one-node node has no pair and no WireGuard key"""

    def test_a_node_with_no_pair_ends_with_one_line_and_no_key_read(self):
        here = KeylessHere()
        said, asked, stopped = serving(here, [None])
        self.assertFalse(stopped)
        self.assertEqual(asked, 1)
        self.assertEqual(here.asked_key, 0)
        self.assertEqual(said["out"], [dbposition.NOTHING])
        self.assertEqual(said["err"], [])

    def test_a_pair_with_no_key_stops_at_once_and_says_why(self):
        here = KeylessHere()
        with self.assertRaises(dbposition.KeyUnreadable) as caught:
            serving(here, [(VIP, True)])
        self.assertIn(NO_KEY, str(caught.exception))
        self.assertEqual(here.asked_key, 1)

    def test_a_replica_with_no_key_stops_too(self):
        with self.assertRaises(dbposition.KeyUnreadable):
            serving(KeylessHere(), [(VIP, False)])

    def test_a_holder_with_its_key_publishes_and_reads_the_key_once(self):
        here = KeyedHere()
        answers = [(VIP, True)] * (dbposition.DELAY + 2) + [None]
        said = {"out": [], "err": []}
        asked = []

        def pair_of():
            asked.append(1)
            return answers[len(asked) - 1]

        sample = subprocess.CompletedProcess([], 0, "0-1-100\t0\t1\tON\n", "")
        with mock.patch.object(dbposition, "POLL", 0):
            dbposition.serve(here, pair_of, threading.Event(),
                             said["err"].append,
                             runner=mock.Mock(return_value=sample),
                             out=said["out"].append)
        self.assertEqual(here.asked_key, 1)
        self.assertEqual(said["err"], [])
        here.client.put.assert_called_once_with(
            dbposition.key("mesh", VIP),
            dbposition.Record("0-1-100", False, "holder-key").text())

    def test_an_error_that_can_pass_is_said_once_and_the_loop_goes_on(self):
        here = KeylessHere()
        down = EtcdError("etcd does not answer")
        said, asked, stopped = serving(here, [down, down, down, None])
        self.assertFalse(stopped)
        self.assertEqual(asked, 4)
        self.assertEqual(said["err"],
                         ["database position: etcd does not answer"])
        self.assertEqual(here.asked_key, 0)


ONE_NODE = """\
version: 1
appliance:
  name: {name}
installation:
  mode: cloud_simple
database:
  server:
    engine: {engine}
    role: standalone
    listen:
      - "::1"
"""


class TestUnit(unittest.TestCase):
    """What keel-database-position.service runs, on a node as the 0090
    test found it (keel#313)"""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.root)
        patcher = mock.patch("keel.manifest.machine.ROOT_UID", os.getuid())
        patcher.start()
        self.addCleanup(patcher.stop)
        # main sets SIGTERM and SIGINT handlers: not on the test runner
        patcher = mock.patch("keel.system.dbpositionunit.signal.signal")
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_main(self, engine: str, name: str):
        path = os.path.join(self.root, "instance.yaml")
        with open(path, "w") as fob:
            fob.write(ONE_NODE.format(engine=engine, name=name))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = dbpositionunit.main(self.root, path)
        return code, out.getvalue(), err.getvalue()

    def test_a_one_node_postgresql_node_exits_0_with_one_line(self):
        code, out, err = self.run_main("postgresql", "postgresql")
        self.assertEqual(code, exits.OK)
        self.assertEqual(out.splitlines(), [dbposition.NOTHING])
        self.assertEqual(err, "")

    def test_a_one_node_mariadb_node_exits_0_with_one_line(self):
        code, out, err = self.run_main("mariadb", "mariadb")
        self.assertEqual(code, exits.OK)
        self.assertEqual(out.splitlines(), [dbposition.NOTHING])
        self.assertEqual(err, "")

    def test_a_pair_with_no_key_fails_once_with_one_line(self):
        err = io.StringIO()
        with mock.patch.object(dbfollow, "_here",
                               return_value=KeylessHere()), \
                mock.patch.object(dbpositionunit, "pair_of",
                                  return_value=(VIP, True)), \
                contextlib.redirect_stderr(err):
            code = dbpositionunit.main(self.root, "unused.yaml")
        self.assertEqual(code, exits.SECRET_ERROR)
        lines = err.getvalue().splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn(NO_KEY, lines[0])
        self.assertNotIn("Traceback", err.getvalue())


class TestUnitOnAPair(Pair):
    """The real pair_of on a node of a MariaDB pair under etcd whose key
    file is not there: a pair, and so a failure, not nothing to publish"""

    def setUp(self):
        super().setUp()
        patcher = mock.patch("keel.system.dbpositionunit.signal.signal")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.nodes()
        self.here = self.all[0]
        doc = self.here.node.document()
        doc["database"] = {"server": {"engine": "mariadb",
                                      "role": "primary"}}
        self.here.node.write(doc)

    def test_a_mariadb_pair_with_no_key_file_fails_with_exit_4(self):
        no_key = (None, "/etc/wireguard/wg0.key: secret file not found")
        err = io.StringIO()
        with mock.patch("keel.system.dbpair.wgkeys.public",
                        return_value=no_key), \
                mock.patch.object(self.here.node, "public_key",
                                  return_value=no_key), \
                mock.patch.object(dbposition, "with_etcd",
                                  return_value=True), \
                mock.patch.object(dbfollow, "_here", return_value=self.here):
            found = dbpositionunit.pair_of(self.here.root,
                                           self.here.node.path,
                                           self.here)
            with contextlib.redirect_stderr(err):
                code = dbpositionunit.main(self.here.root,
                                           self.here.node.path)
        self.assertEqual(found[0], PAIR_VIP)
        self.assertEqual(code, exits.SECRET_ERROR)
        self.assertIn("secret file not found", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


UNIT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(
    __file__))), "debian", "keel.keel-database-position.service")


class TestUnitFile(unittest.TestCase):
    """A key that cannot be read is no cause for systemd to start the
    unit again each 5 s until its start limit (keel#313)"""

    def setUp(self):
        with open(UNIT) as fob:
            self.lines = [line.strip() for line in fob
                          if not line.startswith("#")]

    def test_the_exit_of_a_key_that_cannot_be_read_is_not_restarted(self):
        self.assertIn(f"RestartPreventExitStatus={exits.SECRET_ERROR}",
                      self.lines)

    def test_other_failures_are_still_restarted(self):
        self.assertIn("Restart=on-failure", self.lines)


if __name__ == "__main__":
    unittest.main()
