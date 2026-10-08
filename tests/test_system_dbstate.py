# Copyright (c) 2026 KeelLinux maintainers
"""What the database phase reads before it decides anything

keel.system.dbstate is the only part of the phase with a side effect. It
asks the server the questions keel.inspect already puts to it, so the
phase that reconfigures a machine cannot disagree with the phase that
reports what the machine is.
"""

import os
import stat
import subprocess
import unittest
from unittest import mock

from helpers import spec  # noqa: F401

from keel.inspect.tree import File
from keel.system import dbready, dbseed
from keel.system.dbmariadb import PING
from keel.system.dbstate import (
    Credential,
    credential,
    declared_server,
    needs_copy,
    observe_database,
)

PASSWORD = "a-replication-password"


def declaring(**server) -> dict:
    return {"database": {"server": {"engine": "mariadb", **server}}}


def answer(stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess([], 0, stdout, "")


class TestWhatIsRead(unittest.TestCase):
    def test_a_description_with_no_server_reads_nothing_at_all(self):
        with mock.patch.object(subprocess, "run") as run:
            self.assertIsNone(observe_database("/", {}))
        run.assert_not_called()

    def test_an_engine_that_is_not_one_of_the_three_asks_nothing(self):
        doc = {"database": {"server": {"engine": "oracle", "role": "x"}}}
        with mock.patch.object(subprocess, "run") as run:
            found = observe_database("/", doc)
        run.assert_not_called()
        self.assertEqual(found.engine, "oracle")
        self.assertFalse(found.installed)

    def test_a_root_with_no_server_binary_asks_nothing(self, ):
        with mock.patch.object(subprocess, "run") as run:
            found = observe_database("/nonexistent", declaring(role="x"))
        run.assert_not_called()
        self.assertFalse(found.installed)
        self.assertFalse(found.live)

    def test_an_offline_root_with_a_binary_records_why_it_asked_nothing(self):
        root = self.tree()
        with mock.patch.object(subprocess, "run") as run:
            found = observe_database(root, declaring(role="standalone"))
        run.assert_not_called()
        self.assertTrue(found.installed)
        self.assertFalse(found.live)
        self.assertFalse(found.reading.role.known)
        self.assertIn("not the live system", found.schemas.problem)

    def test_the_machine_id_and_the_drop_in_come_off_the_tree(self):
        root = self.tree(machine_id="abc\n", dropin="server_id = 1\n")
        found = observe_database(root, declaring(role="standalone"))
        self.assertEqual(found.machine_id.text, "abc\n")
        self.assertEqual(found.dropin.text, "server_id = 1\n")

    def tree(self, machine_id: str = "", dropin: str | None = None) -> str:
        """A scratch root that looks like a machine running MariaDB"""
        root = self.enterContext(
            __import__("tempfile").TemporaryDirectory()
        )
        os.makedirs(os.path.join(root, "usr/sbin"))
        open(os.path.join(root, "usr/sbin/mariadbd"), "w").close()
        os.makedirs(os.path.join(root, "etc"))
        if machine_id:
            with open(os.path.join(root, "etc/machine-id"), "w") as fob:
                fob.write(machine_id)
        if dropin is not None:
            path = os.path.join(root, "etc/mysql/mariadb.conf.d")
            os.makedirs(path)
            with open(os.path.join(path, "99-keel-database.cnf"), "w") as fob:
                fob.write(dropin)
        return root


class TestTheServerIsUpBeforeItIsAsked(unittest.TestCase):
    """The first boot race: a server still starting was asked and refused"""

    def live(self, engine: str = "mariadb", binary: str = "usr/sbin/mariadbd"):
        root = self.enterContext(
            __import__("tempfile").TemporaryDirectory()
        )
        os.makedirs(os.path.join(root, os.path.dirname(binary)))
        open(os.path.join(root, binary), "w").close()
        os.makedirs(os.path.join(root, "etc"))
        with open(os.path.join(root, "etc/machine-id"), "w") as fob:
            fob.write("abc\n")
        self.enterContext(
            mock.patch("keel.inspect.constants.ROOT_DEFAULT", root)
        )
        doc = {"database": {"server": {"engine": engine,
                                       "role": "primary"}}}
        return root, doc

    def test_a_server_that_does_not_come_up_is_asked_nothing_else(self):
        root, doc = self.live()
        with mock.patch.object(dbready, "ready",
                               return_value="mariadb is failed") as ready, \
                mock.patch.object(subprocess, "run") as run:
            found = observe_database(root, doc, start=True)
        ready.assert_called_once_with(
            "mariadb", PING, True, dbready.READY_TIMEOUT
        )
        run.assert_not_called()
        self.assertEqual(found.down, "mariadb is failed")
        self.assertTrue(found.installed)
        self.assertFalse(found.reading.role.known)
        self.assertEqual(found.machine_id.text, "abc\n")

    def test_a_server_that_is_up_is_asked_as_before(self):
        root, doc = self.live()
        with mock.patch.object(dbready, "ready", return_value="") as ready, \
                mock.patch.object(subprocess, "run",
                                  return_value=answer("")) as run:
            found = observe_database(root, doc)
        self.assertEqual(ready.call_args.args[2], False)
        self.assertEqual(found.down, "")
        self.assertTrue(found.reading.role.known)
        self.assertTrue(run.called)

    def test_whether_it_starts_at_boot_is_read_once_it_answers(self):
        root, doc = self.live()
        with mock.patch.object(dbready, "ready", return_value=""), \
                mock.patch.object(dbready, "enabled",
                                  return_value="disabled") as enabled, \
                mock.patch.object(subprocess, "run",
                                  return_value=answer("")):
            found = observe_database(root, doc, start=True)
        enabled.assert_called_once_with("mariadb")
        self.assertEqual(found.enabled, "disabled")

    def test_an_engine_keel_does_not_configure_is_not_started(self):
        root, doc = self.live(
            "redis", "usr/bin/redis-server"
        )
        with mock.patch.object(dbready, "ready") as ready, \
                mock.patch.object(subprocess, "run",
                                  return_value=answer("")):
            found = observe_database(root, doc, start=True)
        ready.assert_not_called()
        self.assertEqual(found.down, "")

    def test_the_system_observation_passes_the_permission_on(self):
        from keel.system import state
        root = self.enterContext(
            __import__("tempfile").TemporaryDirectory()
        )
        for start in (True, False):
            with mock.patch.object(state, "observe_database",
                                   return_value=None) as observed:
                state.observe(root, {}, start=start)
            observed.assert_called_once_with(root, {}, start, None)

    def test_an_offline_root_starts_nothing(self):
        root, doc = self.live()
        with mock.patch("keel.inspect.constants.ROOT_DEFAULT", "/"), \
                mock.patch.object(dbready, "ready") as ready:
            found = observe_database(root, doc, start=True)
        ready.assert_not_called()
        self.assertFalse(found.live)
        self.assertEqual(found.down, "")


class TestTheCredential(unittest.TestCase):
    """The one secret --system-only resolves, and every way it fails"""

    def secret_file(self, value: str, mode: int = 0o600) -> str:
        root = self.enterContext(
            __import__("tempfile").TemporaryDirectory()
        )
        path = os.path.join(root, "replication_password")
        with open(path, "w") as fob:
            fob.write(value)
        os.chmod(path, mode)
        return path

    def test_a_file_reference_is_read(self):
        path = self.secret_file(PASSWORD + "\n")
        found = credential({"replication": {"secret": {"file": path}}})
        self.assertEqual(found, Credential(value=PASSWORD))
        self.assertTrue(found.known)

    def test_no_secret_declared_says_what_a_grant_would_authenticate(self):
        found = credential({"replication": {}})
        self.assertFalse(found.known)
        self.assertIn("authenticates nothing", found.problem)

    def test_a_generated_credential_is_refused_with_the_reason(self):
        found = credential({"replication": {"secret": {"generate": True}}})
        self.assertIn("both ends of a pair must hold the same value",
                      found.problem)

    def test_a_file_anybody_can_read_is_refused_by_the_secret_store(self):
        path = self.secret_file(PASSWORD, mode=0o644)
        found = credential({"replication": {"secret": {"file": path}}})
        self.assertIn("0600", found.problem)
        self.assertTrue(stat.S_IMODE(os.stat(path).st_mode) == 0o644)

    def test_a_file_that_is_not_there_is_refused(self):
        found = credential(
            {"replication": {"secret": {"file": "/nonexistent/secret"}}}
        )
        self.assertIn("not found", found.problem)

    def test_a_credential_holding_a_control_character_is_refused(self):
        # It would go into a statement, and MariaDB spells three control
        # characters and no others, so it is refused rather than mangled.
        path = self.secret_file("bad\x00value")
        found = credential({"replication": {"secret": {"file": path}}})
        self.assertIn("control character", found.problem)

    def test_a_credential_with_punctuation_is_kept_as_it_is(self):
        value = "a'b\\c\"d;e"
        path = self.secret_file(value)
        found = credential({"replication": {"secret": {"file": path}}})
        self.assertEqual(found.value, value)


class TestDeclaredServer(unittest.TestCase):
    def test_a_description_without_the_section_is_an_empty_mapping(self):
        self.assertEqual(declared_server({}), {})
        self.assertEqual(declared_server({"database": None}), {})
        self.assertEqual(declared_server({"database": {"client": {}}}), {})


REPLICA_OF = (
    "*************************** 1. row ***************************\n"
    "                   Master_Host: 2001:db8:1::10\n"
    "                   Master_Port: 3306\n"
    "            Slave_SQL_Running: {running}\n"
)


class TestTheCopyIsAskedForOnlyWhenOneWouldBeMade(unittest.TestCase):
    """The primary is dialled before a seed, and never for a healthy one"""

    SERVER = {
        "engine": "mariadb", "role": "replica",
        "replication": {"primary": {"host": "2001:db8:1::10"}},
    }

    def needs(self, status: str = "", **server) -> bool:
        return needs_copy(
            dict(self.SERVER, **server), File("status", status)
        )

    def test_a_node_that_replicates_from_nowhere_needs_one(self):
        self.assertTrue(self.needs(""))

    def test_a_healthy_replica_of_the_declared_primary_does_not(self):
        self.assertFalse(self.needs(REPLICA_OF.format(running="Yes")))

    def test_a_replica_whose_sql_thread_stopped_does(self):
        self.assertTrue(self.needs(REPLICA_OF.format(running="No")))

    def test_a_replica_of_another_primary_does(self):
        self.assertTrue(self.needs(
            REPLICA_OF.format(running="Yes").replace("::10", "::20")
        ))

    def test_another_port_is_another_primary(self):
        self.assertTrue(self.needs(
            REPLICA_OF.format(running="Yes"),
            replication={"primary": {"host": "2001:db8:1::10",
                                     "port": 3307}},
        ))

    def test_a_primary_or_a_standalone_never_does(self):
        self.assertFalse(self.needs("", role="primary"))
        self.assertFalse(self.needs("", role="standalone"))

    def test_a_replica_with_no_primary_declared_does_not(self):
        self.assertFalse(self.needs("", replication={}))


class TestThePrimaryIsAskedOnTheLiveSystem(unittest.TestCase):
    def observe(self, status: str, secret: bool = True):
        root = self.enterContext(
            __import__("tempfile").TemporaryDirectory()
        )
        os.makedirs(os.path.join(root, "usr/sbin"))
        open(os.path.join(root, "usr/sbin/mariadbd"), "w").close()
        path = os.path.join(root, "secret")
        with open(path, "w") as fob:
            fob.write(PASSWORD)
        os.chmod(path, 0o600)
        server = dict(TestTheCopyIsAskedForOnlyWhenOneWouldBeMade.SERVER)
        if secret:
            server["replication"] = dict(
                server["replication"], secret={"file": path}
            )

        def ran(argv, **kwargs):
            if "SHOW REPLICA STATUS\\G" in argv:
                return answer(status)
            return answer("")
        with mock.patch("keel.inspect.constants.ROOT_DEFAULT", root), \
                mock.patch.object(subprocess, "run", side_effect=ran), \
                mock.patch.object(dbseed, "reach", return_value=dbseed.Reach(
                    "refused", ("'wordpress'@'localhost'",),
                )) as reach:
            found = observe_database(root, {"database": {"server": server}})
        return found, reach, root

    def test_a_node_about_to_be_seeded_asks_the_primary(self):
        found, reach, root = self.observe("")
        reach.assert_called_once_with(
            os.path.abspath(root), "2001:db8:1::10", 3306, PASSWORD
        )
        self.assertEqual(found.reach, "refused")
        self.assertEqual(found.shared, ("'wordpress'@'localhost'",))
        self.assertEqual(found.status.text, "")

    def test_a_healthy_replica_asks_nobody(self):
        found, reach, _ = self.observe(REPLICA_OF.format(running="Yes"))
        reach.assert_not_called()
        self.assertEqual(found.reach, "")
        self.assertEqual(found.shared, ())
        self.assertIn("Slave_SQL_Running: Yes", found.status.text)

    def test_no_credential_asks_nobody(self):
        found, reach, _ = self.observe("", secret=False)
        reach.assert_not_called()
