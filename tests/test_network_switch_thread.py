# Copyright (c) 2026 KeelLinux maintainers
"""keel.network.switch.change from a thread that is not the main one

The members' service applies an announcement from its worker thread
(keel.mesh.sync.announced), and signal.signal is the main thread's
alone: a change run from a worker raised ValueError before anything
moved, the peer landed in the spec and never on wg0 (keel#96).
"""

import signal
import threading
import unittest
from unittest import mock

from helpers import spec  # noqa: F401  (puts the repository on sys.path)

from keel import cli  # noqa: F401  (imports the package in its order)
from keel.network import switch


class TestChangeAndTheHangup(unittest.TestCase):
    def changed(self, seen: dict):
        def fake(root, pending, text, run):
            seen["handler"] = signal.getsignal(signal.SIGHUP)
            return None
        return fake

    def test_in_the_main_thread_a_hangup_is_ignored_while_it_runs(self):
        seen: dict = {}
        before = signal.getsignal(signal.SIGHUP)
        with mock.patch.object(switch, "changed", self.changed(seen)):
            self.assertIsNone(switch.change("/r", None, "", None))
        self.assertIs(seen["handler"], signal.SIG_IGN)
        self.assertIs(signal.getsignal(signal.SIGHUP), before)

    def test_from_a_worker_thread_no_signal_is_touched_and_it_runs(self):
        seen: dict = {}
        before = signal.getsignal(signal.SIGHUP)
        found: list = []
        with mock.patch.object(switch, "changed", self.changed(seen)):
            worker = threading.Thread(target=lambda: found.append(
                switch.change("/r", None, "", None)))
            worker.start()
            worker.join()
        self.assertEqual(found, [None])
        self.assertIs(seen["handler"], before)
        self.assertIs(signal.getsignal(signal.SIGHUP), before)

    def test_the_problem_of_a_change_comes_back_from_a_thread_too(self):
        with mock.patch.object(switch, "changed", return_value="no boot id"):
            found: list = []
            worker = threading.Thread(target=lambda: found.append(
                switch.change("/r", None, "", None)))
            worker.start()
            worker.join()
        self.assertEqual(found, ["no boot id"])


if __name__ == "__main__":
    unittest.main()
