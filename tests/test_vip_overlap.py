# Copyright (c) 2026 KeelLinux maintainers
"""tests/vip_overlap.py: an overlap is proven only at one instant, a
handover never is one (keel#126)"""

import json
import os
import tempfile
import time
import unittest

import vip_overlap

VIP = "fd00:6b65:f1b::ffff:100"


class TestProven(unittest.TestCase):
    def test_the_order_is_a_palindrome_turned_each_round(self):
        self.assertEqual(vip_overlap.order(["A", "B", "C"], 0),
                         ["A", "B", "C", "C", "B", "A"])
        self.assertEqual(vip_overlap.order(["A", "B", "C"], 1),
                         ["B", "C", "A", "A", "C", "B"])

    def test_the_outer_node_through_and_an_inner_one_overlap(self):
        reads = [("A", True), ("B", True), ("C", False),
                 ("C", False), ("B", False), ("A", True)]
        self.assertEqual(vip_overlap.proven(reads), [("A", "B")])

    def test_a_handover_is_no_overlap(self):
        # A drops it, B adds it, within the round
        reads = [("A", True), ("B", False), ("C", False),
                 ("C", False), ("B", True), ("A", False)]
        self.assertEqual(vip_overlap.proven(reads), [])
        self.assertEqual(vip_overlap.holders(reads), ["A", "B"])

    def test_the_inner_node_through_and_the_outer_one_once(self):
        # not proven in this round: B is outer in the next one
        reads = [("A", False), ("B", True), ("C", False),
                 ("C", False), ("B", True), ("A", True)]
        self.assertEqual(vip_overlap.proven(reads), [])
        turned = [("B", True), ("C", False), ("A", True),
                  ("A", True), ("C", False), ("B", True)]
        self.assertEqual(vip_overlap.proven(turned), [("A", "B")])

    def test_one_holder_is_no_overlap(self):
        reads = [("A", True), ("B", False), ("B", False), ("A", True)]
        self.assertEqual(vip_overlap.proven(reads), [])

    def test_the_vip_as_the_kernel_writes_it(self):
        self.assertEqual(vip_overlap.wanted(VIP),
                         "fd006b650f1b000000000000ffff0100")


class TestWatcher(unittest.TestCase):
    def test_it_reads_this_process_namespace_and_says_it(self):
        with tempfile.TemporaryDirectory() as scratch:
            out = os.path.join(scratch, "overlap.jsonl")
            process = vip_overlap.start(out, VIP, {"A": os.getpid(),
                                                   "B": os.getpid()})
            time.sleep(0.5)
            found = vip_overlap.stop(process, out)
        self.assertTrue(found["ended"], found)
        self.assertGreater(found["rounds"], 10)
        self.assertEqual(found["overlaps"], [])
        self.assertEqual(found["changes"][0]["holders"], [])

    def test_the_summary_of_an_overlap(self):
        with tempfile.TemporaryDirectory() as scratch:
            out = os.path.join(scratch, "overlap.jsonl")
            with open(out, "w") as fob:
                for one in ({"start": 5.0, "wall_offset": 100.0,
                             "names": ["A", "B"]},
                            {"t": 6.0, "until": 6.0001,
                             "holders": ["A", "B"]},
                            {"t": 6.0, "until": 6.0001,
                             "overlap": [["A", "B"]], "reads": []}):
                    fob.write(json.dumps(one) + "\n")
            found = vip_overlap.summary(out)
        self.assertFalse(found["ended"])
        self.assertEqual(found["overlap_rounds"], 1)
        self.assertEqual(found["overlaps"][0]["wall"], 106.0)
        self.assertEqual(found["changes"][0]["holders"], ["A", "B"])

    def test_a_summary_with_no_file(self):
        found = vip_overlap.summary("/nonexistent/overlap.jsonl")
        self.assertIn("error", found)


if __name__ == "__main__":
    unittest.main()
