"""Tests for backend agnostic callgraph analysis"""

from __future__ import annotations
import unittest
from xrefer_new.analysis import CallGraphAnalyzer
from xrefer_new.backend import CallSite, Function
from tests.test_backend_contract import FakeBackEnd

class CallGraphAnalyzerTests(unittest.TestCase):
    def test_branching_paths_are_preserved(self) -> None:
        backend = FakeBackEnd(
            functions=(
                Function(0x1000, 0x1010, "entry"),
                Function(0x2000, 0x2010, "left"),
                Function(0x3000, 0x3010, "right"),
                Function(0x4000, 0x4010, "leaf"),
                Function(0x5000, 0x5010, "other_leaf"),
            ),
            call_sites=(
                CallSite(0x1000, 0x1001, 0x2000),
                CallSite(0x1000, 0x1002, 0x3000),
                CallSite(0x2000, 0x2001, 0x4000),
                CallSite(0x3000, 0x3001, 0x4000),
                CallSite(0x3000, 0x3002, 0x5000),
            ),
            entry_points=(0x1000,),
        )

        analyzer = CallGraphAnalyzer(backend)
        all_paths = analyzer.generate_all_simple_call_paths(0x1000)

        self.assertEqual(
            all_paths[0x4000],
            [
                [0x1000, 0x2000, 0x4000],
                [0x1000, 0x3000, 0x4000],
            ],
        )
        self.assertEqual(all_paths[0x5000], [[0x1000, 0x3000, 0x5000]])

    def test_cycles_do_not_create_infinite_paths(self) -> None:
        backend = FakeBackEnd(
            functions=(
                Function(0x1000, 0x1010, "entry"),
                Function(0x2000, 0x2010, "loop_a"),
                Function(0x3000, 0x3010, "loop_b"),
                Function(0x4000, 0x4010, "leaf"),
            ),
            call_sites=(
                CallSite(0x1000, 0x1001, 0x2000),
                CallSite(0x2000, 0x2001, 0x3000),
                CallSite(0x3000, 0x3001, 0x2000),
                CallSite(0x3000, 0x3002, 0x4000),
            ),
            entry_points=(0x1000,),
        )

        analyzer = CallGraphAnalyzer(backend)
        paths = analyzer.generate_simple_call_paths(0x1000, 0x4000)

        self.assertEqual(paths, [[0x1000, 0x2000, 0x3000, 0x4000]])

    def test_reachable_leaf_detection_is_entrypoint_scoped(self) -> None:
        backend = FakeBackEnd(
            functions=(
                Function(0x1000, 0x1010, "entry_a"),
                Function(0x1100, 0x1110, "entry_b"),
                Function(0x2000, 0x2010, "shared"),
                Function(0x3000, 0x3010, "leaf_a"),
                Function(0x4000, 0x4010, "leaf_b"),
            ),
            call_sites=(
                CallSite(0x1000, 0x1001, 0x2000),
                CallSite(0x2000, 0x2001, 0x3000),
                CallSite(0x1100, 0x1101, 0x4000),
            ),
            entry_points=(0x1000, 0x1100),
        )

        analyzer = CallGraphAnalyzer(backend)

        self.assertEqual(analyzer.reachable_leaf_functions(0x1000), {0x3000})
        self.assertEqual(analyzer.reachable_leaf_functions(0x1100), {0x4000})


if __name__ == "__main__":
    unittest.main()

