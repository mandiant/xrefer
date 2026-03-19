"""Tests for the backend abstraction contract"""

from __future__ import annotations
import unittest
from typing import Iterator, Optional, Sequence
from xrefer_new.backend import BackEnd, CallSite, Function, ImportEntry, Segment, StringArtifact


class FakeBackEnd(BackEnd):
    """Simple in memory backend for contract testing"""

    def __init__(
        self,
        functions: Sequence[Function],
        call_sites: Sequence[CallSite],
        entry_points: Sequence[int] = (),
        image_base: int = 0x1000,
    ) -> None:
        self._functions = tuple(functions)
        self._call_sites = tuple(call_sites)
        self._entry_points = tuple(entry_points)
        self._image_base = image_base
        self._function_map = {function.start_ea: function for function in self._functions}

    @property
    def name(self) -> str:
        return "fake"
    def get_image_base(self) -> int:
        return self._image_base

    def get_input_sha256(self) -> Optional[str]:
        return None

    def get_entry_points(self) -> Sequence[int]:
        return self._entry_points

    def iter_segments(self) -> Iterator[Segment]:
        return iter(())

    def iter_functions(self) -> Iterator[Function]:
        return iter(self._functions)

    def get_function(self, ea: int) -> Optional[Function]:
        return self._function_map.get(ea)

    def get_function_containing(self, ea: int) -> Optional[Function]:
        for function in self._functions:
            if function.start_ea <= ea < function.end_ea:
                return function
        return None

    def iter_imports(self) -> Iterator[ImportEntry]:
        return iter(())

    def iter_strings(self) -> Iterator[StringArtifact]:
        return iter(())

    def iter_call_sites(self, func_ea: Optional[int] = None) -> Iterator[CallSite]:
        if func_ea is None:
            return iter(self._call_sites)
        return iter(callsite for callsite in self._call_sites if callsite.caller_ea == func_ea)


class BackEndContractTests(unittest.TestCase):
    def test_validate_accepts_consistent_backend(self) -> None:
        backend = FakeBackEnd(
            functions=(
                Function(0x1000, 0x1010, "entry"),
                Function(0x2000, 0x2010, "worker"),
            ),
            call_sites=(
                CallSite(0x1000, 0x1004, 0x2000),
            ),
            entry_points=(0x1000,),
        )

        self.assertEqual(backend.validate(), [])

    def test_validate_reports_missing_caller(self) -> None:
        backend = FakeBackEnd(
            functions=(Function(0x2000, 0x2010, "worker"),),
            call_sites=(CallSite(0x1000, 0x1004, 0x2000),),
        )
        self.assertIn("missing caller", backend.validate()[0])

    def test_iter_callers_and_callees_helpers(self) -> None:
        callsite_a = CallSite(0x1000, 0x1004, 0x3000)
        callsite_b = CallSite(0x2000, 0x2008, 0x3000)
        backend = FakeBackEnd(
            functions=(
                Function(0x1000, 0x1010, "a"),
                Function(0x2000, 0x2010, "b"),
                Function(0x3000, 0x3010, "c"),
            ),
            call_sites=(callsite_a, callsite_b),
        )

        self.assertEqual(list(backend.iter_callees(0x1000)), [callsite_a])
        self.assertEqual(list(backend.iter_callers(0x3000)), [callsite_a, callsite_b])


if __name__ == "__main__":
    unittest.main()

