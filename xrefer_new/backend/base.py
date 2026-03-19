"""Abstract backend contract for future XRefer platform adapters"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterator, List, Optional, Sequence
from .types import CallSite, Function, ImportEntry, Segment, StringArtifact


class BackEnd(ABC):
    """Standardized interface between XRefer and a disassembly host
    The goal of this interface is to isolate analysis logic from platform APIs.
    A backend implementation should normalize host concepts such as functions,
    imports, and strings into the typed models defined in xrefer_new.backend.types
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the canonical backend name"""

    @abstractmethod
    def get_image_base(self) -> int:
        """Return the primary image base for the loaded program"""

    @abstractmethod
    def get_input_sha256(self) -> Optional[str]:
        """Return the input file when the host can provide"""

    @abstractmethod
    def get_entry_points(self) -> Sequence[int]:
        """Return the hosts known entry points"""

    @abstractmethod
    def iter_segments(self) -> Iterator[Segment]:
        """Yield normalized memory segments"""

    @abstractmethod
    def iter_functions(self) -> Iterator[Function]:
        """Yield normalized functions"""

    @abstractmethod
    def get_function(self, ea: int) -> Optional[Function]:
        """Return the function starting at ea if present"""

    @abstractmethod
    def get_function_containing(self, ea: int) -> Optional[Function]:
        """Return the function containing ea if present"""

    @abstractmethod
    def iter_imports(self) -> Iterator[ImportEntry]:
        """Yield normalized imports."""

    @abstractmethod
    def iter_strings(self) -> Iterator[StringArtifact]:
        """Yield normalized strings."""

    @abstractmethod
    def iter_call_sites(self, func_ea: Optional[int] = None) -> Iterator[CallSite]:
        """Yield normalized call edges.

        When func_ea is provided, only callsites originating from that
        function should be returned.
        """

    def get_function_name(self, ea: int) -> str:
        """Return the function name for a start EA or containing EA"""
        func = self.get_function(ea)
        if func is None:
            func = self.get_function_containing(ea)
        return func.name if func else ""

    def iter_callers(self, callee_ea: int) -> Iterator[CallSite]:
        """Yield callsites targeting callee_ea"""
        for callsite in self.iter_call_sites():
            if callsite.callee_ea == callee_ea:
                yield callsite

    def iter_callees(self, caller_ea: int) -> Iterator[CallSite]:
        """Yield callsites originating from caller_ea"""
        yield from self.iter_call_sites(caller_ea)

    def validate(self) -> List[str]:
        """Run lightweight backend contract validation"""
        issues: List[str] = []
        functions = list(self.iter_functions())
        function_map = {}

        for func in functions:
            if func.start_ea in function_map:
                issues.append(f"duplicate function start 0x{func.start_ea:x}")
            function_map[func.start_ea] = func

            if func.end_ea < func.start_ea:
                issues.append(
                    f"function 0x{func.start_ea:x} has invalid range "
                    f"0x{func.start_ea:x}-0x{func.end_ea:x}"
                )
        for callsite in self.iter_call_sites():
            caller = function_map.get(callsite.caller_ea)
            if caller is None:
                issues.append(
                    f"callsite 0x{callsite.call_ea:x} references missing caller "
                    f"0x{callsite.caller_ea:x}"
                )
                continue

            if not (caller.start_ea <= callsite.call_ea < caller.end_ea):
                issues.append(
                    f"callsite 0x{callsite.call_ea:x} falls outside caller "
                    f"0x{caller.start_ea:x}"
                )

        return issues

