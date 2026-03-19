from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set
from xrefer_new.backend.base import BackEnd


@dataclass
class CallGraphIndex:
    """Indexed callgraph"""
    functions: Set[int] = field(default_factory=set)
    callers_by_callee: Dict[int, Set[int]] = field(default_factory=dict)
    callees_by_caller: Dict[int, Set[int]] = field(default_factory=dict)
    @classmethod
    def from_backend(cls, backend: BackEnd) -> "CallGraphIndex":
        callers_by_callee: Dict[int, Set[int]] = defaultdict(set)
        callees_by_caller: Dict[int, Set[int]] = defaultdict(set)
        functions = {function.start_ea for function in backend.iter_functions()}

        for callsite in backend.iter_call_sites():
            callers_by_callee[callsite.callee_ea].add(callsite.caller_ea)
            callees_by_caller[callsite.caller_ea].add(callsite.callee_ea)
            functions.add(callsite.caller_ea)
            functions.add(callsite.callee_ea)

        return cls(
            functions=functions,
            callers_by_callee={key: set(value) for key, value in callers_by_callee.items()},
            callees_by_caller={key: set(value) for key, value in callees_by_caller.items()},
        )

    def callers_of(self, callee_ea: int) -> Set[int]:
        return self.callers_by_callee.get(callee_ea, set())

    def callees_of(self, caller_ea: int) -> Set[int]:
        return self.callees_by_caller.get(caller_ea, set())

    def leaf_functions(self, reachable_subset: Optional[Set[int]] = None) -> Set[int]:
        """Return functions with no outgoing edges in the provided subset."""
        candidates = self.functions if reachable_subset is None else reachable_subset
        return {
            func_ea
            for func_ea in candidates
            if not (self.callees_of(func_ea) & candidates)
        }

class CallGraphAnalyzer:
    """Pure python path analysis built on top of the backend abstraction"""

    def __init__(self, backend: BackEnd, index: Optional[CallGraphIndex] = None) -> None:
        self.index = index or CallGraphIndex.from_backend(backend)
    def reachable_from(self, entrypoint: int) -> Set[int]:
        """Return the forward-reachable subgraph from entrypoint."""
        if entrypoint not in self.index.functions:
            return set()

        reachable = {entrypoint}
        queue = deque([entrypoint])

        while queue:
            node = queue.popleft()
            for callee in sorted(self.index.callees_of(node)):
                if callee in reachable:
                    continue
                reachable.add(callee)
                queue.append(callee)

        return reachable
    def reachable_leaf_functions(self, entrypoint: int) -> Set[int]:
        """Return leaf functions reachable from entrypoint"""
        reachable = self.reachable_from(entrypoint)
        if not reachable:
            return set()
        return {
            func_ea
            for func_ea in self.index.leaf_functions(reachable)
            if func_ea != entrypoint
        }

    def generate_simple_call_paths(
        self,
        entrypoint: int,
        target: int,
        max_limit: int = 10_000,
    ) -> List[List[int]]:
        """Generate simple call paths from entrypoint to target
            The implementation intentionally mirrors the path-building logic
            from the current IDA plugin, but it now consumes backend-normalized
            call edges instead of IDA apis directly
        """
        if entrypoint == target:
            return [[entrypoint]]
        if entrypoint not in self.index.functions or target not in self.index.functions:
            return []

        all_paths: List[List[int]] = []
        path_buffer: deque[List[int]] = deque([[target]])

        while path_buffer and len(all_paths) < max_limit and len(path_buffer) < max_limit:
            current_path = path_buffer.popleft()
            current_target = current_path[-1]
            callers = self.index.callers_of(current_target)

            if not callers:
                continue
            for caller in sorted(callers):
                if caller in current_path:
                    continue

                next_path = current_path + [caller]
                if caller == entrypoint:
                    path = list(reversed(next_path))
                    if path not in all_paths:
                        all_paths.append(path)
                else:
                    path_buffer.append(next_path)

        return all_paths
    def generate_all_simple_call_paths(
        self,
        entrypoint: int,
        targets: Optional[Iterable[int]] = None,
        max_limit: int = 10_000,
    ) -> Dict[int, List[List[int]]]:
        """Generate all simple paths from entrypoint to reachable leaves"""
        if targets is None:
            targets = sorted(self.reachable_leaf_functions(entrypoint))

        results: Dict[int, List[List[int]]] = {}
        for target in targets:
            if target == entrypoint:
                continue
            paths = self.generate_simple_call_paths(entrypoint, target, max_limit=max_limit)
            if paths:
                results[target] = paths
        return results
