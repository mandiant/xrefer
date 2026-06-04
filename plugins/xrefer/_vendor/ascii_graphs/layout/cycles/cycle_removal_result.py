from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Tuple
from xrefer._vendor.ascii_graphs.graph.graph import Graph


@dataclass
class CycleRemovalResult:
    dag: Graph
    reversed_edges: List[Tuple]
    self_edges: List[Tuple]

    def count_self_edges(self, v) -> int:
        return sum(1 for e in self.self_edges if e[0] == v)
