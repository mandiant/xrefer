from __future__ import annotations
from typing import Generic, List, Tuple, TypeVar, Set, FrozenSet, Callable
from xrefer._vendor.ascii_graphs.util.utils import remove_first, multiset_compare, scala_set_key, scala_immutable_set_key

V = TypeVar("V")


class Graph(Generic[V]):
    def __init__(self, vertices, edges, _vertex_order=None):
        self.vertices: FrozenSet = frozenset(vertices)
        self.edges: List[Tuple] = [tuple(e) for e in edges]
        # Preserve insertion order for replicating Scala Set1-4 iteration order (n<=4)
        if _vertex_order is not None:
            self._vertex_order: List = list(_vertex_order)
        elif isinstance(vertices, (list, tuple)):
            self._vertex_order = list(vertices)
        else:
            self._vertex_order = list(vertices)
        # Derived maps
        self._out_map: dict = {}
        self._in_map: dict = {}
        for (src, dst) in self.edges:
            self._out_map.setdefault(src, []).append(dst)
            self._in_map.setdefault(dst, []).append(src)

    @classmethod
    def from_diagram(cls, s) -> Graph:
        from xrefer._vendor.ascii_graphs.diagram.diagram import Diagram
        from xrefer._vendor.ascii_graphs.graph.diagram_to_graph_converter import DiagramToGraphConverter
        if isinstance(s, str):
            d = Diagram(s)
        else:
            d = s
        return DiagramToGraphConverter.to_graph(d)

    def is_empty(self) -> bool:
        return len(self.vertices) == 0

    def in_edges(self, v) -> List[Tuple]:
        return [e for e in self.edges if e[1] == v]

    def out_edges(self, v) -> List[Tuple]:
        return [e for e in self.edges if e[0] == v]

    def in_vertices(self, v) -> List:
        return self._in_map.get(v, [])

    def out_vertices(self, v) -> List:
        return self._out_map.get(v, [])

    def out_degree(self, v) -> int:
        return len(self.out_vertices(v))

    def in_degree(self, v) -> int:
        return len(self.in_vertices(v))

    @property
    def sources(self) -> List:
        return sorted([v for v in self.vertices if self.in_degree(v) == 0], key=scala_set_key)

    @property
    def sinks(self) -> List:
        return sorted([v for v in self.vertices if self.out_degree(v) == 0], key=scala_set_key)

    def remove_edge(self, edge: Tuple) -> Graph:
        return Graph(self.vertices, remove_first(self.edges, tuple(edge)))

    def remove_vertex(self, v) -> Graph:
        new_vertices = frozenset(u for u in self.vertices if u != v)
        new_edges = [(a, b) for (a, b) in self.edges if a != v and b != v]
        return Graph(new_vertices, new_edges)

    def map(self, f: Callable) -> Graph:
        return Graph(
            vertices={f(v) for v in self.vertices},
            edges=[(f(a), f(b)) for a, b in self.edges],
        )

    def copy(self, vertices=None, edges=None) -> Graph:
        new_vertices = self.vertices if vertices is None else vertices
        if vertices is None:
            return Graph(new_vertices, self.edges if edges is None else edges,
                         _vertex_order=self._vertex_order)
        return Graph(new_vertices, self.edges if edges is None else edges)

    def __eq__(self, other):
        if not isinstance(other, Graph):
            return NotImplemented
        return (multiset_compare(list(self.vertices), list(other.vertices)) and
                multiset_compare(self.edges, other.edges))

    def __hash__(self):
        return hash(self.vertices) + hash(tuple(sorted(str(e) for e in self.edges)))

    def __repr__(self):
        return f"Graph(vertices={set(self.vertices)!r}, edges={self.edges!r})"
