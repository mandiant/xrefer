from __future__ import annotations
from xrefer._vendor.ascii_graphs.graph.graph import Graph


class CycleRemovalInfo:
    """Tracks degree-diff info during cycle removal."""

    def __init__(self, graph: Graph):
        self._graph = graph
        self._sources: set = set(graph.sources)
        self._sinks: set = set(graph.sinks)
        self._vertices_to_degree_diff: dict = {}
        self._degree_diff_to_vertices: dict = {}  # sorted int -> list
        self._deleted_vertices: set = set()

        from xrefer._vendor.ascii_graphs.util.utils import scala_set_key
        # Scala Set1-4 (n<=4) iterates in insertion order; HashSet (n>=5) iterates in _improve hash order
        if len(graph.vertices) <= 4:
            vertex_iter = graph._vertex_order
        else:
            vertex_iter = sorted(graph.vertices, key=scala_set_key)
        for v in vertex_iter:
            self._add_vertex_to_degree_diff_maps(v, graph.out_degree(v) - graph.in_degree(v))

    def get_sources(self) -> set:
        return self._sources

    def get_sinks(self) -> set:
        return self._sinks

    def get_largest_degree_diff_vertex(self):
        if not self._degree_diff_to_vertices:
            return None
        max_key = max(self._degree_diff_to_vertices.keys())
        lst = self._degree_diff_to_vertices[max_key]
        return lst[0] if lst else None

    def remove_vertex(self, v):
        self._deleted_vertices.add(v)
        self._sinks.discard(v)
        self._sources.discard(v)
        self._remove_vertex_from_degree_diff_maps(v)

        for out_v in self._get_out_vertices(v):
            self._adjust_degree_diff(out_v, +1)
            if not self._get_in_vertices(out_v):
                self._sources.add(out_v)
        for in_v in self._get_in_vertices(v):
            self._adjust_degree_diff(in_v, -1)
            if not self._get_out_vertices(in_v):
                self._sinks.add(in_v)

    def _get_in_vertices(self, v) -> list:
        return [u for u in self._graph.in_vertices(v) if u not in self._deleted_vertices]

    def _get_out_vertices(self, v) -> list:
        return [u for u in self._graph.out_vertices(v) if u not in self._deleted_vertices]

    def _adjust_degree_diff(self, v, delta: int):
        prev = self._remove_vertex_from_degree_diff_maps(v)
        self._add_vertex_to_degree_diff_maps(v, prev + delta)

    def _add_vertex_to_degree_diff_maps(self, v, degree_diff: int):
        lst = self._degree_diff_to_vertices.get(degree_diff, [])
        self._degree_diff_to_vertices[degree_diff] = [v] + lst
        self._vertices_to_degree_diff[v] = degree_diff

    def _remove_vertex_from_degree_diff_maps(self, v) -> int:
        degree_diff = self._vertices_to_degree_diff.pop(v)
        lst = self._degree_diff_to_vertices[degree_diff]
        updated = [u for u in lst if u != v]
        if not updated:
            del self._degree_diff_to_vertices[degree_diff]
        else:
            self._degree_diff_to_vertices[degree_diff] = updated
        return degree_diff
