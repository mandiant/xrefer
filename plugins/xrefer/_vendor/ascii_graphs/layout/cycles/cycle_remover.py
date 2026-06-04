from __future__ import annotations
from xrefer._vendor.ascii_graphs.graph.graph import Graph
from xrefer._vendor.ascii_graphs.layout.cycles.cycle_removal_info import CycleRemovalInfo
from xrefer._vendor.ascii_graphs.layout.cycles.cycle_removal_result import CycleRemovalResult


def remove_cycles(graph: Graph) -> CycleRemovalResult:
    remover = _CycleRemover()
    graph_no_loops, self_edges = remover.remove_self_loops(graph)
    graph_no_cycles, reversed_edges = remover.remove_cycles_inner(graph_no_loops)
    return CycleRemovalResult(graph_no_cycles, reversed_edges, self_edges)


class _CycleRemover:

    def remove_self_loops(self, graph: Graph):
        self_edges = [e for e in graph.edges if e[0] == e[1]]
        new_edges = [e for e in graph.edges if e[0] != e[1]]
        return graph.copy(edges=new_edges), self_edges

    def remove_cycles_inner(self, graph: Graph):
        seq = self._find_vertex_sequence(graph)
        return self._reflow_graph(graph, seq)

    def _find_vertex_sequence(self, graph: Graph):
        return _Removal(graph).run().get_sequence()

    def _reflow_graph(self, graph: Graph, vertex_sequence: list):
        vertex_index_map = {v: i for i, v in enumerate(vertex_sequence)}
        new_edges = []
        reversed_edges = []
        for (src, dst) in graph.edges:
            src_idx = vertex_index_map[src]
            dst_idx = vertex_index_map[dst]
            if dst_idx < src_idx:
                reversed_edges.insert(0, (dst, src))
                new_edges.insert(0, (dst, src))
            else:
                new_edges.insert(0, (src, dst))
        return graph.copy(edges=new_edges), reversed_edges


class _Removal:
    def __init__(self, graph: Graph):
        self._info = CycleRemovalInfo(graph)
        self._left = []
        self._right = []

    def run(self) -> _Removal:
        while True:
            self._add_sinks_to_right()
            self._add_sources_to_left()
            v = self._info.get_largest_degree_diff_vertex()
            if v is None:
                break
            self._info.remove_vertex(v)
            self._left.insert(0, v)
        return self

    def _add_sinks_to_right(self):
        from xrefer._vendor.ascii_graphs.util.utils import scala_set_key
        while self._info.get_sinks():
            for v in sorted(self._info.get_sinks(), key=scala_set_key):
                self._info.remove_vertex(v)
                self._right.insert(0, v)

    def _add_sources_to_left(self):
        from xrefer._vendor.ascii_graphs.util.utils import scala_set_key
        while self._info.get_sources():
            for v in sorted(self._info.get_sources(), key=scala_set_key):
                self._info.remove_vertex(v)
                self._left.insert(0, v)

    def get_sequence(self) -> list:
        return list(reversed(self._left)) + self._right

