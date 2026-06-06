from __future__ import annotations
from typing import Tuple, Dict
from xrefer._vendor.ascii_graphs.layout.cycles.cycle_removal_result import CycleRemovalResult
from xrefer._vendor.ascii_graphs.layout.layering.layering import (
    Layering, Layer, Vertex, DummyVertex, RealVertex, Edge
)
from xrefer._vendor.ascii_graphs.layout.layering.longest_distances_to_sink_calculator import longest_distances_to_sink
from xrefer._vendor.ascii_graphs.util.utils import mk_multiset


class LayeringCalculator:

    def assign_layers(self, cycle_removal_result: CycleRemovalResult) -> Tuple[Layering, Dict]:
        graph = cycle_removal_result.dag
        distances = longest_distances_to_sink(graph)
        max_layer_num = max(distances.values()) if distances else -1

        def layer_num(v) -> int:
            return max_layer_num - distances[v]

        builder = _LayeringBuilder(max_layer_num + 1)

        from xrefer._vendor.ascii_graphs.util.utils import scala_set_key
        real_vertices: Dict = self._make_real_vertices(cycle_removal_result)
        # Scala uses Set1-4 for n<=4 (insertion/JSON order) vs HashMap for n>=5 (hash order)
        if len(graph.vertices) <= 4:
            vertex_iter = graph._vertex_order
        else:
            vertex_iter = sorted(graph.vertices, key=scala_set_key)
        for v in vertex_iter:
            builder.add_vertex(layer_num(v), real_vertices[v])

        self._add_edges(cycle_removal_result, layer_num, builder, real_vertices)
        return builder.build(), real_vertices

    def _add_edges(self, crr: CycleRemovalResult, layer_num, builder, real_vertices: Dict):
        rev_edges = mk_multiset(crr.reversed_edges)

        for (src, dst) in crr.dag.edges:
            from_layer = layer_num(src)
            to_layer = layer_num(dst)
            dummies = []
            for ln in range(from_layer + 1, to_layer):
                dummy = DummyVertex()
                builder.add_vertex(ln, dummy)
                dummies.append(dummy)

            vertex_chain = [real_vertices[src]] + dummies + [real_vertices[dst]]
            graph_edge = (src, dst)
            is_reversed = False
            if graph_edge in rev_edges:
                cnt = rev_edges[graph_edge]
                if cnt == 1:
                    del rev_edges[graph_edge]
                else:
                    rev_edges[graph_edge] = cnt - 1
                is_reversed = True

            for v1, v2 in zip(vertex_chain, vertex_chain[1:]):
                builder.add_edge(Edge(v1, v2, is_reversed))

    def _make_real_vertices(self, crr: CycleRemovalResult) -> Dict:
        result = {}
        for v in crr.dag.vertices:
            self_edges = crr.count_self_edges(v)
            result[v] = RealVertex(v, self_edges)
        return result


class _LayeringBuilder:
    def __init__(self, num_layers: int):
        self._layers = [[] for _ in range(num_layers)]
        self._edges = []

    def add_vertex(self, layer_num: int, v: Vertex):
        self._layers[layer_num].append(v)

    def add_edge(self, edge: Edge):
        self._edges.insert(0, edge)

    def build(self) -> Layering:
        return Layering(
            layers=[Layer(list(layer)) for layer in self._layers],
            edges=self._edges,
        )
