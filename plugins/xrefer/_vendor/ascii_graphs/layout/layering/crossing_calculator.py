from __future__ import annotations
from xrefer._vendor.ascii_graphs.layout.layering.layering import Layer, Edge


class CrossingCalculator:
    def __init__(self, layer1: Layer, layer2: Layer, edges: list):
        self._layer1 = layer1
        self._layer2 = layer2
        self._edges = edges

    def crossing_number(self, u, v) -> int:
        if u is v:
            return 0
        count = 0
        for e1 in self._edges:
            if e1.finish_vertex is u:
                w = e1.start_vertex
                for e2 in self._edges:
                    if e2.finish_vertex is v:
                        z = e2.start_vertex
                        if self._layer1.position_of(z) < self._layer1.position_of(w):
                            count += 1
        return count

    def number_of_crossings(self) -> int:
        total = 0
        verts = self._layer2.vertices
        for i, u in enumerate(verts):
            for j, v in enumerate(verts):
                if self._layer2.position_of(u) < self._layer2.position_of(v):
                    total += self.crossing_number(u, v)
        return total
