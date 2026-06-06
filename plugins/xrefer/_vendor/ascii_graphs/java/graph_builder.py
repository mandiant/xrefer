"""Port of com.github.mdr.ascii.java.GraphBuilder (GraphBuilder.java). STUB."""
from __future__ import annotations


class GraphBuilder:
    def __init__(self):
        self._vertices = set()
        self._edges = []

    def add_vertex(self, v):
        self._vertices.add(v)
        return self

    def add_edge(self, v1, v2):
        self._vertices.add(v1)
        self._vertices.add(v2)
        self._edges.append((v1, v2))
        return self

    def build(self):
        from xrefer._vendor.ascii_graphs.graph.graph import Graph
        return Graph(vertices=self._vertices, edges=self._edges)
