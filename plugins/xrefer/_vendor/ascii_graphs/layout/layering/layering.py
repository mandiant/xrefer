from __future__ import annotations
from dataclasses import dataclass, field
from itertools import count as _count
from typing import List, Optional

_vertex_counter = _count()


class Vertex:
    def __init__(self):
        self._creation_id = next(_vertex_counter)


class DummyVertex(Vertex):
    def __repr__(self):
        return "DummyVertex"


class RealVertex(Vertex):
    def __init__(self, contents, self_edges: int = 0):
        super().__init__()
        self.contents = contents
        self.self_edges = self_edges

    def __repr__(self):
        return f"RealVertex({self.contents!r}, selfEdges={self.self_edges})"


class Edge:
    def __init__(self, start_vertex: Vertex, finish_vertex: Vertex, reversed: bool = False):
        self.start_vertex = start_vertex
        self.finish_vertex = finish_vertex
        self.reversed = reversed

    def __repr__(self):
        return f"Edge({self.start_vertex}, {self.finish_vertex}, {self.reversed})"

    def __iter__(self):
        return iter((self.start_vertex, self.finish_vertex))


class Layer:
    def __init__(self, vertices: List[Vertex]):
        self.vertices = list(vertices)

    def contains(self, v: Vertex) -> bool:
        return v in self.vertices

    def position_of(self, v: Vertex) -> int:
        return self.vertices.index(v)

    def copy(self, vertices=None) -> Layer:
        return Layer(vertices if vertices is not None else list(self.vertices))

    def __repr__(self):
        return f"Layer(vertices={self.vertices!r})"

    def __hash__(self):
        return id(self)

    def __eq__(self, other):
        return self is other


@dataclass
class Layering:
    layers: List[Layer]
    edges: List[Edge]

    def edges_into(self, layer: Layer) -> List[Edge]:
        return [e for e in self.edges if layer.contains(e.finish_vertex)]

    def copy(self, layers=None, edges=None) -> Layering:
        return Layering(
            layers if layers is not None else list(self.layers),
            edges if edges is not None else list(self.edges),
        )
