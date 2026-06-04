from __future__ import annotations


class EdgeType:
    def include_edge(self, edge, this_box) -> bool:
        raise NotImplementedError


class _Out(EdgeType):
    def include_edge(self, edge, from_box) -> bool:
        return edge.other_has_arrow(from_box)


class _In(EdgeType):
    def include_edge(self, edge, from_box) -> bool:
        return edge.has_arrow(from_box)


class _Undirected(EdgeType):
    def include_edge(self, edge, from_box) -> bool:
        return not edge.has_arrow1 and not edge.has_arrow2


class _All(EdgeType):
    def include_edge(self, edge, from_box) -> bool:
        return True


Out = _Out()
In = _In()
Undirected = _Undirected()
All = _All()
