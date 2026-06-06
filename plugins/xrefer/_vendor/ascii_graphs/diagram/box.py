from __future__ import annotations
from xrefer._vendor.ascii_graphs.diagram.container import Container
from xrefer._vendor.ascii_graphs.diagram.edge_type import All as _All


class Box(Container):
    def connections(self, edge_type=None):
        if edge_type is None:
            edge_type = _All
        result = []
        for edge in self.edges:
            if edge_type.include_edge(edge, self):
                other = edge.other_box(self)
                result.append((edge, other))
        return result
