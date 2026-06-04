from __future__ import annotations
from xrefer._vendor.ascii_graphs.util.utils import make_map


class DiagramToGraphConverter:

    @staticmethod
    def to_graph(diagram):
        from xrefer._vendor.ascii_graphs.graph.graph import Graph
        box_to_vertex = make_map(diagram.child_boxes, lambda b: b.text)

        vertices = set(box_to_vertex.values())
        edges = []
        for edge in diagram.all_edges:
            v1 = box_to_vertex.get(edge.box1)
            v2 = box_to_vertex.get(edge.box2)
            if v1 is None or v2 is None:
                continue
            if edge.has_arrow2:
                edges.append((v1, v2))
            else:
                edges.append((v2, v1))
        return Graph(vertices, edges)
