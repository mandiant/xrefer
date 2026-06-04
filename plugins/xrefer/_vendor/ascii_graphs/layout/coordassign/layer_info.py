from __future__ import annotations
from xrefer._vendor.ascii_graphs.layout.layering.layering import RealVertex, Vertex
from xrefer._vendor.ascii_graphs.layout.coordassign.vertex_info import VertexInfo
from xrefer._vendor.ascii_graphs.util.utils import transform_values


class LayerInfo:
    def __init__(self, vertex_infos: dict):
        self.vertex_infos = vertex_infos  # Vertex -> VertexInfo

    def vertex_info(self, v: Vertex):
        return self.vertex_infos.get(v)

    def is_empty(self) -> bool:
        return not self.vertex_infos

    def max_row(self) -> int:
        if not self.vertex_infos:
            return 0
        return max(vi.greater_region.bottom_row for vi in self.vertex_infos.values())

    def max_column(self) -> int:
        if not self.vertex_infos:
            return 0
        return max(vi.greater_region.right_column for vi in self.vertex_infos.values())

    def _get_self_edge_buffer(self, vi: VertexInfo) -> int:
        return vi.self_in_ports.__len__() + 1 if vi.self_in_ports else 0

    def top_self_edge_buffer(self) -> int:
        if not self.vertex_infos:
            return 0
        return max(self._get_self_edge_buffer(vi) for vi in self.vertex_infos.values())

    def translate(self, down: int = 0, right: int = 0) -> LayerInfo:
        return LayerInfo(transform_values(self.vertex_infos, lambda vi: vi.translate(down, right)))

    def down(self, n: int = 1) -> LayerInfo:
        return self.translate(down=n)

    def real_vertex_infos(self) -> list:
        return [(v, vi) for v, vi in self.vertex_infos.items() if isinstance(v, RealVertex)]

    def copy(self, vertex_infos=None) -> LayerInfo:
        return LayerInfo(vertex_infos if vertex_infos is not None else dict(self.vertex_infos))

