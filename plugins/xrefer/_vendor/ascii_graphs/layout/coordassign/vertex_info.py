from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.region import Region
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.util.utils import transform_values


class VertexInfo:
    def __init__(self, box_region: Region, greater_region: Region,
                 in_edge_to_port_map: dict, out_edge_to_port_map: dict,
                 self_in_ports: list, self_out_ports: list):
        self.box_region = box_region
        self.greater_region = greater_region
        self.in_edge_to_port_map = in_edge_to_port_map
        self.out_edge_to_port_map = out_edge_to_port_map
        self.self_in_ports = self_in_ports
        self.self_out_ports = self_out_ports

    @property
    def content_region(self) -> Region:
        return (self.box_region
                .expand_right(-1).expand_left(-1)
                .expand_down(-1).expand_up(-1))

    def translate(self, down: int = 0, right: int = 0) -> VertexInfo:
        return VertexInfo(
            self.box_region.translate(down, right),
            self.greater_region.translate(down, right),
            transform_values(self.in_edge_to_port_map, lambda p: p.translate(down, right)),
            transform_values(self.out_edge_to_port_map, lambda p: p.translate(down, right)),
            [p.translate(down, right) for p in self.self_in_ports],
            [p.translate(down, right) for p in self.self_out_ports],
        )

    def set_left(self, column: int) -> VertexInfo:
        return self.translate(right=column - self.box_region.left_column)

    def down(self, n: int = 1) -> VertexInfo:
        return self.translate(down=n)

    def copy(self, in_edge_to_port_map=None, out_edge_to_port_map=None) -> VertexInfo:
        return VertexInfo(
            self.box_region,
            self.greater_region,
            in_edge_to_port_map if in_edge_to_port_map is not None else dict(self.in_edge_to_port_map),
            out_edge_to_port_map if out_edge_to_port_map is not None else dict(self.out_edge_to_port_map),
            list(self.self_in_ports),
            list(self.self_out_ports),
        )

