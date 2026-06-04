from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.point import Point


class EdgeInfo:
    def __init__(self, start_vertex, finish_vertex, start_port: Point,
                 finish_port: Point, reversed: bool):
        self.start_vertex = start_vertex
        self.finish_vertex = finish_vertex
        self.start_port = start_port
        self.finish_port = finish_port
        self.reversed = reversed

    @property
    def start_column(self) -> int:
        return self.start_port.column

    @property
    def finish_column(self) -> int:
        return self.finish_port.column

    @property
    def requires_bend(self) -> bool:
        return not self.is_straight

    @property
    def is_straight(self) -> bool:
        return self.start_column == self.finish_column

    def with_finish_column(self, column: int) -> EdgeInfo:
        return EdgeInfo(self.start_vertex, self.finish_vertex,
                        self.start_port, self.finish_port.with_column(column),
                        self.reversed)

    def __repr__(self):
        return (f"EdgeInfo({self.start_vertex!r}, {self.finish_vertex!r}, "
                f"start={self.start_port}, finish={self.finish_port}, "
                f"rev={self.reversed})")

