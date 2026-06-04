from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import DrawingElement


class OccupancyGrid:
    def __init__(self, drawing):
        h = drawing.dimension.height
        w = drawing.dimension.width
        self._grid = [[0] * w for _ in range(h)]
        for el in drawing.elements:
            self._adjust(el, 1)

    def __getitem__(self, point: Point) -> bool:
        return self._grid[point.row][point.column] > 0

    def is_occupied(self, point: Point) -> bool:
        return self[point]

    def replace(self, el1: DrawingElement, el2: DrawingElement):
        self._adjust(el1, -1)
        self._adjust(el2, 1)

    def _adjust(self, el: DrawingElement, delta: int):
        for p in el.points():
            self._grid[p.row][p.column] += delta

