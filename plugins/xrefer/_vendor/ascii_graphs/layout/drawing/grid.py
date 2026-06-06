from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.dimension import Dimension
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.region import Region


class Grid:
    def __init__(self, dimension: Dimension):
        self._dimension = dimension
        self._chars = [[' '] * dimension.width for _ in range(dimension.height)]

    def __getitem__(self, point: Point) -> str:
        try:
            return self._chars[point.row][point.column]
        except IndexError:
            raise IndexError(f"{point} is not in {self._dimension}")

    def __setitem__(self, point_or_pair, value):
        if isinstance(point_or_pair, Point):
            point = point_or_pair
            if isinstance(value, str) and len(value) > 1:
                p = point
                for c in value:
                    self._chars[p.row][p.column] = c
                    p = p.right()
            else:
                self._chars[point.row][point.column] = value
        else:
            raise TypeError(f"Grid key must be Point, got {type(point_or_pair)}")

    def contains(self, point: Point) -> bool:
        r = Region(Point(0, 0), Point(self._dimension.height - 1, self._dimension.width - 1))
        return r.contains_point(point)

    def __str__(self) -> str:
        return '\n'.join(''.join(row) for row in self._chars)

