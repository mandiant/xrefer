from __future__ import annotations
from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Point:
    row: int
    column: int

    @staticmethod
    def _same_column(p1, p2, p3):
        return p1.column == p2.column == p3.column

    @staticmethod
    def _same_row(p1, p2, p3):
        return p1.row == p2.row == p3.row

    @staticmethod
    def _colinear(p1, p2, p3):
        return Point._same_column(p1, p2, p3) or Point._same_row(p1, p2, p3)

    @staticmethod
    def remove_redundant_points(points: List[Point]) -> List[Point]:
        if len(points) <= 2:
            return points
        p1, p2, p3 = points[0], points[1], points[2]
        rest = points[3:]
        if Point._colinear(p1, p2, p3):
            return Point.remove_redundant_points([p1, p3] + rest)
        else:
            return [p1] + Point.remove_redundant_points([p2, p3] + rest)

    def max_row_col(self, other: Point) -> Point:
        return Point(max(self.row, other.row), max(self.column, other.column))

    def translate(self, down: int = 0, right: int = 0) -> Point:
        return Point(self.row + down, self.column + right)

    def transpose(self) -> Point:
        return Point(self.column, self.row)

    @property
    def neighbours(self) -> List[Point]:
        return [self.up(), self.right(), self.down(), self.left()]

    def with_row(self, new_row: int) -> Point:
        return Point(new_row, self.column)

    def with_column(self, new_column: int) -> Point:
        return Point(self.row, new_column)

    @property
    def region(self):
        from xrefer._vendor.ascii_graphs.common.region import Region
        return Region(self, self)

    def up(self, n: int = 1) -> Point:
        return self.translate(down=-n)

    def down(self, n: int = 1) -> Point:
        return self.translate(down=n)

    def left(self, n: int = 1) -> Point:
        return self.translate(right=-n)

    def right(self, n: int = 1) -> Point:
        return self.translate(right=n)

    def go(self, direction) -> Point:
        from xrefer._vendor.ascii_graphs.common.direction import Up, Down, Left, Right
        if direction is Up:
            return self.up()
        elif direction is Down:
            return self.down()
        elif direction is Left:
            return self.left()
        elif direction is Right:
            return self.right()
        else:
            raise ValueError(f"Unknown direction: {direction}")
