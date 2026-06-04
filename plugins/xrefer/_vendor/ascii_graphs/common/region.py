from __future__ import annotations
from dataclasses import dataclass
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from xrefer._vendor.ascii_graphs.common.point import Point
    from xrefer._vendor.ascii_graphs.common.dimension import Dimension


@dataclass(frozen=True)
class Region:
    top_left: object  # Point
    bottom_right: object  # Point

    def __post_init__(self):
        # Cache the hot bounds as plain attributes (computed once). is_disjoint,
        # contains_point, width, height are called millions of times during
        # layout; reading attributes instead of re-dereferencing top_left.row
        # through @property each time is a large speedup and changes NO values.
        tl = self.top_left
        br = self.bottom_right
        object.__setattr__(self, "top_row", tl.row)
        object.__setattr__(self, "left_column", tl.column)
        object.__setattr__(self, "bottom_row", br.row)
        object.__setattr__(self, "right_column", br.column)
        assert self.width >= 0 and self.height >= 0, \
            f"Invalid region: {tl}, {br}"

    @classmethod
    def from_top_left_and_dimension(cls, top_left, dimension) -> Region:
        from xrefer._vendor.ascii_graphs.common.point import Point
        br = Point(top_left.row + dimension.height - 1,
                   top_left.column + dimension.width - 1)
        return cls(top_left, br)

    @property
    def region(self) -> Region:
        return self

    @property
    def bottom_left(self):
        from xrefer._vendor.ascii_graphs.common.point import Point
        return Point(self.bottom_right.row, self.top_left.column)

    @property
    def top_right(self):
        from xrefer._vendor.ascii_graphs.common.point import Point
        return Point(self.top_left.row, self.bottom_right.column)

    # top_row / bottom_row / left_column / right_column are cached as plain
    # attributes in __post_init__ (hot path; see note there).

    def expand_right(self, n: int) -> Region:
        return Region(self.top_left, self.bottom_right.right(n))

    def expand_down(self, n: int) -> Region:
        return Region(self.top_left, self.bottom_right.down(n))

    def expand_up(self, n: int) -> Region:
        return Region(self.top_left.up(n), self.bottom_right)

    def expand_left(self, n: int) -> Region:
        return Region(self.top_left.left(n), self.bottom_right)

    def contains_point(self, point) -> bool:
        return (point.row >= self.top_row and point.column >= self.left_column and
                point.row <= self.bottom_row and point.column <= self.right_column)

    def contains(self, other) -> bool:
        if hasattr(other, 'row') and hasattr(other, 'column'):
            return self.contains_point(other)
        return self.contains_point(other.top_left) and self.contains_point(other.bottom_right)

    def intersects(self, other: Region) -> bool:
        return not self.is_disjoint(other)

    def is_disjoint(self, other: Region) -> bool:
        return (self.right_column < other.left_column or
                other.right_column < self.left_column or
                self.bottom_row < other.top_row or
                other.bottom_row < self.top_row)

    @property
    def width(self) -> int:
        return self.right_column - self.left_column + 1

    @property
    def height(self) -> int:
        return self.bottom_row - self.top_row + 1

    @property
    def dimension(self):
        from xrefer._vendor.ascii_graphs.common.dimension import Dimension
        return Dimension(self.height, self.width)

    @property
    def area(self) -> int:
        return self.width * self.height

    @property
    def points(self) -> List:
        from xrefer._vendor.ascii_graphs.common.point import Point
        result = []
        for row in range(self.top_row, self.bottom_row + 1):
            for col in range(self.left_column, self.right_column + 1):
                result.append(Point(row, col))
        return result

    def translate(self, down: int = 0, right: int = 0) -> Region:
        return Region(self.top_left.translate(down, right),
                      self.bottom_right.translate(down, right))

    def transpose(self) -> Region:
        return Region(self.top_left.transpose(), self.bottom_right.transpose())

    def up(self, n: int = 1) -> Region:
        return self.translate(down=-n)

    def down(self, n: int = 1) -> Region:
        return self.translate(down=n)

    def left(self, n: int = 1) -> Region:
        return self.translate(right=-n)

    def right(self, n: int = 1) -> Region:
        return self.translate(right=n)
