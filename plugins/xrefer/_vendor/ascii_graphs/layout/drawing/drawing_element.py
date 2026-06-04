from __future__ import annotations
from typing import List
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.region import Region
from xrefer._vendor.ascii_graphs.common.direction import Up, Down, Left, Right
from xrefer._vendor.ascii_graphs.util.utils import adjacent_pairs


def _direction(p1: Point, p2: Point):
    if p1.row == p2.row:
        if p1.column < p2.column:
            return Right
        elif p1.column > p2.column:
            return Left
        else:
            raise RuntimeError(f"Same point: {p1}")
    elif p1.column == p2.column:
        if p1.row < p2.row:
            return Down
        elif p1.row > p2.row:
            return Up
        else:
            raise RuntimeError("Same point")
    else:
        raise RuntimeError(f"Points not aligned: {p1}, {p2}")


class DrawingElement:
    pass


class VertexDrawingElement(DrawingElement):
    def __init__(self, region: Region, text_lines: List[str]):
        self.region = region
        self.text_lines = text_lines

    def translate(self, down: int = 0, right: int = 0) -> VertexDrawingElement:
        return VertexDrawingElement(self.region.translate(down, right), self.text_lines)

    def points(self) -> List[Point]:
        return self.region.points

    def transpose(self) -> VertexDrawingElement:
        return VertexDrawingElement(self.region.transpose(), self.text_lines)

    def up(self, n=1): return self.translate(down=-n)
    def down(self, n=1): return self.translate(down=n)
    def left(self, n=1): return self.translate(right=-n)
    def right(self, n=1): return self.translate(right=n)

    def __repr__(self):
        return f"VertexDrawingElement({self.region!r})"


class EdgeDrawingElement(DrawingElement):
    def __init__(self, bend_points: List[Point], has_arrow1: bool, has_arrow2: bool):
        self.bend_points = list(bend_points)
        self.has_arrow1 = has_arrow1
        self.has_arrow2 = has_arrow2
        self._segments = None
        self._cached_points = None

    @property
    def segments(self) -> List[EdgeSegment]:
        if self._segments is None:
            self._segments = [
                EdgeSegment(p1, _direction(p1, p2), p2)
                for p1, p2 in adjacent_pairs(self.bend_points)
            ]
        return self._segments

    def points(self) -> List[Point]:
        if self._cached_points is None:
            seen = set()
            pts = []
            for seg in self.segments:
                for p in seg.points():
                    key = (p.row, p.column)
                    if key not in seen:
                        seen.add(key)
                        pts.append(p)
            self._cached_points = pts
        return self._cached_points

    def translate(self, down: int = 0, right: int = 0) -> EdgeDrawingElement:
        return EdgeDrawingElement(
            [p.translate(down, right) for p in self.bend_points],
            self.has_arrow1, self.has_arrow2
        )

    def transpose(self) -> EdgeDrawingElement:
        return EdgeDrawingElement(
            [p.transpose() for p in self.bend_points],
            self.has_arrow1, self.has_arrow2
        )

    @property
    def start_point(self) -> Point:
        return self.points()[0]

    @property
    def finish_point(self) -> Point:
        return self.points()[-1]

    def replace_segment(self, old_seg: EdgeSegment, new_seg: EdgeSegment) -> EdgeDrawingElement:
        old_idx = self.bend_points.index(old_seg.start)
        new_bps = list(self.bend_points)
        new_bps[old_idx:old_idx+2] = [new_seg.start, new_seg.finish]
        return EdgeDrawingElement(new_bps, self.has_arrow1, self.has_arrow2)

    def copy(self, bend_points=None, has_arrow1=None, has_arrow2=None) -> EdgeDrawingElement:
        return EdgeDrawingElement(
            bend_points if bend_points is not None else list(self.bend_points),
            has_arrow1 if has_arrow1 is not None else self.has_arrow1,
            has_arrow2 if has_arrow2 is not None else self.has_arrow2,
        )

    def __repr__(self):
        return f"EdgeDrawingElement({self.bend_points!r})"


class EdgeSegment:
    def __init__(self, start: Point, direction, finish: Point):
        self.start = start
        self.direction = direction
        self.finish = finish

    def points(self) -> List[Point]:
        result = []
        current = self.start
        while current != self.finish:
            result.append(current)
            current = current.go(self.direction)
        result.append(self.finish)
        return result

    @property
    def region(self) -> Region:
        min_row = min(self.start.row, self.finish.row)
        max_row = max(self.start.row, self.finish.row)
        min_col = min(self.start.column, self.finish.column)
        max_col = max(self.start.column, self.finish.column)
        return Region(Point(min_row, min_col), Point(max_row, max_col))

    def copy(self, start=None, direction=None, finish=None) -> EdgeSegment:
        return EdgeSegment(
            start if start is not None else self.start,
            direction if direction is not None else self.direction,
            finish if finish is not None else self.finish,
        )

    def __repr__(self):
        return f"EdgeSegment({self.start}, {self.direction}, {self.finish})"

