from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.direction import Right, Down
from xrefer._vendor.ascii_graphs.layout.drawing.box_drawing_characters import is_box_drawing_character
from xrefer._vendor.ascii_graphs.diagram.parser.diagram_implementation import BoxImpl


class BoxParser:

    def find_all_boxes(self):
        result = []
        for top_left in self._possible_top_lefts():
            br = self._complete_box(top_left)
            if br is not None:
                result.append(BoxImpl(top_left, br))
        return result

    def _possible_top_lefts(self):
        result = []
        for row in range(self._number_of_rows - 1):
            for col in range(self._number_of_columns - 1):
                point = Point(row, col)
                corner_char = self.char_at(point)
                if not _is_top_left_corner(corner_char):
                    continue
                right_char = self.char_at(point.go(Right))
                down_char = self.char_at(point.go(Down))
                if not (_is_horizontal_box_edge(right_char) or is_box_drawing_character(corner_char)):
                    continue
                if not (_is_vertical_box_edge(down_char) or is_box_drawing_character(corner_char)):
                    continue
                result.append(point)
        return result

    def _scan_box_edge(self, p: Point, direction, is_corner, is_edge):
        while True:
            if not self.in_diagram(p):
                return None
            c = self.char_at(p)
            if is_corner(c):
                return p
            elif is_edge(c):
                p = p.go(direction)
            else:
                return None

    def _complete_box(self, top_left: Point):
        top_right = self._scan_box_edge(top_left.right(), Right, _is_top_right_corner, _is_horizontal_box_edge)
        if top_right is None:
            return None
        bottom_right = self._scan_box_edge(top_right.down(), Down, _is_bottom_right_corner, _is_vertical_box_edge)
        if bottom_right is None:
            return None
        bottom_left = self._scan_box_edge(top_left.down(), Down, _is_bottom_left_corner, _is_vertical_box_edge)
        if bottom_left is None:
            return None
        bottom_right2 = self._scan_box_edge(bottom_left.right(), Right, _is_bottom_right_corner, _is_horizontal_box_edge)
        if bottom_right2 is None or bottom_right != bottom_right2:
            return None
        return bottom_right


def _is_top_right_corner(c: str) -> bool:
    return c in ('╗', '╮', '┐', '+')


def _is_bottom_right_corner(c: str) -> bool:
    return c in ('╝', '╯', '┘', '+')


def _is_top_left_corner(c: str) -> bool:
    return c in ('╔', '╭', '┌', '+')


def _is_bottom_left_corner(c: str) -> bool:
    return c in ('╚', '╰', '└', '+')


def _is_horizontal_box_edge(c: str) -> bool:
    return c in ('═', '─', '-', '╤', '┬', '╧', '┴', '╪', '┼')


def _is_vertical_box_edge(c: str) -> bool:
    return c in ('║', '│', '|', '╢', '┤', '╟', '├', '╫', '┼')
