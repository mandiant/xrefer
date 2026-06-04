from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.direction import Up, Down, Left, Right
from xrefer._vendor.ascii_graphs.layout.drawing.grid import Grid
from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import (
    VertexDrawingElement, EdgeDrawingElement, EdgeSegment
)
from xrefer._vendor.ascii_graphs.util.utils import with_previous


def render(drawing, renderer_prefs) -> str:
    return _Renderer(renderer_prefs).render(drawing)


class _Renderer:
    def __init__(self, prefs):
        self._prefs = prefs
        self._unicode = prefs.unicode
        self._double_vertices = prefs.double_vertices
        self._rounded = prefs.rounded
        self._explicit_ascii_bends = prefs.explicit_ascii_bends

    def render(self, drawing) -> str:
        grid = Grid(drawing.dimension)
        for vde in drawing.vertex_elements:
            self._render_vertex(grid, vde)
        for ede in drawing.edge_elements:
            self._render_edge(grid, ede, drawing)
        return str(grid)

    def _draw_line(self, grid: Grid, p1: Point, direction, p2: Point):
        if direction is Up or direction is Down:
            char = '│' if self._unicode else '|'
        else:
            char = '─' if self._unicode else '-'

        current = p1
        while True:
            existing = grid[current]
            if existing == ' ':
                grid[current] = char
            else:
                new_char = self._intersection_char(char)
                grid[current] = new_char
            if current == p2:
                break
            current = current.go(direction)

    def _intersection_char(self, line_char: str) -> str:
        if self._unicode:
            return '┼'
        return '-'

    def _render_edge(self, grid: Grid, ede: EdgeDrawingElement, drawing):
        segs = ede.segments
        for (prev_opt, seg) in with_previous(segs):
            start_pt = seg.start
            end_pt = seg.finish if seg.finish == ede.bend_points[-1] else seg.finish.go(seg.direction.opposite)
            self._draw_line(grid, start_pt, seg.direction, end_pt)

            if prev_opt is not None:
                bend_char = self._bend_char(prev_opt.direction, seg.direction)
                if bend_char is not None:
                    grid[seg.start] = bend_char

        def draw_box_intersection(intersection_pt: Point, direction):
            if self._unicode and drawing.vertex_element_at(intersection_pt) is not None:
                if grid.contains(intersection_pt):
                    c = self._join_char(direction)
                    grid[intersection_pt] = c

        if segs:
            first_seg = segs[0]
            if ede.has_arrow1:
                grid[first_seg.start] = self._arrow_char(first_seg.direction.opposite)
            else:
                draw_box_intersection(first_seg.start.go(first_seg.direction.opposite),
                                      first_seg.direction.opposite)

            last_seg = segs[-1]
            if ede.has_arrow2:
                grid[last_seg.finish] = self._arrow_char(last_seg.direction)
            else:
                draw_box_intersection(last_seg.finish.go(last_seg.direction),
                                      last_seg.direction)

    def _bend_char(self, prev_dir, curr_dir) -> str:
        u, d, l, r = Up, Down, Left, Right
        if (prev_dir is u and curr_dir is r) or (prev_dir is l and curr_dir is d):
            return self._bend1
        elif (prev_dir is u and curr_dir is l) or (prev_dir is r and curr_dir is d):
            return self._bend2
        elif (prev_dir is d and curr_dir is r) or (prev_dir is l and curr_dir is u):
            return self._bend3
        elif (prev_dir is d and curr_dir is l) or (prev_dir is r and curr_dir is u):
            return self._bend4
        return None

    def _render_vertex(self, grid: Grid, vde: VertexDrawingElement):
        r = vde.region
        grid[r.top_left] = self._top_left_char
        grid[r.top_right] = self._top_right_char
        grid[r.bottom_left] = self._bottom_left_char
        grid[r.bottom_right] = self._bottom_right_char

        bh = self._box_horizontal_char
        bv = self._box_vertical_char
        for col in range(r.left_column + 1, r.right_column):
            grid[Point(r.top_row, col)] = bh
            grid[Point(r.bottom_row, col)] = bh
        for row in range(r.top_row + 1, r.bottom_row):
            grid[Point(row, r.left_column)] = bv
            grid[Point(row, r.right_column)] = bv

        for i, line in enumerate(vde.text_lines):
            grid[r.top_left.right().down(i + 1)] = line

        if self._unicode:
            for row in range(r.top_row + 1, r.bottom_row):
                pt = Point(row, r.left_column)
                if grid[pt.right()] == '─':
                    grid[pt] = '╟' if self._double_vertices else '├'
            for row in range(r.top_row + 1, r.bottom_row):
                pt = Point(row, r.right_column)
                if grid[pt.left()] == '─':
                    grid[pt] = '╢' if self._double_vertices else '┤'

    def _join_char(self, direction) -> str:
        if direction is Up:
            return '╤' if self._double_vertices else '┬'
        elif direction is Down:
            return '╧' if self._double_vertices else '┴'
        elif direction is Right:
            return '╢' if self._double_vertices else '┤'
        elif direction is Left:
            return '╟' if self._double_vertices else '├'

    def _arrow_char(self, direction) -> str:
        return {Up: '^', Down: 'v', Left: '<', Right: '>'}[direction]

    @property
    def _bend1(self):
        if self._unicode: return '╭' if self._rounded else '┌'
        return '/' if self._explicit_ascii_bends else '-'

    @property
    def _bend2(self):
        if self._unicode: return '╮' if self._rounded else '┐'
        return '\\' if self._explicit_ascii_bends else '-'

    @property
    def _bend3(self):
        if self._unicode: return '╰' if self._rounded else '└'
        return '\\' if self._explicit_ascii_bends else '-'

    @property
    def _bend4(self):
        if self._unicode: return '╯' if self._rounded else '┘'
        return '/' if self._explicit_ascii_bends else '-'

    @property
    def _top_left_char(self):
        if self._unicode:
            return '╔' if self._double_vertices else ('╭' if self._rounded else '┌')
        return '+'

    @property
    def _top_right_char(self):
        if self._unicode:
            return '╗' if self._double_vertices else ('╮' if self._rounded else '┐')
        return '+'

    @property
    def _bottom_left_char(self):
        if self._unicode:
            return '╚' if self._double_vertices else ('╰' if self._rounded else '└')
        return '+'

    @property
    def _bottom_right_char(self):
        if self._unicode:
            return '╝' if self._double_vertices else ('╯' if self._rounded else '┘')
        return '+'

    @property
    def _box_horizontal_char(self):
        if self._unicode:
            return '═' if self._double_vertices else '─'
        return '-'

    @property
    def _box_vertical_char(self):
        if self._unicode:
            return '║' if self._double_vertices else '│'
        return '|'

