from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.region import Region
from xrefer._vendor.ascii_graphs.common.direction import Right, Left, Up, Down
from xrefer._vendor.ascii_graphs.layout.drawing.box_drawing_characters import is_box_drawing_character
from xrefer._vendor.ascii_graphs.diagram.parser.diagram_implementation import DiagramImpl, EdgeImpl
from xrefer._vendor.ascii_graphs.diagram.parser.box_parser import BoxParser
from xrefer._vendor.ascii_graphs.diagram.parser.ascii_edge_parser import AsciiEdgeParser
from xrefer._vendor.ascii_graphs.diagram.parser.unicode_edge_parser import UnicodeEdgeParser
from xrefer._vendor.ascii_graphs.diagram.parser.label_parser import LabelParser


class DiagramParser(UnicodeEdgeParser, BoxParser, AsciiEdgeParser, LabelParser):

    def __init__(self, s: str):
        raw_rows = [] if not s else s.split('\n')
        # Strip \r from end of lines (handle \r\n)
        raw_rows = [r.rstrip('\r') for r in raw_rows]

        self._number_of_columns = max((len(r) for r in raw_rows), default=0)
        self._rows = [r.ljust(self._number_of_columns) for r in raw_rows]
        self._number_of_rows = len(self._rows)

        if self._number_of_rows > 0:
            self._diagram_region = Region(
                Point(0, 0),
                Point(self._number_of_rows - 1, self._number_of_columns - 1)
            )
        else:
            self._diagram_region = Region(Point(0, 0), Point(-1, -1))

        self._diagram = DiagramImpl(self)
        self._diagram.all_boxes = self.find_all_boxes()

        # Set up parent/child box relationships
        box_contains = {}
        for outer_box in self._diagram.all_boxes:
            for inner_box in self._diagram.all_boxes:
                if outer_box is not inner_box:
                    if outer_box.region.contains(inner_box.region):
                        box_contains[outer_box] = inner_box

        # Group by inner box (value), find all containers
        from collections import defaultdict
        containers_of = defaultdict(list)
        for outer, inner in box_contains.items():
            containers_of[inner].append(outer)

        for box, containing_boxes in containers_of.items():
            all_boxes = [box] + containing_boxes
            ordered = sorted(all_boxes, key=lambda b: b.region.area)
            for child_box, parent_box in zip(ordered, ordered[1:]):
                child_box.parent = parent_box
                parent_box.child_boxes = [child_box] + parent_box.child_boxes

        for box in self._diagram.all_boxes:
            if box.parent is None:
                self._diagram.child_boxes = [box] + self._diagram.child_boxes
                box.parent = self._diagram

        # Find edges by scanning box boundaries
        raw_edges = []
        for box in self._diagram.all_boxes:
            for start_point in box.right_boundary:
                e = self._follow_edge(Right, start_point)
                if e is not None:
                    raw_edges.append(e)
            for start_point in box.left_boundary:
                e = self._follow_edge(Left, start_point)
                if e is not None:
                    raw_edges.append(e)
            for start_point in box.top_boundary:
                e = self._follow_edge(Up, start_point)
                if e is not None:
                    raw_edges.append(e)
            for start_point in box.bottom_boundary:
                e = self._follow_edge(Down, start_point)
                if e is not None:
                    raw_edges.append(e)

        # Deduplicate edges by their set of points
        seen_point_sets = {}
        for edge in raw_edges:
            key = frozenset(edge.points)
            if key not in seen_point_sets:
                seen_point_sets[key] = edge
        self._diagram.all_edges = list(seen_point_sets.values())

        # Wire edges to boxes
        for edge in self._diagram.all_edges:
            b1 = edge.box1
            b2 = edge.box2
            b1.edges = b1.edges + [edge]
            if b1 is not b2:
                b2.edges = b2.edges + [edge]

        # Compute all edge points (needed by label parser + text collector)
        self._all_edge_points = set()
        for edge in self._diagram.all_edges:
            self._all_edge_points.update(edge.points)

        # Set labels on edges
        for edge in self._diagram.all_edges:
            edge.label_ = self.get_label(edge)

        # Compute all label points (needed by text collector)
        self._all_label_points = set()
        for edge in self._diagram.all_edges:
            if edge.label_ is not None:
                self._all_label_points.update(edge.label_.points)

        # Collect text for boxes and diagram
        for box in self._diagram.all_boxes:
            box.text = self._collect_text(box).strip()
        self._diagram.text = self._collect_text(self._diagram)

    def get_diagram(self):
        return self._diagram

    def in_diagram(self, p: Point) -> bool:
        return self._diagram_region.contains(p)

    def char_at(self, point: Point) -> str:
        return self._rows[point.row][point.column]

    def _char_at_opt(self, point: Point):
        if self.in_diagram(point):
            return self.char_at(point)
        return None

    def is_box_edge(self, point: Point) -> bool:
        if not self.in_diagram(point):
            return False
        for box in self._diagram.all_boxes:
            if point in box.boundary_points:
                return True
        return False

    def _follow_edge(self, direction, start_point: Point):
        initial_points = [start_point.go(direction), start_point]
        start_char = self.char_at(start_point)
        if self.is_edge_start(start_char, direction):
            return self.follow_unicode_edge(initial_points, direction)
        elif not is_box_drawing_character(start_char):
            return self.follow_ascii_edge(initial_points, direction)
        return None

    def _collect_text(self, container) -> str:
        child_box_points = set()
        for box in container.child_boxes:
            child_box_points.update(box.region.points)

        sb = []
        region = container.contents_region
        for row in range(region.top_left.row, region.bottom_right.row + 1):
            for col in range(region.top_left.column, region.bottom_right.column + 1):
                point = Point(row, col)
                if point not in child_box_points and point not in self._all_edge_points and point not in self._all_label_points:
                    sb.append(self.char_at(point))
            sb.append('\n')
        result = "".join(sb)
        if result:
            result = result[:-1]  # remove trailing newline
        return result
