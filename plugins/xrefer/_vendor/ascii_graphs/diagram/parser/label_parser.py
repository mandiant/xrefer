from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.direction import Right, Left
from xrefer._vendor.ascii_graphs.diagram.parser.diagram_parser_exception import DiagramParserException
from xrefer._vendor.ascii_graphs.diagram.parser.diagram_implementation import Label


class LabelParser:

    def get_label(self, edge):
        labels = []
        for point in edge.points:
            for start_point in point.neighbours:
                c = self._char_at_opt(start_point)
                if c in ('[', ']'):
                    label = self._complete_label(start_point, edge.parent)
                    if label is not None:
                        labels.append(label)
        distinct = list({(l.start, l.end): l for l in labels}.values())
        if len(distinct) > 1:
            texts = ", ".join(l.text for l in distinct)
            raise DiagramParserException(f"Multiple labels for edge {edge}, {texts}")
        return distinct[0] if distinct else None

    def _complete_label(self, start_point: Point, parent):
        child_box_points = set()
        for box in parent.child_boxes:
            child_box_points.update(box.region.points)
        occupied_points = child_box_points | self._all_edge_points

        c_start = self.char_at(start_point)
        if c_start == '[':
            final_char = ']'
            direction = Right
        else:
            final_char = '['
            direction = Left

        point = start_point.go(direction)
        while True:
            c = self._char_at_opt(point)
            if c is None:
                return None
            if c == final_char:
                p1, p2 = sorted([start_point, point], key=lambda p: p.column)
                return Label(p1, p2, self)
            if point in occupied_points:
                return None
            point = point.go(direction)
