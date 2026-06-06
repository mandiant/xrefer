from __future__ import annotations
from xrefer._vendor.ascii_graphs.diagram.box import Box
from xrefer._vendor.ascii_graphs.diagram.container import Container
from xrefer._vendor.ascii_graphs.diagram.edge import Edge
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.region import Region


class ContainerImpl(Container):
    def __init__(self):
        self._text = ""
        self._child_boxes = []

    @property
    def text(self) -> str:
        return self._text

    @text.setter
    def text(self, value: str):
        self._text = value

    @property
    def child_boxes(self):
        return self._child_boxes

    @child_boxes.setter
    def child_boxes(self, value):
        self._child_boxes = value


class DiagramImpl(ContainerImpl):
    def __init__(self, parser):
        super().__init__()
        self._parser = parser
        self.all_boxes = []
        self.all_edges = []
        self._parent = None

    @property
    def region(self) -> Region:
        return self._parser._diagram_region

    @property
    def contents_region(self) -> Region:
        return self.region

    @property
    def parent(self):
        return None

    def box_at(self, point: Point):
        for box in self.all_boxes:
            if point in box.boundary_points:
                return box
        return None


class BoxImpl(ContainerImpl, Box):
    def __init__(self, top_left: Point, bottom_right: Point):
        ContainerImpl.__init__(self)
        self.top_left = top_left
        self.bottom_right = bottom_right
        self._edges = []
        self._parent = None

        self.left_boundary = [Point(row, top_left.column)
                               for row in range(top_left.row, bottom_right.row + 1)]
        self.right_boundary = [Point(row, bottom_right.column)
                                for row in range(top_left.row, bottom_right.row + 1)]
        self.top_boundary = [Point(top_left.row, col)
                              for col in range(top_left.column, bottom_right.column + 1)]
        self.bottom_boundary = [Point(bottom_right.row, col)
                                 for col in range(top_left.column, bottom_right.column + 1)]
        self.boundary_points = frozenset(
            self.left_boundary + self.right_boundary +
            self.top_boundary + self.bottom_boundary
        )

    @property
    def region(self) -> Region:
        return Region(self.top_left, self.bottom_right)

    @property
    def contents_region(self) -> Region:
        return Region(self.top_left.right().down(), self.bottom_right.up().left())

    @property
    def edges(self):
        return self._edges

    @edges.setter
    def edges(self, value):
        self._edges = value

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value):
        self._parent = value


class Label:
    def __init__(self, start: Point, end: Point, parser):
        assert start.row == end.row
        self.start = start
        self.end = end
        self._parser = parser
        self.row = start.row

    @property
    def points(self):
        return [Point(self.row, col)
                for col in range(self.start.column, self.end.column + 1)]

    @property
    def text(self) -> str:
        sb = []
        for col in range(self.start.column + 1, self.end.column):
            sb.append(self._parser.char_at(Point(self.row, col)))
        return "".join(sb)

    def __eq__(self, other):
        if not isinstance(other, Label):
            return NotImplemented
        return self.start == other.start and self.end == other.end

    def __hash__(self):
        return hash((self.start, self.end))


class EdgeImpl(Edge):
    def __init__(self, points, diagram):
        self._points = points
        self._diagram = diagram
        self._label = None

    @property
    def points(self):
        return self._points

    @property
    def box1(self) -> BoxImpl:
        return self._diagram.box_at(self._points[0])

    @property
    def box2(self) -> BoxImpl:
        return self._diagram.box_at(self._points[-1])

    @property
    def label_(self):
        return self._label

    @label_.setter
    def label_(self, value):
        self._label = value

    @property
    def label(self):
        if self._label is None:
            return None
        return self._label.text

    @property
    def parent(self):
        b1 = self.box1
        b2 = self.box2
        if b1.parent is b2:
            return b2
        return b2.parent

    @property
    def has_arrow1(self) -> bool:
        return _is_arrow(self._diagram._parser.char_at(self._points[1]))

    @property
    def has_arrow2(self) -> bool:
        return _is_arrow(self._diagram._parser.char_at(self._points[-2]))

    @property
    def edge_and_label_points(self):
        extra = self._label.points if self._label else []
        return self._points + extra


def _is_arrow(c: str) -> bool:
    return c in ('^', '<', '>', 'V', 'v')
