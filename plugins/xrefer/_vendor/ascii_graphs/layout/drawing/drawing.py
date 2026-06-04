from __future__ import annotations
from typing import List, Optional
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.dimension import Dimension
from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import (
    DrawingElement, VertexDrawingElement, EdgeDrawingElement
)


class Drawing:
    def __init__(self, elements: List[DrawingElement]):
        self.elements = list(elements)
        self._dimension = None

    @property
    def dimension(self) -> Dimension:
        if self._dimension is None:
            if not self.elements:
                self._dimension = Dimension(0, 0)
            else:
                largest = Point(-1, -1)
                for el in self.elements:
                    if isinstance(el, VertexDrawingElement):
                        p = el.region.bottom_right
                    elif isinstance(el, EdgeDrawingElement):
                        p = Point(-1, -1)
                        for bp in el.bend_points:
                            p = p.max_row_col(bp)
                    else:
                        continue
                    largest = largest.max_row_col(p)
                self._dimension = Dimension.from_point(largest)
        return self._dimension

    def replace_element(self, element: DrawingElement, replacement: DrawingElement) -> Drawing:
        # Scala puts replacement at front: `replacement :: elements.filterNot(_ == element)`
        new_elements = [replacement] + [e for e in self.elements if e is not element]
        return Drawing(new_elements)

    def vertex_element_at(self, point: Point) -> Optional[VertexDrawingElement]:
        for el in self.elements:
            if isinstance(el, VertexDrawingElement) and el.region.contains_point(point):
                return el
        return None

    @property
    def vertex_elements(self) -> List[VertexDrawingElement]:
        return [e for e in self.elements if isinstance(e, VertexDrawingElement)]

    @property
    def edge_elements(self) -> List[EdgeDrawingElement]:
        return [e for e in self.elements if isinstance(e, EdgeDrawingElement)]

    def transpose(self) -> Drawing:
        return Drawing([e.transpose() for e in self.elements])

    def copy(self, elements=None) -> Drawing:
        return Drawing(elements if elements is not None else list(self.elements))

    def __repr__(self):
        from xrefer._vendor.ascii_graphs.layout.prefs.layout_prefs_impl import LayoutPrefsImpl
        from xrefer._vendor.ascii_graphs.layout.drawing.renderer import render
        return render(self, LayoutPrefsImpl())

