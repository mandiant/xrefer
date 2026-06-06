from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.region import Region
from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import EdgeDrawingElement, EdgeSegment
from xrefer._vendor.ascii_graphs.layout.drawing.edge_segment_info import EdgeSegmentInfo
from xrefer._vendor.ascii_graphs.util.quad_tree import QuadTree


class EdgeTracker:
    def __init__(self, drawing):
        dim = drawing.dimension
        self._h_qt = QuadTree(dim)
        self._v_qt = QuadTree(dim)
        self._vertex_regions = [el.region for el in drawing.vertex_elements]

        arrow_regions = []
        for el in drawing.edge_elements:
            if el.has_arrow1:
                arrow_regions.append(el.start_point.region)
            else:
                arrow_regions.append(el.finish_point.region)

        for r in arrow_regions:
            self._h_qt.add(r)
        for r in self._vertex_regions:
            self._h_qt.add(r)
            self._v_qt.add(r)

        for edge in drawing.edge_elements:
            for seg in edge.segments:
                if seg.direction.is_horizontal():
                    self._h_qt.add(seg.region)
                else:
                    self._v_qt.add(seg.region)

    def add_edge_segments(self, info: EdgeSegmentInfo):
        self._v_qt.add(info.segment1.region)
        self._h_qt.add(info.segment2.region)
        self._v_qt.add(info.segment3.region)

    def remove_edge_segments(self, info: EdgeSegmentInfo):
        self._v_qt.remove(info.segment1.region)
        self._h_qt.remove(info.segment2.region)
        self._v_qt.remove(info.segment3.region)

    def add_horizontal_segment(self, seg: EdgeSegment):
        self._h_qt.add(seg.region)

    def add_vertical_segment(self, seg: EdgeSegment):
        self._v_qt.add(seg.region)

    def remove_horizontal_segment(self, seg: EdgeSegment):
        self._h_qt.remove(seg.region)

    def remove_vertical_segment(self, seg: EdgeSegment):
        self._v_qt.remove(seg.region)

    def collides_horizontal(self, seg: EdgeSegment) -> bool:
        return self._h_qt.collides(seg.region)

    def collides_vertical(self, seg: EdgeSegment) -> bool:
        return self._v_qt.collides(seg.region)

    def collides_with(self, info: EdgeSegmentInfo) -> bool:
        return (self._v_qt.collides(info.segment1.region) or
                self._h_qt.collides(info.segment2.region) or
                self._v_qt.collides(info.segment3.region) or
                (self._v_qt.collides(info.segment2.region) and
                 self._h_qt.collides(info.segment3.region)))

