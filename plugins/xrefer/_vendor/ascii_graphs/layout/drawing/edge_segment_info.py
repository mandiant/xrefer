from __future__ import annotations
from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import EdgeDrawingElement, EdgeSegment


class EdgeSegmentInfo:
    def __init__(self, edge_element: EdgeDrawingElement,
                 segment1: EdgeSegment, segment2: EdgeSegment, segment3: EdgeSegment):
        self.edge_element = edge_element
        self.segment1 = segment1
        self.segment2 = segment2
        self.segment3 = segment3

    @property
    def row(self) -> int:
        return self.segment2.start.row

    def with_row(self, row: int) -> EdgeSegmentInfo:
        new_start2 = self.segment2.start.with_row(row)
        new_finish2 = self.segment2.finish.with_row(row)
        new_seg1 = self.segment1.copy(finish=new_start2)
        new_seg2 = self.segment2.copy(start=new_start2, finish=new_finish2)
        new_seg3 = self.segment3.copy(start=new_finish2)
        return EdgeSegmentInfo(self.edge_element, new_seg1, new_seg2, new_seg3)

