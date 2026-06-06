from __future__ import annotations
from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import EdgeDrawingElement, EdgeSegment
from xrefer._vendor.ascii_graphs.layout.drawing.edge_segment_info import EdgeSegmentInfo
from xrefer._vendor.ascii_graphs.layout.drawing.edge_tracker import EdgeTracker
from xrefer._vendor.ascii_graphs.util.utils import adjacent_triples, add_to_multimap


def elevate_edges(drawing) -> object:
    tracker = EdgeTracker(drawing)
    current = drawing

    segment_infos = []
    for edge in drawing.edge_elements:
        for s1, s2, s3 in adjacent_triples(edge.segments):
            if s2.direction.is_horizontal():
                segment_infos.append(EdgeSegmentInfo(edge, s1, s2, s3))

    segment_updates = {}
    for info in sorted(segment_infos, key=lambda si: si.row):
        updated = _elevate(info, tracker)
        if updated is not None:
            segment_updates = add_to_multimap(segment_updates, info.edge_element,
                                              (info.segment2, updated))

    for edge, updates in segment_updates.items():
        updated_edge = edge
        for (old_seg, new_seg) in updates:
            updated_edge = updated_edge.replace_segment(old_seg, new_seg)
        current = current.replace_element(edge, updated_edge)

    return current


def _elevate(info: EdgeSegmentInfo, tracker: EdgeTracker):
    first_row = info.segment1.start.row + 1
    last_row = info.segment2.start.row - 1
    for row in range(first_row, last_row + 1):
        result = _try_elevate(row, info, tracker)
        if result is not None:
            return result
    return None


def _try_elevate(row: int, info: EdgeSegmentInfo, tracker: EdgeTracker):
    tracker.remove_edge_segments(info)
    new_info = info.with_row(row)
    if tracker.collides_with(new_info):
        tracker.add_edge_segments(info)
        return None
    else:
        tracker.add_edge_segments(new_info)
        return new_info.segment2

