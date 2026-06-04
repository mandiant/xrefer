from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.direction import Down, Up, Left, Right
from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import EdgeDrawingElement, EdgeSegment
from xrefer._vendor.ascii_graphs.layout.drawing.edge_tracker import EdgeTracker
from xrefer._vendor.ascii_graphs.util.utils import adjacent_pairs_with_previous_and_next


def remove_kinks(drawing) -> object:
    tracker = EdgeTracker(drawing)
    current = drawing
    while True:
        result = _find_and_remove_kink(current, tracker)
        if result is None:
            break
        old_edge, new_edge = result
        current = current.replace_element(old_edge, new_edge)
    return current


def _find_and_remove_kink(drawing, tracker):
    for edge in drawing.edge_elements:
        result = _remove_kink(edge, drawing, tracker)
        if result is not None:
            return edge, result
    return None


def _remove_kink(edge: EdgeDrawingElement, drawing, tracker) -> EdgeDrawingElement:
    segments = edge.segments
    for (s1_opt, s2, s3, s4_opt) in adjacent_pairs_with_previous_and_next(segments):

        if s2.direction is Down and s3.direction in (Left, Right):
            start = s2.start
            middle = s2.finish
            end = s3.finish
            alt_middle = Point(start.row, end.column)

            if s1_opt is not None: tracker.remove_horizontal_segment(s1_opt)
            tracker.remove_vertical_segment(s2)
            tracker.remove_horizontal_segment(s3)
            if s4_opt is not None: tracker.remove_vertical_segment(s4_opt)

            new_s1_opt = (s1_opt.copy(finish=alt_middle) if s1_opt is not None else None)
            new_s4_opt = (s4_opt.copy(start=alt_middle) if s4_opt is not None else None)

            collision = ((new_s1_opt is not None and tracker.collides_horizontal(new_s1_opt)) or
                         (new_s4_opt is not None and tracker.collides_vertical(new_s4_opt)))

            if not collision and _check_vertex_connection(drawing, start, alt_middle, Up):
                if s1_opt is not None: tracker.add_horizontal_segment(s1_opt)
                if s4_opt is not None: tracker.add_vertical_segment(s4_opt)
                return _apply_kink_removal(edge, start, alt_middle)
            else:
                if s1_opt is not None: tracker.add_horizontal_segment(s1_opt)
                tracker.add_vertical_segment(s2)
                tracker.add_horizontal_segment(s3)
                if s4_opt is not None: tracker.add_vertical_segment(s4_opt)

        elif s2.direction in (Left, Right) and s3.direction is Down:
            start = s2.start
            middle = s2.finish
            end = s3.finish
            alt_middle = Point(end.row, start.column)

            if s1_opt is not None: tracker.remove_vertical_segment(s1_opt)
            tracker.remove_horizontal_segment(s2)
            tracker.remove_vertical_segment(s3)
            if s4_opt is not None: tracker.remove_horizontal_segment(s4_opt)

            new_s1_opt = (s1_opt.copy(finish=alt_middle) if s1_opt is not None else None)
            new_s4_opt = (s4_opt.copy(start=alt_middle) if s4_opt is not None else None)

            collision = ((new_s1_opt is not None and tracker.collides_vertical(new_s1_opt)) or
                         (new_s4_opt is not None and tracker.collides_horizontal(new_s4_opt)))

            if not collision and _check_vertex_connection(drawing, end, alt_middle, Down):
                if s1_opt is not None: tracker.add_vertical_segment(s1_opt)
                if s4_opt is not None: tracker.add_horizontal_segment(s4_opt)
                return _apply_kink_removal(edge, start, alt_middle)
            else:
                if s1_opt is not None: tracker.add_vertical_segment(s1_opt)
                tracker.add_horizontal_segment(s2)
                tracker.add_vertical_segment(s3)
                if s4_opt is not None: tracker.add_horizontal_segment(s4_opt)

    return None


def _check_vertex_connection(drawing, end: Point, alt_middle: Point, direction) -> bool:
    vertex = drawing.vertex_element_at(end.go(direction))
    if vertex is None:
        return True
    connected_to_same = drawing.vertex_element_at(alt_middle.go(direction)) == vertex
    extreme_left = alt_middle.column == vertex.region.left_column
    extreme_right = alt_middle.column == vertex.region.right_column
    return connected_to_same and not extreme_left and not extreme_right


def _apply_kink_removal(edge: EdgeDrawingElement, start: Point, alt_middle: Point) -> EdgeDrawingElement:
    old_bps = edge.bend_points
    old_idx = old_bps.index(start)
    new_bps = old_bps[:old_idx] + [alt_middle] + old_bps[old_idx+3:]
    # Ensure distinct points
    seen = []
    seen_set = set()
    for p in new_bps:
        key = (p.row, p.column)
        if key not in seen_set:
            seen_set.add(key)
            seen.append(p)
    return edge.copy(bend_points=Point.remove_redundant_points(seen))

