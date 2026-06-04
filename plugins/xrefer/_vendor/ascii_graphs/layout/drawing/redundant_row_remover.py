from __future__ import annotations
from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import (
    EdgeDrawingElement, VertexDrawingElement
)
from xrefer._vendor.ascii_graphs.util.utils import iterate, conditionally_map


def remove_redundant_rows(drawing) -> object:
    return iterate(drawing, _remove_one_redundant_row)


def _remove_one_redundant_row(drawing):
    for row in range(drawing.dimension.height):
        if _can_remove(drawing, row):
            return _remove_rows(drawing, row, row)
    return None


def _can_remove(drawing, row: int) -> bool:
    for el in drawing.elements:
        if isinstance(el, EdgeDrawingElement):
            if not _edge_can_remove(el, row):
                return False
        elif isinstance(el, VertexDrawingElement):
            if el.region.top_row <= row <= el.region.bottom_row:
                return False
    return True


def _edge_can_remove(ede: EdgeDrawingElement, row: int) -> bool:
    bps = ede.bend_points
    if not bps:
        return True

    first = bps[0]
    second = bps[1] if len(bps) > 1 else None
    would_leave_stubby_up = (
        second is not None and
        row == first.row + 1 and
        ede.has_arrow1 and
        second.row == row + 1 and
        len(bps) > 2
    )

    last = bps[-1]
    second_last = bps[-2] if len(bps) > 1 else None
    would_leave_stubby_down = (
        second_last is not None and
        row == last.row - 1 and
        ede.has_arrow2 and
        second_last.row == row - 1 and
        len(bps) > 2
    )

    return not would_leave_stubby_down and not would_leave_stubby_up and all(p.row != row for p in bps)


def _remove_rows(drawing, from_row: int, to_row: int):
    up_shift = to_row - from_row + 1

    def update_element(el):
        if isinstance(el, EdgeDrawingElement):
            new_bps = [p.up(up_shift) if p.row >= from_row else p for p in el.bend_points]
            return el.copy(bend_points=new_bps)
        elif isinstance(el, VertexDrawingElement):
            if el.region.top_row < from_row:
                return el
            return el.up(up_shift)
        return el

    return drawing.copy(elements=[update_element(e) for e in drawing.elements])

