from __future__ import annotations
from xrefer._vendor.ascii_graphs.diagram.parser.diagram_implementation import EdgeImpl


class UnicodeEdgeParser:

    def follow_unicode_edge(self, points, direction):
        while True:
            current_point = points[0]
            if not self.in_diagram(current_point):
                return None
            if self.is_box_edge(current_point):
                return EdgeImpl(list(reversed(points)), self._diagram)
            c = self.char_at(current_point)
            if _unicode_is_straight_ahead(c, direction) or _unicode_is_crossing(c) or _unicode_is_ahead_arrow(c, direction):
                points = [current_point.go(direction)] + points
            elif _unicode_is_left_turn(c, direction) or _unicode_is_left_arrow(c, direction):
                new_dir = direction.turn_left
                points = [current_point.go(new_dir)] + points
                direction = new_dir
            elif _unicode_is_right_turn(c, direction) or _unicode_is_right_arrow(c, direction):
                new_dir = direction.turn_right
                points = [current_point.go(new_dir)] + points
                direction = new_dir
            else:
                return None

    def is_edge_start(self, c: str, direction) -> bool:
        from xrefer._vendor.ascii_graphs.common.direction import Down, Up, Right, Left
        if c in ('╤', '┬') and direction is Down:
            return True
        if c in ('╪', '┼') and direction in (Up, Down):
            return True
        if c in ('╧', '┴') and direction is Up:
            return True
        if c in ('╟', '├') and direction is Right:
            return True
        if c in ('╫', '┼') and direction in (Right, Left):
            return True
        if c in ('╢', '┤') and direction is Left:
            return True
        return False


def _unicode_is_straight_ahead(c: str, direction) -> bool:
    from xrefer._vendor.ascii_graphs.common.direction import Right, Left, Up, Down
    if c == '─' and direction in (Right, Left):
        return True
    if c == '│' and direction in (Up, Down):
        return True
    return False


def _unicode_is_ahead_arrow(c: str, direction) -> bool:
    from xrefer._vendor.ascii_graphs.common.direction import Up, Down, Left, Right
    if c == '^' and direction is Up:
        return True
    if c in ('v', 'V') and direction is Down:
        return True
    if c == '<' and direction is Left:
        return True
    if c == '>' and direction is Right:
        return True
    return False


def _unicode_is_left_arrow(c: str, direction) -> bool:
    return _unicode_is_ahead_arrow(c, direction.turn_left)


def _unicode_is_right_arrow(c: str, direction) -> bool:
    return _unicode_is_ahead_arrow(c, direction.turn_right)


def _unicode_is_right_turn(c: str, direction) -> bool:
    from xrefer._vendor.ascii_graphs.common.direction import Right, Down, Up, Left
    if c in ('╮', '┐') and direction is Right:
        return True
    if c in ('╯', '┘') and direction is Down:
        return True
    if c in ('╭', '┌') and direction is Up:
        return True
    if c in ('╰', '└') and direction is Left:
        return True
    return False


def _unicode_is_left_turn(c: str, direction) -> bool:
    return _unicode_is_right_turn(c, direction.turn_right)


def _unicode_is_crossing(c: str) -> bool:
    return c == '┼'
