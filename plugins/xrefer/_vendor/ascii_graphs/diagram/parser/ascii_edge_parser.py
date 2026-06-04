from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.characters import is_ahead_arrow, is_left_arrow, is_right_arrow
from xrefer._vendor.ascii_graphs.diagram.parser.diagram_implementation import EdgeImpl


class AsciiEdgeParser:

    def follow_ascii_edge(self, points, direction):
        while True:
            current_point = points[0]
            if not self.in_diagram(current_point):
                return None
            if self.is_box_edge(current_point):
                if len(points) <= 2:
                    return None
                return EdgeImpl(list(reversed(points)), self._diagram)
            c = self.char_at(current_point)

            ahead = current_point.go(direction)
            left = current_point.go(direction.turn_left)
            right = current_point.go(direction.turn_right)
            ahead_is_continuation = self._ascii_is_continuation(ahead, direction)
            right_is_continuation = self._ascii_is_continuation(right, direction.turn_right)
            left_is_continuation = self._ascii_is_continuation(left, direction.turn_left)

            if _ascii_is_crossing(c) or is_ahead_arrow(c, direction):
                points = [current_point.go(direction)] + points
                # direction unchanged
            elif _ascii_is_left_turn(c, direction) and len(points) > 2:
                points = [left] + points
                direction = direction.turn_left
            elif _ascii_is_right_turn(c, direction) and len(points) > 2:
                points = [right] + points
                direction = direction.turn_right
            elif _ascii_is_straight_ahead(c, direction):
                if ahead_is_continuation:
                    points = [ahead] + points
                elif left_is_continuation and not right_is_continuation and not _ascii_is_turn_char(self._char_at_opt(left)):
                    points = [left] + points
                    direction = direction.turn_left
                elif not left_is_continuation and right_is_continuation and not _ascii_is_turn_char(self._char_at_opt(right)):
                    points = [right] + points
                    direction = direction.turn_right
                else:
                    points = [ahead] + points
            elif _ascii_is_orthogonal(c, direction):
                if left_is_continuation and not right_is_continuation:
                    points = [left] + points
                    direction = direction.turn_left
                elif not left_is_continuation and right_is_continuation:
                    points = [right] + points
                    direction = direction.turn_right
                else:
                    points = [ahead] + points
            elif is_left_arrow(c, direction):
                points = [left] + points
                direction = direction.turn_left
            elif is_right_arrow(c, direction):
                points = [right] + points
                direction = direction.turn_right
            else:
                return None

    def _ascii_is_continuation(self, point, direction) -> bool:
        if self.is_box_edge(point):
            return True
        c = self._char_at_opt(point)
        if c is None:
            return False
        return (_ascii_is_straight_ahead(c, direction) or _ascii_is_crossing(c) or
                is_ahead_arrow(c, direction) or
                _ascii_is_left_turn(c, direction) or _ascii_is_right_turn(c, direction))


def _ascii_is_straight_ahead(c: str, direction) -> bool:
    from xrefer._vendor.ascii_graphs.common.direction import Right, Left, Up, Down
    if c == '-' and direction in (Right, Left):
        return True
    if c == '|' and direction in (Up, Down):
        return True
    return False


def _ascii_is_orthogonal(c: str, direction) -> bool:
    return _ascii_is_straight_ahead(c, direction.turn_right)


def _ascii_is_crossing(c: str) -> bool:
    return c == '+'


def _ascii_is_turn_char(c) -> bool:
    if c is None:
        return False
    return c in ('\\', '/')


def _ascii_is_right_turn(c: str, direction) -> bool:
    from xrefer._vendor.ascii_graphs.common.direction import Left, Right, Up, Down
    if c == '\\' and direction in (Left, Right):
        return True
    if c == '/' and direction in (Up, Down):
        return True
    return False


def _ascii_is_left_turn(c: str, direction) -> bool:
    return _ascii_is_right_turn(c, direction.turn_right)
