from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.direction import Up, Down, Left, Right


def is_ahead_arrow(c: str, direction) -> bool:
    if c == '^' and direction is Up:
        return True
    if c in ('v', 'V') and direction is Down:
        return True
    if c == '<' and direction is Left:
        return True
    if c == '>' and direction is Right:
        return True
    return False


def is_left_arrow(c: str, direction) -> bool:
    return is_ahead_arrow(c, direction.turn_left)


def is_right_arrow(c: str, direction) -> bool:
    return is_ahead_arrow(c, direction.turn_right)
