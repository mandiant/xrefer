from __future__ import annotations

_CONNECT_SINGLE_RIGHT = {
    '│': '├', '─': '─', '║': '╟', '╢': '╫', '╟': '╟', '╫': '╫',
    '╨': '╨', '╥': '╥', '┼': '┼', '┐': '┬', '┘': '┴', '└': '└',
    '┌': '┌', '┬': '┬', '┴': '┴', '┤': '┼', '├': '├',
}


def is_box_drawing_character(c: str) -> bool:
    return 0x2500 <= ord(c) <= 0x257f


def connect_single_right(c: str) -> str:
    return _CONNECT_SINGLE_RIGHT.get(c, c)

