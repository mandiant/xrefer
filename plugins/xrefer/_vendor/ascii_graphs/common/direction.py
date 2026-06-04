from __future__ import annotations


class Direction:
    def is_vertical(self):
        return self is Up or self is Down

    def is_horizontal(self):
        return not self.is_vertical()


class _Up(Direction):
    turn_left = None  # set after class defs
    turn_right = None
    opposite = None
    def __repr__(self): return "Up"

class _Down(Direction):
    turn_left = None
    turn_right = None
    opposite = None
    def __repr__(self): return "Down"

class _Left(Direction):
    turn_left = None
    turn_right = None
    opposite = None
    def __repr__(self): return "Left"

class _Right(Direction):
    turn_left = None
    turn_right = None
    opposite = None
    def __repr__(self): return "Right"


Up = _Up()
Down = _Down()
Left = _Left()
Right = _Right()

Up.turn_left = Left
Up.turn_right = Right
Up.opposite = Down

Down.turn_left = Right
Down.turn_right = Left
Down.opposite = Up

Left.turn_left = Down
Left.turn_right = Up
Left.opposite = Right

Right.turn_left = Up
Right.turn_right = Down
Right.opposite = Left
