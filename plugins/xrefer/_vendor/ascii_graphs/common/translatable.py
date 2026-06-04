from __future__ import annotations


class Translatable:
    """Mixin for objects that can be shifted in 2D."""

    def translate(self, down: int = 0, right: int = 0):
        raise NotImplementedError

    def up(self, n: int = 1):
        return self.translate(down=-n)

    def down(self, n: int = 1):
        return self.translate(down=n)

    def left(self, n: int = 1):
        return self.translate(right=-n)

    def right(self, n: int = 1):
        return self.translate(right=n)

    def go(self, direction):
        from xrefer._vendor.ascii_graphs.common.direction import Up, Down, Left, Right
        if direction is Up:
            return self.up()
        elif direction is Down:
            return self.down()
        elif direction is Left:
            return self.left()
        elif direction is Right:
            return self.right()
        else:
            raise ValueError(f"Unknown direction: {direction}")
