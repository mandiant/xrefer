from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class Dimension:
    height: int
    width: int

    @classmethod
    def from_point(cls, largest_point) -> Dimension:
        return cls(width=largest_point.column + 1, height=largest_point.row + 1)

    def transpose(self) -> Dimension:
        return Dimension(self.width, self.height)
