from __future__ import annotations


class Edge:
    @property
    def points(self) -> list:
        raise NotImplementedError

    @property
    def parent(self):
        raise NotImplementedError

    @property
    def box1(self):
        raise NotImplementedError

    @property
    def box2(self):
        raise NotImplementedError

    @property
    def has_arrow1(self) -> bool:
        raise NotImplementedError

    @property
    def has_arrow2(self) -> bool:
        raise NotImplementedError

    @property
    def label(self):
        raise NotImplementedError

    def other_box(self, box):
        if box is self.box1:
            return self.box2
        elif box is self.box2:
            return self.box1
        raise ValueError(f"Box not part of edge: {box}")

    def has_arrow(self, box) -> bool:
        if box is self.box1:
            return self.has_arrow1
        elif box is self.box2:
            return self.has_arrow2
        raise ValueError(f"Box not part of edge: {box}")

    def other_has_arrow(self, box) -> bool:
        return self.has_arrow(self.other_box(box))
