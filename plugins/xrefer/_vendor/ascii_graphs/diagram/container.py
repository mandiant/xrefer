from __future__ import annotations


class Container:
    @property
    def text(self) -> str:
        raise NotImplementedError

    @property
    def region(self):
        raise NotImplementedError

    @property
    def child_boxes(self) -> list:
        raise NotImplementedError

    @property
    def parent(self):
        return None
