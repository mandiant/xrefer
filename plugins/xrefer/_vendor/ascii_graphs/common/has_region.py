from __future__ import annotations


class HasRegion:
    @property
    def region(self):
        raise NotImplementedError
