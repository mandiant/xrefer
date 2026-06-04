from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.dimension import Dimension


class VertexRenderingStrategy:
    def get_preferred_size(self, v) -> Dimension:
        raise NotImplementedError

    def get_text(self, v, allocated_size: Dimension) -> list:
        raise NotImplementedError

