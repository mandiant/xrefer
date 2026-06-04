from __future__ import annotations
import re
from xrefer._vendor.ascii_graphs.common.dimension import Dimension
from xrefer._vendor.ascii_graphs.layout.coordassign.vertex_rendering_strategy import VertexRenderingStrategy


class _ToStringVertexRenderingStrategy(VertexRenderingStrategy):

    def get_preferred_size(self, v) -> Dimension:
        lines = self._split_lines(str(v))
        height = len(lines)
        width = max((len(line) for line in lines), default=0)
        return Dimension(height, width)

    def get_text(self, v, allocated_size: Dimension) -> list:
        unpadded = [self._center_line(allocated_size, line)
                    for line in self._split_lines(str(v))[:allocated_size.height]]
        discrepancy = max(0, allocated_size.height - len(unpadded))
        padding = [''] * (discrepancy // 2)
        return padding + unpadded + padding

    def _split_lines(self, s: str) -> list:
        parts = re.split(r'(\r)?\n', s)
        lines = [p for p in parts if p is not None and p != '\r']
        if lines == ['']:
            return []
        return lines

    def _center_line(self, allocated_size: Dimension, line: str) -> str:
        discrepancy = allocated_size.width - len(line)
        padding = ' ' * (discrepancy // 2)
        return padding + line


ToStringVertexRenderingStrategy = _ToStringVertexRenderingStrategy()

