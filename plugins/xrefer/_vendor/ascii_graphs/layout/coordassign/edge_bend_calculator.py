from __future__ import annotations
from xrefer._vendor.ascii_graphs.layout.coordassign.edge_info import EdgeInfo
from xrefer._vendor.ascii_graphs.util.utils import signum


class EdgeBendCalculator:
    def __init__(self, edge_infos: list, edge_zone_top_row: int, self_edge_buffer: int):
        self._edge_rows = self._order_edge_bends(edge_infos)
        self._edge_zone_top_row = edge_zone_top_row
        self._self_edge_buffer = self_edge_buffer

        if not edge_infos:
            self.edge_zone_bottom_row = -1 + self_edge_buffer
        elif not self._edge_rows:
            self.edge_zone_bottom_row = edge_zone_top_row + 2 + self_edge_buffer
        else:
            max_row_idx = max(self._edge_rows.values())
            self.edge_zone_bottom_row = self._bend_row(max_row_idx) + 2 + self_edge_buffer

    def _bend_row(self, row_index: int) -> int:
        return self._edge_zone_top_row + row_index * 1 + 1

    def bend_row(self, edge_info: EdgeInfo) -> int:
        return self._bend_row(self._edge_rows[id(edge_info)])

    def _order_edge_bends(self, edge_infos: list) -> dict:
        def edge_rank(ei: EdgeInfo) -> int:
            return signum(ei.start_column - ei.finish_column) * ei.finish_column

        ordered = sorted([ei for ei in edge_infos if ei.requires_bend], key=edge_rank)
        edge_to_row = {id(ei): i for i, ei in enumerate(ordered)}
        return self._reorder_edges_with_same_start_and_end_columns(edge_to_row, ordered)

    def _reorder_edges_with_same_start_and_end_columns(self, edge_to_row: dict, edge_infos: list) -> dict:
        updated = dict(edge_to_row)
        continue_flag = True
        swapped = set()
        while continue_flag:
            continue_flag = False
            for ei1 in edge_infos:
                for ei2 in edge_infos:
                    if ei1 is ei2:
                        continue
                    if ei1.start_column != ei2.finish_column:
                        continue
                    if ei2.start_column == ei1.finish_column:
                        continue
                    id1, id2 = id(ei1), id(ei2)
                    if id1 not in updated or id2 not in updated:
                        continue
                    row1 = updated[id1]
                    row2 = updated[id2]
                    if row1 <= row2:
                        continue
                    if (id1, id2) in swapped:
                        continue
                    updated[id1] = row2
                    updated[id2] = row1
                    swapped.add((id1, id2))
                    continue_flag = True
        return updated

