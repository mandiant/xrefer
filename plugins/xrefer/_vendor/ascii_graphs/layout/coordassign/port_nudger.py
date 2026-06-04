from __future__ import annotations
from xrefer._vendor.ascii_graphs.layout.layering.layering import DummyVertex, RealVertex
from xrefer._vendor.ascii_graphs.layout.coordassign.layer_info import LayerInfo
from xrefer._vendor.ascii_graphs.util.utils import with_previous


def nudge(layering, layer_infos: dict) -> dict:
    updated = dict(layer_infos)
    for (prev_layer_opt, current_layer) in with_previous(layering.layers):
        prev_info_opt = updated.get(prev_layer_opt) if prev_layer_opt is not None else None
        current_info = layer_infos[current_layer]
        updated[current_layer] = _nudge_layer(prev_info_opt, current_info)
    return updated


def _get_out_edge_columns(prev_info_opt) -> list:
    if prev_info_opt is None:
        return []
    cols = []
    for vi in prev_info_opt.vertex_infos.values():
        for p in vi.out_edge_to_port_map.values():
            cols.append(p.column)
    return cols


def _nudge_layer(prev_info_opt, current_info: LayerInfo) -> LayerInfo:
    prev_edge_cols = set(_get_out_edge_columns(prev_info_opt))
    new_vertex_infos = {}
    for vertex, vi in current_info.vertex_infos.items():
        new_vertex_infos[vertex] = _nudge_vertex_info(vertex, vi, prev_info_opt, prev_edge_cols)
    return current_info.copy(vertex_infos=new_vertex_infos)


def _nudge_vertex_info(vertex, vi, prev_info_opt, prev_edge_cols: set):
    def should_nudge(edge, port) -> bool:
        return port.column in prev_edge_cols and not _is_straight(edge, vi, prev_info_opt)

    nudged_cols = set()
    new_in = {}
    for edge, port in vi.in_edge_to_port_map.items():
        if should_nudge(edge, port):
            nudged_cols.add(port.column)
            new_in[edge] = port.right()
        else:
            new_in[edge] = port

    if isinstance(vertex, DummyVertex):
        new_out = {}
        for edge, port in vi.out_edge_to_port_map.items():
            if port.column in nudged_cols:
                new_out[edge] = port.right()
            else:
                new_out[edge] = port
    else:
        new_out = dict(vi.out_edge_to_port_map)

    return vi.copy(in_edge_to_port_map=new_in, out_edge_to_port_map=new_out)


def _is_straight(edge, vi, prev_info_opt) -> bool:
    if prev_info_opt is None:
        return False
    prev_vi = prev_info_opt.vertex_info(edge.start_vertex)
    if prev_vi is None:
        return False
    col1 = prev_vi.out_edge_to_port_map.get(edge)
    if col1 is None:
        return False
    col2 = vi.in_edge_to_port_map.get(edge)
    if col2 is None:
        return False
    return col1.column == col2.column

