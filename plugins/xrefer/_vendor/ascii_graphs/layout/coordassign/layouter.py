from __future__ import annotations
from xrefer._vendor.ascii_graphs.common.point import Point
from xrefer._vendor.ascii_graphs.common.region import Region
from xrefer._vendor.ascii_graphs.common.dimension import Dimension
from xrefer._vendor.ascii_graphs.layout.layering.layering import (
    Layering, Layer, Vertex, DummyVertex, RealVertex, Edge
)
from xrefer._vendor.ascii_graphs.layout.coordassign.vertex_info import VertexInfo
from xrefer._vendor.ascii_graphs.layout.coordassign.layer_info import LayerInfo
from xrefer._vendor.ascii_graphs.layout.coordassign.edge_info import EdgeInfo
from xrefer._vendor.ascii_graphs.layout.coordassign.edge_bend_calculator import EdgeBendCalculator
from xrefer._vendor.ascii_graphs.layout.coordassign import port_nudger
from xrefer._vendor.ascii_graphs.util.utils import make_map, with_previous_and_next

MINIMUM_VERTEX_HEIGHT = 3

# Experimental hook: if set, real edge infos within a layer are stably sorted by
# this key before becoming edge elements (controls KinkRemover/EdgeElevator order).
_EDGE_SORT_KEY = None
# Experimental hook: transform applied to the real_edge_infos list (and given the
# full edge_infos list as 2nd arg) before becoming edge elements.
_EDGE_LIST_TRANSFORM = None

import os as _os
if _os.environ.get("ASCII_EXP"):
    from xrefer._vendor.ascii_graphs.util import scala_hash as _sh

    def _vhash(v):
        # experimental model of System.identityHashCode
        return v._creation_id

    def _edge_info_hash(ei):
        return _sh.product_hash([
            _vhash(ei.start_vertex) & _sh.MASK,
            _vhash(ei.finish_vertex) & _sh.MASK,
            _sh.point_hash(ei.start_port.row, ei.start_port.column),
            _sh.point_hash(ei.finish_port.row, ei.finish_port.column),
            _sh.bool_hash(ei.reversed),
        ])

    def _hamt_transform(real_edge_infos, edge_infos):
        if len(edge_infos) < 5:
            return real_edge_infos
        return sorted(real_edge_infos,
                      key=lambda p: _sh.hamt_key(_edge_info_hash(p[0])))

    _EDGE_LIST_TRANSFORM = _hamt_transform


class Layouter:
    def __init__(self, vertex_rendering_strategy, vertical: bool = True):
        self._vrs = vertex_rendering_strategy
        self._vertical = vertical

    def layout(self, layering: Layering):
        from xrefer._vendor.ascii_graphs.layout.drawing.drawing import Drawing
        layer_infos = self._calculate_layer_infos(layering)

        prev_layer_info = LayerInfo({})
        incomplete_edges = {}
        all_elements = []

        for layer in layering.layers:
            result = self._layout_layer(
                prev_layer_info, layer_infos[layer], layering.edges, incomplete_edges
            )
            elements, updated_layer_info, updated_incomplete = result
            prev_layer_info = updated_layer_info
            incomplete_edges = updated_incomplete
            all_elements.extend(elements)

        return Drawing(all_elements)

    def _calculate_layer_infos(self, layering: Layering) -> dict:
        layer_infos = {}
        for (prev_opt, current, next_opt) in with_previous_and_next(layering.layers):
            info = self._calculate_layer_info(current, layering.edges, prev_opt, next_opt)
            layer_infos[current] = info
        return port_nudger.nudge(layering, self._space_vertices(layer_infos))

    def _calculate_layer_info(self, layer: Layer, edges: list,
                               prev_layer_opt, next_layer_opt) -> LayerInfo:
        if prev_layer_opt is not None:
            in_edges = sorted(edges, key=lambda e: prev_layer_opt.vertices.index(e.start_vertex)
                              if e.start_vertex in prev_layer_opt.vertices else 0)
        else:
            in_edges = []

        if next_layer_opt is not None:
            out_edges = sorted(edges, key=lambda e: next_layer_opt.vertices.index(e.finish_vertex)
                               if e.finish_vertex in next_layer_opt.vertices else 0)
        else:
            out_edges = []

        def get_in_edges(v: Vertex):
            return [e for e in in_edges if e.finish_vertex is v]

        def get_out_edges(v: Vertex):
            return [e for e in out_edges if e.start_vertex is v]

        def get_dimension(v: Vertex) -> Dimension:
            if isinstance(v, RealVertex):
                return self._calculate_vertex_dimension(v, len(get_in_edges(v)), len(get_out_edges(v)))
            else:
                return Dimension(height=1, width=1)

        dimensions = make_map(layer.vertices, get_dimension)
        regions = self._calculate_vertex_regions(layer, dimensions)

        def build_vertex_info(v: Vertex) -> VertexInfo:
            box_region, greater_region = regions[v]
            return self._make_vertex_info(v, box_region, greater_region, get_in_edges(v), get_out_edges(v))

        return LayerInfo(make_map(layer.vertices, build_vertex_info))

    def _make_vertex_info(self, vertex: Vertex, box_region: Region, greater_region: Region,
                           in_edges: list, out_edges: list) -> VertexInfo:
        if isinstance(vertex, RealVertex):
            return self._make_real_vertex_info(vertex, box_region, greater_region, in_edges, out_edges)
        else:
            return self._make_dummy_vertex_info(vertex, box_region, greater_region, in_edges, out_edges)

    def _make_real_vertex_info(self, vertex: RealVertex, box_region: Region, greater_region: Region,
                                in_edges: list, out_edges: list) -> VertexInfo:
        in_degree = len(in_edges) + vertex.self_edges
        in_ports = [box_region.top_left.right(off) for off in self._port_offsets_count(in_degree, box_region.width)]
        in_edge_map = dict(zip(in_edges, in_ports))
        self_in_ports = in_ports[len(in_edges):]

        out_degree = len(out_edges) + vertex.self_edges
        out_ports = [box_region.bottom_left.right(off) for off in self._port_offsets_count(out_degree, box_region.width)]
        out_edge_map = dict(zip(out_edges, out_ports))
        self_out_ports = out_ports[len(out_edges):]

        return VertexInfo(box_region, greater_region, in_edge_map, out_edge_map, self_in_ports, self_out_ports)

    def _make_dummy_vertex_info(self, vertex: DummyVertex, box_region: Region, greater_region: Region,
                                 in_edges: list, out_edges: list) -> VertexInfo:
        in_edge, = in_edges
        out_edge, = out_edges
        port = box_region.top_left
        return VertexInfo(box_region, greater_region,
                          {in_edge: port}, {out_edge: port}, [], [])

    def _port_offsets_count(self, port_count: int, vertex_width: int) -> list:
        factor = vertex_width // (port_count + 1)
        centraliser = (vertex_width - factor * (port_count + 1)) // 2
        return [(i + 1) * factor + centraliser for i in range(port_count)]

    def _calculate_vertex_dimension(self, v: RealVertex, in_degree: int, out_degree: int) -> Dimension:
        self_edges = v.self_edges

        def required_width(degree: int) -> int:
            return (degree + self_edges) * 2 + 1 + 2

        req_in_w = required_width(in_degree)
        req_out_w = required_width(out_degree)
        pref = self._get_preferred_size(v)
        width = max(max(req_in_w, req_out_w), pref.width + 2)
        height = max(MINIMUM_VERTEX_HEIGHT, pref.height + 2)
        return Dimension(height=height, width=width)

    def _calculate_vertex_regions(self, layer: Layer, dimensions: dict) -> dict:
        regions = {}
        next_top_left = Point(0, 0)
        for vertex in layer.vertices:
            dim = dimensions[vertex]
            box_region = Region.from_top_left_and_dimension(next_top_left, dim)
            if isinstance(vertex, RealVertex) and vertex.self_edges > 0:
                self_edge_spacing = vertex.self_edges * 2
            else:
                self_edge_spacing = 0
            greater_region = (box_region
                              .expand_right(self_edge_spacing)
                              .expand_up(self_edge_spacing)
                              .expand_down(self_edge_spacing))
            regions[vertex] = (box_region, greater_region)
            next_top_left = box_region.top_right.right(self_edge_spacing + 2)
        return regions

    def _calculate_diagram_width(self, layer_infos: dict) -> int:
        def layer_width(li: LayerInfo) -> int:
            vis = list(li.vertex_infos.values())
            return sum(vi.greater_region.width for vi in vis) + len(vis) - 1
        return max((layer_width(li) for li in layer_infos.values()), default=0)

    def _space_vertices(self, layer_infos: dict) -> dict:
        diagram_width = self._calculate_diagram_width(layer_infos)
        return {layer: self._space_vertices_in_layer(layer, info, diagram_width)
                for layer, info in layer_infos.items()}

    def _space_vertices_in_layer(self, layer: Layer, info: LayerInfo, diagram_width: int) -> LayerInfo:
        excess = diagram_width - info.max_column()
        h_spacing = max(excess // (len(info.vertex_infos) + 1), 1)

        layer_height = max((vi.box_region.height for vi in info.vertex_infos.values()), default=1)

        left_col = h_spacing
        new_vis = {}
        for v in layer.vertices:
            vi = info.vertex_info(v)
            if vi is None:
                continue
            old_left = left_col
            left_col += vi.greater_region.width
            left_col += h_spacing
            vert_offset = (layer_height - vi.box_region.height) // 2
            new_vis[v] = vi.set_left(old_left).down(vert_offset)
        return LayerInfo(new_vis)

    def _layout_layer(self, prev_info: LayerInfo, curr_info: LayerInfo,
                       edges: list, incomplete_edges: dict):
        from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import (
            EdgeDrawingElement, VertexDrawingElement
        )

        edge_infos = self._make_edge_infos(edges, prev_info, curr_info)
        edge_zone_top_row = -1 if prev_info.is_empty() else prev_info.max_row() + 1
        bend_calc = EdgeBendCalculator(edge_infos, edge_zone_top_row, curr_info.top_self_edge_buffer())

        def get_edge_points(ei: EdgeInfo) -> list:
            true_finish = ei.finish_port.translate(down=bend_calc.edge_zone_bottom_row + 1)
            if isinstance(ei.start_vertex, DummyVertex):
                prior = incomplete_edges[ei.start_vertex]
            else:
                prior = [ei.start_port]
            last = prior[-1]
            if last.column == true_finish.column:
                pts = prior + [true_finish]
            else:
                assert ei.requires_bend, f"{ei}, prior={prior}"
                bend_r = bend_calc.bend_row(ei)
                pts = prior + [last.with_row(bend_r), true_finish.with_row(bend_r), true_finish]
            return Point.remove_redundant_points(pts)

        ei_to_points = {ei: get_edge_points(ei) for ei in edge_infos}

        updated_incomplete = {}
        for ei, pts in ei_to_points.items():
            if isinstance(ei.finish_vertex, DummyVertex):
                updated_incomplete[ei.finish_vertex] = pts

        updated_layer_info = curr_info.down(bend_calc.edge_zone_bottom_row + 1)

        vertex_elements = [
            VertexDrawingElement(vi.box_region, self._get_text(rv, vi.content_region.dimension))
            for rv, vi in updated_layer_info.real_vertex_infos()
        ]

        # Preserve the natural edgeInfos order (derived from layering.edges).
        # In Scala, edgeInfoToPoints.toList iterates in HashMap order based on
        # EdgeInfo.## which depends on System.identityHashCode of Vertex objects —
        # not reproducible in Python. However, the natural layering.edges order
        # (reversed insertion order from _LayeringBuilder.add_edge) happens to match
        # the Scala golden output because the KinkRemover processes edges in this
        # order and produces the same kink-removal decisions.
        real_edge_infos = [(ei, ei_to_points[ei]) for ei in edge_infos
                           if isinstance(ei.finish_vertex, RealVertex)]
        if _EDGE_SORT_KEY is not None:
            real_edge_infos = sorted(real_edge_infos, key=lambda p: _EDGE_SORT_KEY(p[0]))
        if _EDGE_LIST_TRANSFORM is not None:
            real_edge_infos = _EDGE_LIST_TRANSFORM(real_edge_infos, edge_infos)
        edge_elements = [
            EdgeDrawingElement(pts, ei.reversed, not ei.reversed)
            for ei, pts in real_edge_infos
        ]

        self_edge_elements = self._make_self_edge_elements(updated_layer_info)

        all_elements = vertex_elements + edge_elements + self_edge_elements
        return all_elements, updated_layer_info, updated_incomplete

    def _make_edge_infos(self, edges: list, prev_info: LayerInfo, curr_info: LayerInfo) -> list:
        result = []
        for edge in edges:
            prev_vi = prev_info.vertex_info(edge.start_vertex)
            curr_vi = curr_info.vertex_info(edge.finish_vertex)
            if prev_vi is None or curr_vi is None:
                continue
            start = prev_vi.out_edge_to_port_map.get(edge)
            finish = curr_vi.in_edge_to_port_map.get(edge)
            if start is None or finish is None:
                continue
            result.append(EdgeInfo(edge.start_vertex, edge.finish_vertex,
                                   start.down(), finish.up(), edge.reversed))
        return result

    def _make_self_edge_elements(self, layer_info: LayerInfo) -> list:
        from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import EdgeDrawingElement
        result = []
        for v, vi in layer_info.vertex_infos.items():
            if not isinstance(v, RealVertex):
                continue
            pairs = list(zip(vi.self_out_ports, vi.self_in_ports))
            for i, (out_p, in_p) in enumerate(reversed(pairs)):
                result.append(self._make_self_edge_element(vi, out_p, in_p, i))
        return result

    def _make_self_edge_element(self, vi: VertexInfo, out_port: Point, in_port: Point, idx: int):
        from xrefer._vendor.ascii_graphs.layout.drawing.drawing_element import EdgeDrawingElement
        box_right = vi.box_region.right_column
        p1 = out_port.down()
        p2 = p1.down(idx + 1)
        p3 = p2.right(box_right - p2.column + idx * 2 + 2)
        p4 = p3.up(vi.box_region.height + 2 * (idx + 1) + 1)
        p5 = p4.left(p4.column - in_port.column)
        p6 = in_port.up()
        return EdgeDrawingElement([p1, p2, p3, p4, p5, p6], False, True)

    def _get_preferred_size(self, rv: RealVertex) -> Dimension:
        pref = self._vrs.get_preferred_size(rv.contents)
        if self._vertical:
            return pref
        return pref.transpose()

    def _get_text(self, rv: RealVertex, preferred_size: Dimension) -> list:
        actual = preferred_size if self._vertical else preferred_size.transpose()
        return self._vrs.get_text(rv.contents, actual)
