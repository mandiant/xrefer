from __future__ import annotations
from xrefer._vendor.ascii_graphs.graph.graph import Graph
from xrefer._vendor.ascii_graphs.layout.prefs.layout_prefs_impl import LayoutPrefsImpl
from xrefer._vendor.ascii_graphs.layout.cycles.cycle_remover import remove_cycles
from xrefer._vendor.ascii_graphs.layout.layering.layering_calculator import LayeringCalculator
from xrefer._vendor.ascii_graphs.layout.layering.layer_ordering_calculator import reorder
from xrefer._vendor.ascii_graphs.layout.coordassign.layouter import Layouter
from xrefer._vendor.ascii_graphs.layout.coordassign.to_string_vertex_rendering_strategy import (
    ToStringVertexRenderingStrategy
)
from xrefer._vendor.ascii_graphs.layout.drawing.kink_remover import remove_kinks
from xrefer._vendor.ascii_graphs.layout.drawing.edge_elevator import elevate_edges
from xrefer._vendor.ascii_graphs.layout.drawing.redundant_row_remover import remove_redundant_rows
from xrefer._vendor.ascii_graphs.layout.drawing.renderer import render


def render_graph(graph: Graph, vertex_rendering_strategy=None, layout_prefs=None) -> str:
    if vertex_rendering_strategy is None:
        vertex_rendering_strategy = ToStringVertexRenderingStrategy
    if layout_prefs is None:
        layout_prefs = LayoutPrefsImpl()

    crr = remove_cycles(graph)
    layering, _ = LayeringCalculator().assign_layers(crr)
    reordered = reorder(layering)

    layouter = Layouter(ToStringVertexRenderingStrategy, layout_prefs.vertical)
    drawing = layouter.layout(reordered)

    if layout_prefs.remove_kinks:
        drawing = remove_kinks(drawing)
    if layout_prefs.elevate_edges:
        drawing = elevate_edges(drawing)
    if layout_prefs.compactify:
        drawing = remove_redundant_rows(drawing)
    if not layout_prefs.vertical:
        drawing = drawing.transpose()

    return render(drawing, layout_prefs)
