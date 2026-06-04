"""Port of com.github.mdr.ascii.java.GraphLayouter (GraphLayouter.java). STUB."""
from __future__ import annotations


class GraphLayouter:
    def __init__(self, prefs=None):
        self._prefs = prefs

    def layout(self, graph):
        from xrefer._vendor.ascii_graphs.layout.graph_layout import render_graph
        return render_graph(graph, layout_prefs=self._prefs)
