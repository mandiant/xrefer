"""Pure-Python port of ascii-graphs (com.github.mdr.ascii).

Public API mirrors the `asciinet` wrapper but with NO JVM dependency.

    from ascii_graphs import graph_to_ascii
    print(graph_to_ascii(networkx_graph))

Implementation status: SCAFFOLD. The modules below are stubs to be filled in
1:1 from the Scala source in reference/ascii-graphs. See PORTING_PLAN.md.
"""
from __future__ import annotations

__all__ = ["graph_to_ascii", "render_graph", "Graph"]


def graph_to_ascii(graph, timeout=None):  # noqa: ARG001  (timeout kept for API parity)
    """Render a networkx graph as an ASCII/Unicode diagram.

    Drop-in replacement for ``asciinet.graph_to_ascii``. Mirrors the asciinet
    Server: build a ``Graph[String]`` from the networkx vertices/edges (as
    strings) and call ``GraphLayout.render_graph`` with default layout prefs.
    Returns "" when the graph has no edges (matches the reference Server).
    """
    try:
        import networkx as nx
    except ImportError as exc:  # pragma: no cover
        raise ImportError("graph_to_ascii requires networkx") from exc

    if not isinstance(graph, nx.Graph):
        raise ValueError("graph must be a networkx.Graph")

    vertices = [str(v) for v in graph.nodes()]
    edges = [(str(u), str(v)) for u, v in graph.edges()]
    if not vertices or not edges:
        return ""

    from xrefer._vendor.ascii_graphs.graph.graph import Graph
    from xrefer._vendor.ascii_graphs.layout.graph_layout import render_graph as _render

    return _render(Graph(vertices=vertices, edges=edges))


def render_graph(graph):
    """Render an already-built ascii_graphs Graph (mirrors GraphLayout.renderGraph)."""
    from xrefer._vendor.ascii_graphs.layout.graph_layout import render_graph as _render

    return _render(graph)


def __getattr__(name):  # lazy re-export so the package imports before stubs exist
    if name == "Graph":
        from xrefer._vendor.ascii_graphs.graph.graph import Graph

        return Graph
    raise AttributeError(name)
