from __future__ import annotations
from xrefer._vendor.ascii_graphs.graph.graph import Graph


def topological_sort(g: Graph):
    """Return list of vertices in topological order, or None if cycle exists."""
    sort = []
    sources = list(g.sources)
    deleted_edges = set()
    while sources:
        n = sources.pop(0)
        sort.append(n)
        for m in g.out_vertices(n):
            if (m, n) not in deleted_edges:
                deleted_edges.add((n, m))
                remaining_in = [e for e in g.in_edges(m) if tuple(e) not in deleted_edges]
                if not remaining_in and m not in sources:
                    sources.append(m)
    if deleted_edges == set(tuple(e) for e in g.edges):
        return sort
    else:
        return None


def has_cycle(g: Graph) -> bool:
    return topological_sort(g) is None

