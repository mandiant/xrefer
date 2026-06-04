from __future__ import annotations
from xrefer._vendor.ascii_graphs.graph.graph import Graph


def longest_distances_to_sink(graph: Graph) -> dict:
    """For each vertex, compute the length of the longest path to a sink."""
    finalised: set = set(graph.sinks)
    distances: dict = {v: 0 for v in graph.vertices}
    boundary: set = set(finalised)

    while boundary:
        new_boundary = set()
        for v2 in boundary:
            for v1 in graph.in_vertices(v2):
                new_dist = max(distances[v1], distances[v2] + 1)
                distances[v1] = new_dist
                if all(u in finalised for u in graph.out_vertices(v1)):
                    finalised.add(v1)
                    new_boundary.add(v1)
        boundary = new_boundary

    return distances

