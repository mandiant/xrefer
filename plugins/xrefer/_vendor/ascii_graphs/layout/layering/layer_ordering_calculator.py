from __future__ import annotations
from xrefer._vendor.ascii_graphs.layout.layering.layering import Layering, Layer


def reorder(layering: Layering) -> Layering:
    """Sweep top to bottom, reordering each layer to minimize crossings."""
    previous_layer = None
    new_layers = []
    for current_layer in layering.layers:
        if previous_layer is not None:
            updated = _reorder_layer(previous_layer, current_layer, layering.edges)
        else:
            updated = current_layer
        new_layers.append(updated)
        previous_layer = updated
    return layering.copy(layers=new_layers)


def _reorder_layer(layer1: Layer, layer2: Layer, edges: list) -> Layer:
    def barycenter(vertex) -> float:
        in_vertices = [e.start_vertex for e in edges if e.finish_vertex is vertex]
        if not in_vertices:
            # Scala returns Double.NaN (0.0/0) for empty; Java compareTo treats NaN as
            # greater than everything, so NaN vertices sort to the end.
            return float('inf')
        return sum(layer1.position_of(v) for v in in_vertices) / len(in_vertices)

    sorted_vertices = sorted(layer2.vertices, key=barycenter)
    return layer2.copy(vertices=sorted_vertices)
