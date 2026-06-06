"""Port of com.github.mdr.ascii.graph.GraphFromText (test helper, GraphFromText.scala).

Parses a Graph from a comma/newline text spec (as produced by Graph.toString):
each line is a comma-separated chain of vertices; consecutive vertices in a line
form a directed edge. `\\n` inside a token is unescaped to a real newline.
"""
from __future__ import annotations


def graph_from_text(text):
    from xrefer._vendor.ascii_graphs.graph.graph import Graph

    pieces = [
        [tok.replace("\\n", "\n") for tok in line.split(",")]
        for line in text.split("\n")
    ]
    edges = []
    for chunks in pieces:
        edges.extend(zip(chunks, chunks[1:]))
    vertices = set() if not text.strip() else {v for chunk in pieces for v in chunk}
    return Graph(vertices=vertices, edges=edges)
