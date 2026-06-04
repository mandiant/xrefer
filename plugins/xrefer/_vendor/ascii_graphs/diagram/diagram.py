from __future__ import annotations
from xrefer._vendor.ascii_graphs.diagram.container import Container


class DiagramTrait(Container):
    @property
    def all_boxes(self) -> list:
        raise NotImplementedError

    @property
    def all_edges(self) -> list:
        raise NotImplementedError

    @property
    def parent(self):
        return None

    def box_at(self, point):
        raise NotImplementedError


def Diagram(text: str):  # noqa: N802  — mirrors Scala companion object apply
    from xrefer._vendor.ascii_graphs.diagram.parser.diagram_parser import DiagramParser
    return DiagramParser(text).get_diagram()
