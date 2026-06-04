"""Port of com.github.mdr.ascii.layout.prefs.LayoutPrefsImpl (LayoutPrefsImpl.scala).

This one is exact: the default flags below MUST match the Scala case class
defaults, since asciinet/Server renders with `LayoutPrefsImpl()` (all defaults).
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class LayoutPrefsImpl:
    remove_kinks: bool = True
    compactify: bool = True
    elevate_edges: bool = True
    vertical: bool = True
    unicode: bool = True
    double_vertices: bool = False
    rounded: bool = False  # typical Windows fonts mis-render bend chars
    explicit_ascii_bends: bool = False


# LayoutPrefsImpl.DEFAULT — easy access to the defaults.
DEFAULT = LayoutPrefsImpl()
