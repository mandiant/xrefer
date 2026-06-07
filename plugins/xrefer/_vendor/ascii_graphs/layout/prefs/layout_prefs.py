"""Port of com.github.mdr.ascii.layout.prefs.LayoutPrefs (trait).

A LayoutPrefs exposes: remove_kinks, compactify, elevate_edges, vertical,
unicode, double_vertices, rounded, explicit_ascii_bends.
"""
from __future__ import annotations
from typing import Protocol


class LayoutPrefs(Protocol):
    remove_kinks: bool
    compactify: bool
    elevate_edges: bool
    vertical: bool
    unicode: bool
    double_vertices: bool
    rounded: bool
    explicit_ascii_bends: bool
