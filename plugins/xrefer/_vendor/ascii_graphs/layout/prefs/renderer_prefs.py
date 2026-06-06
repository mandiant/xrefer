"""Port of com.github.mdr.ascii.layout.prefs.RendererPrefs (RendererPrefs.scala). STUB."""
from __future__ import annotations
from typing import Protocol


class RendererPrefs(Protocol):
    unicode: bool
    rounded: bool
    explicit_ascii_bends: bool
