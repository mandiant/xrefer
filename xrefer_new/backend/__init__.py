"""Backend contracts and host-specific adapters for XRefer."""

from .base import BackEnd
from .types import CallSite, Function, ImportEntry, Segment, StringArtifact

__all__ = [
    "BackEnd",
    "CallSite",
    "Function",
    "ImportEntry",
    "Segment",
    "StringArtifact",
]

