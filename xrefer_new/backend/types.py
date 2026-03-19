"""Typed backend models shared by all XRefer host adapters"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Segment:
    """Normalized memory segment description"""

    name: str
    start_ea: int
    end_ea: int


@dataclass(frozen=True)
class Function:
    """Normalized function description"""
    start_ea: int
    end_ea: int
    name: str
    is_library: bool = False
    is_thunk: bool = False


@dataclass(frozen=True)
class ImportEntry:
    """Normalized import entry"""
    ea: int
    name: str
    module: str
    ordinal: Optional[int] = None


@dataclass(frozen=True)
class StringArtifact:
    """Normalized string entry"""

    ea: int
    value: str
    encoding: str = "unknown"


@dataclass(frozen=True)
class CallSite:
    """Normalized function-call edge"""
    caller_ea: int
    call_ea: int
    callee_ea: int
    is_direct: bool = True
