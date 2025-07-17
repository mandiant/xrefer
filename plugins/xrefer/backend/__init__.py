"""backend abstraction with pythonic factory pattern."""

from .base import Address, BackEnd, BackendError, Function, FunctionType, Segment, String, StringEncType, Xref, XrefType
from .factory import backend_manager, get_backend, list_available_backends
from .utils import sample_path

# Legacy compatibility - lazy backend creation
Backend = None
Function = None
String = None
Xref = None
Segment = None
get_indirect_calls = None


def _ensure_backend_initialized():
    """Lazy initialization of backend and related imports."""
    global Backend, Function, String, Xref, Segment, get_indirect_calls

    if Backend is not None:
        return

    try:
        # Check if there's already an active backend set by backend manager
        active_backend = backend_manager.get_active_backend()
        if active_backend is not None:
            Backend = active_backend
        else:
            # Fallback to auto-detection (this will fail for Binary Ninja without bv parameter)
            Backend = get_backend()

        # Import appropriate classes based on detected backend
        available = list_available_backends()
        if "ida" in available:
            from .ida.backend import IDAFunction as Function
            from .ida.backend import IDASegment as Segment
            from .ida.backend import IDAString as String
            from .ida.backend import IDAXref as Xref
            from .utils import _dump_indirect_calls_ida as get_indirect_calls
        elif "binaryninja" in available:
            from .binaryninja.backend import BinaryNinjaFunction as Function
            from .binaryninja.backend import BinaryNinjaSegment as Segment
            from .binaryninja.backend import BinaryNinjaString as String
            from .binaryninja.backend import BinaryNinjaXref as Xref
            from .utils import _dump_indirect_calls_bn as get_indirect_calls
        else:
            raise BackendError("No supported backend found")

    except Exception as e:
        raise BackendError(f"Failed to initialize backend: {e}")


def get_current_backend():
    """Get the current backend instance, initializing if needed."""
    _ensure_backend_initialized()
    return Backend


__all__ = [
    # interface
    "get_backend",
    "list_available_backends",
    "backend_manager",
    "BackendError",
    # Types
    "Address",
    "FunctionType",
    "XrefType",
    "StringEncType",
    # Legacy compatibility
    "Backend",
    "Function",
    "String",
    "Xref",
    "Segment",
    "sample_path",
    "get_indirect_calls",
    # Base classes
    "BackEnd",
]
