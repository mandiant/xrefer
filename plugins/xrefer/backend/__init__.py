"""backend abstraction with pythonic factory pattern."""

from .base import Address, BackEnd, BackendError, Function, FunctionType, Section, SectionType, String, StringEncType, Xref, XrefType, OperandType, Operand, Instruction
from .factory import backend_manager, get_backend, list_available_backends
from .utils import sample_path

# Legacy compatibility - lazy backend creation
Backend = None
get_indirect_calls = None


def _ensure_backend_initialized():
    """Lazy initialization of backend and related imports."""
    global Backend, Function, String, Xref, Section, get_indirect_calls

    if Backend is not None:
        return

    try:
        # Check if there's already an active backend set by backend manager
        active_backend = backend_manager.get_active_backend()
        Backend = active_backend if active_backend is not None else get_backend()

        # Import appropriate classes based on detected backend
        available = list_available_backends()
        if "ida" in available:
            from .ida.backend import IDAFunction as Function
            from .ida.backend import IDASection as Section
            from .ida.backend import IDAString as String
            from .ida.backend import IDAXref as Xref
            from .utils import _dump_indirect_calls_ida as get_indirect_calls
        elif "binaryninja" in available:
            from .binaryninja.backend import BinaryNinjaFunction as Function
            from .binaryninja.backend import BinaryNinjaSection as Section
            from .binaryninja.backend import BinaryNinjaString as String
            from .binaryninja.backend import BinaryNinjaXref as Xref
            from .utils import _dump_indirect_calls_bn as get_indirect_calls
        elif "ghidra" in available:
            from .ghidra.backend import GhidraFunction as Function
            from .ghidra.backend import GhidraSection as Section
            from .ghidra.backend import GhidraString as String
            from .ghidra.backend import GhidraXref as Xref
            from .utils import _dump_indirect_calls_ghidra as get_indirect_calls
        else:
            raise BackendError("No supported backend found")

    except Exception as e:
        raise BackendError(f"Failed to initialize backend: {e}") from e


def get_current_backend():
    """Get the current backend instance, initializing if needed."""
    # First check if backend manager has an active backend
    active_backend = backend_manager.get_active_backend()
    if active_backend is not None:
        return active_backend
    # Fall back to legacy initialization
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
    "Section",
    "SectionType",
    "sample_path",
    "get_indirect_calls",
    # operand
    "Instruction",
    "Operand",
    "OperandType",
    # Base classes
    "BackEnd",
]
