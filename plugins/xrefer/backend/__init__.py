g = globals()


if "binaryninja" in globals():
    # from .binaryninja.backend import BinaryNinjaBackend as BackEnd
    pass
if "idc" in globals() or True:
    # TODO: idc is not loaded when importing this module in IDA Pro. Need to think of a better way to handle this.
    # For now, just fallback
    from .ida.backend import IDABackend as Backend
    from .ida.backend import IDAFunction as Function
    from .ida.backend import IDAString as String
    from .ida.backend import IDAXref as Xref
else:
    raise ImportError("No supported backend found. Please ensure IDA Pro or Binary Ninja is available.")

from .utils import sample_path

__all__ = [
    "Function",
    "String",
    "Xref",
    "Backend",
    "sample_path",
]
