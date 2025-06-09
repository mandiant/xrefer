_BACKEND = {
    "ida": False,
    "binaryninja": False,
    "ghidra": False,
}

for k, v in [("ida", "idc"), ("binaryninja", "binaryninja")]:
    try:
        __import__(v)
        _BACKEND[k] = True
        break
    except ImportError:
        pass

if _BACKEND["ida"]:
    from .ida import IDABackend as Backend
    from .ida import IDAFunction as Function
    from .ida import IDAString as String
    from .ida import IDAXref as Xref
    from .utils import _dump_indirect_calls_ida as get_indirect_calls
elif _BACKEND["binaryninja"]:
    # from .binaryninja.backend import BinaryNinjaBackend as BackEnd
    from .utils import _dump_indirect_calls_bn as get_indirect_calls
else:
    raise ImportError("No supported backend found. Please ensure IDA Pro or Binary Ninja is available.")

from .utils import sample_path

__all__ = [
    "Function",
    "String",
    "Xref",
    "Segment",
    "Backend",
    "sample_path",
    "get_indirect_calls",
]
