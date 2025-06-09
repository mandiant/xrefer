"""IDA-specific wrapper classes."""

from typing import Iterator, Optional, Tuple

import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import ida_xref
import idaapi
import idautils
import idc

from ..base import BackEnd, BasicBlock, Function, Segment, String, Xref
from ..types import Address, FunctionType, XrefType


class IDAFunction(Function):
    """IDA function wrapper."""

    def __init__(self, ida_func: "ida_funcs.func_t"):
        self._func = ida_func
        self._name = None
        self._function_type = None
        # super().__init__(address, name)

    @property
    def start(self) -> Address:
        return Address(self._func.start_ea)

    @property
    def name(self) -> str:
        self._name = idc.get_func_name(self._func.start_ea)
        return self._name

    # @property
    # def total_bytes(self) -> int: # this is dead code
    #     # ref: https://github.com/Vector35/binaryninja-api/blob/dev/docs/dev/concepts.md#how-big-is-a-function
    #     # https://www.youtube.com/watch?v=s1tl5LA6KrI
    #     return self._func.end_ea - self._func.start_ea

    @property
    def type(self) -> FunctionType:
        """Get function classification."""
        if self._function_type is None:
            flags = idc.get_func_flags(self._func.start_ea)

            if flags & idc.FUNC_LIB:
                self._function_type = FunctionType.LIBRARY
            elif flags & idc.FUNC_THUNK:
                self._function_type = FunctionType.THUNK
            elif self._is_import():
                self._function_type = FunctionType.IMPORT
            elif self._is_export():
                self._function_type = FunctionType.EXPORT
            else:
                self._function_type = FunctionType.NORMAL

        return self._function_type

    @property
    def is_thunk(self) -> bool:
        """Check if the function is a thunk."""
        return bool(idc.get_func_flags(self._func.start_ea) & idc.FUNC_THUNK)

    def contains(self, address: Address) -> bool:
        """Check if the address is within the function."""
        return idc.func_contains(self._func.start_ea, address.value)

    @property
    def basic_blocks(self) -> Iterator[BasicBlock]:
        """Iterate over basic blocks in the function."""
        for block in idaapi.FlowChart(self._func):
            yield BasicBlock(Address(block.start_ea), Address(block.end_ea))

    def _is_import(self) -> bool:
        """Return True if the function resides in an import segment."""
        seg: "ida_segment.segment_t" = ida_segment.getseg(self._func.start_ea)
        return bool(seg) and seg.type == ida_segment.SEG_XTRN

    def _is_export(self) -> bool:
        """Return True if the function is exported from the binary."""
        # TODO: do this.
        pass


class IDAString(String):
    """IDA string wrapper."""

    def __init__(self, string_info):
        self._info = string_info
        self._content = None

    @property
    def address(self) -> Address:
        return Address(self._info.ea)

    @property
    def content(self) -> str:
        if self._content is None:
            str_type = idc.get_str_type(self._info.ea)
            if str_type is None:
                return ""
            raw = ida_bytes.get_strlit_contents(self._info.ea, self.length, str_type)
            if raw:
                self._content = raw.decode("utf-8", errors="replace")
            else:
                self._content = ""
        return self._content

    @property
    def length(self) -> int:
        return self._info.length


class IDAXref(Xref):
    """IDA cross-reference wrapper."""

    def __init__(self, xref):
        self._xref: "ida_xref.xrefblk_t" = xref

    @property
    def source(self) -> Address:
        return Address(self._xref.frm)

    @property
    def target(self) -> Address:
        return Address(self._xref.to)

    @property
    def type(self) -> XrefType:
        if self._xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):
            return XrefType.CALL
        elif self._xref.type in (ida_xref.fl_JN, ida_xref.fl_JF, ida_xref.fl_F):
            return XrefType.JUMP
        elif self._xref.type in (ida_xref.dr_R, ida_xref.dr_O, ida_xref.dr_T, ida_xref.dr_I):
            # TODO: ida_xref.dr_O is not DATA_READ exactly, but it is okay for this project now. (Simplicity for now)
            return XrefType.DATA_READ
        elif self._xref.type in (ida_xref.dr_W,):
            return XrefType.DATA_WRITE
        return XrefType.UNKNOWN


class IDASegment(Segment):
    """IDA segment wrapper."""

    def __init__(self, seg: "ida_segment.segment_t"):
        self._seg = seg
        self._name: Optional[str] = None
        self._segment_type: Optional[str] = None

    @property
    def name(self) -> str:
        """Get segment name."""
        if self._name is None:
            self._name = ida_segment.get_segm_name(self._seg)
        return self._name

    @property
    def start(self) -> Address:
        return Address(self._seg.start_ea)

    @property
    def end(self) -> Address:
        return Address(self._seg.end_ea)


class IDABackend(BackEnd):
    """IDA Pro backend implementation."""

    def __init__(self):
        if not idaapi.get_default_radix():
            raise RuntimeError("IDA database not loaded")

    # @property # TODO: I thought property is better, but pickle doesn't allow it. Refactor when drop pickle support.
    def image_base(self):
        return idaapi.get_imagebase()

    def functions(self) -> Iterator[IDAFunction]:
        """Iterate over all functions."""
        for ea in idautils.Functions():
            func = idaapi.get_func(ea)
            if func:
                yield IDAFunction(func)

    def get_function_at(self, address: Address) -> Optional[IDAFunction]:
        """Get function containing address."""
        func = idaapi.get_func(int(address))
        if func and func.start_ea == idaapi.BADADDR:
            return None
        return IDAFunction(func) if func else None

    def strings(self, min_length: int = 5) -> Iterator[IDAString]:
        strings = idautils.Strings(False)
        strings.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16, ida_nalt.STRTYPE_C_32], minlen=min_length)
        for s in strings:
            if idc.get_str_type(s.ea) is not None:
                yield IDAString(s)

    def get_xrefs_to(self, address: Address) -> Iterator[IDAXref]:
        """Get references to address."""
        xref = ida_xref.xrefblk_t()
        if xref.first_to(address.value, ida_xref.XREF_ALL):
            yield IDAXref(xref)
            while xref.next_to():
                yield IDAXref(xref)

    def get_xrefs_from(self, address: Address) -> Iterator[IDAXref]:
        """Get references from address."""
        xref = ida_xref.xrefblk_t()
        if xref.first_from(address.value, ida_xref.XREF_ALL):
            yield IDAXref(xref)
            while xref.next_from():
                yield IDAXref(xref)

    def read_bytes(self, address: Address, size: int) -> Optional[bytes]:
        """Read bytes from address."""
        try:
            data = ida_bytes.get_bytes(address.value, size)
            return data if data else None
        except Exception:
            return None

    def get_segments(self) -> Iterator[IDASegment]:
        """Iterate over all segments."""
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg:
                yield IDASegment(seg)

    def get_segment_by_name(self, name: str) -> Optional[IDASegment]:
        """Get segment by name."""
        seg = ida_segment.get_segm_by_name(name)
        return IDASegment(seg) if seg else None

    def get_imports(self) -> Iterator[Tuple[Address, str, str]]:
        """Get imported functions as (name, address) pairs."""
        imports = []
        for module_idx in range(idaapi.get_import_module_qty()):
            module_name = str(idaapi.get_import_module_name(module_idx))
            if not module_name:
                continue

            clean_module_name = module_name.lower().split("/")[-1]

            def collect_import(ea: int, name: str, ordinal: int) -> bool:
                final_name = name
                final_module = clean_module_name

                if "@@" in name:
                    parts = name.split("@@")
                    final_name = parts[0]
                    if len(parts) > 1 and "_" in parts[1]:
                        final_module = "_".join(parts[1].split("_")[:-1])
                    elif len(parts) > 1:
                        final_module = parts[1]

                full_name = f"{final_module}.{final_name}"
                imports.append((Address(ea), full_name, final_module))
                return True

            idaapi.enum_import_names(module_idx, collect_import)
        for import_addr, import_name, import_module in imports:
            yield (import_addr, import_name, import_module)

    def _path_impl(self) -> str:
        """Get the path of the currently opened IDA database."""
        input_path = idaapi.get_input_file_path()
        return input_path if input_path else ""
