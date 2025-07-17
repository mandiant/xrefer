"""IDA-specific wrapper classes."""

from typing import Iterator, Optional, Tuple

import ida_bytes
import ida_entry
import ida_funcs
import ida_nalt
import ida_segment
import ida_xref
import idaapi
import idautils
import idc

from ..base import Address, BackEnd, BackendError, BasicBlock, Function, FunctionType, Segment, String, StringEncType, Xref, XrefType


class IDAFunction(Function):
    """IDA function wrapper."""

    def __init__(self, ida_func: "ida_funcs.func_t") -> None:
        """Initialize with IDA function object."""
        self._func = ida_func
        self._name: Optional[str] = None
        self._function_type: Optional[FunctionType] = None
        # super().__init__(address, name)

    @property
    def start(self) -> Address:
        return Address(self._func.start_ea)

    @property
    def name(self) -> str:
        self._name = idc.get_func_name(self._func.start_ea)
        return self._name

    @name.setter
    def name(self, value: str) -> str:
        """Set function name."""
        if value:
            idc.set_name(self._func.start_ea, value, idaapi.SN_FORCE)
            self._name = value
            return self._name
        else:
            raise ValueError("Function name cannot be empty")

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
        seg: Optional["ida_segment.segment_t"] = ida_segment.getseg(self._func.start_ea)
        return bool(seg) and seg.type == ida_segment.SEG_XTRN

    def _is_export(self) -> bool:
        """Return True if the function is exported from the binary."""
        # TODO: do this.
        return False


class IDAString(String):
    """IDA string wrapper."""

    def __init__(self, string_info):
        self._info = string_info
        self._content: Optional[str] = None
        self._encoding: Optional[StringEncType] = None

    @property
    def address(self) -> Address:
        return Address(self._info.ea)

    @property
    def content(self) -> str:
        if self._content is None:
            str_type: Optional[int] = idc.get_str_type(self._info.ea)
            if str_type is None:
                return ""
            raw: Optional[bytes] = ida_bytes.get_strlit_contents(self._info.ea, self.length, str_type)
            if raw:
                self._content = raw.decode("utf-8", errors="replace")
            else:
                self._content = ""
        return self._content

    @property
    def length(self) -> int:
        return self._info.length

    @property
    def encoding(self) -> StringEncType:
        """Get string encoding type (cached for performance)."""
        if self._encoding is None:
            str_type: Optional[int] = idc.get_str_type(self._info.ea)
            enc_map: dict[int, StringEncType] = {
                ida_nalt.STRTYPE_C: StringEncType.ASCII,
                ida_nalt.STRTYPE_C_16: StringEncType.UTF16,
                ida_nalt.STRTYPE_C_32: StringEncType.UTF32,
            }
            self._encoding = enc_map.get(str_type, StringEncType.UTF8)
        return self._encoding


class IDAXref(Xref):
    """IDA cross-reference wrapper."""

    def __init__(self, xref: "ida_xref.xrefblk_t") -> None:
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

    def __init__(self, seg: "ida_segment.segment_t") -> None:
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

    def __init__(self) -> None:
        """Initialize IDA backend with database validation."""
        super().__init__()
        if not idaapi.get_default_radix():
            raise BackendError("IDA database not loaded")

    @property
    def image_base(self) -> Address:
        """Get IDA image base address."""
        return Address(idaapi.get_imagebase())

    def _path_impl(self) -> str:
        """Get the path of the currently opened IDA database."""
        input_path: Optional[str] = idc.get_idb_path()
        if input_path:
            input_path = input_path.rsplit(".i64", 1)[0]
        return input_path if input_path else ""

    def _binary_hash_impl(self):
        return ida_nalt.retrieve_input_file_sha256().hex()

    #
    # Function Analysis
    #

    def functions(self) -> Iterator[IDAFunction]:
        """Iterate over all functions."""
        for ea in idautils.Functions():
            func: Optional["ida_funcs.func_t"] = idaapi.get_func(ea)
            if func:
                yield IDAFunction(func)

    def get_function_at(self, address: Address) -> Optional[IDAFunction]:
        """Get function containing address."""
        func: Optional["ida_funcs.func_t"] = idaapi.get_func(int(address))
        if func and func.start_ea == idaapi.BADADDR:
            return None
        return IDAFunction(func) if func else None

    def strings(self, min_length: int = 5) -> Iterator[IDAString]:
        strings: "idautils.Strings" = idautils.Strings(False)
        strings.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16, ida_nalt.STRTYPE_C_32], minlen=min_length)
        for s in strings:
            if idc.get_str_type(s.ea) is not None:
                yield IDAString(s)

    #
    # Symbol Resolution
    #

    def get_name_at(self, address: Address) -> str:
        """Get symbol name at the specified address."""
        return idc.get_name(int(address)) or ""

    def get_address_for_name(self, name: str) -> Optional[Address]:
        """Get address for the specified symbol name."""
        ea: int = idc.get_name_ea_simple(name)
        return None if ea == idaapi.BADADDR else Address(ea)

    #
    # Cross-Reference Analysis
    #

    def get_xrefs_to(self, address: Address) -> Iterator[IDAXref]:
        """Get all references TO the specified address."""
        xref: "ida_xref.xrefblk_t" = ida_xref.xrefblk_t()
        if xref.first_to(address.value, ida_xref.XREF_ALL):
            yield IDAXref(xref)
            while xref.next_to():
                yield IDAXref(xref)

    def get_xrefs_from(self, address: Address) -> Iterator[IDAXref]:
        """Get all references FROM the specified address."""
        xref: "ida_xref.xrefblk_t" = ida_xref.xrefblk_t()
        if xref.first_from(address.value, ida_xref.XREF_ALL):
            yield IDAXref(xref)
            while xref.next_from():
                yield IDAXref(xref)

    def read_bytes(self, address: Address, size: int) -> Optional[bytes]:
        """Read bytes from address."""
        try:
            data: Optional[bytes] = ida_bytes.get_bytes(address.value, size)
            return data if data else None
        except Exception:
            return None

    def instructions(self, start: Address, end: Address) -> Iterator[Address]:
        """Iterate over instruction addresses in the specified range."""
        for ea in idautils.Heads(int(start), int(end)):
            yield Address(ea)

    #
    # Segment Analysis
    #

    def get_segments(self) -> Iterator[IDASegment]:
        """Iterate over all segments."""
        for seg_ea in idautils.Segments():
            seg: Optional["ida_segment.segment_t"] = ida_segment.getseg(seg_ea)
            if seg:
                yield IDASegment(seg)

    def get_segment_by_name(self, name: str) -> Optional[IDASegment]:
        """Get segment by name."""
        seg: Optional["ida_segment.segment_t"] = ida_segment.get_segm_by_name(name)
        return IDASegment(seg) if seg else None

    #
    # Import/Export Analysis
    #

    def _get_raw_imports(self) -> Iterator[Tuple[Address, str, str]]:
        """Get raw import data from IDA's import tables."""
        imports: list[Tuple[Address, str, str]] = []

        for module_idx in range(idaapi.get_import_module_qty()):
            module_name: str = str(idaapi.get_import_module_name(module_idx))
            if not module_name:
                continue

            def collect_import(ea: int, name: str, ordinal: int) -> bool:
                """Callback to collect import information."""
                imports.append((Address(ea), name, module_name))
                return True

            idaapi.enum_import_names(module_idx, collect_import)

        for import_data in imports:
            yield import_data

    def get_exports(self) -> Iterator[tuple[str, Address]]:
        """Get exported functions from the binary."""
        entry_qty: int = ida_entry.get_entry_qty()
        for i in range(entry_qty):
            ordinal: int = ida_entry.get_entry_ordinal(i)
            ea: int = ida_entry.get_entry(ordinal)
            name: str = ida_entry.get_entry_name(ordinal)

            if ea != idaapi.BADADDR and name:
                yield (name, Address(ea))

    #
    # User Annotations
    #

    def _add_user_xref_impl(self, source: Address, target: Address) -> None:
        """Add user-defined cross reference in IDA."""
        ida_xref.add_cref(int(source), int(target), idc.XREF_USER)

    def _set_comment_impl(self, address: Address, comment: str) -> None:
        """Set comment at address in IDA."""
        idc.set_cmt(int(address), comment, 0)

    def _set_function_comment_impl(self, address: Address, comment: str) -> None:
        """Set function comment in IDA."""
        idc.set_func_cmt(int(address), comment, 0)
