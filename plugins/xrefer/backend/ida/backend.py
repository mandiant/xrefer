"""IDA-specific wrapper classes."""

from typing import Iterator, List, Optional, Tuple

import ida_bytes
import ida_entry
import ida_funcs
import ida_ida
import ida_nalt
import ida_segment
import ida_ua
import ida_xref
import idaapi
import idautils
import idc

from ..base import Address,BackEnd,BackendError,BasicBlock,Function,FunctionType,Section,SectionType,String,StringEncType,Xref,XrefType,Instruction,Operand,OperandType


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
    def name(self, value: str) -> None:
        """Set function name."""
        if not value:
            raise ValueError("Function name cannot be empty")
        idc.set_name(self._func.start_ea, value, idaapi.SN_FORCE)
        self._name = value

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

    @property
    def has_default_name(self) -> bool:
        """True if IDA still shows a dummy/auto name (sub_/loc_/nullsub_/…)
        rather than a FLIRT, import, or user-assigned name. Precise override of
        the base name-prefix heuristic, via IDA's own dummy-name flag."""
        return bool(ida_bytes.has_dummy_name(ida_bytes.get_flags(self._func.start_ea)))

    def contains(self, address: Address) -> bool:
        """Check if the address is within the function."""
        return idc.func_contains(self._func.start_ea, address.value)

    @property
    def chunk_ranges(self) -> List[Tuple[int, int]]:
        """Half-open [start, end) ranges of the function's chunks, tail
        chunks included — the same coverage idc.func_contains answers
        against, so containment can be checked Python-side."""
        return [(int(start), int(end)) for start, end in idautils.Chunks(self._func.start_ea)]

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
    """IDA cross-reference wrapper (eager snapshot).

    Every wrapper yielded by an xrefblk_t enumeration used to alias the
    SAME live mutable struct — reading a previously-yielded ref after the
    iterator advanced (e.g. ``list(get_xrefs_from(...))``) silently
    returned the wrong values, and every property read was a fresh SWIG
    crossing. Snapshotting frm/to/type at yield time fixes the aliasing
    and makes repeated property reads free.
    """

    __slots__ = ("_frm", "_to", "_type_code")

    def __init__(self, frm: int, to: int, type_code: int) -> None:
        self._frm = frm
        self._to = to
        self._type_code = type_code

    @property
    def source(self) -> Address:
        return Address(self._frm)

    @property
    def target(self) -> Address:
        return Address(self._to)

    @property
    def type(self) -> XrefType:
        if self._type_code in (ida_xref.fl_CN, ida_xref.fl_CF):
            return XrefType.CALL
        elif self._type_code in (ida_xref.fl_JN, ida_xref.fl_JF, ida_xref.fl_F):
            return XrefType.JUMP
        elif self._type_code in (ida_xref.dr_R, ida_xref.dr_O, ida_xref.dr_T, ida_xref.dr_I):
            # TODO: ida_xref.dr_O is not DATA_READ exactly, but it is okay for this project now. (Simplicity for now)
            return XrefType.DATA_READ
        elif self._type_code in (ida_xref.dr_W,):
            return XrefType.DATA_WRITE
        return XrefType.UNKNOWN


class IDASection(Section):
    """IDA section wrapper."""

    def __init__(self, seg: "ida_segment.segment_t") -> None:
        self._seg = seg
        self._name: Optional[str] = None
        self._segment_type: Optional[SectionType] = None

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

    @property
    def type(self) -> SectionType:
        """Get segment type."""
        if self._segment_type is None:
            self._segment_type = self._classify_segment_type()
        return self._segment_type

    @property
    def is_readable(self) -> bool:
        """Check if segment is readable."""
        return bool(self._seg.perm & ida_segment.SEGPERM_READ)

    @property
    def perm(self) -> str:
        """Get segment permissions as string."""
        perms = ""
        perms += "r" if self._seg.perm & ida_segment.SEGPERM_READ else "-"
        perms += "w" if self._seg.perm & ida_segment.SEGPERM_WRITE else "-"
        perms += "x" if self._seg.perm & ida_segment.SEGPERM_EXEC else "-"
        return perms

    def _classify_segment_type(self) -> SectionType:
        """Classify segment type based on IDA segment properties."""
        # Check segment type first
        if self._seg.type == ida_segment.SEG_XTRN:
            return SectionType.EXTERN
        elif self._seg.type == ida_segment.SEG_BSS:
            return SectionType.BSS

        # Check permissions for executable segments
        if self._seg.perm & ida_segment.SEGPERM_EXEC:
            return SectionType.CODE
        elif self._seg.perm & ida_segment.SEGPERM_WRITE:
            return SectionType.DATA
        elif self._seg.perm & ida_segment.SEG_DATA:
            return SectionType.DATA
        elif self._seg.perm & ida_segment.SEGPERM_READ:
            return SectionType.DATA
        else:
            return SectionType.UNKNOWN


class IDABackend(BackEnd):
    """IDA Pro backend implementation."""

    def __init__(self) -> None:
        """Initialize IDA backend with database validation."""
        super().__init__()
        if not idaapi.get_default_radix():
            raise BackendError("IDA database not loaded")

    @property
    def name(self) -> str:
        """Backend name for language module lookup."""
        return "ida"

    @property
    def image_base(self) -> Address:
        """Get IDA image base address."""
        return Address(idaapi.get_imagebase())

    @property
    def size(self) -> int:
        """Get size of the currently opened IDA database."""
        return ida_nalt.retrieve_input_file_size()

    def _path_impl(self) -> str:
        """Get the path of the currently opened IDA database."""
        input_path: Optional[str] = idc.get_idb_path()
        if input_path:
            input_path = input_path.rsplit(".i64", 1)[0]
        return input_path if input_path else ""

    def _binary_hash_impl(self):
        return ida_nalt.retrieve_input_file_sha256().hex()

    def filetype(self) -> str:
        """Get the file type of the binary (e.g., 'PE', 'ELF', 'Mach-O')."""
        return idaapi.get_file_type_name()

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
            yield IDAXref(xref.frm, xref.to, xref.type)
            while xref.next_to():
                yield IDAXref(xref.frm, xref.to, xref.type)

    def get_xrefs_from(self, address: Address, far_only: bool = False) -> Iterator[IDAXref]:
        """Get all references FROM the specified address.

        ``far_only`` maps to XREF_FAR: ordinary fall-through flow refs
        (one per instruction under XREF_ALL) are skipped at the source.
        """
        flags = ida_xref.XREF_FAR if far_only else ida_xref.XREF_ALL
        xref: "ida_xref.xrefblk_t" = ida_xref.xrefblk_t()
        if xref.first_from(address.value, flags):
            yield IDAXref(xref.frm, xref.to, xref.type)
            while xref.next_from():
                yield IDAXref(xref.frm, xref.to, xref.type)

    def read_bytes(self, address: Address, size: int) -> Optional[bytes]:
        """Read bytes from address."""
        try:
            data: Optional[bytes] = ida_bytes.get_bytes(address.value, size)
            return data if data else None
        except Exception:
            return None

    def _resolve_file_offset_impl(self, file_offset: int) -> Address | None:
        """Resolve a file offset to a linear address using IDA APIs."""
        ea = idaapi.get_fileregion_ea(file_offset)
        if ea == idaapi.BADADDR:
            return None
        return Address(int(ea))

    def instructions(self, start: Address, end: Address) -> Iterator[Address]:
        """Iterate over instruction addresses in the specified range."""
        for ea in idautils.Heads(int(start), int(end)):
            yield Address(ea)

    #
    # Segment Analysis
    #

    def _get_sections_impl(self) -> Iterator[IDASection]:
        """Backend-specific implementation for getting segments."""
        for seg_ea in idautils.Segments():
            seg: Optional["ida_segment.segment_t"] = ida_segment.getseg(seg_ea)
            if seg:
                yield IDASection(seg)

    def get_section_by_name(self, name: str) -> Optional[IDASection]:
        """Get segment by name."""
        seg: Optional["ida_segment.segment_t"] = ida_segment.get_segm_by_name(name)
        return IDASection(seg) if seg else None

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

    def _get_disassembly_impl(self, address: Address) -> Instruction:
        """Backend-specific implementation for getting disassembly at a specific address."""
        ea = int(address)

        # Full disassembly text and mnemonic
        text = idc.generate_disasm_line(ea, 0) or ""
        mnem = (idc.print_insn_mnem(ea) or "").lower()

        # Collect operands with best-effort typing
        operands: list[Operand] = []
        for i in range(8):  # x86/x64 has max 4; use 8 as a safe cap
            op_type_id = idc.get_operand_type(ea, i)
            if op_type_id == idc.o_void:
                break

            op_text = idc.print_operand(ea, i) or ""
            op_kind = OperandType.OTHER
            op_value = None

            try:
                if op_type_id == idc.o_imm:
                    op_kind = OperandType.IMMEDIATE
                    val = idc.get_operand_value(ea, i)
                    op_value = Address(int(val))
                elif op_type_id == idc.o_reg:
                    op_kind = OperandType.REGISTER
                elif op_type_id in (idc.o_mem,):
                    op_kind = OperandType.MEMORY
                    val = idc.get_operand_value(ea, i)
                    op_value = Address(int(val))
                elif op_type_id in (idc.o_phrase, idc.o_displ):
                    # Memory with computed address; keep value None (use xrefs to resolve)
                    op_kind = OperandType.MEMORY
                else:
                    op_kind = OperandType.OTHER
            except Exception as e:
                from logging import getLogger
                logger = getLogger(__name__)
                logger.exception(f"Failed to parse operand at {ea:#x} operand {i}: {e}")
                op_kind = OperandType.OTHER
                op_value = None

            operands.append(Operand(type=op_kind, text=op_text, value=op_value))

        ins = Instruction(
            address=Address(ea),
            mnemonic=mnem,
            operands=tuple(operands),
            text=text
        )
        return ins

    def find_rust_main_candidate(self, main_addr: Address) -> Optional[Address]:
        """IDA-specific rust_main detection — byte-walk through a CRT main wrapper.

        Two CRT shapes are handled:

        1. **Linux / glibc style.** The wrapper itself (``main`` / ``_main``)
           loads a function pointer to user main into a register and calls
           ``__libc_start_main``. The byte-walk on the wrapper finds a non-call
           data-ref to a function-start followed within 8 instructions by a
           call to ``__libc_start_main`` (directly or via PLT thunk).

        2. **MinGW Windows PE style.** ``start`` is the PE entry: it inlines
           CRT initialisation, calls ``__getmainargs`` for argv setup, then
           directly calls a Rust-compiler-generated bootstrap function which
           holds the data-ref + call pattern. The byte-walk doesn't match on
           ``start`` itself (the user-bootstrap call is ``fl_CN``, which the
           walk filters out), so we recurse one level into each user callee
           of ``start`` — skipping imports, library, thunk, and known CRT
           helper functions — and re-run the byte-walk there.

        Side effect: when a candidate is found, the function is renamed to
        ``rust_main`` in the IDB so subsequent calls to
        ``get_address_for_name("rust_main")`` short-circuit the scan.
        """
        main_ea = int(main_addr)

        # Path A: the supplied wrapper itself contains the data-ref +
        # bootstrap-call pattern (Linux / glibc shape).
        candidate = self._scan_wrapper_for_rust_main(main_ea)
        if candidate is not None:
            idc.set_name(candidate, "rust_main", idc.SN_NOCHECK)
            return Address(candidate)

        # Path B: the wrapper is a CRT entry that calls a Rust bootstrap
        # which in turn carries the pattern (MinGW PE shape). Recurse one
        # level into each user callee.
        for callee_ea in self._iter_user_callees(main_ea):
            candidate = self._scan_wrapper_for_rust_main(callee_ea)
            if candidate is not None:
                idc.set_name(candidate, "rust_main", idc.SN_NOCHECK)
                return Address(candidate)

        return None

    def _scan_wrapper_for_rust_main(self, func_ea: int) -> Optional[int]:
        """Byte-walk ``func_ea`` looking for a non-call out-of-function
        data-reference to a function-start followed within 8 instructions
        by a recognised bootstrap call. Returns the data-ref's target ea
        or ``None``. Does not rename — caller is responsible.
        """
        func_start = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
        end_attr = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        if func_start == idc.BADADDR or end_attr == idc.BADADDR:
            return None
        func_end = idc.prev_addr(end_attr)
        # idaapi.get_inf_structure() was removed in IDA 9.x — ida_ida.inf_is_64bit()
        # is the modern equivalent.
        is_64 = ida_ida.inf_is_64bit()

        for addr in range(func_start, func_end):
            for ref in idautils.XrefsFrom(addr):
                # Only refs that leave the wrapper, and aren't direct calls.
                if func_start <= ref.to <= func_end:
                    continue
                if ref.type == idc.fl_CN:
                    continue
                target_func = idaapi.get_func(ref.to)
                if not target_func or target_func.start_ea != ref.to:
                    continue
                if self._has_following_user_call(addr, max_instructions=8, is_64=is_64):
                    return ref.to
        return None

    def _iter_user_callees(self, func_ea: int) -> Iterator[int]:
        """Yield function addresses called from ``func_ea`` that are plausible
        Rust bootstrap candidates: not imports, not FUNC_LIB / FUNC_STATIC /
        FUNC_THUNK, not a known CRT helper. Used to descend one level below
        a PE entry into the Rust-compiler-generated ``main``.
        """
        func = idaapi.get_func(func_ea)
        if not func:
            return
        is_64 = ida_ida.inf_is_64bit()
        seen: set[int] = set()
        ins = ida_ua.insn_t()
        call_itypes = (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni)
        for ea in idautils.FuncItems(func.start_ea):
            if not idaapi.decode_insn(ins, ea):
                continue
            if ins.itype not in call_itypes:
                continue
            target = idc.get_operand_value(ea, 0)
            target_flags = idc.get_func_flags(target)
            # Indirect call through a function pointer: dereference.
            if target_flags < 0:
                target = (ida_bytes.get_qword if is_64 else ida_bytes.get_dword)(target)
                target_flags = idc.get_func_flags(target)
            if target == idaapi.BADADDR or target_flags < 0:
                continue
            if target_flags & (idc.FUNC_LIB | idc.FUNC_STATIC | idc.FUNC_THUNK):
                continue
            if self._is_crt_helper_name(idc.get_name(target) or ""):
                continue
            if target in seen:
                continue
            seen.add(target)
            yield target

    # Known C-runtime entry symbols that bootstrap user main with the user
    # function passed as a function-pointer argument. The PLT-thunk variants
    # are recognized by name match — IDA labels both the thunk and the
    # extern alike, modulo leading dots/underscores.
    _RUNTIME_ENTRY_BASES = ("libc_start_main", "libc_start_call_main")

    def _has_following_user_call(self, start_addr: int, max_instructions: int, is_64: bool) -> bool:
        """Return True if any of the next ``max_instructions`` instructions is a
        call that bootstraps user code.

        Two shapes are accepted:

        1. A direct call to a non-import / non-library / non-thunk function —
           the statically-linked Rust runtime wrapper that invokes user main.
        2. A call (typically through a PLT thunk) to a known C runtime entry
           such as ``__libc_start_main``, which receives the user main as
           its first argument on Linux/glibc PIE binaries.

        Used by :meth:`find_rust_main_candidate` to confirm that an out-of-
        function reference is followed by an actual bootstrap call rather
        than a stray data offset.
        """
        ins = ida_ua.insn_t()
        ins_ea = start_addr
        call_itypes = (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni)
        for _ in range(max_instructions):
            ins_ea = idc.next_head(ins_ea)
            if not idaapi.decode_insn(ins, ins_ea):
                break
            if ins.itype not in call_itypes:
                continue
            target = idc.get_operand_value(ins_ea, 0)
            target_flags = idc.get_func_flags(target)
            # Function-pointer indirection: dereference to get the real target.
            if target_flags < 0:
                target = (ida_bytes.get_qword if is_64 else ida_bytes.get_dword)(target)
                target_flags = idc.get_func_flags(target)
            if not (target_flags & (idc.FUNC_LIB | idc.FUNC_STATIC | idc.FUNC_THUNK)):
                return True
            if self._resolves_to_runtime_entry(target):
                return True
        return False

    def _resolves_to_runtime_entry(self, ea: int) -> bool:
        """Return True if ``ea`` is (or thunks to) a known C runtime entry."""
        if self._matches_runtime_entry_name(idc.get_name(ea) or ""):
            return True
        func = idaapi.get_func(ea)
        if not (func and (func.flags & idaapi.FUNC_THUNK)):
            return False
        thunk_target = ida_funcs.calc_thunk_func_target(func)
        # IDA returns either an int or a (target_ea, fptr_ea) tuple depending
        # on version — normalise.
        if isinstance(thunk_target, tuple):
            thunk_target = thunk_target[0]
        if thunk_target is None or thunk_target == idaapi.BADADDR:
            return False
        return self._matches_runtime_entry_name(idc.get_name(thunk_target) or "")

    @classmethod
    def _matches_runtime_entry_name(cls, name: str) -> bool:
        if not name:
            return False
        stripped = name.lstrip(".").lstrip("_")
        return any(stripped.startswith(base) for base in cls._RUNTIME_ENTRY_BASES)

    # MinGW / MSVCRT helper-function name fragments. Calls to these from
    # ``start`` are CRT plumbing, not the Rust runtime bootstrap, and should
    # not be recursed into by :meth:`_iter_user_callees`.
    _CRT_HELPER_PATTERNS = (
        "getmainargs",
        "set_app_type",
        "initterm",
        "cexit",
        "amsg_exit",
        "mingwthr_",
        "mingw_tlscallback",
        "pei386_runtime",
        "lconv_init",
        "gcc_register_frame",
        "gcc_deregister_frame",
    )

    @classmethod
    def _is_crt_helper_name(cls, name: str) -> bool:
        """True for MinGW / MSVCRT helper functions we don't want to recurse
        into. Conservative — false positives only cost a wasted byte-walk.
        """
        if not name:
            return False
        stripped = name.lstrip(".").lstrip("_").split(".")[0]
        # MinGW's static-init helper is named ``__main`` / ``___main`` —
        # strips down to ``main``. The Rust bootstrap is unnamed (sub_…)
        # in the stripped binaries we land here for, so an exact ``main``
        # is always the CRT helper at this stage.
        if stripped.lower() == "main":
            return True
        base = stripped.lower()
        return any(p in base for p in cls._CRT_HELPER_PATTERNS)
