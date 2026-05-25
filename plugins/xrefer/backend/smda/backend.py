"""SMDA backend for xrefer — read-only static disassembly via danielplohmann/smda."""

import logging
from collections.abc import Iterator
from typing import Optional

import lief

from ..base import (
    Address,
    BackEnd,
    BackendError,
    BasicBlock,
    Function,
    FunctionType,
    Instruction,
    Operand,
    OperandType,
    Section,
    SectionType,
    String,
    StringEncType,
    UnsupportedOperationError,
    Xref,
    XrefType,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Wrapper: Xref
# ---------------------------------------------------------------------------

class SMDAXref(Xref):
    def __init__(self, source: Address, target: Address, xref_type: XrefType) -> None:
        self._source = source
        self._target = target
        self._type = xref_type

    @property
    def source(self) -> Address:
        return self._source

    @property
    def target(self) -> Address:
        return self._target

    @property
    def type(self) -> XrefType:
        return self._type


# ---------------------------------------------------------------------------
# Wrapper: String
# ---------------------------------------------------------------------------

class SMDAString(String):
    def __init__(self, address: Address, content: str, length: int, encoding: StringEncType) -> None:
        self._address = address
        self._content = content
        self._length = length
        self._encoding = encoding

    @property
    def address(self) -> Address:
        return self._address

    @property
    def content(self) -> str:
        return self._content

    @property
    def length(self) -> int:
        return self._length

    @property
    def encoding(self) -> StringEncType:
        return self._encoding


# ---------------------------------------------------------------------------
# Wrapper: Section
# ---------------------------------------------------------------------------

class SMDASection(Section):
    def __init__(self, name: str, start_va: int, end_va: int) -> None:
        self._name = name
        self._start = Address(start_va)
        self._end = Address(end_va)

    @property
    def name(self) -> str:
        return self._name

    @property
    def start(self) -> Address:
        return self._start

    @property
    def end(self) -> Address:
        return self._end

    @property
    def type(self) -> SectionType:
        n = self._name.lower()
        if n in (".text", ".init", ".plt", ".fini"):
            return SectionType.CODE
        if n == ".bss":
            return SectionType.BSS
        if n.startswith("extern"):
            return SectionType.EXTERN
        if n in (".data", ".rodata", ".got", ".got.plt", ".data.rel.ro"):
            return SectionType.DATA
        return SectionType.UNKNOWN

    @property
    def is_readable(self) -> bool:
        return True

    @property
    def perm(self) -> str:
        n = self._name.lower()
        if n in (".text", ".init", ".plt", ".fini"):
            return "r-x"
        if n == ".rodata":
            return "r--"
        return "rw-"


# ---------------------------------------------------------------------------
# Wrapper: Function
# Wraps a plain dict so the backend is fully pickle-safe.
#
# func_data structure:
#   {
#     'offset': int,              # entry VA
#     'name': str,                # function name
#     'blocks': [(start, end)],   # list of (block_start_va, block_end_va)
#     'instrs': [int],            # all instruction VAs (sorted)
#   }
# ---------------------------------------------------------------------------

class SMDAFunction(Function):
    def __init__(self, func_data: dict, backend: "SMDABackend") -> None:
        self._data = func_data
        self._backend = backend

    @property
    def start(self) -> Address:
        return Address(self._data["offset"])

    @property
    def name(self) -> str:
        return self._data["name"] or f"sub_{self._data['offset']:x}"

    @name.setter
    def name(self, value: str) -> None:
        raise UnsupportedOperationError("SMDA is read-only: cannot set function name")

    @property
    def type(self) -> FunctionType:
        try:
            exported_vas = {addr for _, addr in self._backend.get_exports()}
            if Address(self._data["offset"]) in exported_vas:
                return FunctionType.EXPORT
        except Exception:
            pass
        return FunctionType.NORMAL

    @property
    def is_thunk(self) -> bool:
        blocks = self._data["blocks"]
        instrs = self._data["instrs"]
        if len(blocks) != 1 or len(instrs) != 1:
            return False
        mnem = self._backend._get_mnemonic_at(instrs[0])
        return mnem.startswith("jmp")

    @property
    def basic_blocks(self) -> Iterator[BasicBlock]:
        for start, end in self._data["blocks"]:
            yield BasicBlock(Address(start), Address(end))

    def contains(self, address: Address) -> bool:
        addr_int = int(address)
        return any(s <= addr_int < e for s, e in self._data["blocks"])


# ---------------------------------------------------------------------------
# Main Backend
# All internal state is plain Python (ints, strings, lists, dicts).
# No SMDA or lief objects are kept after __init__ — fully pickle-safe.
# ---------------------------------------------------------------------------

class SMDABackend(BackEnd):
    """Read-only xrefer backend powered by SMDA static disassembler."""

    def __init__(self, report, path: str) -> None:
        super().__init__()
        self._binary_path = path

        # --- Metadata (plain scalars) ---
        self._base_addr: int = report.base_addr
        self._binary_size: int = report.binary_size
        self._sha256: str = report.sha256
        self._filename: str = report.filename or path
        self._bitness: int = getattr(report, "bitness", 64)

        # LIEF: filetype + symbol names + data section ranges (parsed once, no objects kept)
        lief_data = self._extract_lief_data(path)
        self._filetype: str = lief_data["filetype"]
        self._lief_symbols: list = lief_data["symbols"]       # [(va_int, name_str)]
        self._data_section_ranges: list = lief_data["data_ranges"]  # [(start_va, end_va)]

        # --- Binary buffer (bytes — picklable) ---
        buf = report.getBuffer()
        self._buffer: bytes = bytes(buf) if buf else b""

        # --- Function data as plain dicts (picklable) ---
        # _func_list: list of func_data dicts
        # _addr_to_funcidx: instr_va → index into _func_list
        # _instr_mnemonic: instr_va → mnemonic string (for xref type detection)
        self._func_list: list = []
        self._addr_to_funcidx: dict = {}
        self._instr_mnemonic: dict = {}

        for func in report.getFunctions():
            blocks = []
            instrs_all = []
            for block_offset, instr_list in func.blocks.items():
                if not instr_list:
                    continue
                last = instr_list[-1]
                try:
                    block_end = last.offset + len(bytes.fromhex(last.bytes))
                except Exception:
                    block_end = last.offset + 1
                blocks.append((block_offset, block_end))
                for instr in instr_list:
                    instrs_all.append(instr.offset)
                    self._instr_mnemonic[instr.offset] = instr.mnemonic.lower()

            func_data = {
                "offset": func.offset,
                "name": func.function_name or f"sub_{func.offset:x}",
                "blocks": blocks,
                "instrs": sorted(instrs_all),
            }
            idx = len(self._func_list)
            self._func_list.append(func_data)
            for va in instrs_all:
                self._addr_to_funcidx[va] = idx

        # --- Name → VA index ---
        self._name_to_addr: dict = {
            fd["name"]: fd["offset"] for fd in self._func_list if fd["name"]
        }

        # --- Xrefs via capstone (block-by-block — avoids initCodeXrefs() OOM spike) ---
        # initCodeXrefs() runs capstone over the entire binary at once and can spike
        # several GB of RAM on large files.  We replicate the same data by iterating
        # one basic block at a time; capstone objects are GC'd after each block.
        self._xrefs_from: dict = {}
        self._xrefs_to: dict = {}
        if self._buffer:
            try:
                import capstone
                _mode = capstone.CS_MODE_64 if self._bitness == 64 else capstone.CS_MODE_32
                _md = capstone.Cs(capstone.CS_ARCH_X86, _mode)
                _md.detail = True
                _CALL = frozenset(["call"])
                _JUMP = frozenset([
                    "jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
                    "ja", "jae", "jb", "jbe", "js", "jns", "jo", "jno",
                    "jp", "jnp", "jcxz", "jecxz", "jrcxz",
                ])
                for _fd in self._func_list:
                    for _bs, _be in _fd["blocks"]:
                        _off = _bs - self._base_addr
                        _end = _be - self._base_addr
                        if _off < 0 or _end > len(self._buffer) or _off >= _end:
                            continue
                        for _insn in _md.disasm(self._buffer[_off:_end], _bs):
                            _mnem = _insn.mnemonic.lower()
                            if _mnem not in _CALL and _mnem not in _JUMP:
                                continue
                            for _op in _insn.operands:
                                if _op.type == capstone.x86.X86_OP_IMM:
                                    _tgt = int(_op.imm)
                                    self._xrefs_from.setdefault(_insn.address, []).append(_tgt)
                                    self._xrefs_to.setdefault(_tgt, []).append(_insn.address)
                                    self._instr_mnemonic[_insn.address] = _mnem
            except Exception as _e:
                logger.warning("capstone xref build failed (%s) — falling back to SMDA initCodeXrefs", _e)
                report.initCodeXrefs()
                for func in report.getFunctions():
                    for xref in func.getCodeOutrefs():
                        try:
                            fva = xref.from_instruction.offset
                            tva = xref.to_instruction.offset
                            self._xrefs_from.setdefault(fva, []).append(tva)
                            self._xrefs_to.setdefault(tva, []).append(fva)
                        except Exception:
                            continue

        # --- Sections from report.code_sections (plain tuples) ---
        self._sections: list = []
        try:
            for entry in report.code_sections:
                name, start_va, end_va = entry[0], entry[1], entry[2]
                if start_va == 0 or end_va == 0 or end_va <= start_va:
                    continue
                self._sections.append(SMDASection(name, start_va, end_va))
        except Exception as e:
            logger.warning("Failed to build section list: %s", e)

        # --- Exports (plain list of (name, Address)) ---
        self._exports: list = []
        try:
            for exp in report.getExportedFunctions():
                self._exports.append((exp.function_name, Address(exp.offset)))
        except Exception:
            pass

        # --- Imports (built from apirefs, plain list) ---
        self._raw_imports: list = []
        seen_apis: set = set()
        for func in report.getFunctions():
            for call_va, api_name in func.apirefs.items():
                if not api_name or api_name in seen_apis:
                    continue
                seen_apis.add(api_name)
                if "!" in api_name:
                    module, function_name = api_name.split("!", 1)
                    module = module.split("_")[0]          # keep original case (e.g. GLIBC not glibc)
                else:
                    function_name = api_name
                    module = "unknown"
                self._raw_imports.append((int(call_va), function_name, module))

        logger.debug(
            "SMDABackend init: %d functions, %d instr→func entries, %d xref-from entries, %d sections",
            len(self._func_list),
            len(self._addr_to_funcidx),
            len(self._xrefs_from),
            len(self._sections),
        )

    @staticmethod
    def _extract_lief_data(path: str) -> dict:
        """Parse binary once with LIEF; extract filetype, named symbols, and data section ranges.

        Returns plain Python dicts/lists — no lief objects are kept.
        """
        result: dict = {"filetype": "unknown", "symbols": [], "data_ranges": []}
        try:
            lb = lief.parse(path)
            if lb is None:
                return result

            result["filetype"] = str(lb.format).split(".")[-1]

            seen: set = set()

            def _add(va: int, name: str) -> None:
                name = name.rstrip("\x00").strip()
                if name and (va, name) not in seen:
                    seen.add((va, name))
                    result["symbols"].append((va, name))

            # Section names (ELF + PE)
            for sec in lb.sections:
                if sec.name:
                    _add(0, sec.name)

            # ELF: static + dynamic symbols
            if hasattr(lb, "dynamic_symbols"):
                try:
                    for sym in lb.symbols:
                        if sym.name and sym.value:
                            _add(int(sym.value), sym.name)
                except Exception:
                    pass
                try:
                    for sym in lb.dynamic_symbols:
                        if sym.name:
                            _add(int(sym.value), sym.name)
                except Exception:
                    pass

            # PE: imports + exports
            if hasattr(lb, "imports"):
                try:
                    for imp_lib in lb.imports:
                        for entry in imp_lib.entries:
                            if entry.name:
                                _add(0, entry.name)
                except Exception:
                    pass
                try:
                    exp = lb.get_export() if hasattr(lb, "get_export") else None
                    if exp:
                        for fn in exp.entries:
                            if fn.name:
                                _add(int(fn.address), fn.name)
                except Exception:
                    pass

            # Data section ranges — used to restrict string scanning to non-code regions
            _DATA = {
                ".rodata", ".data", ".bss", ".data.rel.ro", ".rdata",
                ".dynstr", ".strtab", ".shstrtab", ".comment",
                ".idata", ".edata", ".rsrc",
            }
            for sec in lb.sections:
                name = sec.name.lower().rstrip("\x00")
                va = int(sec.virtual_address)
                sz = int(sec.size)
                if va > 0 and sz > 0 and (
                    name in _DATA or "data" in name or "str" in name
                ):
                    result["data_ranges"].append((va, va + sz))

        except Exception as e:
            logger.debug("LIEF extraction failed: %s", e)

        return result

    # -----------------------------------------------------------------------
    # Properties
    # -----------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "smda"

    @property
    def image_base(self) -> Address:
        return Address(self._base_addr)

    @property
    def size(self) -> int:
        return self._binary_size

    def _binary_hash_impl(self) -> str:
        return self._sha256

    def _path_impl(self) -> str:
        return self._binary_path

    def filetype(self) -> str:
        return self._filetype

    # -----------------------------------------------------------------------
    # Function analysis
    # -----------------------------------------------------------------------

    def functions(self) -> Iterator[Function]:
        for func_data in self._func_list:
            yield SMDAFunction(func_data, self)

    def get_function_at(self, address: Address) -> Optional[Function]:
        idx = self._addr_to_funcidx.get(int(address))
        if idx is not None:
            return SMDAFunction(self._func_list[idx], self)
        return None

    # -----------------------------------------------------------------------
    # Strings
    # -----------------------------------------------------------------------

    def strings(self, min_length: int = String.MIN_LENGTH) -> Iterator[String]:
        if not self._buffer:
            return
        base = self._base_addr
        buf = self._buffer

        def is_printable(b: int) -> bool:
            return 32 <= b <= 126

        visited_va: set = set()

        # Restrict buffer scan to data/rodata sections to avoid false positives
        # from code bytes.  Fall back to the whole buffer if section info is missing.
        if self._data_section_ranges:
            scan_ranges = []
            for va_s, va_e in self._data_section_ranges:
                off_s = va_s - base
                off_e = va_e - base
                if off_s >= 0 and off_e <= len(buf) and off_s < off_e:
                    scan_ranges.append((off_s, off_e))
            if not scan_ranges:
                scan_ranges = [(0, len(buf))]
        else:
            scan_ranges = [(0, len(buf))]

        # ASCII scan (data sections only)
        for r_start, r_end in scan_ranges:
            i = r_start
            while i < r_end:
                if is_printable(buf[i]):
                    j = i
                    while j < r_end and is_printable(buf[j]):
                        j += 1
                    if j - i >= min_length:
                        ea = base + i
                        if ea not in visited_va:
                            s = buf[i:j].decode("ascii", errors="ignore")
                            yield SMDAString(Address(ea), s, len(s), StringEncType.ASCII)
                            visited_va.add(ea)
                    i = j + 1
                else:
                    i += 1

        # UTF-16LE scan (data sections only)
        for r_start, r_end in scan_ranges:
            i = r_start
            while i + 1 < r_end:
                if is_printable(buf[i]) and buf[i + 1] == 0:
                    j = i
                    chars = []
                    while j + 1 < r_end and is_printable(buf[j]) and buf[j + 1] == 0:
                        chars.append(chr(buf[j]))
                        j += 2
                    if len(chars) >= min_length:
                        ea = base + i
                        if ea not in visited_va:
                            s = "".join(chars)
                            yield SMDAString(Address(ea), s, len(s), StringEncType.UTF16)
                            visited_va.add(ea)
                    i = j + 2
                else:
                    i += 2

        # LIEF symbol names — ELF strtab/dynsym, PE import/export tables, section names.
        # These close the entity gap vs Ghidra which reads the symbol table natively.
        visited_names: set = set()
        for sym_va, sym_name in self._lief_symbols:
            if not sym_name or len(sym_name) < min_length or sym_name in visited_names:
                continue
            visited_names.add(sym_name)
            addr = Address(sym_va) if sym_va > 0 else Address(0)
            yield SMDAString(addr, sym_name, len(sym_name), StringEncType.ASCII)

    # -----------------------------------------------------------------------
    # Symbol lookups
    # -----------------------------------------------------------------------

    def get_name_at(self, address: Address) -> str:
        idx = self._addr_to_funcidx.get(int(address))
        if idx is not None:
            fd = self._func_list[idx]
            if fd["offset"] == int(address):
                return fd["name"]
        return ""

    def get_address_for_name(self, name: str) -> Optional[Address]:
        addr = self._name_to_addr.get(name)
        return Address(addr) if addr is not None else None

    # -----------------------------------------------------------------------
    # Cross-references
    # -----------------------------------------------------------------------

    def get_xrefs_from(self, address: Address) -> Iterator[Xref]:
        for target_va in self._xrefs_from.get(int(address), []):
            mnem = self._instr_mnemonic.get(int(address), "")
            xtype = XrefType.JUMP if mnem.startswith("j") else XrefType.CALL
            yield SMDAXref(address, Address(target_va), xtype)

    def get_xrefs_to(self, address: Address) -> Iterator[Xref]:
        for source_va in self._xrefs_to.get(int(address), []):
            mnem = self._instr_mnemonic.get(source_va, "")
            xtype = XrefType.JUMP if mnem.startswith("j") else XrefType.CALL
            yield SMDAXref(Address(source_va), address, xtype)

    def _get_mnemonic_at(self, va: int) -> str:
        return self._instr_mnemonic.get(va, "")

    # -----------------------------------------------------------------------
    # Memory access
    # -----------------------------------------------------------------------

    def read_bytes(self, address: Address, size: int) -> Optional[bytes]:
        try:
            if not self._buffer:
                return None
            offset = int(address) - self._base_addr
            if offset < 0 or offset + size > len(self._buffer):
                return None
            return self._buffer[offset: offset + size]
        except Exception as e:
            logger.debug("read_bytes failed at %s: %s", address, e)
            return None

    def instructions(self, start: Address, end: Address) -> Iterator[Address]:
        idx = self._addr_to_funcidx.get(int(start))
        if idx is None:
            return
        start_int = int(start)
        end_int = int(end)
        for va in self._func_list[idx]["instrs"]:
            if start_int <= va < end_int:
                yield Address(va)

    # -----------------------------------------------------------------------
    # Sections
    # -----------------------------------------------------------------------

    def _get_sections_impl(self) -> Iterator[Section]:
        yield from self._sections

    def get_section_by_name(self, name: str) -> Optional[Section]:
        for section in self._sections:
            if section.name == name:
                return section
        return None

    # -----------------------------------------------------------------------
    # Imports & Exports
    # -----------------------------------------------------------------------

    def _get_raw_imports(self) -> Iterator[tuple]:
        for call_va, function_name, module in self._raw_imports:
            yield (Address(call_va), function_name, module)

    def get_exports(self) -> Iterator[tuple]:
        yield from self._exports

    # -----------------------------------------------------------------------
    # Write-back — SMDA is read-only
    # -----------------------------------------------------------------------

    def _add_user_xref_impl(self, source: Address, target: Address) -> None:
        raise UnsupportedOperationError("SMDA is read-only: cannot add xref")

    def _set_comment_impl(self, address: Address, comment: str) -> None:
        raise UnsupportedOperationError("SMDA is read-only: cannot set comment")

    def _set_function_comment_impl(self, address: Address, comment: str) -> None:
        raise UnsupportedOperationError("SMDA is read-only: cannot set function comment")

    # -----------------------------------------------------------------------
    # Disassembly
    # -----------------------------------------------------------------------

    def _get_disassembly_impl(self, address: Address) -> Instruction:
        va = int(address)
        mnem = self._instr_mnemonic.get(va)
        if mnem is None:
            raise BackendError(f"No instruction at {address}")

        # Re-disassemble via capstone for operand detail
        try:
            import capstone
            offset = va - self._base_addr
            if 0 <= offset < len(self._buffer):
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                md.detail = True
                chunk = self._buffer[offset: offset + 15]
                for insn in md.disasm(chunk, va):
                    operands = []
                    for op in insn.operands:
                        if op.type == capstone.x86.X86_OP_REG:
                            operands.append(Operand(type=OperandType.REGISTER, text=insn.reg_name(op.reg), value=None))
                        elif op.type == capstone.x86.X86_OP_IMM:
                            val = op.imm
                            operands.append(Operand(type=OperandType.IMMEDIATE, text=hex(val), value=Address(val) if val >= 0 else None))
                        elif op.type == capstone.x86.X86_OP_MEM:
                            operands.append(Operand(type=OperandType.MEMORY, text=insn.op_str, value=None))
                        else:
                            operands.append(Operand(type=OperandType.OTHER, text=insn.op_str, value=None))
                    return Instruction(
                        address=Address(va),
                        mnemonic=insn.mnemonic.lower(),
                        operands=tuple(operands),
                        text=f"{insn.mnemonic} {insn.op_str}".strip(),
                    )
        except Exception as e:
            logger.debug("capstone disasm failed at %s: %s", address, e)

        # Fallback: mnemonic only
        return Instruction(address=Address(va), mnemonic=mnem, operands=(), text=mnem)

    # -----------------------------------------------------------------------
    # File offset resolution
    # -----------------------------------------------------------------------

    def _resolve_file_offset_impl(self, file_offset: int) -> Optional[Address]:
        try:
            return Address(self._base_addr + file_offset)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class SMDABackendFactory:
    """Factory for SMDA backend."""

    @property
    def name(self) -> str:
        return "SMDA"

    def is_available(self) -> bool:
        import importlib.util
        return importlib.util.find_spec("smda") is not None

    def create_backend(self, path=None, **kwargs) -> SMDABackend:
        if path is None:
            raise BackendError("SMDA backend requires 'path' parameter")
        from smda.SmdaConfig import SmdaConfig
        from smda.Disassembler import Disassembler

        config = SmdaConfig()
        config.STORE_BUFFER = True
        config.WITH_STRINGS = True

        logger.info("Running SMDA analysis on %s ...", path)
        report = Disassembler(config=config).disassembleFile(str(path))

        if report is None or report.status != "ok":
            status = getattr(report, "status", "unknown") if report else "None"
            raise BackendError(f"SMDA disassembly failed: status={status}")

        return SMDABackend(report, str(path))
