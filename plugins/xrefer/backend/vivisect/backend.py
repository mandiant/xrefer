"""
Vivisect backend for xrefer.

Uses vivisect VivWorkspace as the disassembly engine.
All data is extracted to plain Python at __init__ time — no vivisect
objects are stored as instance attributes, guaranteeing pickle safety.

Fixes applied vs naive vivisect extraction:
  1. Resolve import modules via LIEF (.gnu.version_r / PE import table)
  2. Manual string scanner on data sections (supplements LOC_STRING)
  3. LIEF symbol enrichment (.dynsym, .symtab, section names) — Ghidra parity

Vivisect xref types (vivisect.const):
    REF_CODE = 1   calls / branches
    REF_DATA = 2   data reads / writes
    REF_PTR  = 3   pointer references
"""

import bisect
import hashlib
import logging
import os
import struct
from collections.abc import Iterator
from typing import Optional, Tuple

import vivisect
import vivisect.const as vc

from xrefer.backend.base import (
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
    Xref,
    XrefType,
)

logger = logging.getLogger(__name__)

# ── REF_PTR (vivisect's "pointer reference", e.g. lea) → DATA_OFFSET ────────
# REF_DATA is classified per-opcode below (read vs write).
_DATA_RTYPE_MAP = {
    vc.REF_PTR:  XrefType.DATA_OFFSET,
}

# Mnemonics that may write to a memory operand at position 0.
# Covers x86/x86_64 + common ARM store ops.
_WRITE_MNEMONICS = {
    # x86/x86_64 — pure store
    'mov', 'movzx', 'movsx', 'movsxd', 'movabs', 'movdqa', 'movdqu',
    'movups', 'movaps', 'movnti',
    # x86/x86_64 — RMW (read-modify-write); we report as WRITE since the
    # write side dominates for entity-tracking purposes.
    'add', 'sub', 'and', 'or', 'xor', 'inc', 'dec', 'neg', 'not',
    'shl', 'shr', 'sar', 'rol', 'ror', 'sbb', 'adc',
    'xchg', 'xadd',
    # ARM / AArch64 — store
    'str', 'strb', 'strh', 'strd', 'stp', 'stm', 'stmia', 'stmdb',
    'stlr', 'stxr', 'stlxr',
}


def _classify_data_xref(vw, source_va: int) -> XrefType:
    """
    Classify a REF_DATA xref as DATA_READ / DATA_WRITE / DATA_OFFSET
    by inspecting the source opcode.

    Heuristic:
      - lea / adr → DATA_OFFSET (taking the address, no access)
      - write-class mnemonic with memory at operand 0 → DATA_WRITE
      - everything else → DATA_READ
    """
    try:
        op = vw.parseOpcode(source_va)
    except Exception:
        return XrefType.DATA_READ

    mnem = op.mnem.lower()

    # LEA / ARM ADR — compute address only, no actual access
    if mnem in ('lea', 'adr', 'adrp'):
        return XrefType.DATA_OFFSET

    # Check whether the memory operand is the destination (operand 0 for x86)
    if op.opers:
        first = op.opers[0]
        tname = type(first).__name__
        is_mem_dest = (
            'Mem' in tname or 'Deref' in tname or 'RipRel' in tname
        )
        if is_mem_dest and mnem in _WRITE_MNEMONICS:
            return XrefType.DATA_WRITE

    return XrefType.DATA_READ

# ── Memory permissions ───────────────────────────────────────────────────────
MM_READ  = 4
MM_WRITE = 2
MM_EXEC  = 1

# ── Sections to scan for real strings ───────────────────────────────────────
# Note: Ghidra includes symbol-table strings (.dynstr/.strtab/.shstrtab) as
# string entities because they're loaded into memory at runtime, so we do
# the same — extracted via LIEF for accurate naming.
#
# Each binary format uses a different section-name convention:
#   ELF:    .text / .data / .rodata / .bss      (dot prefix)
#   PE:     .text / .data / .rdata / .rsrc      (dot prefix)
#   Mach-O: __text / __data / __cstring / __const   (double-underscore)
# We cover all three so the backend works across formats.
_DATA_SECTIONS = {
    # ELF / PE
    '.rodata', '.data', '.rdata', '.data.rel.ro',
    '.bss', '.idata', '.edata', '.rsrc',
    # Mach-O
    '__cstring', '__const', '__data', '__rodata',
    '__cfstring', '__objc_classname', '__objc_methname',
    '__objc_methtype', '__ustring', '__os_log',
}


# ════════════════════════════════════════════════════════════════════════════
#  Concrete helper classes  (pure Python, fully picklable)
# ════════════════════════════════════════════════════════════════════════════

class VivisectFunction(Function):
    __slots__ = ('_start', '_name', '_type', '_is_thunk', '_blocks')

    def __init__(self, start: int, name: str, ftype: FunctionType,
                 is_thunk: bool, blocks: list):
        self._start    = Address(start)
        self._name     = name
        self._type     = ftype
        self._is_thunk = is_thunk
        self._blocks   = blocks  # list of (start_va, end_va) ints

    @property
    def start(self) -> Address:
        return self._start

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        self._name = value

    @property
    def type(self) -> FunctionType:
        return self._type

    @property
    def is_thunk(self) -> bool:
        return self._is_thunk

    @property
    def basic_blocks(self) -> Iterator[BasicBlock]:
        for s, e in self._blocks:
            yield BasicBlock(Address(s), Address(e))

    def contains(self, address: Address) -> bool:
        addr = int(address)
        return any(s <= addr < e for s, e in self._blocks)


class VivisectString(String):
    __slots__ = ('_address', '_content', '_length', '_encoding')

    def __init__(self, address: int, content: str, length: int,
                 encoding: StringEncType):
        self._address  = Address(address)
        self._content  = content
        self._length   = length
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


class VivisectXref(Xref):
    __slots__ = ('_source', '_target', '_type')

    def __init__(self, source: int, target: int, xref_type: XrefType):
        self._source = Address(source)
        self._target = Address(target)
        self._type   = xref_type

    @property
    def source(self) -> Address:
        return self._source

    @property
    def target(self) -> Address:
        return self._target

    @property
    def type(self) -> XrefType:
        return self._type


# Conditional + unconditional jump mnemonics across architectures.
# Anything starting with these is treated as JUMP for xref classification.
_JUMP_MNEMONICS = (
    # x86 / x86_64
    'jmp', 'jz', 'jnz', 'je', 'jne', 'jg', 'jge', 'jl', 'jle',
    'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
    'jc', 'jnc', 'jcxz', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne',
    # ARM / AArch64
    'b', 'bl', 'bx', 'blx',          # NB: 'bl'/'blx' are calls — handled below
    'bne', 'beq', 'bgt', 'blt', 'bge', 'ble', 'bcs', 'bcc', 'bmi', 'bpl',
    'cbz', 'cbnz', 'tbz', 'tbnz',
)
_CALL_MNEMONICS = ('call', 'callq', 'lcall', 'bl', 'blx', 'blr')


def _classify_code_xref(vw, source_va: int) -> XrefType:
    """
    For REF_CODE xrefs, distinguish CALL vs JUMP by inspecting the
    source opcode. Indirect jumps/calls (memory operand — e.g., PLT
    thunks `jmp [GOT_slot]`) return UNKNOWN to match Ghidra/IDA/BN.
    Works for x86/x86_64/ARM/AArch64.
    """
    try:
        op = vw.parseOpcode(source_va)
    except Exception:
        return XrefType.UNKNOWN

    mnem = op.mnem.lower()

    # Indirect (memory-operand) call/jump → UNKNOWN.
    # PcRel = direct relative branch (jcc, direct jmp/call with immediate);
    # RipRel = x86_64 [rip+disp] memory operand — dereferences, so indirect.
    # We treat Mem/Deref/RipRel as indirect, but NOT PcRel.
    is_indirect = any(
        ('Mem' in type(o).__name__)
        or ('Deref' in type(o).__name__)
        or ('RipRel' in type(o).__name__)
        for o in op.opers
    )

    if mnem in _CALL_MNEMONICS:
        return XrefType.UNKNOWN if is_indirect else XrefType.CALL
    if mnem.startswith('j') or mnem in _JUMP_MNEMONICS or mnem.startswith('b'):
        return XrefType.UNKNOWN if is_indirect else XrefType.JUMP
    return XrefType.CALL  # fallback for unexpected mnemonics


class VivisectSection(Section):
    __slots__ = ('_name', '_start', '_end', '_perms', '_stype')

    def __init__(self, name: str, start: int, size: int, perms: int):
        self._name  = name
        self._start = Address(start)
        self._end   = Address(start + size)
        self._perms = perms

        if perms & MM_EXEC:
            self._stype = SectionType.CODE
        elif perms & MM_WRITE:
            self._stype = SectionType.DATA
        elif perms & MM_READ:
            self._stype = SectionType.DATA
        else:
            self._stype = SectionType.UNKNOWN

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
    def is_readable(self) -> bool:
        return bool(self._perms & MM_READ)

    @property
    def type(self) -> SectionType:
        return self._stype

    @property
    def perm(self) -> str:
        r = 'r' if self._perms & MM_READ  else '-'
        w = 'w' if self._perms & MM_WRITE else '-'
        x = 'x' if self._perms & MM_EXEC  else '-'
        return r + w + x


# ════════════════════════════════════════════════════════════════════════════
#  LIEF helper — module resolution + string extraction
# ════════════════════════════════════════════════════════════════════════════

def _extract_lief_data(path: str) -> dict:
    """
    Use LIEF to extract:
      - import_module_map  : func_name -> module_name  (e.g. 'printf' -> 'GLIBC')
      - extra_strings      : list of (va, content) from symbol tables + section names
      - data_section_ranges: list of (start_va, end_va) for real data sections
      - file_offset_map    : list of (file_off_start, file_off_end, va_start)
                             for translating file offsets to virtual addresses
    """
    result = {
        'import_module_map':   {},   # str -> str
        'extra_strings':       [],   # list of (va_int, content_str)
        'data_section_ranges': [],   # list of (start_va, end_va)
        'file_offset_map':     [],   # list of (file_off, file_off+size, va_start)
    }
    try:
        import lief
        lb = lief.parse(path)
        if lb is None:
            return result

        # ── ELF ──────────────────────────────────────────────────────────
        if hasattr(lb, 'dynamic_symbols'):
            # Map function name → version/library (e.g. printf → GLIBC)
            for sym in lb.dynamic_symbols:
                if not sym.name:
                    continue
                sym_version = sym.symbol_version
                if sym_version and hasattr(sym_version, 'symbol_version_auxiliary'):
                    sva = sym_version.symbol_version_auxiliary
                    if sva and hasattr(sva, 'name') and sva.name:
                        # e.g. "GLIBC_2.17" → "GLIBC"
                        ver_name = sva.name
                        module   = ver_name.split('_')[0] if '_' in ver_name else ver_name
                        result['import_module_map'][sym.name] = module

            # Dynamic symbol NAMES (Ghidra parity — picks these up via .dynstr block scan)
            # Include ALL symbols, not just those with addresses
            for sym in lb.dynamic_symbols:
                if sym.name:
                    result['extra_strings'].append((int(sym.value or 0), sym.name))

            # Versioned symbol library names (e.g., "libc.so.6", "GLIBC_2.34")
            try:
                if hasattr(lb, 'symbols_version_requirement'):
                    for svr in lb.symbols_version_requirement:
                        if svr.name:
                            result['extra_strings'].append((0, svr.name))
                        for aux in svr.get_auxiliary_symbols():
                            if aux.name:
                                result['extra_strings'].append((0, aux.name))
            except Exception:
                pass

            # Static symbols (.symtab) — function/data labels in unstripped binaries.
            # Use an O(1) set for dedup to stay fast on binaries with many symbols.
            try:
                existing_names = {s for _, s in result['extra_strings']}
                for sym in lb.symbols:
                    if sym.name and sym.name not in existing_names:
                        existing_names.add(sym.name)
                        result['extra_strings'].append((int(sym.value or 0), sym.name))
            except Exception:
                pass

            # Section names (.shstrtab) — Ghidra includes these
            for sec in lb.sections:
                name = sec.name.rstrip('\x00').strip()
                if name:
                    result['extra_strings'].append((0, name))

        # ── PE ───────────────────────────────────────────────────────────
        if hasattr(lb, 'imports'):
            for imp_lib in lb.imports:
                lib_name = imp_lib.name or ''
                # Normalise: "KERNEL32.DLL" → "kernel32"
                mod = lib_name.lower()
                for ext in ('.dll', '.exe', '.sys'):
                    if mod.endswith(ext):
                        mod = mod[:-len(ext)]
                        break
                mod = mod.split('/')[-1].split('\\')[-1]
                for entry in imp_lib.entries:
                    if entry.name:
                        result['import_module_map'][entry.name] = mod

        # ── Mach-O ───────────────────────────────────────────────────────
        # binary.libraries lists dependent dylibs; binary.imported_functions
        # gives the symbols imported from them.
        if hasattr(lb, 'libraries') and hasattr(lb, 'imported_functions'):
            try:
                libs = []
                for lib in lb.libraries:
                    raw = lib.name if hasattr(lib, 'name') else str(lib)
                    base = raw.split('/')[-1]      # /usr/lib/libSystem.B.dylib → libSystem.B.dylib
                    for ext in ('.dylib', '.so'):
                        if base.endswith(ext):
                            base = base[:-len(ext)]
                            break
                    libs.append(base)
                # All Mach-O imports get the first library as a sensible default;
                # better than 'unknown'. Real resolution would need DYLD bindings,
                # which LIEF exposes but isn't worth the complexity here.
                default_lib = libs[0] if libs else 'unknown'
                for fn in lb.imported_functions:
                    fname = fn.name if hasattr(fn, 'name') else str(fn)
                    if fname and fname not in result['import_module_map']:
                        result['import_module_map'][fname] = default_lib
                    if fname:
                        result['extra_strings'].append((0, fname))
                # Library names as entities too
                for lib_name in libs:
                    result['extra_strings'].append((0, lib_name))
            except Exception:
                pass

        # ── Data section ranges (for string scanner) ──────────────────────
        _DATA = {
            '.rodata', '.data', '.rdata', '.data.rel.ro',
            '.bss', '.idata', '.edata', '.rsrc',
            '.dynstr', '.strtab',  # yes — include these for LIEF symbol yield
        }
        for sec in lb.sections:
            sname = sec.name.rstrip('\x00').lower()
            va    = int(sec.virtual_address)
            sz    = int(sec.size)
            if va > 0 and sz > 0 and (sname in _DATA or 'data' in sname or 'str' in sname):
                result['data_section_ranges'].append((va, va + sz))

        # ── File offset → VA mapping (for resolve_file_offset) ────────────
        for sec in lb.sections:
            va = int(sec.virtual_address)
            sz = int(sec.size)
            try:
                file_off = int(sec.offset)
            except Exception:
                continue
            if va > 0 and sz > 0 and file_off >= 0:
                result['file_offset_map'].append((file_off, file_off + sz, va))

    except Exception as exc:
        logger.debug("LIEF extraction failed: %s", exc)

    return result


def _manual_string_scan(vw, segments: list, min_len: int = 5) -> list:
    """
    Manually scan data sections for ASCII and UTF-16LE strings.

    Uses vw.readMemory() — the workspace already loaded the binary with
    correct file_offset ↔ virtual_address translation, so we don't need
    file-offset heuristics. This is the same approach Ghidra uses.

    segments: list of (name, va, size) from vivisect
    Returns list of VivisectString objects.
    """
    results = []
    seen_content = set()

    # Symbol tables / code sections — skip (handled separately).
    # Covers ELF, PE, and Mach-O conventions.
    _SKIP = {
        # ELF symbol/relocation/code sections
        '.dynstr', '.strtab', '.shstrtab', '.plt', '.plt.got', '.plt.sec',
        '.init', '.fini', '.eh_frame', '.eh_frame_hdr',
        '.gnu.hash', '.hash', '.dynsym', '.symtab',
        '.rela.dyn', '.rela.plt', '.rel.dyn', '.rel.plt',
        '.gnu.version', '.gnu.version_r', '.gnu.version_d',
        '.note.gnu.property', '.note.gnu.build-id', '.note.abi-tag',
        '.interp', '.dynamic', '.got', '.got.plt',
        # PE code/header sections
        '.text', '.code',
        # Mach-O code/symbol sections
        '__text', '__stubs', '__stub_helper', '__symbol_stub',
        '__la_symbol_ptr', '__nl_symbol_ptr', '__got',
        '__unwind_info', '__eh_frame',
    }

    # Data sections we scan — strict allowlist for stable Ghidra-like output.
    # Covers ELF, PE, and Mach-O conventions.
    _SCAN = {
        # ELF data sections
        '.rodata', '.data', '.rdata', '.data.rel.ro',
        '.idata', '.edata', '.rsrc',
        '.interp', '.comment',
        # Mach-O data sections (typical string-holding sections)
        '__cstring', '__const', '__data', '__rodata',
        '__cfstring', '__objc_classname', '__objc_methname',
        '__objc_methtype', '__ustring', '__os_log',
    }

    def _looks_like_real_string(s: str) -> bool:
        """
        Reject code-bytes-as-text false positives.
        Generic heuristic — works across architectures (x86/ARM/MIPS):
        real strings have a high alphanumeric ratio; instruction-byte
        garbage interpreted as text has a high punctuation ratio.
        """
        if len(s) < min_len:
            return False
        alpha = sum(1 for c in s if c.isalnum() or c == ' ')
        if alpha < len(s) * 0.6:
            return False
        return True

    for seg_name, seg_va, seg_size in segments:
        # Case-insensitive match (PE binaries may use mixed case)
        clean_name = seg_name.rstrip('\x00').lower()
        if clean_name in _SKIP:
            continue
        if clean_name not in _SCAN or seg_size == 0:
            continue

        # Get actual section bytes from the workspace (correct VA→bytes mapping)
        try:
            data = vw.readMemory(seg_va, seg_size)
        except Exception:
            continue
        if not data:
            continue

        # ── ASCII scan ───────────────────────────────────────────────────
        cur = []
        cur_va = seg_va
        for i, byte in enumerate(data):
            if 0x20 <= byte < 0x7F or byte in (0x09, 0x0A, 0x0D):  # printable + tab/lf/cr
                cur.append(chr(byte))
            else:
                if len(cur) >= min_len:
                    content = ''.join(cur).rstrip()
                    if (_looks_like_real_string(content)
                            and content not in seen_content):
                        seen_content.add(content)
                        results.append(VivisectString(
                            cur_va, content, len(content), StringEncType.ASCII))
                cur = []
                cur_va = seg_va + i + 1

        # Tail of section (no terminator)
        if len(cur) >= min_len:
            content = ''.join(cur).rstrip()
            if _looks_like_real_string(content) and content not in seen_content:
                seen_content.add(content)
                results.append(VivisectString(
                    cur_va, content, len(content), StringEncType.ASCII))

        # ── UTF-16LE scan ────────────────────────────────────────────────
        i = 0
        while i + 1 < len(data):
            if data[i+1] == 0 and 0x20 <= data[i] < 0x7F:
                j = i
                chars = []
                while j + 1 < len(data) and data[j+1] == 0 and 0x20 <= data[j] < 0x7F:
                    chars.append(chr(data[j]))
                    j += 2
                if len(chars) >= min_len:
                    content = ''.join(chars)
                    if (_looks_like_real_string(content)
                            and content not in seen_content):
                        seen_content.add(content)
                        results.append(VivisectString(
                            seg_va + i, content, len(content), StringEncType.UTF16))
                i = j if j > i else i + 2
            else:
                i += 1

    return results


# ════════════════════════════════════════════════════════════════════════════
#  Main Backend
# ════════════════════════════════════════════════════════════════════════════

class VivisectBackend(BackEnd):
    """
    xrefer backend powered by Vivisect (vivisect.VivWorkspace).

    Pickle-safe: all attributes are plain Python types.
    Memory-efficient: vivisect lazy workspace, no full-buffer load.
    Import-resolved: LIEF maps function names to library modules.
    String-complete: manual section scanner + vivisect LOC_STRING.
    """

    def __init__(self, path: str) -> None:
        super().__init__()

        if not os.path.isfile(path):
            raise BackendError(f"File not found: {path}")

        self._binary_path: str = path

        # ── Load & analyse ────────────────────────────────────────────────
        vw = vivisect.VivWorkspace()
        try:
            vw.loadFromFile(path)
            vw.analyze()
        except Exception as exc:
            raise BackendError(f"Vivisect failed to load {path}: {exc}") from exc

        # ── Second-pass function discovery (Ghidra parity) ───────────────
        # Vivisect's default analysis is conservative compared to Ghidra's
        # decompiler-guided discovery. funcentries is cheap (sub-second) and
        # always run. emucode does emulation-based discovery that is valuable
        # on small/medium binaries but becomes pathologically slow on large
        # dense binaries (>2 minutes on a 3MB Rust binary), so we gate it by
        # file size. Override the threshold with XREFER_VIV_EMUCODE_MAX_MB.
        try:
            from vivisect.analysis.generic import emucode, funcentries
            funcentries.analyze(vw)
            _emucode_max_mb = float(os.environ.get("XREFER_VIV_EMUCODE_MAX_MB", "2"))
            if os.path.getsize(path) <= _emucode_max_mb * 1024 * 1024:
                emucode.analyze(vw)
            else:
                logger.info("Skipping emucode pass (binary > %.0fMB) for performance", _emucode_max_mb)
        except Exception as exc:
            logger.debug("Second-pass discovery skipped: %s", exc)

        # ── File metadata ─────────────────────────────────────────────────
        self._size: int       = os.path.getsize(path)
        self._sha256: str     = self._compute_sha256(path)
        maps                  = vw.getMemoryMaps()
        self._image_base: int = min(m[0] for m in maps) if maps else 0
        self._filetype: str   = self._detect_filetype(path)

        # ── LIEF enrichment ───────────────────────────────────────────────
        lief_data            = _extract_lief_data(path)
        import_module_map    = lief_data['import_module_map']   # func → module
        lief_extra_strings   = lief_data['extra_strings']       # [(va, name)]
        self._file_offset_map: list = lief_data['file_offset_map']  # [(off_start, off_end, va_start)]

        # ── User-annotation storage (avoids lazy hasattr checks) ──────────
        self._comments: dict = {}

        # ── Sections ─────────────────────────────────────────────────────
        # Named segments (fine-grained, .text / .data / etc.)
        viv_segments = []  # [(name, va, size)] — used for string scan
        self._named_sections: list = []
        for seg in vw.getSegments():
            va, size, name, fname = seg
            perms = self._lookup_perms(maps, va)
            self._named_sections.append(VivisectSection(name, va, size, perms))
            viv_segments.append((name, va, size))

        # Memory maps (coarser, has perms) — used as fallback sections
        self._sections: list = []
        for mm in maps:
            va, size, perms, fname = mm
            self._sections.append(VivisectSection(fname or '', va, size, perms))

        # ── Functions ────────────────────────────────────────────────────
        import_vas = {imp[0] for imp in vw.getImports()}
        export_vas = {exp[0] for exp in vw.getExports()}

        self._functions: list       = []
        self._func_start_index: dict = {}
        self._func_containing: dict  = {}

        for fva in vw.getFunctions():
            fname_raw = vw.getName(fva) or f'sub_{fva:x}'
            is_thunk  = bool(vw.isFunctionThunk(fva))

            # Ghidra parity: thunk (PLT stub) takes precedence over IMPORT classification
            if is_thunk:
                ftype = FunctionType.THUNK
            elif fva in import_vas:
                ftype = FunctionType.IMPORT
            elif fva in export_vas:
                ftype = FunctionType.EXPORT
            else:
                ftype = FunctionType.NORMAL

            blocks = []
            for bva, bsize, _ in vw.getFunctionBlocks(fva):
                if bsize > 0:
                    blocks.append((bva, bva + bsize))
                    for offset in range(bva, bva + bsize):
                        self._func_containing[offset] = fva

            vf  = VivisectFunction(fva, fname_raw, ftype, is_thunk, blocks)
            idx = len(self._functions)
            self._functions.append(vf)
            self._func_start_index[fva] = idx

        # ── Xrefs ────────────────────────────────────────────────────────
        # REF_CODE covers BOTH calls and conditional/unconditional jumps in
        # vivisect, so we classify each by inspecting the source mnemonic
        # (works for x86, x86_64, ARM, AArch64).
        #
        # Two cleanup steps to match Ghidra/IDA/BN semantics:
        #   1) Indirect PLT thunks emit both REF_CODE + REF_DATA — dedup the
        #      (source, target) pair so the code classification wins.
        #   2) For DIRECT calls/jumps (PcRel operand), vivisect also emits
        #      "thunk-resolved" targets (e.g. GOT slot after PLT). We keep
        #      only xrefs whose target matches the operand-encoded direct
        #      target — matches what Ghidra `getReferencesFrom` returns.
        self._xrefs_from: dict = {}
        self._xrefs_to:   dict = {}
        seen_pairs: dict = {}        # (source, target) → already-recorded
        direct_target_cache: dict = {}  # source_va → expected direct target or None

        def _direct_target(va: int) -> Optional[int]:
            """Return the direct branch target encoded in the source opcode,
            or None for indirect / non-branch instructions."""
            if va in direct_target_cache:
                return direct_target_cache[va]
            target = None
            try:
                op = vw.parseOpcode(va)
                for oper in op.opers:
                    tname = type(oper).__name__
                    if 'PcRel' in tname and hasattr(oper, 'imm'):
                        # Direct relative branch: PC + len + offset
                        target = va + len(op) + oper.imm
                        break
                    if 'Imm' in tname and hasattr(oper, 'imm') and oper.imm > 0:
                        # Absolute immediate target (e.g., x86 `call 0xADDR`)
                        target = int(oper.imm)
                        break
            except Exception:
                target = None
            direct_target_cache[va] = target
            return target

        # Two-pass: code xrefs first so they win over data xrefs for same pair
        all_xrefs = list(vw.getXrefs())
        ordered = (
            [x for x in all_xrefs if x[2] == vc.REF_CODE]
            + [x for x in all_xrefs if x[2] != vc.REF_CODE]
        )

        for xfrom, xto, rtype, _flags in ordered:
            if rtype == vc.REF_CODE:
                # Drop thunk-resolved targets: keep xref only if it matches
                # the opcode's direct target (or if no direct target — indirect).
                direct = _direct_target(xfrom)
                if direct is not None and xto != direct:
                    continue
                xtype = _classify_code_xref(vw, xfrom)
            elif rtype == vc.REF_DATA:
                # READ vs WRITE depends on the source opcode; vivisect's
                # REF_DATA itself doesn't distinguish.
                xtype = _classify_data_xref(vw, xfrom)
            else:
                xtype = _DATA_RTYPE_MAP.get(rtype, XrefType.UNKNOWN)

            if (xfrom, xto) in seen_pairs:
                continue
            seen_pairs[(xfrom, xto)] = xtype

            xr = VivisectXref(xfrom, xto, xtype)
            self._xrefs_from.setdefault(xfrom, []).append(xr)
            self._xrefs_to.setdefault(xto,   []).append(xr)

        # ── Strings ──────────────────────────────────────────────────────
        # Ghidra parity: do NOT skip symbol-table sections (.dynstr/.strtab/
        # .shstrtab). Those sections are loaded into memory and Ghidra
        # treats their contents as string entities. We extract them via
        # LIEF for accurate naming/addresses below.
        self._strings: list = []
        seen_content: set   = set()

        # 1. Vivisect LOC_STRING
        for loc in vw.getLocations(ltype=vc.LOC_STRING):
            va, size, _ltype, _linfo = loc
            try:
                raw     = vw.readMemory(va, size)
                content = raw.rstrip(b'\x00').decode('ascii', errors='replace')
                if content and len(content) >= String.MIN_LENGTH and content not in seen_content:
                    seen_content.add(content)
                    self._strings.append(
                        VivisectString(va, content, len(content), StringEncType.ASCII))
            except Exception:
                pass

        # 2. Vivisect LOC_UNI (unicode)
        for loc in vw.getLocations(ltype=vc.LOC_UNI):
            va, size, _ltype, _linfo = loc
            try:
                raw     = vw.readMemory(va, size)
                content = raw.rstrip(b'\x00\x00').decode('utf-16-le', errors='replace')
                if content and len(content) >= String.MIN_LENGTH and content not in seen_content:
                    seen_content.add(content)
                    self._strings.append(
                        VivisectString(va, content, len(content), StringEncType.UTF16))
            except Exception:
                pass

        # 3. FIX 3: Manual string scanner on data/rodata sections
        # Pass vw so the scanner can use accurate VA→bytes translation
        # (replaces the broken file-offset heuristic).
        manual_strings = _manual_string_scan(vw, viv_segments, min_len=String.MIN_LENGTH)
        for ms in manual_strings:
            if ms.content not in seen_content:
                seen_content.add(ms.content)
                self._strings.append(ms)

        # 4. LIEF extra strings (symbol names, section names).
        # xrefer's downstream string store is a dict keyed by address
        # (lang_base.py:277), so multiple names at the same VA (e.g.
        # __bss_start / _edata / completed.0 all at the BSS base) would
        # collide and only the last would survive. We assign every LIEF
        # extra a unique synthetic address in a sentinel range above any
        # real VA so each becomes a distinct entity (Ghidra parity).
        SYNTH_BASE = 0xF000_0000_0000_0000
        synth_offset = 0
        for _sym_va, sym_name in lief_extra_strings:
            clean = sym_name.strip()
            if not clean or len(clean) < String.MIN_LENGTH or clean in seen_content:
                continue
            seen_content.add(clean)
            addr = SYNTH_BASE + synth_offset
            synth_offset += len(clean) + 1
            self._strings.append(
                VivisectString(addr, clean, len(clean), StringEncType.ASCII))

        # ── Imports (FIX 2: resolve module via LIEF) ──────────────────────
        # Ghidra parity: for ELF binaries, default unknown modules to 'GLIBC'
        # (matches ghidra/backend.py:705 `library_name or ("GLIBC" if is_elf else "unknown")`)
        is_elf = 'ELF' in self._filetype
        default_module = 'GLIBC' if is_elf else 'unknown'

        self._raw_imports: list = []
        for imp in vw.getImports():
            va, _size, _ltype, raw_name = imp
            raw_name = raw_name or ''

            # Vivisect format: '*.printf'  or  'kernel32.CreateFileA'
            if raw_name.startswith('*.'):
                func_name = raw_name[2:]
                module_name = import_module_map.get(func_name, default_module)
            elif '.' in raw_name:
                parts       = raw_name.rsplit('.', 1)
                module_name = parts[0]
                func_name   = parts[1]
                if module_name in ('*', 'unknown'):
                    module_name = import_module_map.get(func_name, default_module)
            else:
                func_name   = raw_name
                module_name = import_module_map.get(func_name, default_module)

            self._raw_imports.append((Address(va), func_name, module_name))

        # ── Exports ──────────────────────────────────────────────────────
        self._exports: list = []
        for exp in vw.getExports():
            va, _etype, ename, _fname = exp
            if ename:
                self._exports.append((ename, Address(va)))

        # ── Name ↔ VA maps ───────────────────────────────────────────────
        # Vivisect qualifies every symbol with the module prefix, e.g.
        # 'binary.main', 'binary._start'. xrefer (and the Ghidra backend it
        # mirrors) looks symbols up by their BARE name ('main', '_start'),
        # so we also index the unqualified alias. When a short name maps to
        # several addresses, prefer the one that is a real function start —
        # otherwise 'main' can resolve to a data/pointer slot (e.g. an entry
        # in .data) and entry-point detection picks a non-code address.
        self._name_to_va: dict = {}
        self._va_to_name: dict = {}
        for va, name in vw.getNames():
            if not name:
                continue
            self._name_to_va[name] = va
            self._va_to_name[va]   = name
            # Unqualified alias: strip the module prefix (text before first '.')
            if '.' in name:
                short = name.split('.', 1)[1]
                if short and short != name:
                    is_func = va in self._func_start_index
                    if short not in self._name_to_va or is_func:
                        self._name_to_va[short] = va

        # ── Memory snapshot for read_bytes ────────────────────────────────
        self._mem_maps: list = []
        for mm in maps:
            va, size, perms, _fname = mm
            try:
                data = vw.readMemory(va, size)
                self._mem_maps.append((va, size, data))
            except Exception:
                self._mem_maps.append((va, size, b''))
        # Sort memory maps by start VA + keep a parallel start-key list so
        # read_bytes() can locate the containing map with bisect in O(log n)
        # instead of a linear scan on every call (read_bytes is called heavily
        # by language modules, e.g. lang_rust's pointer scanning).
        self._mem_maps.sort(key=lambda m: m[0])
        self._mem_map_starts: list = [m[0] for m in self._mem_maps]

        # ── Opcode cache ─────────────────────────────────────────────────
        self._insn_cache: dict = {}
        # Indirect-call dispatch displacements: call-site VA -> displacement of a
        # single-base memory deref (`call [reg + disp]`). Captured here because
        # the structured operand (oper.disp) is only available while `vw` is
        # alive; the cached Operand.text is not parseable for this. Used solely by
        # recover_vtable_edges() (Rust trait dispatch); harmless/empty otherwise.
        self._indirect_call_disp: dict = {}
        for fva in vw.getFunctions():
            for bva, bsize, _ in vw.getFunctionBlocks(fva):
                offset = bva
                end    = bva + bsize
                while offset < end:
                    try:
                        op   = vw.parseOpcode(offset)
                        insn = self._opcode_to_instruction(op)
                        self._insn_cache[offset] = insn
                        if op.mnem.lower().startswith('call'):
                            disp = self._call_deref_disp(op)
                            if disp is not None:
                                self._indirect_call_disp[offset] = disp
                        offset += len(op)
                    except Exception:
                        offset += 1
        # Pre-sort instruction addresses ONCE for O(log n) range lookups in
        # instructions() — avoids re-sorting on every call (see instructions()).
        self._sorted_insn_addrs: list = sorted(self._insn_cache)

        del vw  # release vivisect workspace — all data extracted to plain Python

    # ── Internal helpers ──────────────────────────────────────────────────

    @staticmethod
    def _compute_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _detect_filetype(path: str) -> str:
        try:
            with open(path, 'rb') as f:
                hdr = f.read(8)
            if hdr[:4] == b'\x7fELF':
                return 'ELF64' if hdr[4] == 2 else 'ELF32'
            if hdr[:2] in (b'MZ', b'ZM'):
                return 'PE'
            if hdr[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                            b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe'):
                return 'Mach-O'
        except Exception:
            pass
        return 'Unknown'

    @staticmethod
    def _lookup_perms(maps: list, va: int) -> int:
        for mva, msize, perms, _fname in maps:
            if mva <= va < mva + msize:
                return perms
        return MM_READ

    @staticmethod
    def _opcode_to_instruction(op) -> Instruction:
        operands = []
        for oper in op.opers:
            tname = type(oper).__name__
            text  = str(oper)
            if 'Reg' in tname:
                otype, val = OperandType.REGISTER, None
            elif 'PcRel' in tname or 'RipRel' in tname:
                otype = OperandType.RELATIVE
                try:
                    target = op.va + len(op) + oper.imm
                    val    = Address(target) if target >= 0 else None
                except Exception:
                    val = None
            elif 'Imm' in tname:
                otype = OperandType.IMMEDIATE
                val   = Address(oper.imm) if hasattr(oper, 'imm') and oper.imm >= 0 else None
            elif 'Mem' in tname or 'Deref' in tname:
                otype, val = OperandType.MEMORY, None
            else:
                otype, val = OperandType.OTHER, None
            operands.append(Operand(type=otype, text=text, value=val))

        return Instruction(
            address  = Address(op.va),
            mnemonic = op.mnem.lower(),
            operands = tuple(operands),
            text     = repr(op),
        )

    @staticmethod
    def _call_deref_disp(op) -> Optional[int]:
        """Displacement of a `call [reg + disp]` single-base memory dereference.

        Returns the (signed) displacement for an indirect call through a single
        base register (envi ``i386RegMemOper``, or a ``i386SibOper`` with no
        index register) — the shape Rust trait dispatch uses (``call [reg]`` is
        disp 0). Returns None for direct calls, register-only indirect calls
        (`call rax`), and scaled/indexed derefs (`call [base + idx*scale]`,
        array-style) which don't map to a fixed vtable slot. Used to recover
        trait-dispatch edges; see recover_vtable_edges().
        """
        opers = getattr(op, 'opers', None)
        if not opers or len(opers) != 1:
            return None
        oper = opers[0]
        cls = type(oper).__name__
        if 'RegMemOper' in cls:
            return int(getattr(oper, 'disp', 0))
        if 'SibOper' in cls and getattr(oper, 'index', None) is None:
            return int(getattr(oper, 'disp', 0))
        return None

    # ════════════════════════════════════════════════════════════════════════
    #  BackEnd ABC — all 24 methods
    # ════════════════════════════════════════════════════════════════════════

    @property
    def name(self) -> str:
        return 'vivisect'

    @property
    def image_base(self) -> Address:
        return Address(self._image_base)

    @property
    def size(self) -> int:
        return self._size

    def _binary_hash_impl(self) -> str:
        return self._sha256

    def filetype(self) -> str:
        return self._filetype

    def functions(self) -> Iterator[Function]:
        yield from self._functions

    def get_function_at(self, address: Address) -> Optional[Function]:
        addr = int(address)
        if addr in self._func_start_index:
            return self._functions[self._func_start_index[addr]]
        func_va = self._func_containing.get(addr)
        if func_va is not None and func_va in self._func_start_index:
            return self._functions[self._func_start_index[func_va]]
        return None

    def strings(self, min_length: int = String.MIN_LENGTH) -> Iterator[String]:
        for s in self._strings:
            if s.length >= min_length:
                yield s

    def get_name_at(self, address: Address) -> str:
        return self._va_to_name.get(int(address), '')

    def get_address_for_name(self, name: str) -> Optional[Address]:
        va = self._name_to_va.get(name)
        return Address(va) if va is not None else None

    def get_xrefs_to(self, address: Address) -> Iterator[Xref]:
        yield from self._xrefs_to.get(int(address), [])

    def get_xrefs_from(self, address: Address, far_only: bool = False) -> Iterator[Xref]:
        """Get all references FROM the specified address.

        ``far_only`` is accepted for interface parity and is a no-op here:
        Vivisect's xref store is built solely from ``vw.getXrefs()`` — REF_CODE
        (call/jump) and REF_DATA (read/write/offset) refs — so it never contains
        the per-instruction fall-through flow refs that ``far_only`` is meant to
        exclude (same situation as the Ghidra backend). Returning everything is
        therefore already equivalent to returning only far refs.
        """
        yield from self._xrefs_from.get(int(address), [])

    @property
    def recover_incomplete_call_graph(self) -> bool:
        # Vivisect misses indirect / Rust trait-dispatch call edges, so opt into
        # the Rust EP / clustering repair heuristics (see base class docstring).
        return True

    def read_bytes(self, address: Address, size: int) -> Optional[bytes]:
        va = int(address)
        # Locate the candidate map via bisect (maps sorted by start VA) — the
        # rightmost map whose start <= va — then verify containment. O(log n).
        idx = bisect.bisect_right(self._mem_map_starts, va) - 1
        if idx < 0:
            return None
        mva, msize, data = self._mem_maps[idx]
        if mva <= va < mva + msize:
            off = va - mva
            end = off + size
            if end <= len(data):
                return data[off:end]
            return None  # partial reads return None (Ghidra/IDA parity)
        return None

    def instructions(self, start: Address, end: Address) -> Iterator[Address]:
        # Use the pre-sorted address list + bisect for an O(log n + range) range
        # scan. (Previously this re-sorted the entire insn cache on EVERY call —
        # O(n log n) per call — which made callers that invoke instructions()
        # per-basic-block, e.g. lang_rust, explode to a multi-minute hang on
        # large binaries with hundreds of thousands of cached instructions.)
        s, e = int(start), int(end)
        addrs = self._sorted_insn_addrs
        lo = bisect.bisect_left(addrs, s)
        hi = bisect.bisect_left(addrs, e)
        for va in addrs[lo:hi]:
            yield Address(va)

    def _get_sections_impl(self) -> Iterator[Section]:
        seen = set()
        for sec in self._named_sections:
            if sec.start not in seen:
                seen.add(sec.start)
                yield sec
        for sec in self._sections:
            if sec.start not in seen:
                seen.add(sec.start)
                yield sec

    def get_section_by_name(self, name: str) -> Optional[Section]:
        for sec in self._named_sections:
            if sec.name == name:
                return sec
        return None

    def _get_raw_imports(self) -> Iterator[Tuple[Address, str, str]]:
        yield from self._raw_imports

    def get_exports(self) -> Iterator[Tuple[str, Address]]:
        yield from self._exports

    # ── Rust user-entry (rust_main) detection ─────────────────────────────
    # Ports the IDA backend's byte-walk heuristic to Vivisect primitives.
    # A Rust CRT `main` wrapper takes a *data reference* (lea/mov, NOT a call)
    # to a function-start (the user's real main) and, within a few
    # instructions, calls the runtime bootstrap (`__libc_start_main` on glibc,
    # or a statically-linked Rust runtime wrapper). The data-ref target is the
    # user's rust_main. Without this, the Vivisect backend falls back to the
    # CRT entry point, so path-building (and clustering) starts inside the Rust
    # runtime instead of user code.

    _CRT_HELPERS = ('getmainargs', 'set_app_type', 'security_init_cookie',
                    'cexit', 'amsg_exit', 'initterm', 'getstartupinfo',
                    'setusermatherr', 'p__commode', 'p__fmode')

    def _func_insn_addrs(self, fva: int) -> list:
        """Sorted instruction addresses belonging to function `fva`."""
        fn = self.get_function_at(Address(fva))
        if fn is None:
            return []
        ranges = [(int(b.start), int(b.end)) for b in fn.basic_blocks]
        if not ranges:
            return []
        lo = min(s for s, _ in ranges)
        hi = max(e for _, e in ranges)
        return [a for a in self._sorted_insn_addrs
                if lo <= a < hi and any(s <= a < e for s, e in ranges)]

    def _bootstrap_target_name(self, tgt: int) -> str:
        return (self.get_name_at(Address(tgt)) or self._va_to_name.get(tgt, '')).lower()

    # Rust/glibc bootstrap routines that receive the user main as an argument.
    _BOOTSTRAP_NAMES = ('lang_start', 'libc_start_main', 'libc_start_call_main')

    def _is_bootstrap_call_target(self, tgt: int) -> bool:
        """True if a call to `tgt` is a Rust-runtime bootstrap — by name
        (`lang_start*`, `__libc_start_main`) directly or via a PLT thunk, or a
        direct call to a statically-linked runtime wrapper (non-import func)."""
        name = self._bootstrap_target_name(tgt)
        if any(s in name for s in self._BOOTSTRAP_NAMES):
            return True
        tfn = self.get_function_at(Address(tgt))
        if tfn is None:
            return False
        if tfn.type == FunctionType.THUNK:
            for xr in self.get_xrefs_from(Address(int(tfn.start))):
                tn = self._bootstrap_target_name(int(xr.target))
                if any(s in tn for s in self._BOOTSTRAP_NAMES):
                    return True
            return False
        # statically-linked Rust runtime wrapper: a direct call to a real
        # (non-import / non-library) user function counts.
        return tfn.type not in (FunctionType.IMPORT, FunctionType.LIBRARY)

    def _has_following_bootstrap_call(self, addrs: list, idx: int, maxn: int) -> bool:
        for j in range(idx + 1, min(idx + 1 + maxn, len(addrs))):
            insn = self._insn_cache.get(addrs[j])
            if insn is None or not insn.mnemonic.startswith('call'):
                continue
            # Accept ALL resolved targets of a call instruction — an indirect
            # `call [rip+off]` (Rust's lang_start via a pointer slot) is recorded
            # with XrefType.UNKNOWN, not CALL, so we don't filter on xref type.
            for xr in self.get_xrefs_from(Address(addrs[j])):
                if self._is_bootstrap_call_target(int(xr.target)):
                    return True
        return False

    def _scan_wrapper_for_rust_main(self, func_ea: int) -> Optional[int]:
        fn = self.get_function_at(Address(func_ea))
        if fn is None:
            return None
        ranges = [(int(b.start), int(b.end)) for b in fn.basic_blocks]
        addrs = self._func_insn_addrs(int(fn.start))
        for i, addr in enumerate(addrs):
            for xr in self.get_xrefs_from(Address(addr)):
                tgt = int(xr.target)
                if xr.type in (XrefType.CALL, XrefType.JUMP):
                    continue                       # data ref only, not a branch
                if any(s <= tgt < e for s, e in ranges):
                    continue                       # must leave the wrapper
                if tgt not in self._func_start_index:
                    continue                       # must point at a function start
                # Reject trivial trampolines (jmp rax, etc.) — rust_main must have
                # at least 2 basic blocks OR a single block with ≥1 outgoing call.
                cand_fn = self.get_function_at(Address(tgt))
                if cand_fn is None:
                    continue
                cand_bbs = list(cand_fn.basic_blocks)
                if len(cand_bbs) < 2:
                    if not any(True for xr2 in self.get_xrefs_from(Address(tgt))
                               if xr2.type == XrefType.CALL):
                        continue
                if self._has_following_bootstrap_call(addrs, i, 8):
                    return tgt
        return None

    def _iter_user_callees(self, func_ea: int) -> Iterator[int]:
        seen: set = set()
        for addr in self._func_insn_addrs(func_ea):
            insn = self._insn_cache.get(addr)
            if insn is None or not insn.mnemonic.startswith('call'):
                continue
            for xr in self.get_xrefs_from(Address(addr)):
                if xr.type != XrefType.CALL:
                    continue
                tgt = int(xr.target)
                if tgt not in self._func_start_index or tgt in seen:
                    continue
                tfn = self.get_function_at(Address(tgt))
                if tfn is None or tfn.type in (FunctionType.IMPORT, FunctionType.LIBRARY, FunctionType.THUNK):
                    continue
                nm = self._bootstrap_target_name(tgt).lstrip('._')
                if any(h in nm for h in self._CRT_HELPERS):
                    continue
                seen.add(tgt)
                yield tgt

    def find_rust_main_candidate(self, main_addr: Address) -> Optional[Address]:
        main_ea = int(main_addr)
        cand = self._scan_wrapper_for_rust_main(main_ea)
        if cand is None:
            for callee in self._iter_user_callees(main_ea):
                cand = self._scan_wrapper_for_rust_main(callee)
                if cand is not None:
                    break
        if cand is not None:
            # rename so get_address_for_name("rust_main") short-circuits later
            self._name_to_va["rust_main"] = cand
            self._va_to_name.setdefault(cand, "rust_main")
            return Address(cand)
        return None

    # ── Rust trait-object (vtable) dispatch-edge recovery ─────────────────
    # Vivisect's static analysis can't resolve `call [reg + off]` dyn-Trait
    # dispatch (the target depends on the concrete type at runtime), so the
    # call graph is under-connected and xrefer's clustering over-fragments
    # user code vs Ghidra (whose decompiler does whole-program type prop).
    # We recover the edges STATICALLY and conservatively: locate Rust vtables
    # in read-only data by their fixed header shape, then connect each indirect
    # call to a method ONLY when the calling function references exactly one
    # vtable that has a method at that dispatch offset. The edges flow through
    # the normal user-xref mechanism (see LangRust._process_if_rust), so the
    # shared clustering algorithm reconnects naturally — no core changes.

    def _detect_pointer_size(self) -> int:
        """Pointer size from the file header (NOT a VA-range heuristic).

        A VA-range guess misclassifies low-based 64-bit PIE ELF (image base
        ~0x2000000, every VA < 4 GiB) as 32-bit, which would corrupt every
        pointer read below. Reading the format header is exact.
        """
        try:
            with open(self._binary_path, 'rb') as f:
                head = f.read(0x40)
        except Exception:
            head = b''
        if head[:4] == b'\x7fELF' and len(head) > 4:
            return 8 if head[4] == 2 else 4          # EI_CLASS: 1=32, 2=64
        if head[:2] == b'MZ':
            try:
                pe_off = int.from_bytes(head[0x3c:0x40], 'little')
                with open(self._binary_path, 'rb') as f:
                    f.seek(pe_off + 0x18)
                    magic = int.from_bytes(f.read(2), 'little')
                return 8 if magic == 0x20b else 4    # 0x20b=PE32+, 0x10b=PE32
            except Exception:
                pass
        if head[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf'):
            return 8                                  # Mach-O 64
        if head[:4] in (b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xce'):
            return 4                                  # Mach-O 32
        # Last resort: any section ending above 4 GiB implies 64-bit.
        try:
            return 8 if max(int(s.end) for s in self.get_sections()) > 0xFFFFFFFF else 4
        except Exception:
            return 8

    def _executable_ranges(self) -> list:
        """[(start, end)] of executable sections, for code-pointer validation."""
        ranges = []
        for sec in self.get_sections():
            try:
                is_exec = ('x' in (sec.perm or '')) or sec.type == SectionType.CODE \
                          or sec.name in ('.text', '.plt', '.init', '.fini')
            except Exception:
                is_exec = sec.name in ('.text', '.plt', '.init', '.fini')
            if is_exec:
                ranges.append((int(sec.start), int(sec.end)))
        return ranges

    def recover_vtable_edges(self) -> list:
        ps = self._detect_pointer_size()
        exec_ranges = self._executable_ranges()
        if not exec_ranges:
            return []

        def in_exec(va: int) -> bool:
            return any(s <= va < e for s, e in exec_ranges)

        # Read each candidate section once; reused by both discovery passes.
        sec_data: dict = {}                          # name -> (base_va, bytes)
        for secname in ('.rodata', '.data.rel.ro', '.rdata',
                        '.data', '.got', '.got.plt'):
            sec = self.get_section_by_name(secname)
            if sec is None:
                continue
            base = int(sec.start)
            data = self.read_bytes(Address(base), int(sec.end) - base)
            if data:
                sec_data[secname] = (base, data)

        # ── Phase A: discover vtables in read-only data ────────────────────
        # A Rust vtable is: [0] drop_in_place (fn ptr), [1] size (usize),
        # [2] align (power-of-two usize), [3..] method fn ptrs. We require the
        # drop slot AND >=1 method slot to be real function starts — a strong
        # filter that makes false positives on random data extremely unlikely.
        SIZE_MAX = 1 << 28
        vtables: dict = {}        # base_va -> {byte_offset: target_func_va}
        for secname in ('.rodata', '.data.rel.ro', '.rdata'):
            if secname not in sec_data:
                continue
            base, data = sec_data[secname]
            n = len(data)
            off = 0
            while off + 4 * ps <= n:
                p0 = int.from_bytes(data[off:off + ps], 'little')
                if p0 not in self._func_start_index:
                    off += ps
                    continue
                size_f = int.from_bytes(data[off + ps:off + 2 * ps], 'little')
                align_f = int.from_bytes(data[off + 2 * ps:off + 3 * ps], 'little')
                if size_f > SIZE_MAX or not (0 < align_f <= 4096 and (align_f & (align_f - 1)) == 0):
                    off += ps
                    continue
                slots = {0: p0}
                moff = 3 * ps
                while off + moff + ps <= n:
                    mp = int.from_bytes(data[off + moff:off + moff + ps], 'little')
                    if not in_exec(mp):
                        break
                    if mp in self._func_start_index:
                        slots[moff] = mp
                    moff += ps
                if any(k >= 3 * ps for k in slots):     # has >=1 real method
                    vtables[base + off] = slots
                    off += moff                         # skip past this vtable
                else:
                    off += ps
        if not vtables:
            return []
        vtable_bases = set(vtables)

        # Global index: dispatch offset -> vtable bases that have a method there.
        # Used for the tier-2 fallback (offset globally unique => unambiguous even
        # when the dispatching function never references the vtable directly, e.g.
        # a trait object received as a parameter).
        methods_by_offset: dict = {}
        for vb, slots in vtables.items():
            for o in slots:
                methods_by_offset.setdefault(o, set()).add(vb)

        # ── Phase A.5: pointer slots holding a vtable base ─────────────────
        # PIE / relocated builds load the vtable via a data slot
        # (`lea reg,[rip+slot]` where *slot* stores the vtable pointer) rather
        # than referencing the vtable address directly. Map slot_va -> vtable so
        # a function that references the slot counts as referencing the vtable.
        ptr_slots: dict = {}
        fmt = '<Q' if ps == 8 else '<I'
        for base, data in {b: d for b, d in sec_data.values()}.items():
            usable = len(data) - (len(data) % ps)
            for i, (val,) in enumerate(struct.iter_unpack(fmt, data[:usable])):
                if val in vtable_bases:
                    ptr_slots[base + i * ps] = val

        DATA_REF = (XrefType.DATA_OFFSET, XrefType.DATA_READ, XrefType.DATA_WRITE)

        # ── Phase B: tie indirect call offsets to vtables ──────────────────
        # Tier 1 (precise): the function references exactly one vtable (directly
        #   or via a ptr slot) that has a method at the call's offset.
        # Tier 2 (fallback): the function references none, but the offset belongs
        #   to exactly one vtable binary-wide (globally unambiguous).
        # Ambiguous cases are dropped, never guessed.
        edges = []
        seen = set()
        for fva in self._func_start_index:
            insn_addrs = self._func_insn_addrs(fva)
            if not insn_addrs:
                continue
            calls = [(a, self._indirect_call_disp[a])
                     for a in insn_addrs if a in self._indirect_call_disp]
            if not calls:
                continue
            # vtables this function references (construction / load sites)
            refd = set()
            for a in insn_addrs:
                for xr in self.get_xrefs_from(Address(a)):
                    if xr.type not in DATA_REF:
                        continue
                    t = int(xr.target)
                    if t in vtable_bases:
                        refd.add(t)
                    elif t in ptr_slots:
                        refd.add(ptr_slots[t])
            for a, disp in calls:
                cands = [vt for vt in refd if disp in vtables[vt]]
                if len(cands) == 1:                     # tier 1
                    target = vtables[cands[0]][disp]
                elif len(cands) == 0:                   # tier 2 (global unique)
                    glob = methods_by_offset.get(disp)
                    if not glob or len(glob) != 1:
                        continue
                    target = vtables[next(iter(glob))][disp]
                else:                                   # ambiguous -> skip
                    continue
                if target == fva:                       # ignore trivial self-edge
                    continue
                key = (a, target)
                if key not in seen:
                    seen.add(key)
                    edges.append(key)
        return edges

    def _add_user_xref_impl(self, source: Address, target: Address) -> None:
        # User-added xrefs are treated as CALL by convention (matches Ghidra)
        xr = VivisectXref(int(source), int(target), XrefType.CALL)
        self._xrefs_from.setdefault(int(source), []).append(xr)
        self._xrefs_to.setdefault(int(target),   []).append(xr)

    def _set_comment_impl(self, address: Address, comment: str) -> None:
        self._comments[int(address)] = comment

    def _set_function_comment_impl(self, address: Address, comment: str) -> None:
        func = self.get_function_at(address)
        if func:
            self._set_comment_impl(Address(int(func.start)), comment)

    def _path_impl(self) -> str:
        return self._binary_path

    @property
    def output_base(self) -> str:
        """Backend-qualified output base so vivisect artifacts
        (``<binary>_vivisect.xrefer`` / ``<binary>_vivisect_report.html``) do not
        clobber a ghidra run's ``<binary>_ghidra.*`` outputs in the same dir."""
        return f"{self._binary_path}_vivisect"

    def _get_disassembly_impl(self, address: Address) -> Instruction:
        va = int(address)
        if va in self._insn_cache:
            return self._insn_cache[va]
        raise BackendError(f"No disassembly cached for address {address!r}")

    def _resolve_file_offset_impl(self, file_offset: int) -> Optional[Address]:
        for off_start, off_end, va_start in self._file_offset_map:
            if off_start <= file_offset < off_end:
                return Address(va_start + (file_offset - off_start))
        return None


# ════════════════════════════════════════════════════════════════════════════
#  Factory
# ════════════════════════════════════════════════════════════════════════════

# NOTE: VivisectBackendFactory now lives in xrefer.backend.factory so that
# importing the factory registry does not eagerly import vivisect (which this
# module does at top level). See factory.VivisectBackendFactory.
