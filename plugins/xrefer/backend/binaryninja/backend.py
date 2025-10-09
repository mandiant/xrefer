"""Binary Ninja backend implementation."""

from __future__ import annotations

import hashlib
from typing import Iterator, Optional, Tuple

import binaryninja as bn
from binaryninja.enums import LowLevelILOperation

from ..base import Address, BackEnd, BasicBlock, Function, FunctionType, Operand, OperandType, Section, SectionType, String, StringEncType, Xref, XrefType, Instruction


class BinaryNinjaFunction(Function):
    """Wrapper around ``binaryninja`` Function."""

    def __init__(self, func: bn.function.Function):
        self._func = func
        self._type: Optional[FunctionType] = None

    @property
    def start(self) -> Address:
        return Address(self._func.start)

    @property
    def name(self) -> str:
        return self._func.name

    @name.setter
    def name(self, value: str) -> None:
        """Set the function name."""
        if not value:
            raise ValueError("Function name cannot be empty")
        self._func.name = value

    @property
    def type(self) -> FunctionType:
        if self._type is None:
            sym = self._func.symbol
            if sym.type == bn.SymbolType.LibraryFunctionSymbol:
                self._type = FunctionType.LIBRARY
            elif sym.type == bn.SymbolType.ImportedFunctionSymbol:
                self._type = FunctionType.IMPORT
            elif sym.binding == bn.SymbolBinding.GlobalBinding:
                self._type = FunctionType.EXPORT
            elif self.is_thunk:
                self._type = FunctionType.THUNK
            else:
                self._type = FunctionType.NORMAL
        return self._type

    @property
    def is_thunk(self) -> bool:
        return self._func.is_thunk

    def contains(self, address: Address) -> bool:
        return self._func.start <= int(address) <= self._func.highest_address

    @property
    def basic_blocks(self) -> Iterator[BasicBlock]:
        """Iterate over basic blocks in the function."""
        for bb in self._func.basic_blocks:
            yield BasicBlock(Address(bb.start), Address(bb.end))


class BinaryNinjaString(String):
    """Wrapper around Binary Ninja string reference."""

    def __init__(self, s: bn.binaryview.StringReference):
        self._str = s

    @property
    def address(self) -> Address:
        return Address(self._str.start)

    @property
    def content(self) -> str:
        return self._str.value

    @property
    def length(self) -> int:
        return self._str.length

    @property
    def encoding(self) -> StringEncType:
        enc = {
            bn.StringType.AsciiString: StringEncType.ASCII,
            bn.StringType.Utf8String: StringEncType.UTF8,
            bn.StringType.Utf16String: StringEncType.UTF16,
            bn.StringType.Utf32String: StringEncType.UTF32,
        }
        return enc.get(self._str.type, StringEncType.UTF8)


class BinaryNinjaXref(Xref):
    """Simple xref representation."""

    def __init__(self, source: int, target: int, kind: XrefType = XrefType.UNKNOWN):
        self._src = source
        self._dst = target
        self._kind = kind

    @property
    def source(self) -> Address:
        return Address(self._src)

    @property
    def target(self) -> Address:
        return Address(self._dst)

    @property
    def type(self) -> XrefType:  # pragma: no cover - heuristic mapping not critical
        return self._kind


class BinaryNinjaSection(Section):
    """Wrapper for Binary Ninja sections (used as segments for consistency)."""

    def __init__(self, name: str, section: bn.binaryview.Section, bv: bn.BinaryView):
        self._name = name
        self._section = section
        self._bv = bv

    @property
    def name(self) -> str:
        return self._name

    @property
    def start(self) -> Address:
        return Address(self._section.start)

    @property
    def end(self) -> Address:
        return Address(self._section.end)

    @property
    def type(self) -> SectionType:
        """Get segment type based on Binary Ninja section semantics and properties."""
        # Primary classification based on Binary Ninja's native semantics
        if self._section.semantics == bn.SectionSemantics.ReadOnlyCodeSectionSemantics:
            return SectionType.CODE
        elif self._section.semantics == bn.SectionSemantics.ReadWriteDataSectionSemantics:
            # Use section type to distinguish BSS from regular data
            # BSS sections have NOBITS type (no actual data in file)
            if self._section.type == "NOBITS":
                return SectionType.BSS
            return SectionType.DATA
        elif self._section.semantics == bn.SectionSemantics.ReadOnlyDataSectionSemantics:
            return SectionType.DATA
        elif self._section.semantics == bn.SectionSemantics.ExternalSectionSemantics:
            return SectionType.EXTERN
        else:
            # For DefaultSectionSemantics (0), use additional Binary Ninja properties
            # Check if section is loaded into memory - non-loaded sections are typically debug/metadata
            containing_segment = self._get_containing_section()
            if not containing_segment:
                # Section not in any loadable segment - likely debug/metadata
                return SectionType.UNKNOWN

            # For loaded sections with default semantics, classify by containing segment permissions
            if containing_segment.executable:
                return SectionType.CODE
            elif containing_segment.writable:
                return SectionType.DATA
            else:
                return SectionType.DATA  # Read-only data

    def _get_containing_section(self) -> Optional[bn.binaryview.Segment]:
        """Find the ELF segment that overlaps with this section."""
        # Find segment that overlaps with this section (not necessarily fully contains)
        for seg in self._bv.segments:
            # Check if section overlaps with segment
            if self._section.start < seg.end and self._section.end > seg.start:
                return seg
        return None

    @property
    def is_readable(self) -> bool:
        """Check if segment is readable."""
        containing_seg = self._get_containing_section()
        return containing_seg.readable if containing_seg else False

    @property
    def is_writable(self) -> bool:
        """Check if segment is writable."""
        containing_seg = self._get_containing_section()
        return containing_seg.writable if containing_seg else False

    @property
    def is_executable(self) -> bool:
        """Check if segment is executable."""
        containing_seg = self._get_containing_section()
        return containing_seg.executable if containing_seg else False

    @property
    def perm(self) -> str:
        """Get segment permissions as string."""
        containing_seg = self._get_containing_section()
        if not containing_seg:
            return "---"
        perms = ""
        perms += "r" if containing_seg.readable else "-"
        perms += "w" if containing_seg.writable else "-"
        perms += "x" if containing_seg.executable else "-"
        return perms


class BNBackend(BackEnd):
    """Binary Ninja backend."""

    def __init__(self, bv):
        """
        Initialize the Binary Ninja backend.

        Args:
            bv (binaryninja.BinaryView): The BinaryView object from Binary Ninja.
        """
        super().__init__()
        self._bv: "bn.BinaryView" = bv

    def __getstate__(self):
        """Make backend pickle-safe by removing BinaryView/ctypes state.

        Binary Ninja's objects are ctypes-backed and cannot be pickled. We
        drop references here so the analyzer state can be serialized.
        """
        state = self.__dict__.copy()
        # Remove BinaryView (and any other transient analysis handles) from state
        state["_bv"] = None
        return state

    def __setstate__(self, state):
        """Restore state without BinaryView. Caller must re-set if needed."""
        self.__dict__.update(state)

    @property
    def name(self) -> str:
        """Backend name for language module lookup."""
        return "binaryninja"

    @property
    def image_base(self) -> Address:
        return Address(self._bv.start)

    def functions(self) -> Iterator[BinaryNinjaFunction]:
        for f in self._bv.functions:
            yield BinaryNinjaFunction(f)

    def get_function_at(self, address: Address) -> Optional[BinaryNinjaFunction]:
        funcs = self._bv.get_functions_containing(int(address))
        return BinaryNinjaFunction(funcs[0]) if funcs else None

    def strings(self, min_length: int = 5) -> Iterator[BinaryNinjaString]:
        """
        Get all strings in the Binary Ninja file.

        Args:
            min_length (int): Minimum length of strings to return

        Yields:
            BinaryNinjaString: Strings found in the binary
        """
        # Only return strings from non-executable memory to align with Ghidra/IDA behavior
        for s in self._bv.get_strings(length=min_length):
            if len(s.value) < min_length:
                continue
            seg = self._bv.get_segment_at(s.start)
            if seg and seg.executable:
                continue
            yield BinaryNinjaString(s)

    def get_xrefs_to(self, address: Address) -> Iterator[BinaryNinjaXref]:
        addr = int(address)
        code_refs = list(self._bv.get_code_refs(addr))
        data_refs = list(self._bv.get_data_refs(addr))

        sym = self._bv.get_symbol_at(addr)
        # sym_type = sym.type
        # sym_name = sym.full_name if sym else ""

        # If nothing found, try common import normalization variants (IAT/GOT cell)
        if not code_refs and not data_refs and sym is not None:
            # BN often records refs to the IAT/GOT cell (data ref from import symbol)
            iat_cells = list(self._bv.get_data_refs(addr))
            for cell in iat_cells:  # limit debug noise
                cr2 = list(self._bv.get_code_refs(cell))
                dr2 = list(self._bv.get_data_refs(cell))
                if cr2 or dr2:
                    code_refs = cr2
                    data_refs = dr2
                    break

        for ref in code_refs:
            yield BinaryNinjaXref(ref.address, addr, self._classify_code_xref(ref.address))
        for ref in data_refs:
            yield BinaryNinjaXref(ref, addr, XrefType.DATA_READ)

    def get_xrefs_from(self, address: Address) -> Iterator[BinaryNinjaXref]:
        addr = int(address)
        code_dsts = list(self._bv.get_code_refs_from(addr))
        data_dsts = list(self._bv.get_data_refs_from(addr))
        for dst in code_dsts:
            yield BinaryNinjaXref(addr, dst, self._classify_code_xref(addr))
        for dst in data_dsts:
            yield BinaryNinjaXref(addr, dst, XrefType.DATA_WRITE)

    def _classify_code_xref(self, source_addr: int) -> XrefType:
        """Best-effort classification of a code reference originating at `source_addr`."""
        func = self._bv.get_function_at(source_addr)
        if func is None:
            return XrefType.UNKNOWN

        try:
            llil = func.get_low_level_il_at(source_addr)
        except Exception:
            llil = None

        if llil is None:
            return XrefType.UNKNOWN

        op = llil.operation

        if op in (
            LowLevelILOperation.LLIL_CALL,
            LowLevelILOperation.LLIL_TAILCALL,
            LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
            LowLevelILOperation.LLIL_CALL_PARAM,
            LowLevelILOperation.LLIL_SYSCALL,
        ):
            return XrefType.CALL

        if op in (
            LowLevelILOperation.LLIL_JUMP,
            LowLevelILOperation.LLIL_JUMP_TO,
            LowLevelILOperation.LLIL_GOTO,
            LowLevelILOperation.LLIL_RET,
            LowLevelILOperation.LLIL_IF,
        ):
            return XrefType.JUMP

        return XrefType.UNKNOWN

    def get_name_at(self, address: Address) -> str:
        sym = self._bv.get_symbol_at(int(address))
        return sym.full_name if sym else ""

    def get_address_for_name(self, name: str) -> Optional[Address]:
        syms = self._bv.get_symbols_by_name(name)
        return Address(syms[0].address) if syms else None

    def read_bytes(self, address: Address, size: int) -> Optional[bytes]:
        data = self._bv.read(int(address), size)
        return data if data else None

    def _get_sections_impl(self) -> Iterator[BinaryNinjaSection]:
        for name, section in self._bv.sections.items():
            yield BinaryNinjaSection(name, section, self._bv)

    def get_section_by_name(self, name: str) -> Optional[BinaryNinjaSection]:
        section = self._bv.sections.get(name)
        if section:
            return BinaryNinjaSection(name, section, self._bv)
        return None

    def _get_raw_imports(self) -> Iterator[Tuple[Address, str, str]]:
        """Get raw import data from Binary Ninja."""
        processed_addresses = set()

        # Heuristic to detect ELF: presence of a .plt section
        is_elf = any(name in self._bv.sections for name in (".plt", ".plt.got", ".rela.plt"))

        for ext_loc in self._bv.get_external_locations():
            source_symbol = ext_loc.source_symbol
            symbol_address = source_symbol.address
            data_refs = list(self._bv.get_data_refs(symbol_address))
            # Prefer the callable stub if Binary Ninja lifted one; otherwise fall back to IAT/GOT cell.
            target_addr = symbol_address
            if not self._bv.get_function_at(symbol_address) and data_refs:
                target_addr = data_refs[0]
            iat_addr = data_refs[0] if data_refs else None
            if target_addr in processed_addresses:
                continue
            processed_addresses.add(target_addr)
            target_name = ext_loc.target_symbol if ext_loc.has_target_symbol else source_symbol.raw_name
            module_name = ext_loc.library.name.split("/")[-1] if ext_loc.library else ("GLIBC" if is_elf else "unknown")

            # Yield raw import data: (address, function_name, module_name)
            yield (Address(target_addr), target_name, module_name)

    def get_exports(self) -> Iterator[Tuple[str, Address]]:
        """Get all exports from the Binary Ninja binary."""
        for sym in self._bv.entry_functions:
            assert isinstance(sym, bn.Function)
            yield (sym.name, Address(sym.start))

    def _path_impl(self) -> str:
        input_path = self._bv.file.filename
        if ".bndb" in input_path:
            input_path = input_path.rsplit(".bndb", 1)[0]
        return input_path if input_path else ""

    def _binary_hash_impl(self):
        raw_bv = self._bv.file.raw
        all_bytes = raw_bv.read(0, raw_bv.length)
        return hashlib.sha256(all_bytes).hexdigest()

    def instructions(self, start: Address, end: Address) -> Iterator[Address]:
        """Iterate over instruction addresses in the specified range."""
        current = int(start)
        while current < int(end):
            if self._bv.get_instruction_length(current) > 0:
                yield Address(current)
                current += self._bv.get_instruction_length(current)
            else:
                current += 1

    def _add_user_xref_impl(self, source: Address, target: Address) -> None:
        """Add user-defined cross reference in Binary Ninja."""
        self._bv.add_user_code_ref(int(source), int(target))

    def _set_comment_impl(self, address: Address, comment: str) -> None:
        """Set comment at address in Binary Ninja."""
        self._bv.set_comment_at(int(address), comment)

    def _set_function_comment_impl(self, address: Address, comment: str) -> None:
        """Set function comment in Binary Ninja."""
        func = self._bv.get_function_at(int(address))
        if func:
            func.comment = comment

    # def _create_string_object(self, address: Address, content: str, encoding: StringEncType) -> String:
    #     """Create a BinaryNinjaString object for the enhanced string extractor."""

    #     # Create a mock StringReference object that mimics Binary Ninja's output
    #     class MockStringReference:
    #         def __init__(self, start: int, value: str, length: int, encoding: StringEncType):
    #             self.start = start
    #             self.value = value
    #             self.length = length
    #             # Map our encoding back to Binary Ninja's string types
    #             encoding_map = {
    #                 StringEncType.ASCII: bn.StringType.AsciiString,
    #                 StringEncType.UTF8: bn.StringType.Utf8String,
    #                 StringEncType.UTF16: bn.StringType.Utf16String,
    #                 StringEncType.UTF32: bn.StringType.Utf32String,
    #             }
    #             self.type = encoding_map.get(encoding, bn.StringType.Utf8String)

    #     string_ref = MockStringReference(int(address), content, len(content), encoding)
    #     return BinaryNinjaString(string_ref)
    def _get_disassembly_impl(self, address: Address) -> Instruction:
        """Backend-specific implementation for getting disassembly at a specific address."""
        ea = int(address)

        # Full disassembly text for this instruction (Binary Ninja formatted)
        text = self._bv.get_disassembly(ea)

        # Get tokens for ONLY this instruction at `ea` using the architecture
        # Returns (List[InstructionTextToken], length)
        inst_len = self._bv.get_instruction_length(ea)
        # Read a safe number of bytes for decoding this instruction
        data = self._bv.read(ea, inst_len if inst_len and inst_len > 0 else 16) or b""
        tokens, _ = self._bv.arch.get_instruction_text(data, ea)

        # Extract mnemonic from tokens
        mnemonic = ""
        for tok in tokens:
            if tok.type == bn.InstructionTextTokenType.InstructionToken:
                mnemonic = tok.text.strip().lower()
                break

        # Split operand tokens by OperandSeparatorToken to mimic IDA operand indexing
        operands_list: list[Operand] = []
        collecting = False
        current: list = []
        for tok in tokens:
            if tok.type == bn.InstructionTextTokenType.InstructionToken:
                # Start collecting after mnemonic
                collecting = True
                continue
            if not collecting:
                continue
            if tok.type == bn.InstructionTextTokenType.OperandSeparatorToken:
                if current:
                    # finalize current operand
                    ttypes = {t.type for t in current}
                    g_text = "".join(t.text for t in current).strip()
                    kind: OperandType
                    if (
                        bn.InstructionTextTokenType.BeginMemoryOperandToken in ttypes
                        or (
                            bn.InstructionTextTokenType.CodeRelativeAddressToken in ttypes
                            and any(t.type == bn.InstructionTextTokenType.BraceToken and t.text == '[' for t in current)
                        )
                    ):
                        kind = OperandType.MEMORY
                    elif (
                        bn.InstructionTextTokenType.IntegerToken in ttypes
                        or bn.InstructionTextTokenType.PossibleAddressToken in ttypes
                        or bn.InstructionTextTokenType.CodeRelativeAddressToken in ttypes
                    ):
                        kind = OperandType.IMMEDIATE
                    elif bn.InstructionTextTokenType.RegisterToken in ttypes:
                        kind = OperandType.REGISTER
                    else:
                        kind = OperandType.OTHER

                    val = None
                    for t in current:
                        if t.type in (
                            bn.InstructionTextTokenType.IntegerToken,
                            bn.InstructionTextTokenType.PossibleAddressToken,
                            bn.InstructionTextTokenType.CodeRelativeAddressToken,
                        ):
                            try:
                                val = Address(int(t.value))
                            except Exception:
                                val = None
                            break
                    operands_list.append(Operand(type=kind, text=g_text, value=val))
                    current = []
                continue
            current.append(tok)

        # Flush the last operand if any
        if current:
            ttypes = {t.type for t in current}
            g_text = "".join(t.text for t in current).strip()
            if (
                bn.InstructionTextTokenType.BeginMemoryOperandToken in ttypes
                or (
                    bn.InstructionTextTokenType.CodeRelativeAddressToken in ttypes
                    and any(t.type == bn.InstructionTextTokenType.BraceToken and t.text == '[' for t in current)
                )
            ):
                kind = OperandType.MEMORY
            elif (
                bn.InstructionTextTokenType.IntegerToken in ttypes
                or bn.InstructionTextTokenType.PossibleAddressToken in ttypes
                or bn.InstructionTextTokenType.CodeRelativeAddressToken in ttypes
            ):
                kind = OperandType.IMMEDIATE
            elif bn.InstructionTextTokenType.RegisterToken in ttypes:
                kind = OperandType.REGISTER
            else:
                kind = OperandType.OTHER

            val = None
            for t in current:
                if t.type in (
                    bn.InstructionTextTokenType.IntegerToken,
                    bn.InstructionTextTokenType.PossibleAddressToken,
                    bn.InstructionTextTokenType.CodeRelativeAddressToken,
                ):
                    try:
                        val = Address(int(t.value))
                    except Exception:
                        val = None
                    break
            operands_list.append(Operand(type=kind, text=g_text, value=val))
        if not mnemonic:
            mnemonic = (text.split()[0].lower() if text else "")

        ins = Instruction(
            address=Address(ea),
            mnemonic=mnemonic,
            operands=tuple(operands_list),
            text=text
        )
        return ins
