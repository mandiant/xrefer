"""Binary Ninja backend implementation."""

from __future__ import annotations

from typing import Iterator, Optional, Tuple

import binaryninja as bn

from ..base import Address, BackEnd, BasicBlock, Function, FunctionType, Segment, String, StringEncType, Xref, XrefType


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
    def name(self, value: str) -> str:
        """Set the function name."""
        if not value:
            raise ValueError("Function name cannot be empty")
        self._func.name = value
        return self._func.name

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
        return self._func.is_thunk()

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

    def __init__(self, source: int, target: int):
        self._src = source
        self._dst = target

    @property
    def source(self) -> Address:
        return Address(self._src)

    @property
    def target(self) -> Address:
        return Address(self._dst)

    @property
    def type(self) -> XrefType:  # pragma: no cover - heuristic mapping not critical
        return XrefType.UNKNOWN


class BinaryNinjaSegment(Segment):
    """Wrapper for Binary Ninja sections."""

    def __init__(self, sec: bn.binaryview.Section):
        self._sec = sec

    @property
    def name(self) -> str:
        return self._sec.name

    @property
    def start(self) -> Address:
        return Address(self._sec.start)

    @property
    def end(self) -> Address:
        return Address(self._sec.end)


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

    @property
    def image_base(self) -> Address:
        return Address(self._bv.start)

    def functions(self) -> Iterator[BinaryNinjaFunction]:
        for f in self._bv.functions:
            yield BinaryNinjaFunction(f)

    def get_function_at(self, address: Address) -> Optional[BinaryNinjaFunction]:
        funcs = self._bv.get_functions_containing(int(address))
        return BinaryNinjaFunction(funcs[0]) if funcs else None

    def strings(self, min_length: int = 3) -> Iterator[BinaryNinjaString]:
        """
        Get all strings in the Binary Ninja file.

        Args:
            min_length (int): Minimum length of strings to return

        Yields:
            BinaryNinjaString: Strings found in the binary
        """
        for s in self._bv.get_strings(length=min_length):
            if len(s.value) >= min_length:
                yield BinaryNinjaString(s)

    def get_xrefs_to(self, address: Address) -> Iterator[BinaryNinjaXref]:
        for ref in self._bv.get_code_refs(int(address)):
            yield BinaryNinjaXref(ref.address, int(address))
        for ref in self._bv.get_data_refs(int(address)):
            yield BinaryNinjaXref(ref, int(address))

    def get_xrefs_from(self, address: Address) -> Iterator[BinaryNinjaXref]:
        for dst in self._bv.get_code_refs_from(int(address)):
            yield BinaryNinjaXref(int(address), dst)
        for dst in self._bv.get_data_refs_from(int(address)):
            yield BinaryNinjaXref(int(address), dst)

    def get_name_at(self, address: Address) -> str:
        sym = self._bv.get_symbol_at(int(address))
        return sym.full_name if sym else ""

    def get_address_for_name(self, name: str) -> Optional[Address]:
        syms = self._bv.get_symbols_by_name(name)
        return Address(syms[0].address) if syms else None

    def read_bytes(self, address: Address, size: int) -> Optional[bytes]:
        data = self._bv.read(int(address), size)
        return data if data else None

    def get_segments(self) -> Iterator[BinaryNinjaSegment]:
        for sec in self._bv.sections.values():
            yield BinaryNinjaSegment(sec)

    def get_segment_by_name(self, name: str) -> Optional[BinaryNinjaSegment]:
        sec = self._bv.sections.get(name)
        return BinaryNinjaSegment(sec) if sec else None

    def _get_raw_imports(self) -> Iterator[Tuple[Address, str, str]]:
        """Get raw import data from Binary Ninja."""
        processed_addresses = set()

        for ext_loc in self._bv.get_external_locations():
            source_symbol = ext_loc.source_symbol
            symbol_address = source_symbol.address
            data_refs = list(self._bv.get_data_refs(symbol_address))
            if len(data_refs) != 1:
                print(f"Warning: Symbol at {hex(symbol_address)} has {len(data_refs)} data references, expected 1")
                if len(data_refs) == 0:
                    continue
            # Use the data reference address (IAT/GOT entry)
            address = data_refs[0] if data_refs else symbol_address
            if address in processed_addresses:
                continue
            processed_addresses.add(address)
            target_name = ext_loc.target_symbol if ext_loc.has_target_symbol else source_symbol.raw_name
            module_name = ext_loc.library.name.lower().split("/")[-1] if ext_loc.library else "unknown"

            # Yield raw import data: (address, function_name, module_name)
            yield (Address(address), target_name, module_name)

    def _path_impl(self) -> str:
        return self._bv.file.filename

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
