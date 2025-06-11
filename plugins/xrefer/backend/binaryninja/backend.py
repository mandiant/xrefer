from __future__ import annotations

from xrefer import backend

"""Binary Ninja backend implementation."""

from typing import Iterator, Optional

import binaryninja as bn

from ..base import Address, BackEnd, Function, FunctionType, Segment, String, Xref, XrefType


class BinaryNinjaFunction(Function):
    """Wrapper around ``binaryninja`` Function."""

    def __init__(self, func: bn.function.Function):
        self._func = func
        self._type: Optional[FunctionType] = None

    @property
    def address(self) -> Address:
        return Address(self._func.start)

    @property
    def name(self) -> str:
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
    def encoding(self) -> str:
        enc = {
            bn.StringType.AsciiString: "ascii",
            bn.StringType.Utf8String: "utf-8",
            bn.StringType.Utf16String: "utf-16",
            bn.StringType.Utf32String: "utf-32",
        }
        return enc.get(self._str.type, "utf-8")


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
        super().__init__(bv)
        self._bv: "bn.BinaryView" = bv

    def image_base(self) -> int:
        return self._bv.start

    def functions(self) -> Iterator[BinaryNinjaFunction]:
        for f in self._bv.functions:
            yield BinaryNinjaFunction(f)

    def get_function_at(self, address: Address) -> Optional[BinaryNinjaFunction]:
        funcs = self._bv.get_functions_containing(int(address))
        return BinaryNinjaFunction(funcs[0]) if funcs else None

    def strings(self, min_length: int = 3) -> Iterator[String]:
        """
        Get all strings in the Binary Ninja file.

        Args:
            min_length (int): Minimum length of strings to return

        Returns:
            List[backend.String]: List of strings found in the binary
        """
        for s in self._bv.get_strings(length=min_length):
            if len(s.value) >= min_length:
                yield backend.String(s.start, s.value, s.length)

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

    def get_name(self, address: Address) -> str:
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

    def get_imports(self):
        # ida: .idata (0x6ec5b8)
        # bn: .extern (0x702b24) -↑ (Data reference)
        entries = []
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
            for ext in [".so", ".dll", ".dylib"]:
                if module_name.endswith(ext):
                    module_name = module_name[: -len(ext)]
                    break
            if "@@" in target_name:
                splitted = target_name.split("@@")
                target_name = splitted[0]
                if "_" in splitted[1]:
                    module_name = "_".join(splitted[1].split("_")[:-1])
                else:
                    module_name = splitted[1]
            full_name = f"{module_name}.{target_name}"
            ordinal = 0  # BinaryNinja doesn't expose ordinals directly
            entries.append((address, full_name, ordinal, module_name))

    def _path_impl(self) -> str:
        return self._bv.file.filename
