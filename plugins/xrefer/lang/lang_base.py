# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from xrefer.backend import Address, BackEnd, SectionType, get_current_backend
from xrefer.core.helpers import log


class LanguageBase(ABC):
    """
    Abstract base class for language-specific analyzers.

    Provides common functionality for analyzing binaries compiled from different
    programming languages. Subclasses implement language-specific analysis methods.

    Attributes:
        backend (BackEnd): Backend abstraction instance for binary analysis
        entry_point (Optional[int]): Program entry point address
        strings (Dict[int, List[str]]): Dictionary mapping addresses to string content
        lib_refs (List[Tuple[int, str, int]]): List of library references
        user_xrefs (List[Tuple[int, int]]): List of user-defined cross-references
        ep_annotation (str): Annotation for entry point function
        id (str): Identifier for language analyzer
    """

    def __init__(self, backend: Optional[BackEnd] = None):
        """Initialize common attributes."""
        self.backend: "BackEnd" = backend or get_current_backend()
        self.entry_point = None
        self.strings = None
        self.lib_refs = []
        self.user_xrefs = []
        self.ep_annotation = ""
        self.id = "base"


    def initialize(self) -> None:
        """Initialize language-specific data after language matching."""
        self.entry_point = self.get_entry_point()
        if self.entry_point is None:
            raise AssertionError("Language analysis failed to determine an entry point")
        if self.entry_point < 0x100:
            raise AssertionError(f"Entry point 0x{self.entry_point:x} is suspiciously low")
        self.strings = self.get_strings()

    def __str__(self) -> str:
        """Return a string representation of the language analyzer."""
        return f"{self.__class__.__name__} (ID: {self.id}, Entry Point: {self.entry_point})"

    @abstractmethod
    def lang_match(self) -> bool:
        """
        Check if binary matches this language type.

        Abstract method that must be implemented by subclasses to determine
        if the current binary matches their language type.

        Returns:
            bool: True if binary matches this language, False otherwise
        """
        """Check if this language matches the current binary."""
        pass

    def get_entry_point(self) -> Optional[int]:
        """
        Get the user-defined entry point address by checking a prioritized list of common
        entry point function names. We skip CRT startup routines and focus only on the
        functions that the user is likely to have defined.

        Precedence:
        1. main variants
        - main, _main, __main
        2. WinMain variants
        - WinMain, _WinMain@16, wmain, _wmain, wWinMain, _wWinMain@16
        3. DllMain variants
        - DllMain, _DllMain@12
        4. DllEntryPoint variants
        - DllEntryPoint
        5. DriverEntry variants
        - DriverEntry, _DriverEntry@8
        6. Remaining known user-defined entry points
        - _start, start, __start

        Returns:
            Optional[int]: The address of the discovered user-defined entry point or None if not found.
        """

        entry_points = [
            # 6. Golang (not supported yet, but reserving the spot)
            "main.main",
            # 7. rust, if we are lucky
            "main::main",
            # 1. Main variants (standard CLI entry points; underscores often used by older toolchains)
            "main",
            "_main",
            "__main",
            # 2. WinMain variants (Windows GUI/console entry points; decorated forms on 32-bit)
            "WinMain",
            "_WinMain@16",
            "wmain",  # wide-char console variant on Windows
            "_wmain",  # underscore-prefixed wide-char console variant
            "wWinMain",  # wide-char GUI variant on Windows
            "_wWinMain@16",  # decorated wide-char GUI variant on 32-bit Windows
            # 3. DllMain variants
            "DllMain",
            "_DllMain@12",
            # 4. DllEntryPoint variants
            "DllEntryPoint",
            # 5. DriverEntry variants (Windows driver entry points; decorated form for 32-bit)
            "DriverEntry",
            "_DriverEntry@8",
            # 7. Remaining known user-defined entry points
            "_start",
            "start",
            "__start",
            # 8. Fallback alias observed in some backends (e.g., Ghidra)
            "entry",
        ]
        # addr: score
        scores = {}
        kExists = 1
        kExported = 2
        kFavored = 3

        for point in entry_points:
            if (address := self.backend.get_address_for_name(point)):
                scores[address.value] = scores.get(address.value, 0) + kExists
        for export in self.backend.get_exports():
            name, addr = export
            if addr.value in scores:
                scores[addr.value] += kExported
        for value in scores:
            try:
                name = self.backend.get_function_at(Address(value)).name # Ghidra can have a symbol, while failing to identify a function boundary -> None.name caused AttributeError.
                scores[value] += kExists
            except AttributeError:
                continue
        if scores:
            best_entry = max(scores.items(), key=lambda item: item[1])[0]
            best_name = self.backend.get_name_at(Address(best_entry))
            log(f"Resolved entry point at 0x{best_entry:x} ({best_name}), score {scores[best_entry]}")
            log(f"scores: {scores}")
            return best_entry

        if fallback := self.fallback_cmain_detection(self.backend):
            return fallback
        exports = self.backend.get_exports()
        first_export = next(exports, None)
        if first_export:
            return first_export[1].value

        return None

    def preferred_entry_name(self) -> str:
        """Preferred symbol name for the resolved user entry point."""

        return "main"

    def _resolve_ghidra_user_entry(self, entry_symbol: Optional[Address]) -> Optional[int]:
        """Attempt to resolve the user entry point via Ghidra-specific heuristics."""

        if self.backend.name != "ghidra":
            return None

        entry_address_obj: Optional[Address]
        if entry_symbol is not None:
            entry_address_obj = entry_symbol if isinstance(entry_symbol, Address) else Address(int(entry_symbol))
        else:
            resolved = self.backend.get_address_for_name("entry")
            entry_address_obj = resolved if resolved is not None else None

        if entry_address_obj is None:
            return None

        text_section = self.backend.get_section_by_name(".text")
        if text_section is None:
            return None

        exec_sections = [section for section in self.backend.get_sections() if section.type == SectionType.CODE]

        def _in_exec_section(addr: Address) -> bool:
            if text_section.contains(addr):
                if text_section.type == SectionType.CODE:
                    return True
            for section in exec_sections:
                if section.contains(addr):
                    return True
            return False

        start = max(text_section.start.value, entry_address_obj.value - 0x400)
        end = min(text_section.end.value, entry_address_obj.value + 0x2000)

        candidates: list[tuple[int, int]] = []
        for inst_addr in self.backend.instructions(Address(start), Address(end)):
            inst = self.backend.disassemble(inst_addr)
            if inst.mnemonic != "call" or not inst.operands:
                continue
            target_val = inst.operands[0].value if inst.operands[0].value is not None else None
            if target_val is None:
                continue
            if not _in_exec_section(target_val):
                continue
            if target_val == entry_address_obj:
                continue
            candidates.append((int(target_val), int(inst_addr)))

        if not candidates:
            return None

        # Prefer calls that land before the CRT stub; fall back to the lowest candidate.
        before_stub = [pair for pair in candidates if pair[0] < entry_address_obj.value]
        target_value, _ = min(before_stub or candidates, key=lambda item: item[0])

        self._maybe_rename_entry_function(Address(target_value))
        log(f"Ghidra fallback resolved entry point at 0x{target_value:x}")
        return target_value

    def _maybe_rename_entry_function(self, address: Address) -> None:
        """Rename the resolved entry function if it uses a placeholder name."""

        preferred = self.preferred_entry_name()
        if not preferred:
            return

        try:
            entry_function = self.backend.get_function_at(address)
        except Exception:
            return

        if not entry_function:
            return

        current_name = entry_function.name
        normalized = current_name.lower()
        placeholder_prefixes = ("fun_", "sub_", "entry")
        if current_name and not normalized.startswith(placeholder_prefixes):
            return
        if current_name == preferred:
            return
        entry_function.name = preferred

    def get_strings(self, filters: Optional[List[str]] = None) -> Dict[int, List[str]]:
        """
        Extract strings from the binary with optional filtering.

        Retrieves all defined strings from the binary and optionally filters
        them based on provided filter strings.

        Args:
            filters (Optional[List[str]]): List of strings to filter out. If None,
                                         no filtering is applied.

        Returns:
            Dict[int, List[str]]: Dictionary mapping string addresses to lists containing
                                 the string content. Each list typically has one string,
                                 but may contain multiple elements for special cases.
        """
        if filters is None:
            filters = []

        str_dict = {}
        for s in self.backend.strings():
            if not any(f in s.content for f in filters):
                str_dict[s.address.value] = [s.content]
        return str_dict

    @staticmethod
    def fallback_cmain_detection(backend: "BackEnd") -> Optional[int]:
        """
        Attempt to detect main function through common C runtime patterns.

        Looks for references to common C runtime initialization symbols and
        analyzes the code patterns to find the main function.

        Returns:
            Optional[int]: Address of detected main function, or None if not found
        """
        # Look for common C runtime initialization symbols
        init_symbols = ["__initenv", "__libc_start_main", "_start_main"]

        for symbol in init_symbols:
            if init_addr := backend.get_address_for_name(symbol):
                # Look for cross-references to this symbol
                for xref in backend.get_xrefs_to(init_addr):
                    # Try to find function calls near this reference
                    containing_func = backend.get_function_at(xref.source)
                    if containing_func:
                        # Look for functions called within this function
                        for call_xref in backend.get_xrefs_from(xref.source):
                            target_func = backend.get_function_at(call_xref.target)
                            log(f"WARNING: we are fallbacking to {target_func = }")
                            if target_func:
                                return call_xref.target.value

        return None
