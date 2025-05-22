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
from typing import Dict, List, Optional, Tuple

import ida_bytes
import ida_entry
import ida_nalt
import ida_ua
import idaapi
import idautils
import idc


class LanguageBase(ABC):
    """
    Abstract base class for language-specific analyzers.

    Provides common functionality for analyzing binaries compiled from different
    programming languages. Subclasses implement language-specific analysis methods.

    Attributes:
        entry_point (Optional[int]): Program entry point address
        strings (Dict[int, List[str]]): Dictionary mapping addresses to string content
        lib_refs (List[Tuple[int, str, int]]): List of library references
        user_xrefs (List[Tuple[int, int]]): List of user-defined cross-references
        ep_name (str): Name of entry point function
        ep_annotation (str): Annotation for entry point function
        id (str): Identifier for language analyzer
    """

    def __init__(self):
        """Initialize common attributes."""
        self.entry_point = self.get_entry_point()
        self.strings = self.get_strings()
        self.lib_refs = []
        self.user_xrefs = []
        self.ep_name = idc.get_name(self.entry_point)
        self.ep_annotation = ""
        self.id = "base"

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

    @staticmethod
    def get_entry_point() -> Optional[int]:
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
            # 6. Remaining known user-defined entry points
            "_start",
            "start",
            "__start",
        ]

        for point in entry_points:
            ea = idc.get_name_ea_simple(point)
            if ea != idc.BADADDR:
                return ea

        fallback = LanguageBase.fallback_cmain_detection()

        if fallback:
            return fallback
        else:
            ep_count = ida_entry.get_entry_qty()

            if ep_count > 0:
                ep = idc.get_entry_ordinal(ep_count - 1)
                if ep != -1:
                    return ep

        return None

    @staticmethod
    def get_strings(filters: Optional[List[str]] = None) -> Dict[int, List[str]]:
        """
        Extract strings from the IDB with optional filtering.

        Retrieves all defined strings from IDA's database and optionally filters
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
        strings = idautils.Strings(False)
        strings.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16, ida_nalt.STRTYPE_C_32])

        for s in strings:
            str_type = idc.get_str_type(s.ea)
            if str_type is not None:
                contents = ida_bytes.get_strlit_contents(s.ea, -1, str_type)
                if not any(f in contents for f in filters):
                    str_dict[s.ea] = [contents.decode("utf-8")]

        return str_dict

    @staticmethod
    def fallback_cmain_detection() -> Optional[int]:
        """
        Attempt to detect C main function through __initenv reference.

        Looks for references to __initenv variable and analyzes the code
        pattern to find the main function.

        Returns:
            Optional[int]: Address of detected main function, or None if not found
        """
        init_ea = idc.get_name_ea_simple("__initenv")
        if init_ea == idc.BADADDR:
            return None

        xref = next(idautils.XrefsTo(init_ea), None)
        if not xref:
            return None

        ins = ida_ua.insn_t()
        ins_ea = xref.frm

        for _ in range(20):
            ins_ea = idc.next_head(ins_ea)
            idaapi.decode_insn(ins, ins_ea)

            if not ins:
                break

            if ins.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
                return idc.get_operand_value(ins_ea, 0)

        return None
