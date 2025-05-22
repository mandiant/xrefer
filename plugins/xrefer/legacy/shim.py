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

from typing import Optional, Tuple

import ida_bytes
import ida_ida
import ida_lines
import ida_search
import idaapi
import idc


def get_ida_version() -> float:
    """Get IDA version as a float for comparison."""
    version = idaapi.get_kernel_version()
    # Extract major.minor version (e.g., "7.5" from "7.5.123456")
    return float(".".join(version.split(".")[:2]))


class ColorFormatter:
    """
    Workaround for IDA 8.4 simple custom viewer UI bug
    """

    def __init__(self):
        self.ida_version = self._get_ida_version()
        self.is_ida_84 = self._is_ida_84()

    def _get_ida_version(self) -> float:
        """Get IDA version as a float for comparison."""
        version = idaapi.get_kernel_version()
        # Extract major.minor version (e.g., "7.5" from "7.5.123456")
        return float(".".join(version.split(".")[:2]))

    def _is_ida_84(self) -> bool:
        """Check if current version is IDA 8.4."""
        return self.ida_version == 8.4

    def format_ribbon(self, text: str) -> Tuple[str, Optional[int]]:
        """
        Format ribbon text with appropriate coloring based on IDA version.

        Args:
            text (str): Text to format

        Returns:
            Tuple[str, Optional[int]]: Formatted text and background color (only for IDA 8.4)
        """
        if self.is_ida_84:
            # IDA 8.4 workaround using bgcolor
            formatted = ida_lines.COLSTR(f"{text}", "\x05")
            return formatted, 0x2D8BB7
        else:
            # Normal color formatting for all other versions
            return ida_lines.COLSTR(f"\x04{text}", ida_lines.SCOLOR_DEMNAME), None

    def format_line(self, line: str) -> str:
        """
        Format a regular line with appropriate coloring.

        Args:
            line (str): Line to format

        Returns:
            str: Formatted line
        """
        if self.is_ida_84:
            return line  # Return unmodified for IDA 8.4
        else:
            return ida_lines.COLSTR(line, ida_lines.SCOLOR_DEMNAME)


class IDAShim:
    """
    Minimal shim layer for APIs used within the plugin for compatibility with
    versions < 9.0. Does NOT take care of all arguments, just the ones we need.

    From 9.0 changelog:
    BUGFIX: UI: when using COLOR_INV color code (e.g. in a custom viewer),
    IDA would use default color for the text instead of the previous background color
    """

    def __init__(self):
        self.ida_version = get_ida_version()
        self._setup_api_mappings()

    def _setup_api_mappings(self):
        """Setup version-specific API mappings."""
        # Pre-9.0 mappings
        if self.ida_version < 9.0:
            self.find_bytes = self._legacy_find_bytes
            self.check_32bit = self._legacy_is_32bit
            self.find_code = self._legacy_find_code
        # 9.0+ mappings
        else:
            self.find_bytes = self._modern_find_bytes
            self.check_32bit = ida_ida.inf_is_32bit_exactly
            self.find_code = self._modern_find_code

    def _legacy_find_bytes(self, search_str: str, range_start: int, range_end: int, flags: int = 0, radix: int = 16) -> int:
        """Legacy implementation of find_bytes using find_binary."""
        return idaapi.find_binary(range_start, range_end, search_str, 0, idaapi.SEARCH_DOWN)

    def _modern_find_bytes(self, search_str: str, range_start: int, range_end: int, flags: int = ida_bytes.BIN_SEARCH_FORWARD, radix: int = 16) -> int:
        """Modern implementation using ida_bytes.find_bytes."""
        return ida_bytes.find_bytes(bs=search_str, range_start=range_start, range_end=range_end, flags=flags, radix=radix)

    def _legacy_is_32bit(self) -> bool:
        """Legacy implementation of 32-bit check."""
        info = idaapi.get_inf_structure()
        return not info.is_64bit()

    def _legacy_find_code(self, ea: int, flags: int = idaapi.SEARCH_DOWN) -> int:
        """Legacy implementation of find_code."""
        return idc.find_code(ea, flags)

    def _modern_find_code(self, ea: int, flags: int = ida_search.SEARCH_DOWN) -> int:
        """Modern implementation of find_code."""
        return ida_search.find_code(ea, flags)

    def get_search_flags(self, is_modern: bool = True) -> int:
        """Get appropriate search flags based on IDA version."""
        if is_modern and self.ida_version >= 9.0:
            return ida_bytes.BIN_SEARCH_FORWARD
        return idaapi.SEARCH_DOWN


# Create global instances
ida_shim = IDAShim()
color_formatter = ColorFormatter()


def find_bytes(search_str: str, range_start: int, range_end: int, flags: Optional[int] = None, radix: int = 16) -> int:
    """
    Version-independent wrapper for finding bytes in memory.

    Args:
        search_str: String pattern to search for
        range_start: Start address of search range
        range_end: End address of search range
        flags: Search flags (optional, will use version-appropriate default if None)
        radix: Base for number interpretation (default 16)

    Returns:
        int: Address where pattern was found, or BADADDR if not found
    """
    if flags is None:
        flags = ida_shim.get_search_flags(True)
    return ida_shim.find_bytes(search_str, range_start, range_end, flags, radix)


def is_32bit() -> bool:
    """
    Version-independent wrapper for checking if binary is 32-bit.

    Returns:
        bool: True if binary is 32-bit, False for 64-bit
    """
    return ida_shim.check_32bit()


def find_code(ea: int, flags: Optional[int] = None) -> int:
    """
    Version-independent wrapper for finding next code instruction.

    Args:
        ea: Address to start search from
        flags: Search flags (optional, will use version-appropriate default if None)

    Returns:
        int: Address of next code instruction
    """
    if flags is None:
        flags = ida_shim.get_search_flags(False)
    return ida_shim.find_code(ea, flags)


def format_ribbon(text: str) -> tuple[str, Optional[int]]:
    """
    Format ribbon text for all IDA versions.

    Args:
        text (str): Text to format

    Returns:
        tuple[str, Optional[int]]: Formatted text and optional background color
    """
    return color_formatter.format_ribbon(text)


def format_line(line: str) -> str:
    """
    Format line text for all IDA versions.

    Args:
        line (str): Line to format

    Returns:
        str: Formatted line
    """
    return color_formatter.format_line(line)


# Constants that can be imported
SEARCH_DOWN = ida_search.SEARCH_DOWN if hasattr(ida_search, "SEARCH_DOWN") else idaapi.SEARCH_DOWN
BIN_SEARCH_FORWARD = ida_bytes.BIN_SEARCH_FORWARD if hasattr(ida_bytes, "BIN_SEARCH_FORWARD") else idaapi.SEARCH_DOWN
