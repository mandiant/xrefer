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

"""
Abstraction layer for disassembler-specific operations.

This module provides a backend abstraction that handles differences between
disassemblers (IDA Pro, Binary Ninja, etc.) for operations like string extraction.
"""

import idc
import ida_nalt
import idautils
import ida_bytes
import idaapi
from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class DisassemblerBackend(ABC):
    """
    Abstract base class for disassembler backend implementations.
    
    This provides a common interface for operations that differ across
    different disassemblers (IDA Pro, Binary Ninja, etc.).
    """
    
    @abstractmethod
    def get_strings(self, filters: Optional[List[str]] = None) -> Dict[int, List[str]]:
        """
        Extract strings from the binary with optional filtering.
        
        Args:
            filters: List of strings to filter out. If None, no filtering is applied.
        
        Returns:
            Dictionary mapping string addresses to lists containing the string content.
        """
        pass
    
    @abstractmethod
    def get_xrefs_to(self, address: int) -> List[int]:
        """
        Get cross-references to a given address.
        
        Args:
            address: The address to find cross-references to.
        
        Returns:
            List of addresses that reference the given address.
        """
        pass
    
    @abstractmethod
    def is_code(self, address: int) -> bool:
        """
        Check if an address contains code.
        
        Args:
            address: The address to check.
        
        Returns:
            True if address contains code, False otherwise.
        """
        pass


class IDABackend(DisassemblerBackend):
    """
    IDA Pro backend implementation.
    
    This implementation uses IDA's native string extraction which is
    xref-based and provides cleaner output.
    """
    
    def get_strings(self, filters: Optional[List[str]] = None) -> Dict[int, List[str]]:
        """
        Extract strings using IDA's native string extraction.
        
        IDA uses cross-references to intelligently delimit strings, which
        provides much cleaner output compared to naive byte scanning.
        
        Args:
            filters: List of strings to filter out. If None, no filtering is applied.
        
        Returns:
            Dictionary mapping string addresses to lists containing the string content.
        """
        if filters is None:
            filters = []
            
        str_dict = {}
        strings = idautils.Strings(False)
        strings.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16,
                              ida_nalt.STRTYPE_C_32])
                              
        for s in strings:
            str_type = idc.get_str_type(s.ea)
            if str_type is not None:
                contents = ida_bytes.get_strlit_contents(s.ea, -1, str_type)
                if contents and not any(f in contents for f in filters):
                    try:
                        str_dict[s.ea] = [contents.decode('utf-8')]
                    except (UnicodeDecodeError, AttributeError):
                        # Skip strings that can't be decoded
                        pass

        return str_dict
    
    def get_xrefs_to(self, address: int) -> List[int]:
        """
        Get cross-references to a given address using IDA's API.
        
        Args:
            address: The address to find cross-references to.
        
        Returns:
            List of addresses that reference the given address.
        """
        return [xref.frm for xref in idautils.XrefsTo(address)]
    
    def is_code(self, address: int) -> bool:
        """
        Check if an address contains code using IDA's API.
        
        Args:
            address: The address to check.
        
        Returns:
            True if address contains code, False otherwise.
        """
        return idaapi.is_code(idaapi.get_flags(address))


class XRefBasedStringExtractor(DisassemblerBackend):
    """
    Custom string extraction backend using xref-based delimiting.
    
    This implementation provides a more controlled approach to string extraction
    that mimics IDA's behavior by using cross-references to delimit strings.
    This helps reduce noise compared to naive string scanning.
    
    This can be used as a fallback or alternative when IDA's native extraction
    needs to be supplemented or when working with other disassemblers.
    """
    
    def get_strings(self, filters: Optional[List[str]] = None) -> Dict[int, List[str]]:
        """
        Extract strings using xref-based delimiting for cleaner output.
        
        This method:
        1. Uses IDA's basic string detection as a starting point
        2. Uses cross-references to intelligently delimit strings
        3. Filters out garbage strings based on xref patterns
        
        Args:
            filters: List of strings to filter out. If None, no filtering is applied.
        
        Returns:
            Dictionary mapping string addresses to lists containing the string content.
        """
        if filters is None:
            filters = []
        
        str_dict = {}
        
        # Get all defined strings from IDA
        strings = idautils.Strings(False)
        strings.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16,
                              ida_nalt.STRTYPE_C_32])
        
        for s in strings:
            # Get the string type
            str_type = idc.get_str_type(s.ea)
            if str_type is None:
                continue
            
            # Get xrefs to this string
            xrefs = list(idautils.XrefsTo(s.ea))
            
            # If no xrefs, it might be garbage or unused - skip it
            # This is one way IDA provides cleaner output
            if not xrefs:
                continue
            
            # Get the string content
            contents = ida_bytes.get_strlit_contents(s.ea, -1, str_type)
            if not contents:
                continue
            
            # Apply filters
            if any(f in contents for f in filters):
                continue
            
            # Decode and store
            try:
                decoded = contents.decode('utf-8')
                # Additional heuristics to filter garbage:
                # - Skip very short strings (likely noise)
                # - Skip strings with too many non-printable characters
                if len(decoded) >= 2 and self._is_likely_valid_string(decoded):
                    str_dict[s.ea] = [decoded]
            except (UnicodeDecodeError, AttributeError):
                # Skip strings that can't be decoded
                pass
        
        return str_dict
    
    def _is_likely_valid_string(self, s: str) -> bool:
        """
        Heuristic to determine if a string is likely valid and not garbage.
        
        Args:
            s: The string to check.
        
        Returns:
            True if the string appears valid, False if it looks like garbage.
        """
        # Count printable vs non-printable characters
        printable_count = sum(1 for c in s if c.isprintable())
        total_count = len(s)
        
        if total_count == 0:
            return False
        
        # Require at least 70% printable characters
        printable_ratio = printable_count / total_count
        if printable_ratio < 0.7:
            return False
        
        # Check for common garbage patterns (all same character, etc.)
        if len(set(s)) == 1:  # All characters are the same
            return False
        
        return True
    
    def get_xrefs_to(self, address: int) -> List[int]:
        """
        Get cross-references to a given address using IDA's API.
        
        Args:
            address: The address to find cross-references to.
        
        Returns:
            List of addresses that reference the given address.
        """
        return [xref.frm for xref in idautils.XrefsTo(address)]
    
    def is_code(self, address: int) -> bool:
        """
        Check if an address contains code using IDA's API.
        
        Args:
            address: The address to check.
        
        Returns:
            True if address contains code, False otherwise.
        """
        return idaapi.is_code(idaapi.get_flags(address))


# Global backend instance
_backend: Optional[DisassemblerBackend] = None


def get_backend() -> DisassemblerBackend:
    """
    Get the current disassembler backend instance.
    
    Returns:
        The active backend instance.
    """
    global _backend
    if _backend is None:
        # Default to IDA backend since this is an IDA plugin
        _backend = IDABackend()
    return _backend


def set_backend(backend: DisassemblerBackend):
    """
    Set the disassembler backend to use.
    
    Args:
        backend: The backend instance to use.
    """
    global _backend
    _backend = backend
