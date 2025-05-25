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

import binascii
import collections
from abc import ABC, abstractmethod
from typing import Any, DefaultDict, Dict, List

import ida_nalt
import ida_ua
import idaapi
import idc


class BaseTraceParser(ABC):
    """
    Abstract base class for API trace parsers.

    Provides common functionality and interface that must be implemented
    by specific trace format parsers.

    Attributes:
        image_base (int): Base address of binary in IDB
        sample_sha256 (str): SHA256 hash of analyzed sample
        parser_id (Optional[str]): Identifier for parser type
        current_index (int): Current global index for call ordering
    """

    def __init__(self):
        self.image_base = idaapi.get_imagebase()
        self.sample_sha256 = self._get_input_file_sha256()
        self.parser_id = None
        self.current_index = 0

    def _get_input_file_sha256(self) -> str:
        """Get SHA256 hash of the input file."""
        sha256_bytes = ida_nalt.retrieve_input_file_sha256()
        return binascii.hexlify(sha256_bytes).decode("utf-8")

    def get_standard_api_name(self, api_name: str, known_imports: Dict[str, str]) -> str:
        """
        Standardize API name with proper prefixing.

        Ensures consistent API naming by applying appropriate prefixes
        (ntdll, dynamic, etc.) based on API type and known imports.

        Args:
            api_name (str): Raw API name
            known_imports (Dict[str, str]): Dictionary of known import mappings

        Returns:
            str: Standardized API name with appropriate prefix
        """
        if api_name in known_imports:
            return known_imports[api_name]
        elif api_name.startswith(("Nt", "Ldr", "Rtl")):
            return f"ntdll.{api_name}"
        return f"dynamic.{api_name}"

    def get_call_address(self, return_addr: int) -> int:
        """
        Get call instruction address from return address.

        Analyzes previous instruction before return address to find
        corresponding call instruction.

        Args:
            return_addr (int): Return address from trace

        Returns:
            int: Address of call instruction, or return_addr if not found
        """
        cmd = idaapi.insn_t()
        if ida_ua.decode_prev_insn(cmd, return_addr):
            if cmd.ea != idc.BADADDR:
                # Get the function of the return address
                ret_func = idaapi.get_func(return_addr)
                # Get the function of the call address
                call_func = idaapi.get_func(cmd.ea)
                # Check if both addresses belong to the same function
                if ret_func is not None and call_func is not None:
                    if ret_func == call_func:
                        return cmd.ea
        return return_addr

    def get_parent_function(self, addr: int) -> int:
        """
        Get address of function containing given address.

        Args:
            addr (int): Address to find containing function for

        Returns:
            int: Start address of containing function, or addr if not in function
        """
        func = idaapi.get_func(addr)
        return func.start_ea if func else addr

    def get_event_data_key(self, event_data: Dict[str, Any], api_name: str) -> tuple:
        """
        Create hashable key for event deduplication.

        Creates tuple key from event data excluding variable elements
        like index, count, and return value.

        Args:
            event_data (Dict[str, Any]): Event data dictionary
            api_name (str): Name of API being called

        Returns:
            tuple: Hashable key for event deduplication
        """
        # Create a hashable key excluding 'index', 'count' and 'return_value'
        return (api_name, tuple(event_data["args"]), event_data["call_addr"], event_data["return_addr"])

    def get_next_index(self) -> int:
        """
        Get next global index and increment counter.

        Returns:
            int: Next available global index
        """
        index = self.current_index
        self.current_index += 1
        return index

    def format_arg_list(self, params: List[Dict[str, Any]]) -> List[str]:
        """
        Format parameters into standardized argument strings.

        Converts parameter dictionaries into consistently formatted
        strings, handling different value types appropriately.

        Args:
            params: List of parameter dictionaries with 'name' and 'value' keys

        Returns:
            List[str]: List of formatted strings like "name=value" or "argN=value"
        """
        formatted_args = []
        for i, param in enumerate(params, 1):
            name = param.get("name", "")
            value = param.get("value", "")

            # Format the value appropriately
            if isinstance(value, str):
                if "\\" in value or "/" in value or " " in value:
                    formatted_value = f'"{value}"'
                elif value.startswith("0x"):
                    formatted_value = value
                else:
                    formatted_value = f'"{value}"'
            elif isinstance(value, int):
                formatted_value = hex(value)
            elif isinstance(value, (list, tuple)):
                inner_values = [str(v) for v in value]
                formatted_value = f"({', '.join(inner_values)})"
            else:
                formatted_value = str(value)

            # Use provided name or generate argN
            arg_name = name if name else f"arg{i}"
            formatted_args.append(f"{arg_name}={formatted_value}")

        return formatted_args

    def handle_duplicates(self, trace_dict: DefaultDict[int, DefaultDict[str, List[Dict[str, Any]]]]) -> Dict[int, Dict[str, List[Dict[str, Any]]]]:
        """
        Handle duplicate API calls across all functions.

        Consolidates duplicate API calls by incrementing count rather than
        creating duplicate entries.

        Args:
            trace_dict: Raw trace dictionary with potential duplicates

        Returns:
            Dict[int, Dict[str, List[Dict[str, Any]]]]: Deduplicated trace data
                with counts updated for duplicate calls
        """
        final_dict = collections.defaultdict(lambda: collections.defaultdict(list))
        event_data_by_key = collections.defaultdict(dict)

        for func_ea, apis in trace_dict.items():
            for api_name, events in apis.items():
                for event in events:
                    event_key = self.get_event_data_key(event, api_name)

                    # Check if this event_data is already recorded
                    existing_event = event_data_by_key[func_ea].get(event_key)
                    if existing_event is None:
                        # First occurrence; add to the list and record the key
                        final_dict[func_ea][api_name].append(event)
                        event_data_by_key[func_ea][event_key] = event
                    else:
                        # Duplicate found; increment the count
                        existing_event["count"] += 1

        return dict(final_dict)

    @abstractmethod
    def parse_trace(self, known_imports: Dict[str, str], trace_path: str) -> Dict[int, Dict[str, List[Dict[str, Any]]]]:
        """
        Parse API trace and return standardized format.

        Must be implemented by subclasses to handle specific trace formats.

        Args:
            known_imports: Dictionary mapping short names to full API names
            trace_path: Path to trace file

        Returns:
            Dict[int, Dict[str, List[Dict[str, Any]]]]: Standardized trace data
        """
        pass

    @abstractmethod
    def supports_format(self, trace_path: str) -> bool:
        """
        Check if given trace file is supported by this parser.

        Must be implemented by subclasses to detect their specific format.

        Args:
            trace_path (str): Path to trace file to check

        Returns:
            bool: True if file format is supported by this parser
        """
        pass
