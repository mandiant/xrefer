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

import collections
import json
import re
from typing import Any, Dict, List, Optional

from xrefer.core.helpers import log
from xrefer.loaders.trace import BaseTraceParser


class CapeTraceParser(BaseTraceParser):
    """
    Parser for Cape sandbox API traces.

    Handles parsing and processing of API traces from Cape sandbox JSON format,
    including process identification and address translation.

    Attributes:
        parser_id (str): Identifier for this parser type ('Cape')
    """

    def __init__(self, backend=None):
        super().__init__(backend)
        self.parser_id = "Cape"

    def supports_format(self, trace_path: str) -> bool:
        """
        Check if file is a valid Cape sandbox trace.

        Verifies JSON structure matches Cape sandbox format.

        Args:
            trace_path (str): Path to trace file to check

        Returns:
            bool: True if file is valid Cape trace
        """
        try:
            with open(trace_path, "r") as f:
                data = json.load(f)
                return isinstance(data, dict) and "behavior" in data and "processes" in data["behavior"] and isinstance(data["behavior"]["processes"], (list, dict))
        except Exception:
            return False

    def _get_image_base(self, debug_log: str, process_data: dict) -> Optional[int]:
        """
        Extract base address from debug log or process environment.

        Attempts to parse a line like:
            "DumpProcess: Instantiating PeParser with address: 0x1234abcd"
        from the debug log. If that fails, falls back to checking
        the 'DllBase' or 'MainExeBase' fields in process_data['environ'].

        Args:
            debug_log (str): A string containing debug log output from the trace file.
            process_data (dict): Process-related dictionary from the Cape sandbox trace,
                                which may contain environment details.

        Returns:
            Optional[int]: The base address if found, or None otherwise.
        """
        pattern = r"DumpProcess: Instantiating PeParser with address: (0x[0-9a-fA-F]+)"

        # 1. Attempt to find the base address in debug_log lines
        if "DumpProcess: Instantiating PeParser with address:" in debug_log:
            match = re.search(pattern, debug_log)
            if match:
                try:
                    return int(match.group(1), 16)
                except ValueError:
                    pass  # If malformed, fall through to environment fallback

        # 2. Fallback to environment-based fields: DllBase or MainExeBase
        env_data = process_data.get("environ", {})
        base_str = env_data.get("DllBase", "") or env_data.get("MainExeBase", "")
        if base_str:
            try:
                return int(base_str, 16)
            except ValueError:
                pass

        # 3. If all attempts fail, return None
        return None

    def _format_arg_value(self, arg: Dict[str, Any]) -> str:
        """
        Format argument value for display.

        Handles different value types and includes pretty value if available.

        Args:
            arg (Dict[str, Any]): Argument dictionary with value and metadata

        Returns:
            str: Formatted string representation of value
        """
        name = arg.get("name", "")
        value = arg.get("value", "")
        pretty_value = arg.get("pretty_value", "")

        if isinstance(value, str):
            if "\\" in str(value) or "/" in str(value):
                return f'"{value}"'
            elif str(value).startswith("0x"):
                return value
            elif pretty_value:
                return f"{value} ({pretty_value})"
            return f'"{value}"'
        elif isinstance(value, int):
            return hex(value)
        return str(value)

    def _format_api_call(self, api_call: Dict[str, Any]) -> str:
        """
        Format complete API call for display.

        Creates colored string representation including arguments and return value.

        Args:
            api_call (Dict[str, Any]): API call information dictionary

        Returns:
            str: Formatted API call string with color codes
        """
        args = []
        for arg in api_call.get("arguments", []):
            arg_name = arg.get("name", "")
            arg_value = self._format_arg_value(arg)
            if arg_name:
                args.append(f"{arg_name}={arg_value}")
            else:
                args.append(arg_value)

        args_str = f"({', '.join(args)})"
        # TODO(rand0m): This is formatting. Should be in gui/. Refactoring the entire code is needed. No time for this now.  There was a colorize_api_call function in the original code.

        ret_val = api_call.get("return", "0x0")
        if isinstance(ret_val, str) and ret_val.startswith("0x"):
            try:
                ret_val = hex(int(ret_val, 16))
            except ValueError:
                pass
        ret_str = str(ret_val)

        return f"{args_str} = {ret_str}"

    def parse_trace(self, known_imports: Dict[str, str], trace_path: str) -> Dict[int, Dict[str, List[Dict[str, Any]]]]:
        """
        Parse Cape sandbox trace file into standardized format.

        Processes complete trace file including process identification,
        SHA256 verification, image base synchronization, and API call extraction.

        Args:
            known_imports: Dictionary mapping short names to full API names
            trace_path: Path to Cape trace file

        Returns:
            Dict[int, Dict[str, List[Dict[str, Any]]]]: Structured API call data:
                - Top level key: Function address
                - Second level key: API name
                - Value: List of API call information dictionaries containing:
                    * index: Global sequence number
                    * args: List of formatted argument strings
                    * call_addr: Call instruction address
                    * return_addr: Return address
                    * return_value: Call return value
                    * count: Number of identical calls
                    * call_str: Formatted call string with colors

        Note: This function performs several validation steps:
            1. Verifies trace file SHA256 matches IDB
            2. Extracts and verifies image base address
            3. Adjusts addresses if image base differs
            4. Standardizes API names using known imports
        """
        trace_dict = collections.defaultdict(lambda: collections.defaultdict(list))

        try:
            with open(trace_path, "r") as f:
                data = json.load(f)

            # Get process data
            processes = data["behavior"]["processes"]
            if isinstance(processes, dict):
                process_data = processes.get("0", {})
            else:
                process_data = processes[0] if processes else {}

            # Get target hash and verify
            trace_sha256 = data.get("target", {}).get("file", {}).get("sha256")
            if trace_sha256 != self.sample_sha256:
                log("Trace file SHA256 does not match IDB")
                return {}

            # Attempt to determine the trace base address
            debug_log = data.get("debug", {}).get("log", "")
            trace_base = self._get_image_base(debug_log, process_data)
            if trace_base is None:
                log("Could not determine trace image base.")
                return {}

            # Process API calls
            api_calls = process_data.get("calls", [])
            for call in api_calls:
                api_name = call.get("api", "")
                caller = int(call.get("caller", "0x0"), 16)

                return_addr = caller
                call_addr = self.get_call_address(return_addr)

                # Adjust addresses if needed
                if trace_base != self.image_base:
                    delta = self.image_base - trace_base
                    call_addr += delta
                    return_addr += delta

                # Get function containing this call
                func_ea = self.get_parent_function(call_addr)

                # Format call string
                call_str = self._format_api_call(call)

                # Standardize API name
                full_name = self.get_standard_api_name(api_name, known_imports)

                params = []
                for arg in call.get("arguments", []):
                    params.append({"name": arg.get("name", ""), "value": arg.get("value", "")})

                formatted_args = self.format_arg_list(params)

                trace_dict[func_ea][full_name].append(
                    {
                        "index": self.get_next_index(),
                        "args": formatted_args,
                        "call_addr": call_addr,
                        "return_addr": return_addr,
                        "return_value": call.get("return", "0x0"),
                        "count": 1,
                        "call_str": call_str,
                    }
                )

        except Exception as e:
            log(f"Error parsing Cape sandbox trace: {str(e)}")
            return {}

        # Handle duplicates
        return self.handle_duplicates(trace_dict)
