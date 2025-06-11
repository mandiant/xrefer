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

from typing import Any, Dict, List, Optional, Type

from xrefer.gui.helpers import log
from xrefer.loaders.trace.base import BaseTraceParser
from xrefer.loaders.trace.cape_parser import CapeTraceParser
from xrefer.loaders.trace.vmray_parser import VMRayTraceParser


class TraceParserFactory:
    """
    Factory for creating appropriate trace parser instances.

    Manages registration and instantiation of parser implementations
    for different trace formats.

    Class Attributes:
        _parsers (List[Type[BaseTraceParser]]): List of available parser classes
    """

    _parsers: List[Type[BaseTraceParser]] = [VMRayTraceParser, CapeTraceParser]

    @classmethod
    def get_parser(cls, trace_path: str) -> Optional[BaseTraceParser]:
        """
        Get appropriate parser for trace file.

        Tests file against each parser's format detection until match is found.

        Args:
            trace_path (str): Path to trace file

        Returns:
            Optional[BaseTraceParser]: Instance of matching parser or None if no match
        """
        for parser_class in cls._parsers:
            parser = parser_class()
            if parser.supports_format(trace_path):
                log(f"{parser.parser_id} trace detected")
                return parser
        return None

    @classmethod
    def register_parser(cls, parser_class: Type[BaseTraceParser]) -> None:
        """
        Register a new parser type.

        Args:
            parser_class: Parser class to register
        """
        if parser_class not in cls._parsers:
            cls._parsers.append(parser_class)


def parse_api_trace(known_imports: Dict[str, str], trace_path: str) -> Dict[int, Dict[str, List[Dict[str, Any]]]]:
    """
    Main entry point for API trace parsing.

    Detects trace format and delegates to appropriate parser implementation.
    Supported formats include VMRay and Cape.

    Args:
        known_imports: Dictionary mapping short names to full API names
        trace_path: Path to trace file

    Returns:
        Dict[int, Dict[str, List[Dict[str, Any]]]]: Standardized API call data
            organized by function address and API name
    """
    parser = TraceParserFactory.get_parser(trace_path)
    if parser is None:
        log(f"No suitable parser found for {trace_path}")
        return {}
    return parser.parse_trace(known_imports, trace_path)
