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
import idautils
import idc
from xrefer.lang.lang_base import LanguageBase


class LangDefault(LanguageBase):
    """
    Default language analyzer when no specific language is detected.

    Provides basic analysis capabilities for any binary that doesn't match
    other language-specific analyzers.
    """

    def __init__(self):
        super().__init__()
        self.id = "lang_default"
        self._process_lib_refs()

    def lang_match(self) -> bool:
        """Always matches as fallback."""
        return True

    def _process_lib_refs(self) -> None:
        """
        Process and store library references for a non-Rust (default) binary.

        Iterates over all functions in the binary, checks if they are library
        functions, and if so, stores them in self.lib_refs in a raw format:

        (function_address, function_name, 1, 'uncategorized')

        Here:
         - function_address: The address of the library function in the binary.
         - function_name: The name of the library function (imported or recognized by IDA).
         - 1: The category number as per the discussed format.
         - 'lib': The fallback category to be used if LLM-based categorization is not applied.
        """
        for func_ea in idautils.Functions():
            func_flags = idc.get_func_flags(func_ea)
            if func_flags != -1 and (func_flags & idc.FUNC_LIB) != 0:
                func_name = idc.get_func_name(func_ea)
                # Store the lib ref: address, lib_name, category=1, fallback_category='lib'
                self.lib_refs.append((func_ea, func_name, 1, "uncategorized"))
