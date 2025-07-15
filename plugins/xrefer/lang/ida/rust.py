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

import re
import typing
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import ida_bytes
import ida_funcs
import ida_ida
import ida_name
import ida_offset
import ida_segment
import ida_ua
import idaapi
import idautils
import idc
from tabulate import tabulate
from xrefer.core.helpers import filter_null_string, log, normalize_path
from xrefer.gui.legacy.shim import BIN_SEARCH_FORWARD, SEARCH_DOWN, find_bytes, find_code, is_32bit
from xrefer.lang.lang_base import LanguageBase
from xrefer.lang.lang_default import LangDefault

if typing.TYPE_CHECKING:
    from xrefer.core.analyzer import XRefer


@dataclass
class RustStringInfo:
    """
    Container for Rust string information.

    Attributes:
        text (str): The actual string content
        length (int): Length of the string in bytes
        xrefs (Optional[List[int]]): List of cross-reference addresses to this string
    """

    text: str
    length: int
    xrefs: Optional[List[int]] = None


class RustStringParser:
    """
    Parser for Rust string formats in binary.

    Handles parsing of various Rust string representations including those in
    .data.rel.ro, .rdata sections, and strings referenced from text section.

    Attributes:
        is_64bit (bool): Whether binary is 64-bit
        sizeof_rust_string (int): Size of Rust string structure (16 or 8 bytes)
        next_offset (int): Offset to next string field (8 or 4 bytes)
        ror_num (int): Rotation number for validation (32 or 16)
        poi (Callable): Function to read pointer-sized values
    """

    def __init__(self):
        self.is_64bit = not is_32bit()
        self.sizeof_rust_string = 16 if self.is_64bit else 8
        self.next_offset = 8 if self.is_64bit else 4
        self.ror_num = 32 if self.is_64bit else 16
        self.poi = ida_bytes.get_qword if self.is_64bit else ida_bytes.get_dword

    def get_data_rel_ro_strings(self) -> Dict[int, RustStringInfo]:
        """
        Extract Rust strings from .data.rel.ro section.

        Scans the .data.rel.ro section for Rust string patterns, validates them,
        and converts them to RustStringInfo objects.

        Returns:
            Dict[int, RustStringInfo]: Dictionary mapping addresses to RustStringInfo objects
                                     for all valid strings found in .data.rel.ro
        """
        strings = {}

        data_rel_ro = ida_segment.get_segm_by_name(".data.rel.ro")
        if not data_rel_ro:
            return strings

        rdata = ida_segment.get_segm_by_name(".rdata")
        if not rdata:
            return strings

        curr_ea = data_rel_ro.start_ea
        while curr_ea < data_rel_ro.end_ea:
            ea_candidate = self.poi(curr_ea)
            len_candidate = self.poi(curr_ea + self.next_offset)

            if self._is_valid_string(len_candidate, ea_candidate, rdata):
                try:
                    s = ida_bytes.get_bytes(ea_candidate, len_candidate).decode("utf-8")
                    s, len_s = filter_null_string(s, len_candidate)
                    if len_s == len_candidate and ea_candidate not in strings:
                        ida_offset.op_plain_offset(curr_ea, 0, 0)
                        strings[ea_candidate] = RustStringInfo(s, len_candidate)
                        curr_ea += self.sizeof_rust_string
                        continue
                except:
                    pass
            curr_ea += 1

        return strings

    def get_rdata_strings(self) -> Dict[int, RustStringInfo]:
        """
        Extract Rust strings from .rdata section.

        Similar to get_data_rel_ro_strings but processes the .rdata section.
        Uses the same validation and extraction logic for consistency.

        Returns:
            Dict[int, RustStringInfo]: Dictionary mapping addresses to RustStringInfo objects
                                    for all valid strings found in .rdata
        """
        strings = {}

        rdata = ida_segment.get_segm_by_name(".rdata")
        if not rdata:
            return strings

        curr_ea = rdata.start_ea
        while curr_ea < rdata.end_ea:
            ea_candidate = self.poi(curr_ea)
            len_candidate = self.poi(curr_ea + self.next_offset)

            if self._is_valid_string(len_candidate, ea_candidate, rdata):
                try:
                    s = ida_bytes.get_bytes(ea_candidate, len_candidate).decode("utf-8")
                    s, len_s = filter_null_string(s, len_candidate)
                    if len_s == len_candidate and ea_candidate not in strings:
                        ida_offset.op_plain_offset(curr_ea, 0, 0)
                        strings[ea_candidate] = RustStringInfo(s, len_candidate)
                        curr_ea += self.sizeof_rust_string
                        continue
                except:
                    pass
            curr_ea += 1

        return strings

    def get_text_strings(self) -> Dict[int, RustStringInfo]:
        """
        Extract Rust strings referenced from .text section.

        Analyzes code in .text section to find string references and extracts
        corresponding strings from .rdata section. More complex than other methods
        as it needs to handle various instruction patterns.

        Returns:
            Dict[int, RustStringInfo]: Dictionary mapping addresses to RustStringInfo objects
                                    for strings referenced from code
        """
        strings = {}
        text = ida_segment.get_segm_by_name(".text")
        rdata = ida_segment.get_segm_by_name(".rdata")

        if not text or not rdata:
            return strings

        for func in idautils.Functions(text.start_ea, text.end_ea):
            # Get function bounds
            start = func
            end = idc.find_func_end(start)

            # Collect all instruction addresses first
            addrs = []
            inst = start
            while inst < end:
                addrs.append(inst)
                inst = find_code(inst, SEARCH_DOWN)

            # Process instructions for string references
            for i in range(len(addrs) - 2):  # Need at least 2 more instructions
                curr_addr = addrs[i]
                mnem = idc.print_insn_mnem(curr_addr)

                # Only care about lea/mov instructions
                if mnem not in ("lea", "mov"):
                    continue

                # Skip if already matches offset
                if "off_" in idc.print_operand(curr_addr, 1):
                    continue

                ea_candidate = idc.get_operand_value(curr_addr, 1)

                # Must be in rdata segment
                if not (rdata.start_ea <= ea_candidate <= rdata.end_ea):
                    continue

                ea_xref = curr_addr

                # Handle case where string already exists
                if ea_candidate in strings:
                    self._update_existing_string(strings[ea_candidate], ea_xref)
                    continue

                # Look ahead for length in next instructions
                len_found = False
                len_candidate = 0

                for j in range(i + 1, min(i + 3, len(addrs))):  # Look at next 2 instructions max
                    if idc.print_insn_mnem(addrs[j]) == "mov":
                        if idc.get_operand_type(addrs[j], 1) == idc.o_imm:
                            len_candidate = idc.get_operand_value(addrs[j], 1)
                            len_found = True
                            break

                if not len_found or not (0 < len_candidate <= 0x200):
                    continue

                try:
                    s = ida_bytes.get_bytes(ea_candidate, len_candidate).decode("utf-8")
                    s, len_s = filter_null_string(s, len_candidate)
                    if len_s == len_candidate:
                        strings[ea_candidate] = RustStringInfo(s, len_candidate, [ea_xref])
                except:
                    continue

        return strings

    def _is_valid_string(self, length: int, addr: int, rdata: ida_segment.segment_t) -> bool:
        """
        Validate a potential Rust string candidate.

        Args:
            length (int): Length of potential string
            addr (int): Address where string content is located
            rdata (ida_segment.segment_t): .rdata section segment

        Returns:
            bool: True if string appears valid based on Rust string criteria
        """
        return (length >> self.ror_num) == 0 and 0 < length <= 0x200 and rdata.start_ea <= addr <= rdata.end_ea

    def _update_existing_string(self, string_info: RustStringInfo, xref: int) -> None:
        """
        Update cross-references for an existing string.

        Args:
            string_info (RustStringInfo): String information to update
            xref (int): New cross-reference address to add
        """


class LangRust(LanguageBase):
    """
    Rust-specific language analyzer.

    Handles detection and analysis of Rust binaries, including string extraction,
    library references, and thread handling.

    Attributes:
        strings (Optional[Dict[int, List[str]]]): Extracted strings
        ep_annotation (Optional[str]): Entry point annotation
        lib_refs (List[Any]): Library references
        crate_columns (List[List[str]]): Crate names and versions
        user_xrefs (List[Tuple[int, int]]): User-defined cross-references
    """

    def __init__(self):
        super().__init__()
        self.id = "lang_rust"
        self.strings = None
        self.ep_annotation = None
        self.lib_refs = []
        self.crate_columns = [[], []]  # [names], [versions]
        self.user_xrefs = []  # Store thread xrefs here

    def initialize(self) -> None:
        """Initialize Rust-specific data after language matching."""
        super().initialize()
        self._process_if_rust()

    def lang_match(self) -> bool:
        """Check if binary is Rust."""
        search_patterns = [
            "3A 3A 75 6E 77 72 61 70 28 29 60 20",  # ::unwrap()`
            "5C 2E 63 61 72 67 6F 5C",  # \.cargo\
            "2F 2E 63 61 72 67 6F 2F",  # /.cargo/
            "2F 63 61 72 67 6F 2F",  # /cargo/
            "74 68 72 65 61 64 20 70 61 6E 69 63",  # thread panic
        ]

        for pattern in search_patterns:
            if find_bytes(pattern, ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea(), BIN_SEARCH_FORWARD, 16) != idc.BADADDR:
                return True

        return False

    def _process_if_rust(self) -> None:
        """
        Process binary as Rust if language detection matches.

        Performs Rust-specific analysis including user cross-references,
        string processing, and entry point annotation if binary is detected as Rust.
        """
        if not self.lang_match():
            return

        log("Rust compiled binary detected")
        self.user_xrefs = self.get_user_xrefs() or []
        self._process_strings()
        self.ep_annotation = self._get_ep_annotation()

    def _process_strings(self) -> None:
        """
        Process Rust strings and library references.

        Combines strings from multiple sources (Rust string parser and IDA default strings),
        processes library references, and updates internal string storage.
        """
        # Get Rust-specific strings
        parser = RustStringParser()
        rust_strings = {}
        rust_strings.update(parser.get_data_rel_ro_strings())
        rust_strings.update(parser.get_rdata_strings())
        rust_strings.update(parser.get_text_strings())

        # Get default IDA strings
        default_lang = LangDefault(backend=self.backend)
        default_strings = default_lang.get_strings()

        # Merge both string sets
        combined_strings = {}
        combined_strings.update({ea: RustStringInfo(s[0], len(s[0])) for ea, s in default_strings.items()})
        combined_strings.update(rust_strings)

        # Process library references
        self._process_lib_refs(combined_strings)

        # Create final string dict
        self.strings = {ea: [info.text] if info.xrefs is None else [info.text, info.length, info.xrefs] for ea, info in combined_strings.items()}

    def _process_lib_refs(self, strings: Dict[int, RustStringInfo]) -> None:
        """
        Process library references from string data.

        Analyzes strings to extract and process library references,
        including version information and crate details. Particularly
        important for Rust binary analysis.

        Args:
            strings: Dictionary of string information to process

        Side Effects:
            - Updates crate_columns with crate information
            - Updates lib_refs with processed references
            - Creates new entity entries for libraries

        Note:
            Processes different reference types:
            - Git repository references
            - Crate version information
            - Local library paths
            - Source file references
        """
        if not strings:
            return

        # Define regex patterns
        lib_patterns = {
            "git": (
                r"(?:github\.com-[a-z0-9]+|crates\.io(?:-[a-z0-9]+)*)[\/\\]{1,2}"
                r"([^\/\\]+)-(\d[^\/\\]+?)[\/\\]{1,2}.*?[\/\\]{1,2}"
                r"([^\/\\]+?)[\/\\]+([^\/\\]+)\.rs"
            ),
            "git_simple": (
                r"(?:github\.com-[a-z0-9]+|crates\.io(?:-[a-z0-9]+)*)[\/\\]{1,2}"
                r"([^\/\\]+)-(\d[^\/\\]+?)[\/\\]{1,2}[^\/\\]+?[\/\\]+([^\/\\]+)\.rs"
            ),
            "lib": (r"(?:library|src)[/\\]{1,2}([^/\\]+).*?[/\\]([^/\\]+?)[/\\]+([^/\\]+)\.rs"),
            "lib_simple": (r"(?:library|src)[/\\]{1,2}([^/\\]+?)[/\\]+([^/\\]+)\.rs"),
        }

        patterns = {k: re.compile(v) for k, v in lib_patterns.items()}

        # Track addresses to remove (we can't modify dict during iteration)
        to_remove = set()

        for str_ea, string_info in strings.items():
            string_contents = string_info.text

            # Skip non-printable strings
            if not all(c.isprintable() or c.isspace() for c in string_contents):
                to_remove.add(str_ea)
                continue

            string_contents = normalize_path(string_contents)
            string_contents_lower = string_contents.lower()
            matched = False

            # Process git references
            if "github." in string_contents or "crates.io" in string_contents:
                match = patterns["git"].search(string_contents)
                if match:
                    self._handle_git_match(match, (1, 3, 4), str_ea)
                    matched = True
                else:
                    match = patterns["git_simple"].search(string_contents)
                    if match:
                        self._handle_git_match(match, (1, 3), str_ea)
                        matched = True

            # Process library references
            elif "library" in string_contents_lower or "src" in string_contents_lower:
                match = patterns["lib"].search(string_contents)
                if match:
                    self._handle_lib_match(match, (1, 2, 3), str_ea)
                    matched = True
                else:
                    match = patterns["lib_simple"].search(string_contents)
                    if match:
                        self._handle_lib_match(match, (1, 2), str_ea)
                        matched = True

            # If we matched either git or lib reference, remove the string
            if matched:
                to_remove.add(str_ea)

        # Remove processed strings
        for str_ea in to_remove:
            del strings[str_ea]

    def _handle_git_match(self, match: re.Match, group_ids: Tuple[int, ...], str_ea: int) -> None:
        """
        Handle git repository reference matches.

        Process matched git repository references to extract crate information
        and add to library references.

        Args:
            match (re.Match): Regex match object containing git reference
            group_ids (Tuple[int, ...]): Tuple of group IDs to extract from match
            str_ea (int): Address where the string was found
        """
        crate_name = match.group(1)
        version = match.group(2)

        if crate_name not in self.crate_columns[0]:
            self.crate_columns[0].append(crate_name)
            self.crate_columns[1].append(version)

        self._add_lib_ref(match, group_ids, str_ea)

    def _handle_lib_match(self, match: re.Match, group_ids: Tuple[int, ...], str_ea: int):
        """Handle library reference match."""
        crate_name = match.group(1)

        if crate_name not in self.crate_columns[0]:
            self.crate_columns[0].append(crate_name)
            self.crate_columns[1].append("n/a")

        self._add_lib_ref(match, group_ids, str_ea)

    def _add_lib_ref(self, match: re.Match, group_ids: Tuple[int, ...], str_ea: int):
        """Add library reference to lib_refs list."""
        # Get base token and details
        tokens = [match.group(i).replace("-", "").replace("_", "") for i in group_ids]
        lib_ref = f"{tokens[0]}::{tokens[1]}"
        if len(tokens) == 3:
            lib_ref = f"{lib_ref}::{tokens[2]}"

        self.lib_refs.append((str_ea, lib_ref, 1, tokens[0]))

    def _get_ep_annotation(self) -> str:
        """Generate entry point annotation with crate information."""
        if not self.crate_columns[0]:
            return ""

        headings = ["CRATE", "VERSION"]
        columns = self.crate_columns
        rows = []

        max_col_len = max(len(col) for col in columns)
        for i in range(max_col_len):
            row = [col[i] if i < len(col) else "" for col in columns]
            rows.append(row)

        annotation = f"{tabulate(rows, headers=headings, tablefmt='github')}\n\n"
        annotation = f"@ xrefer - crate listing\n\n{annotation}"
        return annotation

    def get_user_xrefs(self) -> Optional[List[Tuple[int, int]]]:
        """
        Parse Rust thread objects and refs.

        Returns:
            Optional[List[Tuple[int, int]]]: List of (call address, thread function address) pairs,
                                          or None if not a Rust binary
        """
        if not self.lang_match():
            return None

        result = []
        ptr_size = 4 if is_32bit() else 8

        # Get CreateThread import
        createthread_ea = idc.get_name_ea_simple("CreateThread")
        if createthread_ea == idc.BADADDR:
            return result

        # Find Rust's thread creation function
        xrefs = idautils.XrefsTo(createthread_ea)
        mw_createthread_xref = next(xrefs, None)
        if not mw_createthread_xref:
            return result

        # Get the function containing the CreateThread call
        mw_createthread_ea = ida_funcs.get_func(mw_createthread_xref.frm).start_ea

        # Rename Rust's thread creation function
        idaapi.set_name(mw_createthread_ea, "mw_createthread", idc.SN_NOCHECK)

        # Find all calls to Rust's thread creation function
        threadcall_xrefs = idautils.XrefsTo(mw_createthread_ea)

        for xref in threadcall_xrefs:
            # Check if reference is a call
            if xref.type == idc.fl_CN:
                ref = xref.frm
                _ref = ref

                # Search 10 instructions back for thread function pointer
                for _ in range(10):
                    thread_func = None
                    _ref = idc.prev_head(_ref)

                    if "offset" in idc.generate_disasm_line(_ref, 0):
                        # Thread object structure:
                        # [0] vtable ptr
                        # [1] state
                        # [2] name
                        # [3] thread function ptr
                        pthread_func = idc.get_operand_value(_ref, 0) + ptr_size * 3

                        # Get actual thread function pointer
                        thread_func = ida_bytes.get_qword(pthread_func) if ptr_size == 8 else ida_bytes.get_dword(pthread_func)

                        result.append((ref, thread_func))
                        break

        return result

    def get_entry_point(self) -> Optional[int]:
        """Get Rust program entry point."""
        # Only perform Rust-specific analysis if this is actually a Rust binary
        if not self.lang_match():
            return super().get_entry_point()

        # Try explicit rust_main first
        rust_main = idc.get_name_ea_simple("rust_main")
        if rust_main != idc.BADADDR:
            return rust_main
        # Try main/_main and analyze for rust_main pattern
        for main_name in ("main", "_main"):
            main_ea = idc.get_name_ea_simple(main_name)
            if main_ea != idc.BADADDR:
                rust_main = self._find_rust_main(main_ea)
                if rust_main:
                    return rust_main

        # Try finding main via __initenv analysis. just a hack for now, fix later.
        main_ea = LanguageBase.fallback_cmain_detection(self.backend)
        if main_ea:
            rust_main = self._find_rust_main(main_ea)
            if rust_main:
                return rust_main

        # Fallback to default entry point finder if everything else fails
        return super().get_entry_point()

    def _find_rust_main(self, main_ea: int) -> Optional[int]:
        """Find rust_main by analyzing main function."""
        start = idc.get_func_attr(main_ea, idc.FUNCATTR_START)
        end = idc.prev_addr(idc.get_func_attr(main_ea, idc.FUNCATTR_END))

        is_64 = not is_32bit()  # Use different variable name

        for addr in range(start, end):
            refs = idautils.XrefsFrom(addr)

            for ref in refs:
                if start <= ref.to <= end:
                    continue

                if ref.type != idc.fl_CN:  # Not a direct call
                    target_func = idaapi.get_func(ref.to)
                    if not target_func or target_func.start_ea != ref.to:
                        continue

                    # Look for call within next 8 instructions
                    call_found = self._find_call_after_ref(addr, 8, is_64)  # Use new variable name
                    if call_found:
                        idaapi.set_name(ref.to, "rust_main", idc.SN_NOCHECK)
                        return ref.to

        return None

    def _find_call_after_ref(self, start_addr: int, max_instructions: int, is_64bit: bool) -> bool:
        """Find call instruction after reference."""
        ins = ida_ua.insn_t()
        ins_ea = start_addr

        for _ in range(max_instructions):
            ins_ea = idc.next_head(ins_ea)
            idaapi.decode_insn(ins, ins_ea)

            if not ins:
                break

            if ins.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
                target = idc.get_operand_value(ins_ea, 0)
                target_flags = idc.get_func_flags(target)

                if target_flags < 0:  # Handle pointer to function
                    target = (ida_bytes.get_qword if is_64bit else ida_bytes.get_dword)(target)
                    target_flags = idc.get_func_flags(target)

                # Skip imports, library functions and thunks
                if not (target_flags & (idc.FUNC_LIB | idc.FUNC_STATIC | idc.FUNC_THUNK)):
                    return True

        return False

    def rename_functions(self, xrefer_obj: "XRefer") -> None:
        """
        Rename functions based on their references.

        Args:
            xrefer_obj: XreferenceLLM object containing global xrefs.
        """
        # de-prioritize refs that have a chance of overlapping occurrence even in non-lined methods
        depriori_list = ["std", "core", "alloc", "gimli", "object"]
        selected_ref = None
        name_index = {}
        idaapi.show_wait_box("HIDECANCEL\nRenaming...")

        for func_ea, func_ref in xrefer_obj.global_xrefs.items():
            depriori_refs = set()
            priori_refs = set()

            # only rename default function labels
            orig_func_name = idc.get_func_name(func_ea)
            if not orig_func_name.startswith("sub_"):
                log(f"Renaming skipped: {orig_func_name}")
                continue

            for xref_entity in func_ref[xrefer_obj.DIRECT_XREFS]["libs"]:
                xref = xrefer_obj.entities[xref_entity][1]
                if xref.split("::")[0] in depriori_list:
                    depriori_refs.add(xref)
                else:
                    priori_refs.add(xref)

            if len(priori_refs):
                selected_ref = self.find_common_denominator(list(priori_refs))

            else:
                selected_ref = None

            method_name_index = 0

            if selected_ref:
                if selected_ref not in name_index:
                    name_index[selected_ref] = method_name_index
                else:
                    name_index[selected_ref] += 1
                    method_name_index = name_index[selected_ref]

                orig_method_name = idc.get_func_name(func_ea)
                method_name = f"{selected_ref}_{method_name_index}"
                log(f"Renaming {orig_method_name} to {method_name}")
                idaapi.set_name(func_ea, method_name, ida_name.SN_NOWARN | ida_name.SN_AUTO)

        idaapi.hide_wait_box()

    @staticmethod
    def find_common_denominator(lib_refs: List[str]) -> Optional[str]:
        """
        Find the common denominator among library references.

        Args:
            lib_refs (List[str]): List of library references.

        Returns:
            Optional[str]: Common denominator if found, None otherwise.
        """
        if not lib_refs:
            return None

        zipped_parts = zip(*[s.split("::") for s in lib_refs])
        common_parts = [parts[0] for parts in zipped_parts if all(p == parts[0] for p in parts)]

        if not common_parts:
            return None

        return "::".join(common_parts)
