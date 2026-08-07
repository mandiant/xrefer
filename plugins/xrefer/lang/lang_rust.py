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
from tabulate import tabulate
from xrefer.backend.base import Instruction
from xrefer.backend import Address, FunctionType, OperandType, Section, XrefType
from xrefer.core.helpers import dlog, filter_null_string, log, normalize_path
from xrefer.lang.lang_base import LanguageBase
from xrefer.lang.lang_default import LangDefault

if typing.TYPE_CHECKING:
    from xrefer.core.analyzer import BackEnd, XRefer


STATIC_DATA_SECTIONS: Tuple[str, ...] = (".rdata", ".data.rel.ro", ".rodata", ".data")
ADDRESS_TOKEN_RE = re.compile(r"(?:0x)?[0-9A-Fa-f]{5,}")
PLACEHOLDER_PREFIXES = ("sub_", "fun_", "lab_", "nullsub_", "thunk_")


def operand_address(inst: Instruction, operand_index: int) -> Optional[int]:
    """Best-effort resolve operand address across backends."""

    operands = inst.operands
    if not operands or operand_index >= len(operands):
        return None

    operand = operands[operand_index]

    # Prefer explicit value if backend populated one
    if (value := operand.value) is not None:
        resolved = int(value)
        return resolved
    texts = []
    if op_text := operand.text:
        texts.append(op_text)

    if inst_text := inst.text:
        texts.append(inst_text)

    for text in texts:
        for match in ADDRESS_TOKEN_RE.finditer(text):
            token = match.group(0)
            # Skip small immediates (e.g., stack offsets)
            cleaned = token[2:] if token.lower().startswith("0x") else token
            if len(cleaned) < 5:
                continue
            try:
                return int(token, 16)
            except ValueError:
                continue
    return None


def address_in_sections(backend: "BackEnd", addr: Optional[int], section_names: Tuple[str, ...] = STATIC_DATA_SECTIONS) -> bool:
    if addr is None:
        return False
    address_obj = Address(int(addr))
    for name in section_names:
        section = backend.get_section_by_name(name)
        if section and section.contains(address_obj):
            return True
    return False


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

    def __init__(self, backend):
        self.backend: BackEnd = backend
        self.ptr_size = self._guess_ptr_size()
        self.is_64bit = self.ptr_size == 8
        self.sizeof_rust_string = 16 if self.is_64bit else 8
        self.next_offset = 8 if self.is_64bit else 4
        self.ror_num = 32 if self.is_64bit else 16

    def _get_ro_section(self):
        """Return the primary read-only data section, format-agnostically.

        Rust string literals live in the read-only data section, which is
        named ``.rdata`` on PE and ``.rodata`` on ELF/Mach-O. The original
        code hardcoded ``.rdata`` only, so the precise (ptr, len) string
        slicers silently produced nothing on ELF binaries — collapsing the
        packed Rust string blob into a single un-sliced entry and starving
        cluster candidates of their string artifacts. Trying both names keeps
        one code path working across formats.
        """
        return (self.backend.get_section_by_name(".rdata")
                or self.backend.get_section_by_name(".rodata"))

    def get_data_rel_ro_strings(self) -> Dict[int, RustStringInfo]:
        """
        Extract Rust strings from .data.rel.ro section.

        Scans the .data.rel.ro section for Rust string patterns, validates them,
        and converts them to RustStringInfo objects.

        Returns:
            Dict[int, RustStringInfo]: Dictionary mapping addresses to RustStringInfo objects
                                     for all valid strings found in .data.rel.ro
        """
        strings: Dict[int, RustStringInfo] = {}

        data_rel_ro = self.backend.get_section_by_name(".data.rel.ro")
        if not data_rel_ro:
            return strings

        rdata = self._get_ro_section()
        if not rdata:
            return strings

        curr_ea = data_rel_ro.start.value
        while curr_ea < data_rel_ro.end.value:
            ea_candidate = self._read_ptr(curr_ea)
            len_candidate = self._read_ptr(curr_ea + self.next_offset)
            if ea_candidate is None or len_candidate is None:
                curr_ea += 1
                continue

            if self._is_valid_string(len_candidate, ea_candidate, rdata):
                try:
                    raw = self.backend.read_bytes(Address(ea_candidate), len_candidate)
                    if raw:
                        s = raw.decode("utf-8", errors="strict")
                        s, len_s = filter_null_string(s, len_candidate)
                        if len_s == len_candidate and ea_candidate not in strings:
                            strings[ea_candidate] = RustStringInfo(s, len_candidate)
                            curr_ea += self.sizeof_rust_string
                            continue
                except UnicodeDecodeError:
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

        rdata = self._get_ro_section()
        if not rdata:
            return strings

        curr_ea = rdata.start.value
        while curr_ea < rdata.end.value:
            ea_candidate = self._read_ptr(curr_ea)
            len_candidate = self._read_ptr(curr_ea + self.next_offset)
            if ea_candidate is None or len_candidate is None:
                curr_ea += 1
                continue

            if self._is_valid_string(len_candidate, ea_candidate, rdata):
                try:
                    raw = self.backend.read_bytes(Address(ea_candidate), len_candidate)
                    if raw:
                        s = raw.decode("utf-8", errors="strict")
                        s, len_s = filter_null_string(s, len_candidate)
                        if len_s == len_candidate and ea_candidate not in strings:
                            strings[ea_candidate] = RustStringInfo(s, len_candidate)
                            curr_ea += self.sizeof_rust_string
                            continue
                except UnicodeDecodeError:
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
        text = self.backend.get_section_by_name(".text")
        rdata = self._get_ro_section()
        if not text or not rdata:
            return strings

        # for func in idautils.Functions(text.start_ea, text.end_ea):
        for fn in self.backend.functions():
            if not text.contains(fn.start):
                continue

            # Process instructions for string references
            for bb in fn.basic_blocks:
                for ins in self.backend.instructions(bb.start, bb.end):  # TODO: This is ugly. Fix design in backend/.
                    inst = self.backend.disassemble(ins)
                    # Only care about lea/mov instructions
                    if inst.mnemonic not in ("lea", "mov"):
                        continue
                    if not inst.operands or len(inst.operands) < 2:
                        continue

                    # Skip if already matches offset
                    # TODO: This used to check for IDA's `off_` strings. We now resolve operand
                    #       addresses directly so Binary Ninja/Ghidra paths share the same code.
                    ea_candidate = operand_address(inst, 1)
                    if ea_candidate is None:
                        continue
                    ea_candidate_addr = Address(ea_candidate)

                    operand = inst.operands[1]
                    if operand.value is not None:
                        assert Address(int(operand.value)) == ea_candidate_addr

                    # Must be in rdata segment (matches legacy behavior)
                    if not rdata.contains(ea_candidate_addr):
                        continue

                    # Handle case where string already exists
                    if ea_candidate in strings:
                        self._update_existing_string(strings[ea_candidate], ins.value)
                        continue

                    # Look ahead for length in next instructions
                    len_found = False
                    len_candidate = 0
                    curr_addr = ins.value

                    for cnt, j in enumerate(self.backend.instructions(curr_addr + 1, curr_addr + 20)):  # TODO: Look at next 20 bytes max (design issue. 2 ins -> 20 bytes heuristics. )
                        # just 2 ins
                        if cnt >= 2:
                            break
                        inst2 = self.backend.disassemble(j)
                        if inst2.mnemonic == "mov":
                            if inst2.operands and inst2.operands[1].value and inst2.operands[1].type == OperandType.IMMEDIATE:
                                len_candidate = inst2.operands[1].value
                                len_found = True
                                break

                    if not len_found or not (0 < len_candidate <= 0x200):
                        continue

                    try:
                        s = self.backend.read_bytes(ea_candidate_addr, len_candidate).decode("utf-8")
                        s, len_s = filter_null_string(s, len_candidate)
                        if len_s == len_candidate:
                            strings[ea_candidate] = RustStringInfo(s, len_candidate, [ins.value])
                    except UnicodeDecodeError:
                        continue
        return strings

    def _is_valid_string(self, length: int, addr: int, rdata: "Section") -> bool:
        """
        Validate a potential Rust string candidate.

        Args:
            length (int): Length of potential string
            addr (int): Address where string content is located
            rdata (Section): .rdata section segment

        Returns:
            bool: True if string appears valid based on Rust string criteria
        """
        return (length >> self.ror_num) == 0 and 0 < length <= 0x200 and rdata.contains(Address(addr))

    def _guess_ptr_size(self) -> int:
        # Heuristic: if any section end exceeds 32-bit, assume 64-bit
        try:
            max_end = max(sec.end.value for sec in self.backend.get_sections())
            return 8 if max_end > 0xFFFFFFFF else 4
        except Exception:
            # Safe default
            return 8

    def _read_ptr(self, ea: int) -> Optional[int]:
        raw = self.backend.read_bytes(Address(ea), self.ptr_size)
        if not raw or len(raw) != self.ptr_size:
            return None
        return int.from_bytes(raw, byteorder="little", signed=False)

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

    def __init__(self, backend=None):
        super().__init__(backend)
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
        string_markers = [
            "::unwrap()",
            ".cargo",
            "/cargo/",
            "thread panic",
        ]
        hits = 0
        for s in self.backend.strings(min_length=5):
            sc = s.content
            if any(tok in sc for tok in string_markers):
                hits += 1
                if hits >= 2:
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
        log(f"Found {len(self.user_xrefs)} Rust thread xrefs")

        # Recover trait-object (vtable) dispatch edges the backend's static
        # analysis missed. Injecting them through user_xrefs reconnects the call
        # graph so clustering converges to the decompiler's view instead of
        # over-fragmenting. Backends that can't recover them return [] (default),
        # so this is a no-op for them.
        try:
            vtable_edges = self.backend.recover_vtable_edges()
        except Exception as e:
            vtable_edges = []
            log(f"Rust vtable edge recovery skipped: {e}")
        if vtable_edges:
            self.user_xrefs.extend(vtable_edges)
            log(f"Recovered {len(vtable_edges)} Rust vtable/trait-dispatch edges")
        self._process_strings()
        log(f"Extracted {len(self.strings or {})} Rust strings")
        # self._ensure_rust_entry_alias()
        self.ep_annotation = self._get_ep_annotation()
        log("Rust analysis complete")

    def _process_strings(self) -> None:
        """
        Process Rust strings and library references.

        Combines strings from multiple sources (Rust string parser and IDA default strings),
        processes library references, and updates internal string storage.
        """
        # Get Rust-specific strings
        parser = RustStringParser(self.backend)
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

    def _ensure_rust_entry_alias(self) -> None:
        """Ensure the real Rust entry point is labeled `rust_main` when possible."""

        if not self.entry_point or self.backend.name != "ghidra":
            return

        text_section = self.backend.get_section_by_name(".text")
        if not text_section:
            return

        try:
            main_function = self.backend.get_function_at(Address(self.entry_point))
        except Exception:
            return

        if not main_function:
            return

        for bb in main_function.basic_blocks:
            for inst_addr in self.backend.instructions(bb.start, bb.end):
                inst = self.backend.disassemble(inst_addr)
                if inst.mnemonic != "lea" or len(inst.operands) < 2:
                    continue

                candidate = operand_address(inst, 1)
                if candidate is None:
                    continue

                candidate_addr = Address(candidate)
                if not text_section.contains(candidate_addr):
                    continue
                fn = self.backend.get_function_at(candidate_addr)

                if not fn:
                    continue

                placeholder_prefixes = ("fun_", "sub_", "entry", "nullsub_", "se_func")
                if fn.name.lower().startswith(placeholder_prefixes):
                    fn.name = "rust_main"
                return

    def get_user_xrefs(self) -> Optional[List[Tuple[int, int]]]:
        """
        Parse Rust thread objects and refs.

        Returns:
            Optional[List[Tuple[int, int]]]: List of (call address, thread function address) pairs,
                                          or None if not a Rust binary
        """
        if not self.lang_match():
            return None

        result: List[Tuple[int, int]] = []
        ptr_size = self._ptr_size()

        # Get CreateThread import
        createthread_addr: Optional[Address] = None
        for addr, full, module in self.backend.get_imports():
            # Normalize to "kernel32.createthread"
            if full.lower().endswith(".createthread") and module.lower() in ("kernel32", "unknown"):
                createthread_addr = addr
                break

        if not createthread_addr:
            return result
        first_ref = next(iter(self.backend.get_xrefs_to(createthread_addr)), None)
        if not first_ref: return result  # This gives us the `CreateThread` from imported ones
        first_ref = next(iter(self.backend.get_xrefs_to(first_ref.source)), None)
        if not first_ref: return result

        # Get the function containing the CreateThread call
        wrapper_func = self.backend.get_function_at(first_ref.source)
        if not wrapper_func:
            return result
        # Rename Rust's thread creation function
        wrapper_func.name = "mw_createthread"
        # Find all calls to Rust's thread creation function
        for xref in self.backend.get_xrefs_to(wrapper_func.start):
            # Check if reference is a call
            if xref.type == XrefType.CALL:
                ref = xref.source
                _ref = ref.value

                # Search 10 instructions back for thread function pointer
                caller_fn = self.backend.get_function_containing(_ref)
                if caller_fn is None:
                    continue  # ghidra(sha256:a9d6789ecb90346d5cef1818b2d9d4ecbcb2f4458d739414e77607f1ac554ab6)
                caller_bb = [bb for bb in caller_fn.basic_blocks if bb.contains(_ref)]
                assert len(caller_bb) == 1, "There are cases where #bb>=2, but ignore for now. open issue when this is the case"
                ins = list(self.backend.instructions(caller_bb[0].start, _ref))
                for prev_ea in reversed(ins[-10:]):
                    _ref = prev_ea
                    thread_func = None

                    disasm = self.backend.disassemble(_ref)
                    base_pointer = self._extract_thread_object_base(disasm)
                    if base_pointer is not None:
                        # Thread object structure:
                        # [0] vtable ptr
                        # [1] state
                        # [2] name
                        # [3] thread function ptr
                        try:
                            pthread_func_addr_int = base_pointer + ptr_size * 3
                            pthread_func_addr = Address(pthread_func_addr_int)
                        except Exception:
                            continue

                        thread_func = self._read_ptr(pthread_func_addr, ptr_size)
                        if thread_func is None:
                            continue

                        # Double-check the dereference for parity with the legacy code.
                        func_ptr = self._read_ptr(pthread_func_addr, ptr_size)
                        if func_ptr != thread_func:
                            continue

                        result.append((ref.value, thread_func))
        return result

    def _extract_thread_object_base(self, inst) -> Optional[int]:
        """
        Backend-neutral helper replacing the old IDA-only "offset" text check.

        Attempts operand 1 first (Binja/Ghidra place the address here), then
        operand 0 (IDA sometimes emits OFFSET there). Only addresses that fall
        inside read-only data sections are considered valid.
        """

        for candidate_idx in (1, 0):
            addr = operand_address(inst, candidate_idx)
            if addr is None:
                continue
            if address_in_sections(self.backend, addr):
                return addr
        return None

    def get_entry_point(self) -> Optional[int]:
        """Get Rust program entry point."""
        # Only perform Rust-specific analysis if this is actually a Rust binary
        if not self.lang_match():
            return super().get_entry_point()

        ep = self._select_entry_point()
        # Guard against a disconnected entry point. On some binaries (observed on
        # PE Rust) the CRT->main::main link is an indirect call the backend never
        # resolved, so rust_main detection lands on a function that reaches almost
        # nothing in the static call graph. Path generation then collapses and the
        # whole program degenerates into one edgeless cluster. If the chosen EP is
        # essentially dead, re-root at the dominant reachable function (the real
        # user main). Strictly gated, so well-connected EPs are returned untouched.
        #
        # Only applied for backends that actually under-connect the call graph
        # (recover_incomplete_call_graph == True: Ghidra, Vivisect). IDA / Binary
        # Ninja resolve these indirect edges statically, so their EP is never dead
        # for this reason — they inherit False and get the raw selected EP, leaving
        # their downstream results unchanged.
        if not self.backend.recover_incomplete_call_graph:
            return ep
        return self._connectivity_guarded_ep(ep)

    def _select_entry_point(self) -> Optional[int]:
        """Run the rust_main detection cascade (no connectivity guard)."""
        # Try explicit rust_main first
        rust_main = self.backend.get_address_for_name("rust_main")
        if rust_main:
            return rust_main.value

        # Try main/_main and analyze for rust_main pattern (after super() has
        # already triggered Ghidra's entry rename heuristics).
        for main_name in ("main", "_main"):
            if main_ea := self.backend.get_address_for_name(main_name):
                if candidate := self._find_rust_main(main_ea):
                    return candidate

        base_entry = super().get_entry_point()
        if base_entry:
            # Trigger Rust rename heuristics even if we keep the base entry.
            return self._find_rust_main(Address(base_entry)) or base_entry

        # Fallback: probe CRT init pattern directly if we still have nothing.
        fallback_main = LanguageBase.fallback_cmain_detection(self.backend)
        if fallback_main:
            candidate = self._find_rust_main(Address(fallback_main))
            return candidate or fallback_main

        # Last resort: nothing matched.
        return None

    # Connectivity guard: the static call graph reachable from a function.
    _GUARD_MIN_REACH = 16        # an EP reaching fewer than this is "dead"
    _GUARD_MIN_ALT = 50          # a replacement must reach at least this many
    _GUARD_TOPK = 40             # only probe the K highest out-degree functions
    _GUARD_MAJORITY = 0.5        # an EP reaching < this fraction of all funcs is
                                 # not trusted as the real root: a larger,
                                 # disconnected island may hold the true user main
                                 # (an orphaned rust_main whose indirect bootstrap
                                 # edge the backend never resolved).
    _GUARD_DOMINANCE = 4         # on a fragmented binary the real main may reach
                                 # only a minority, yet still dwarf the stuck EP.
                                 # Re-root at an island reaching >= this many times
                                 # the EP *and* >= a quarter of the program.

    def _func_callees(self, fva: int, cache: dict) -> set:
        """Callee function-starts of `fva`, memoized.

        Counts the SAME edges the path-builder uses for reachability
        (create_xref_mapping -> caller_xrefs_cache): every far cross-function
        reference, via far_only=True, not just CALL. Rust leans on tail-call
        JMPs and vtable / trait-dispatch DATA_OFFSET function pointers; a
        CALL-only filter misses those, which made the connectivity guard see
        the real user main as low-reach and decline to re-root (the residual
        052e0fa2 collapse: guard saw reach 548 < majority where the path
        builder actually reaches 1774). Aligning the metric with far_only=True
        makes the guard's reach predict the true cluster-forming reach. (Also
        cheaper: far_only skips the per-instruction fall-through flow refs.)
        """
        if fva in cache:
            return cache[fva]
        out: set = set()
        fn = self.backend.get_function_at(Address(fva))
        if fn is not None:
            for bb in fn.basic_blocks:
                for ia in self.backend.instructions(bb.start, bb.end):
                    for xr in self.backend.get_xrefs_from(ia, far_only=True):
                        cf = self.backend.get_function_at(xr.target)
                        if cf is not None and int(cf.start) != fva:
                            out.add(int(cf.start))
        cache[fva] = out
        return out

    def _reachable(self, start: int, cache: dict, cap: Optional[int] = None) -> set:
        """Functions reachable from `start` via call edges (optional early stop)."""
        seen = {int(start)}
        stack = [int(start)]
        while stack:
            x = stack.pop()
            for y in self._func_callees(x, cache):
                if y not in seen:
                    seen.add(y)
                    if cap is not None and len(seen) >= cap:
                        return seen
                    stack.append(y)
        return seen

    def _connectivity_guarded_ep(self, ep: Optional[int]) -> Optional[int]:
        if ep is None:
            return ep
        ep = int(ep)
        cache: dict = {}
        # How many functions would the EP have to reach to be unambiguously the
        # real root? A majority of the program. Counting functions is cheap
        # (no reach computation).
        total_funcs = sum(1 for _ in self.backend.functions())
        majority = max(self._GUARD_MIN_REACH, int(self._GUARD_MAJORITY * total_funcs))
        # Cheap path: stop the BFS as soon as the EP is shown to reach a
        # majority — then it is the real root and we skip the dominant-island
        # search entirely (the common, well-connected case: no overhead added).
        reached = self._reachable(ep, cache, cap=majority)
        if len(reached) >= majority:
            return ep
        # The EP reaches only a MINORITY. Two failure modes land here, both
        # wanting the same remedy: (a) a genuinely dead EP (reaches almost
        # nothing), and (b) — the bimodal Rust collapse — an EP stuck at the CRT
        # stub that reaches a moderate runtime sliver while the real user main
        # sits on a much larger DISCONNECTED island. That island's root is an
        # orphaned rust_main: the indirect Rust bootstrap call
        # (__lang_start_internal(main_ptr, ...)) was not resolved, so rust_main
        # has zero incoming edges and is unreachable from the EP — but it still
        # has high OUT-degree and reach. Find it by out-degree/reach (not by
        # reachability from the EP) and re-root there. Only runs in this
        # pathological minority case.
        try:
            ep_reach = len(reached)   # BFS finished below the cap -> full reach
            degree = []
            for fn in self.backend.functions():
                cs = self._func_callees(int(fn.start), cache)
                if cs:
                    degree.append((len(cs), int(fn.start)))
            degree.sort(reverse=True)
            best, best_reach = None, 0
            for _, f in degree[:self._GUARD_TOPK]:
                r = len(self._reachable(f, cache))
                if r > best_reach:
                    best, best_reach = f, r
            dlog(f"GUARD ep=0x{ep:x} ep_reach={ep_reach} total_funcs={total_funcs} "
                 f"majority={majority} best={('0x%x' % best) if best else None} "
                 f"best_reach={best_reach} top_outdeg={[(d, hex(a)) for d, a in degree[:5]]}")
            # Re-root only at a clearly dominant island: it must reach a program
            # MAJORITY (robust signal that it is the true root), or dwarf the EP
            # by 10x (the original strict rule, for genuinely-dead EPs). Where no
            # function dominates (a genuinely fragmented binary), neither holds
            # and the EP is kept untouched.
            if (best is not None and best != ep
                    and best_reach >= self._GUARD_MIN_ALT
                    and (best_reach >= majority
                         or best_reach >= 10 * max(1, ep_reach)
                         or (best_reach >= self._GUARD_DOMINANCE * max(1, ep_reach)
                             and best_reach >= total_funcs // 4))):
                log(f"Rust EP connectivity guard: EP 0x{ep:x} reaches only {ep_reach} "
                    f"function(s) of {total_funcs}; re-rooting at dominant function "
                    f"0x{best:x} (reaches {best_reach}).")
                return best
        except Exception as e:
            log(f"Rust EP connectivity guard skipped: {e}")
        return ep

    def _find_rust_main(self, main_addr: Address) -> Optional[int]:
        """Delegate rust_main detection to the active backend.

        The detection heuristic (which call patterns indicate the user's
        rust_main inside a CRT main wrapper) is backend-specific — it depends
        on instruction-level navigation primitives that don't generalise
        cleanly. Each backend provides its own implementation; the IDA
        backend ports main-branch's byte-walk algorithm verbatim. Backends
        that don't implement the heuristic inherit a default that returns
        None, so this method falls through to the base EP.
        """
        candidate = self.backend.find_rust_main_candidate(main_addr)
        return candidate.value if candidate else None

    # def _define_function_if_absent(self, addr: int) -> None:
    #     """Ensure a function exists at `addr` when backends defer closure emission.
    #     HACK: Ghidra is the only backend as of now that requires this (i.e. )
    #     """

    #     if self.backend.name != "ghidra":
    #         return

    #     program = self.backend._get_actual_program()  # type: ignore[attr-defined]
    #     addr_factory = program.getAddressFactory()
    #     gh_addr = addr_factory.getAddress(f"{addr:x}")
    #     from ghidra.program.flatapi import FlatProgramAPI

    #     flat_api = FlatProgramAPI(program)
    #     existing = program.getFunctionManager().getFunctionAt(gh_addr)
    #     if existing is None:
    #         flat_api.createFunction(gh_addr, f"FUN_{addr:x}")

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
        for func_ea, func_ref in xrefer_obj.global_xrefs.items():
            depriori_refs = set()
            priori_refs = set()
            fn = self.backend.get_function_at(Address(func_ea))
            if not fn:
                continue

            # # only rename default function labels
            if not any(
                fn.name.startswith(x) for x in ("sub_", "FUN_")
            ):  # TODO: limit the logic depending on the backend. In practice, no one manually names a function like FUN_addr, so just ignore for now.
                # TODO: expose property in backend/ to detect if auto-named
                log(f"Renaming skipped: {fn.name}")
            if fn.type in (FunctionType.IMPORT, FunctionType.LIBRARY, FunctionType.THUNK, FunctionType.EXPORT, FunctionType.EXTERN):
                log(f"Renaming skipped (type): {fn.name}")
                continue

            for xref_entity in func_ref[xrefer_obj.DIRECT_XREFS]["libs"]:
                xref = xrefer_obj.entities[xref_entity][1]
                if xref.split("::")[0] in depriori_list:
                    depriori_refs.add(xref)
                else:
                    priori_refs.add(xref)

            selected_ref = self.find_common_denominator(list(priori_refs)) if len(priori_refs) else None
            if not selected_ref:
                continue

            idx = name_index.get(selected_ref, 0)
            name_index[selected_ref] = idx + 1
            method_name = f"{selected_ref}_{name_index[selected_ref]}"
            log(f"Renaming {fn.name} to {method_name}")
            fn.name = method_name

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

    def _ptr_size(self) -> int:
        # Mirrors RustStringParser._guess_ptr_size: an unguarded max() raises
        # ValueError on a binary whose backend reports no sections, and this
        # runs inside _process_if_rust, so it would abort ALL Rust analysis
        # rather than just the pointer-size probe.
        try:
            max_end = max(sec.end.value for sec in self.backend.get_sections())
            return 8 if max_end > 0xFFFFFFFF else 4
        except Exception:
            # Safe default (64-bit), same fallback as the sibling helper.
            return 8

    def _read_ptr(self, addr: Address, size: int) -> Optional[int]:
        raw = self.backend.read_bytes(addr, size)
        if not raw or len(raw) != size:
            return None
        return int.from_bytes(raw, "little")
