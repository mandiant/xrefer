import logging
import os
import re
from collections.abc import Iterator

from ..base import Address, BackEnd, BackendError, BasicBlock, Function, FunctionType, Instruction, InvalidAddressError, Operand, OperandType, Section, SectionType, String, StringEncType, Xref, XrefType

# Ghidra's Program.getExecutablePath() hands back a URI-style path. On
# Windows that is "/D:/dir/sample.bin" — a leading slash in front of the
# drive letter — which Python's open() rejects with EINVAL. It is not just
# the binary: every derived path (the .xrefer cache, _capa.json,
# _user_xrefs.txt, _trace.zip) is built from this string, so a headless
# Windows run fails at save time having done all the analysis work.
# Invisible on Linux and macOS, where a leading slash is simply correct.
_URI_DRIVE_PATH = re.compile(r"^/([A-Za-z]:[\\/])")


def _native_path(path: str) -> str:
    """Convert a Ghidra URI-style path into one the host OS accepts."""
    if _URI_DRIVE_PATH.match(path):
        return os.path.normpath(path[1:])
    return path


def configure_fast_analysis(program) -> None:
    """Disables time-consuming analyzers while keeping essential analyzers enabled.
    This should be called before running analyzeAll() on a program.

    note:
    - Decompiler analyzers: +4.29s overhead (17x slower)
    - Demanglers: +0.14s overhead
    - Stack analyzer: +0.01s overhead

    Args:
        program: Ghidra Program object
    """
    from ghidra.program.model.listing import Program as GhidraProgram

    logger = logging.getLogger(__name__)
    logger.info("Configuring optimized Ghidra analysis...")

    options = program.getOptions(GhidraProgram.ANALYSIS_PROPERTIES)

    disabled_analyzers = [
        "Decompiler Parameter ID",
        "Decompiler Switch Analysis",
    ]

    for analyzer in disabled_analyzers:
        options.setBoolean(analyzer, False)
        logger.info(f"Disabled analyzer: {analyzer}")

    essential = ["Subroutine References", "ASCII Strings", "Scalar Operand References"]
    for analyzer in essential:
        options.setBoolean(analyzer, True)
        logger.debug(f"Enabled analyzer: {analyzer}")

class GhidraFunction(Function):
    def __init__(self, ghidra_func, backend) -> None:
        """Initialize with Ghidra function object."""
        if ghidra_func is None:
            raise ValueError("Ghidra function cannot be None")
        if backend is None:
            raise ValueError("Backend cannot be None")
        self._func = ghidra_func
        self._backend = backend
        self._name: str | None = None
        self._function_type: FunctionType | None = None

    def _get_program(self):
        """Get program object from backend."""
        return self._backend._get_actual_program()

    @property
    def start(self) -> Address:
        """Get function start address."""
        try:
            return Address(self._func.getEntryPoint().getOffset())
        except Exception as e:
            raise InvalidAddressError(f"Failed to get function start address: {e}")

    @property
    def name(self) -> str:
        """Get function name."""
        if self._name is None:
            self._name = self._func.getName()
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        """Set function name."""
        if not value:
            raise ValueError("Function name cannot be empty")
        try:
            from ghidra.program.model.symbol import SourceType
            self._func.setName(value, SourceType.USER_DEFINED)
            self._name = value
        except Exception as e:
            raise BackendError(f"Failed to set function name: {e}") from e

    @property
    def type(self) -> FunctionType:
        """Get function classification."""
        if self._function_type is None:
            if self._func.isThunk():
                self._function_type = FunctionType.THUNK
            elif self._func.isExternal():
                self._function_type = FunctionType.IMPORT
            elif self._is_export():
                self._function_type = FunctionType.EXPORT
            else:
                self._function_type = FunctionType.NORMAL

        return self._function_type

    @property
    def is_thunk(self) -> bool:
        """Check if the function is a thunk."""
        return self._func.isThunk()

    def contains(self, address: Address) -> bool:
        """Check if the address is within the function."""
        program = self._get_program()
        addr_factory = program.getAddressFactory()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = addr_factory.getAddress(f"{addr_value:x}")
        return self._func.getBody().contains(ghidra_addr)

    @property
    def basic_blocks(self) -> Iterator[BasicBlock]:
        """Iterate over basic blocks in the function."""
        from ghidra.program.model.block import BasicBlockModel

        program = self._get_program()
        block_model = BasicBlockModel(program)
        blocks = block_model.getCodeBlocksContaining(self._func.getBody(), None)

        while blocks.hasNext():
            block = blocks.next()
            yield BasicBlock(Address(block.getMinAddress().getOffset()), Address(block.getMaxAddress().getOffset() + 1))

    def _is_export(self) -> bool:
        """Return True if the function is exported from the binary."""
        program = self._get_program()
        symbol_table = program.getSymbolTable()
        ghidra_addr = self._func.getEntryPoint()
        symbols = symbol_table.getSymbols(ghidra_addr)

        return any(symbol.isExternalEntryPoint() for symbol in symbols)


class GhidraString(String):
    """Ghidra string wrapper."""

    def __init__(self, address: Address, content: str, length: int, encoding: StringEncType) -> None:
        """Initialize with string data."""
        self._address = address
        self._content = content
        self._length = length
        self._encoding = encoding

    @property
    def address(self) -> Address:
        return self._address

    @property
    def content(self) -> str:
        return self._content

    @property
    def length(self) -> int:
        return self._length

    @property
    def encoding(self) -> StringEncType:
        return self._encoding


class GhidraXref(Xref):
    """Ghidra cross-reference wrapper."""

    def __init__(self, source: Address, target: Address, xref_type: XrefType) -> None:
        """Initialize with xref data."""
        self._source = source
        self._target = target
        self._type = xref_type

    @property
    def source(self) -> Address:
        return self._source

    @property
    def target(self) -> Address:
        return self._target

    @property
    def type(self) -> XrefType:
        return self._type


class GhidraSection(Section):
    """Ghidra section wrapper."""

    def __init__(self, ghidra_section) -> None:
        """Initialize with Ghidra memory block."""
        if ghidra_section is None:
            raise ValueError("Ghidra section cannot be None")
        self._section = ghidra_section

    @property
    def name(self) -> str:
        return self._section.getName()

    @property
    def start(self) -> Address:
        try:
            return Address(self._section.getStart().getOffset())
        except Exception as e:
            raise InvalidAddressError(f"Failed to get section start address: {e}")

    @property
    def end(self) -> Address:
        """
        Get section end address (exclusive).

        Ghidra's getEnd() returns the last valid address in the section (inclusive),
        so we add 1 to make it exclusive following the base class convention.
        """
        try:
            ghidra_end = self._section.getEnd().getOffset()
            return Address(ghidra_end + 1)
        except Exception as e:
            raise InvalidAddressError(f"Failed to get section end address: {e}") from e

    @property
    def type(self) -> SectionType:
        """Get section type based on section properties."""
        return self._classify_section_type()

    def _classify_section_type(self) -> SectionType:
        """Classify section type based on Ghidra memory block properties."""
        section_name = self._section.getName()

        # Check for external sections first (by name)
        if section_name.startswith("EXTERNAL"):
            return SectionType.EXTERN

        if self._section.isExecute():
            return SectionType.CODE
        elif not self._section.isInitialized() and self._section.isRead():
            return SectionType.BSS
        elif self._section.isWrite() or self._section.isRead():
            return SectionType.DATA
        else:
            return SectionType.UNKNOWN

    @property
    def is_readable(self) -> bool:
        """Check if section is readable."""
        return self._section.isRead()

    @property
    def perm(self) -> str:
        """Get section permissions as string."""
        perms = ""
        perms += "r" if self._section.isRead() else "-"
        perms += "w" if self._section.isWrite() else "-"
        perms += "x" if self._section.isExecute() else "-"
        return perms


class GhidraBackend(BackEnd):
    """Ghidra backend implementation."""

    def __init__(self, program=None) -> None:
        """Initialize Ghidra backend.

        Args:
            program: Optional Ghidra program object.
        """
        super().__init__()
        self._program = program
        self._addr_factory = None
        if program is not None:
            self._addr_factory = program.getAddressFactory()

    @property
    def program(self):
        """Get the current Ghidra program."""
        if self._program is None:
            self._ensure_program_loaded()
        return self._program

    def __getstate__(self):
        """Custom pickle state - exclude unpicklable program object."""
        state = self.__dict__.copy()
        state["_program"] = None
        state["_addr_factory"] = None
        state["_rustmain_insn_cache"] = None  # transient per-search memo; don't persist
        return state

    def __setstate__(self, state):
        """Custom unpickle state - restore without program object."""
        self.__dict__.update(state)
        # Program will need to be re-set after unpickling

    @program.setter
    def program(self, program) -> None:
        """Set the current Ghidra program."""
        if program is None:
            raise ValueError("Program cannot be None")
        self._program = program
        self._addr_factory = program.getAddressFactory()

    def _ensure_program_loaded(self):
        """Ensure program is loaded and cached."""
        if self._program is None:
            raise BackendError("No program is currently loaded in Ghidra")

    def _get_actual_program(self):
        """Get the actual program object."""
        self._ensure_program_loaded()

        if self._addr_factory is None and self._program:
            self._addr_factory = self._program.getAddressFactory()

        return self._program

    def _is_executable_address(self, ghidra_addr) -> bool:
        """Return True if address is in an executable memory block."""
        program = self._get_actual_program()
        mem = program.getMemory()
        block = mem.getBlock(ghidra_addr)
        return bool(block and block.isExecute())

    @property
    def name(self) -> str:
        """Backend name for language module lookup."""
        return "ghidra"

    @property
    def image_base(self) -> Address:
        """Get image base address where binary is loaded."""
        try:
            program = self._get_actual_program()
            return Address(program.getImageBase().getOffset())
        except Exception as e:
            raise BackendError(f"Failed to get image base: {e}")

    @property
    def size(self) -> int:
        """Get total size of the binary in bytes."""
        program = self._get_actual_program()
        memory = program.getMemory()
        file_bytes_list = memory.getAllFileBytes()

        if file_bytes_list:
            max_size = 0
            for file_bytes in file_bytes_list:
                original_size = file_bytes.getSize()
                offset = file_bytes.getFileOffset()
                max_size = max(max_size, int(original_size + offset))

            if max_size > 0:
                return max_size

    def functions(self) -> Iterator[Function]:
        """Iterate over all functions in the binary."""
        program = self._get_actual_program()
        function_manager = program.getFunctionManager()
        for func in function_manager.getFunctions(True):
            if func is None:
                continue
            # Match IDA semantics more closely: include all non-external
            # functions discovered by Ghidra (including thunks and small
            # helper stubs). External functions map to imports and are not
            # yielded as code functions in IDA either.
            if func.isExternal():
                continue
            yield GhidraFunction(func, self)

    def get_function_at(self, address: Address) -> Function | None:
        """Get function containing the specified address."""
        program = self._get_actual_program()
        # Use cached address factory for performance
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")
        function_manager = program.getFunctionManager()
        ghidra_func = function_manager.getFunctionContaining(ghidra_addr)
        if ghidra_func:
            # Normalize: ignore EXTERNAL functions only
            if ghidra_func.isExternal():
                return None
            return GhidraFunction(ghidra_func, self)
        return None

    def strings(self, min_length: int = String.MIN_LENGTH) -> Iterator[String]:
        """Iterate over all strings in the binary."""
        program = self._get_actual_program()
        listing = program.getListing()

        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext():
            data = data_iter.next()
            if not data.hasStringValue():
                continue
            value = data.getValue()
            if not (value and isinstance(value, str) and len(value) >= min_length):
                continue
            addr = Address(data.getAddress().getOffset())
            dt_name = data.getDataType().getName().lower()
            enc = StringEncType.UTF16 if ("unicode" in dt_name or "wide" in dt_name) else StringEncType.ASCII
            yield GhidraString(addr, value, len(value), enc)

        memory = program.getMemory()
        for block in memory.getBlocks():
            if not block.isInitialized() or block.isVolatile() or block.isExecute() or not block.isRead():
                continue
            yield from self._scan_block_for_strings(block, min_length)

    def _scan_block_for_strings(self, block, min_length: int) -> Iterator[String]:
        """Detect ASCII and UTF-16LE strings directly from block bytes."""
        start_off = int(block.getStart().getOffset())
        end_off = int(block.getEnd().getOffset())
        size = end_off - start_off + 1

        try:
            from ghidra.program.flatapi import FlatProgramAPI
            flat = FlatProgramAPI(self._get_actual_program())
            raw = flat.getBytes(block.getStart(), size)
            buf = bytes(raw)
        except Exception:
            # Fallback to small-chunk reads via read_bytes
            chunk = self.read_bytes(Address(start_off), size)
            if not chunk:
                return
            buf = chunk

        def is_printable(b: int) -> bool:
            return 32 <= b <= 126

        visited = set()

        # ASCII scan
        i = 0
        while i < len(buf):
            if is_printable(buf[i]):
                j = i
                while j < len(buf) and is_printable(buf[j]):
                    j += 1
                if j - i >= min_length:
                    ea = start_off + i
                    if ea not in visited:
                        s = buf[i:j].decode('ascii', errors='ignore')
                        yield GhidraString(Address(ea), s, len(s), StringEncType.ASCII)
                        visited.add(ea)
                i = j + 1
            else:
                i += 1

        # UTF-16LE scan (simple pattern: printable ASCII with null bytes)
        i = 0
        while i+1 < len(buf):
            # require little-endian wide char: printable, then 0x00
            if is_printable(buf[i]) and buf[i+1] == 0:
                j = i
                run = 0
                chars = []
                while j+1 < len(buf) and is_printable(buf[j]) and buf[j+1] == 0:
                    chars.append(chr(buf[j]))
                    run += 1
                    j += 2
                if run >= min_length:
                    ea = start_off + i
                    if ea not in visited:
                        s = ''.join(chars)
                        yield GhidraString(Address(ea), s, len(s), StringEncType.UTF16)
                        visited.add(ea)
                i = j + 2
            else:
                i += 2

    def get_name_at(self, address: Address) -> str:
        """Get symbol name at the specified address."""
        program = self._get_actual_program()
        # Use program's address factory instead of gl.resolve()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")
        symbol_table = program.getSymbolTable()
        symbol = symbol_table.getPrimarySymbol(ghidra_addr)
        return symbol.getName() if symbol else ""

    def get_address_for_name(self, name: str) -> Address | None:
        """Get address for the specified symbol name."""
        program = self._get_actual_program()
        symbol_table = program.getSymbolTable()
        symbols = symbol_table.getSymbols(name)
        if symbols and symbols.hasNext():
            symbol = symbols.next()
            return Address(symbol.getAddress().getOffset())
        return None

    def get_xrefs_to(self, address: Address) -> Iterator[Xref]:
        """Get all references TO the specified address."""
        program = self._get_actual_program()
        # Use program's reference manager
        ref_manager = program.getReferenceManager()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")

        raw_refs = ref_manager.getReferencesTo(ghidra_addr)
        for ref in raw_refs:
            xref_type = self._convert_ref_type(ref.getReferenceType())
            yield GhidraXref(Address(ref.getFromAddress().getOffset()), Address(ref.getToAddress().getOffset()), xref_type)

    def get_xrefs_from(self, address: Address, far_only: bool = False) -> Iterator[Xref]:
        """Get all references FROM the specified address.

        ``far_only`` is accepted for interface parity and ignored: Ghidra's
        reference manager does not produce ordinary fall-through refs.
        """
        program = self._get_actual_program()
        ref_manager = program.getReferenceManager()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")

        raw_refs = ref_manager.getReferencesFrom(ghidra_addr)
        memory = program.getMemory()
        stack_refs_skipped = 0
        for ref in raw_refs:
            xref_type = self._convert_ref_type(ref.getReferenceType())

            to_addr = ref.getToAddress()
            if to_addr is None:
                continue

            # Skip stack references as they use a different address space
            if to_addr.isStackAddress():
                stack_refs_skipped += 1
                continue

            # Only keep references that resolve to a valid memory block
            if not to_addr.isMemoryAddress():
                continue

            if memory.getBlock(to_addr) is None:
                continue

            from_ghidra = ref.getFromAddress()
            var_from = Address(int(from_ghidra.toString(), 16))

            var_to = Address(int(to_addr.toString(), 16))

            yield GhidraXref(var_from, var_to, xref_type)

        if stack_refs_skipped > 0:
            logger = logging.getLogger(__name__)
            logger.debug(f"Skipped {stack_refs_skipped} stack references from %s", address)

    @property
    def recover_incomplete_call_graph(self) -> bool:
        # Ghidra misses indirect / Rust trait-dispatch call edges, so opt into
        # the Rust EP / clustering repair heuristics (see base class docstring).
        return True

    def _resolve_file_offset_impl(self, file_offset: int) -> Address | None:
        """Translate a file offset to an Address within the current program."""
        program = self._get_actual_program()
        memory = program.getMemory()
        addresses = memory.locateAddressesForFileOffset(file_offset)

        for addr in addresses:
            return Address(addr.getOffset())
        return None

    def _convert_ref_type(self, ghidra_ref_type) -> XrefType:
        """Convert Ghidra reference type to XrefType."""
        import ghidra.program.model.symbol as symbol_module

        RefType = symbol_module.RefType
        if ghidra_ref_type == RefType.UNCONDITIONAL_CALL:
            return XrefType.CALL
        if ghidra_ref_type == RefType.UNCONDITIONAL_JUMP:
            return XrefType.JUMP
        if ghidra_ref_type == RefType.CONDITIONAL_JUMP:
            return XrefType.BRANCH_TRUE
        if ghidra_ref_type == RefType.PARAM:
            return XrefType.DATA_READ
        if ghidra_ref_type in (RefType.DATA, RefType.READ):
            return XrefType.DATA_READ
        if ghidra_ref_type == RefType.WRITE:
            return XrefType.DATA_WRITE
        if ghidra_ref_type == RefType.DATA_IND:
            return XrefType.DATA_OFFSET
        return XrefType.UNKNOWN

    def read_bytes(self, address: Address, size: int) -> bytes | None:
        """Read raw bytes from the specified address."""
        program = self._get_actual_program()
        # Use program's address factory instead of gl.resolve()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")
        # Guard against invalid or non-readable regions and partial reads.
        try:
            memory = program.getMemory()
            block = memory.getBlock(ghidra_addr)
            if block is None or not block.isRead():
                return None

            # Compute how many bytes remain in this block from the start address.
            remaining = int(block.getEnd().getOffset() - ghidra_addr.getOffset() + 1)
            if remaining <= 0:
                return None

            # For consistent semantics with IDA/Binary Ninja backends, only
            # return data if the full requested size is available.
            if remaining < size:
                return None

            from ghidra.program.flatapi import FlatProgramAPI
            flat_api = FlatProgramAPI(program)
            buffer = flat_api.getBytes(ghidra_addr, size)
            return bytes(buffer) if buffer is not None else None
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to read bytes from {address}: {e}")
            # Match other backends: on any memory access issue, return None
            # instead of raising, so higher-level scanners can skip gracefully.
            return None


    def instructions(self, start: Address, end: Address) -> Iterator[Address]:
        """Iterate over instruction addresses in the specified range."""
        program = self._get_actual_program()
        listing = program.getListing()
        start_value = start.value if isinstance(start, Address) else int(start)
        end_value = end.value if isinstance(end, Address) else int(end)
        start_addr = self._addr_factory.getAddress(f"{start_value:x}")
        end_addr = self._addr_factory.getAddress(f"{end_value:x}")

        inst_iter = listing.getInstructions(start_addr, True)
        while inst_iter.hasNext():
            inst = inst_iter.next()
            inst_addr = inst.getAddress()
            if inst_addr.compareTo(end_addr) >= 0:
                break
            yield Address(inst_addr.getOffset())

    def _get_sections_impl(self) -> Iterator[Section]:
        """Iterate over all memory sections."""
        program = self._get_actual_program()
        memory = program.getMemory()
        for block in memory.getBlocks():
            yield GhidraSection(block)

    def get_section_by_name(self, name: str) -> Section | None:
        """Get section by name."""
        program = self._get_actual_program()
        memory = program.getMemory()
        block = memory.getBlock(name)
        if block:
            return GhidraSection(block)
        return None

    def _get_raw_imports(self) -> Iterator[tuple[Address, str, str]]:
        """Get raw import data from backend.

        For ELF binaries, external references often appear as THUNK references
        (e.g., PLT stubs). To better match IDA/Binary Ninja behavior, we accept
        both data-like references (DATA/READ/DATA_IND) and THUNK references,
        preferring data-like when available.
        """
        program = self._get_actual_program()
        import ghidra.program.model.symbol as symbol_module

        symbol_table: symbol_module.SymbolTable = program.getSymbolTable()
        em: symbol_module.ExternalManager = program.getExternalManager()

        seen_addrs: set[int] = set()

        # Detect executable format for module normalization
        try:
            fmt = self.filetype()
            is_elf = "ELF" in fmt
        except Exception:
            is_elf = False

        for symbol in symbol_table.getExternalSymbols():
            # Resolve external location for name/library if available
            external_loc: symbol_module.ExternalLocation = em.getExternalLocation(symbol)

            function_name = ""
            library_name = ""
            if external_loc is not None:
                function_name = external_loc.getLabel() or ""
                library_name = external_loc.getLibraryName() or ""
                # Normalize EXTERNAL library placeholder to empty so we can apply ELF default
                lib_str = library_name.strip()
                if lib_str.upper().startswith("<EXTERNAL>") or lib_str.lower() == "unknown":
                    library_name = ""

            if not function_name:
                function_name = symbol.getName() or ""

            refs = symbol.getReferences()
            if not refs:
                continue

            RefType = symbol_module.RefType
            data_like: list = []
            thunk_like: list = []
            for ref in refs:
                rtype = ref.getReferenceType()
                # Prefer data-like references that point to IAT/GOT entries
                if rtype in (RefType.DATA, RefType.READ, RefType.DATA_IND):
                    data_like.append(ref)
                elif rtype == RefType.THUNK or str(rtype) == "THUNK":
                    thunk_like.append(ref)

            # Prefer data-like references (IAT/GOT) for stability; fallback to thunk/code
            chosen = data_like[0] if data_like else (thunk_like[0] if thunk_like else None)
            if not chosen:
                continue

            from_addr = chosen.getFromAddress()
            addr_int = from_addr.getOffset()

            if addr_int in seen_addrs:
                continue
            seen_addrs.add(addr_int)

            # Normalize module for ELF when missing
            module_out = library_name or ("GLIBC" if is_elf else "unknown")
            yield (Address(addr_int), function_name, module_out)

    def get_exports(self) -> Iterator[tuple[str, Address]]:
        """Get all exported symbols from the binary."""
        program = self._get_actual_program()
        symbol_table = program.getSymbolTable()

        # Iterate through all symbols and find exports
        for symbol in symbol_table.getAllSymbols(True):
            if symbol.isExternalEntryPoint():
                name = symbol.getName()
                addr = Address(symbol.getAddress().getOffset())
                yield (name, addr)

    def _add_user_xref_impl(self, source: Address, target: Address) -> None:
        """Backend-specific implementation for adding user cross-references."""
        program = self._get_actual_program()
        # Import locally to avoid module-level dependency issues
        import ghidra.program.model.symbol as symbol_module

        RefType = symbol_module.RefType
        SourceType = symbol_module.SourceType

        ref_manager = program.getReferenceManager()
        source_addr = self._addr_factory.getAddress(f"{source.value:x}")
        target_addr = self._addr_factory.getAddress(f"{target.value:x}")

        ref_manager.addMemoryReference(source_addr, target_addr, RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0)

    def _set_comment_impl(self, address: Address, comment: str) -> None:
        """Backend-specific implementation for setting comments."""
        program = self._get_actual_program()
        listing = program.getListing()
        ghidra_addr = self._addr_factory.getAddress(f"{address.value:x}")
        # Use numeric constant instead of importing the class
        EOL_COMMENT = 0
        listing.setComment(ghidra_addr, EOL_COMMENT, comment)

    def _set_function_comment_impl(self, address: Address, comment: str) -> None:
        """Backend-specific implementation for setting function comments."""
        program = self._get_actual_program()
        # Use cached address factory
        ghidra_addr = self._addr_factory.getAddress(f"{address.value:x}")
        function_manager = program.getFunctionManager()
        func = function_manager.getFunctionContaining(ghidra_addr)
        if func:
            listing = program.getListing()
            # Use numeric constant instead of importing the class
            PLATE_COMMENT = 1
            listing.setComment(func.getEntryPoint(), PLATE_COMMENT, comment)
        else:
            raise BackendError("Function not found at specified address")

    def _path_impl(self) -> str:
        """Backend-specific implementation for getting binary path."""
        try:
            program = self._get_actual_program()
            executable_path = program.getExecutablePath()
            if executable_path:
                return _native_path(executable_path)
            # Fallback to program name
            return program.getName()
        except Exception as e:
            raise BackendError(f"Failed to get binary path: {e}")

    def _binary_hash_impl(self) -> str:
        """Compute SHA256 hash of the binary file."""
        program = self._get_actual_program()
        sha256 = program.getExecutableSHA256()
        if sha256:
            return sha256
        raise BackendError("Failed to compute binary hash")

    def filetype(self) -> str:
        program = self._get_actual_program()
        format_name = program.getExecutableFormat()
        return format_name

    def _get_disassembly_impl(self, address: Address) -> Instruction:
        """Disassemble a single instruction at `address` using Ghidra APIs."""
        program = self._get_actual_program()
        listing = program.getListing()

        ea = int(address)
        gh_addr = self._addr_factory.getAddress(f"{ea:x}")

        inst = listing.getInstructionAt(gh_addr)
        if inst is None:
            raise BackendError(f"No instruction at address 0x{ea:x}")

        text = inst.toString()
        mnem = inst.getMnemonicString().lower()

        # Import Java classes for operand inspection
        from ghidra.program.model.scalar import Scalar as GScalar
        from ghidra.program.model.address import Address as GAddress
        from ghidra.program.model.lang import Register as GRegister

        operands: list[Operand] = []
        num_ops = inst.getNumOperands()
        # Pre-fetch references for value recovery (e.g., RIP-relative immediates)
        memory = program.getMemory()
        inst_refs = list(inst.getReferencesFrom())
        for i in range(num_ops):
            op_text = inst.getDefaultOperandRepresentation(i)
            objs = inst.getOpObjects(i)

            is_mem = ("[" in op_text and "]" in op_text)
            has_reg = any(isinstance(o, GRegister) for o in objs)
            has_addr = any(isinstance(o, GAddress) for o in objs)
            has_scalar = any(isinstance(o, GScalar) for o in objs)

            if is_mem:
                op_kind = OperandType.MEMORY
            elif has_reg and not (has_addr or has_scalar):
                op_kind = OperandType.REGISTER
            elif has_addr or has_scalar:
                op_kind = OperandType.IMMEDIATE
            else:
                op_kind = OperandType.OTHER

            val = None
            if op_kind == OperandType.MEMORY:
                # Only treat embedded absolute addresses as values for memory operands
                if has_addr:
                    for o in objs:
                        if isinstance(o, GAddress):
                            val = Address(int(o.toString(), 16))
                            break
            elif op_kind == OperandType.IMMEDIATE:
                if has_addr:
                    for o in objs:
                        if isinstance(o, GAddress):
                            val = Address(int(o.toString(), 16))
                            break
                elif has_scalar:
                    for o in objs:
                        if isinstance(o, GScalar):
                            # Keep only non-negative immediates as Address values
                            uv = int(o.getValue())
                            if uv is not None and uv >= 0:
                                val = Address(uv)
                            break

            # Use instruction references to recover operand target addresses
            # when operand objects do not expose a GAddress (e.g., LEA with
            # RIP-relative immediate shown as Scalar).
            if val is None and inst_refs:
                for ref in inst_refs:
                    if ref.getOperandIndex() == i:
                        to_addr = ref.getToAddress()
                        if to_addr is None:
                            continue
                        if to_addr.isStackAddress() or not to_addr.isMemoryAddress():
                            continue
                        if memory and not memory.contains(to_addr):
                            continue
                        offset = Address(int(to_addr.toString(), 16))
                        # offset = to_addr.getUnsignedOffset()
                        # if offset < 0 and hasattr(to_addr, "getUnsignedOffset"):
                        #     offset = to_addr.getUnsignedOffset()
                        if offset is None or offset < 0:
                            continue
                        try:
                            val = Address(int(offset))

                        except ValueError:
                            continue
                        break

            operands.append(Operand(type=op_kind, text=op_text, value=val))

        ins = Instruction(
            address=Address(ea),
            mnemonic=mnem,
            operands=tuple(operands),
            text=text
        )
        return ins

    # ── Rust rust_main detection (parity with IDA / Vivisect backends) ────────
    # Rust wraps user code in a CRT-emitted ``main``/``_main`` (or a PE bootstrap
    # one level below ``start``) that loads a function pointer to the user
    # ``main::main`` and then calls a Rust-runtime bootstrap. Without recovering
    # that pointer the dominator anchor in analyzer.py never fires on Ghidra, so
    # Rust binaries stay rooted at the PE entry and report "Undetermined". This
    # ports the byte-walk used by the IDA and Vivisect backends onto Ghidra's API
    # so Rust comparisons are apples-to-apples across backends.

    # Rust/glibc bootstrap routines that receive the user main as an argument.
    _BOOTSTRAP_NAMES = ('lang_start', 'libc_start_main', 'libc_start_call_main')

    # MinGW / MSVCRT helper-function fragments. Calls to these from a PE entry
    # are CRT plumbing, not the Rust bootstrap, so don't recurse into them.
    _CRT_HELPER_PATTERNS = (
        'getmainargs', 'set_app_type', 'security_init_cookie', 'initterm',
        'cexit', 'amsg_exit', 'getstartupinfo', 'setusermatherr', 'commode',
        'fmode', 'mingwthr_', 'mingw_tlscallback', 'pei386_runtime',
        'lconv_init', 'gcc_register_frame', 'gcc_deregister_frame',
    )

    def _gh_addr(self, addr_int: int):
        """Build a Ghidra Address from an int offset via the cached factory."""
        # Ensure the factory is live: it is reset to None across pickling
        # (__setstate__), and _get_actual_program() lazily restores it. Every
        # sibling accessor calls _get_actual_program() first; do the same here so
        # this helper is safe to call as the first factory access after unpickle.
        if self._addr_factory is None:
            self._get_actual_program()
        return self._addr_factory.getAddress(f"{addr_int:x}")

    def _ghidra_func_at_start(self, addr_int: int):
        """Return the raw Ghidra Function whose ENTRY POINT is exactly
        ``addr_int`` (not merely containing it), excluding externals; else None.
        """
        program = self._get_actual_program()
        fn = program.getFunctionManager().getFunctionAt(self._gh_addr(addr_int))
        if fn is None or fn.isExternal():
            return None
        return fn

    def _func_insn_addrs(self, func_ea: int) -> list[int]:
        """Sorted instruction addresses belonging to the function containing
        ``func_ea`` (ascending — ``getInstructions`` walks the body forward).

        Memoised by the containing function's entry point for the duration of one
        rust_main search: the reachability probe revisits the same functions many
        times, and re-walking the listing each time is the dominant cost.
        """
        program = self._get_actual_program()
        fn = program.getFunctionManager().getFunctionContaining(self._gh_addr(func_ea))
        if fn is None:
            return []
        key = fn.getEntryPoint().getOffset()
        cache = getattr(self, "_rustmain_insn_cache", None)
        if cache is None:
            cache = self._rustmain_insn_cache = {}
        cached = cache.get(key)
        if cached is not None:
            return cached
        listing = program.getListing()
        addrs: list[int] = []
        it = listing.getInstructions(fn.getBody(), True)
        while it.hasNext():
            addrs.append(it.next().getAddress().getOffset())
        cache[key] = addrs
        return addrs

    def _is_call_at(self, addr_int: int) -> bool:
        """True if a recognised call instruction starts at ``addr_int``."""
        program = self._get_actual_program()
        inst = program.getListing().getInstructionAt(self._gh_addr(addr_int))
        return inst is not None and inst.getFlowType().isCall()

    def _is_bootstrap_call_target(self, tgt: int) -> bool:
        """True if a call to ``tgt`` is a Rust-runtime bootstrap — by name
        (``lang_start*``, ``__libc_start_main``) directly or via a thunk, or a
        direct call to a statically-linked runtime wrapper (non-external func).
        """
        name = (self.get_name_at(Address(tgt)) or "").lower()
        if any(s in name for s in self._BOOTSTRAP_NAMES):
            return True
        fn = self._ghidra_func_at_start(tgt)
        if fn is None:
            return False
        if fn.isThunk():
            thunked = fn.getThunkedFunction(True)
            if thunked is not None:
                tn = (thunked.getName() or "").lower()
                return any(s in tn for s in self._BOOTSTRAP_NAMES)
            return False
        # A named CRT helper is plumbing, never the Rust bootstrap — reject it so
        # a ``mov reg,<ptr>; call <crt_helper>`` shape is not misread as a handoff.
        if self._is_crt_helper_name(name.lstrip("._")):
            return False
        # Statically-linked Rust runtime wrapper: a direct call to a real
        # (non-external) user function counts as a bootstrap call.
        return not fn.isExternal()

    def _has_following_bootstrap_call(self, addrs: list[int], idx: int, maxn: int) -> bool:
        """True if any of the next ``maxn`` instructions is a call whose
        resolved target is a Rust bootstrap routine.
        """
        for j in range(idx + 1, min(idx + 1 + maxn, len(addrs))):
            if not self._is_call_at(addrs[j]):
                continue
            # Accept ALL resolved targets of the call — an indirect call through
            # a pointer slot is recorded as a data/unknown ref, not CALL.
            for xr in self.get_xrefs_from(Address(addrs[j])):
                if self._is_bootstrap_call_target(int(xr.target)):
                    return True
        return False

    def _loaded_code_pointers_at(self, addr: int, body) -> list[int]:
        """Code-pointer targets *loaded* (not branched to) at ``addr`` that leave
        ``body``. Collected from BOTH Ghidra data-ref xrefs AND the instruction's
        immediate operand — the latter so detection doesn't depend on Ghidra
        having created a reference for a ``mov reg, <imm>`` (its auto-analysis is
        not consistent about that, which is exactly the resolvable case the mentor
        flagged). De-duplicated, order-preserving.
        """
        out: list[int] = []
        seen: set[int] = set()

        def add(t: int):
            if t not in seen and not body.contains(self._gh_addr(t)):
                seen.add(t)
                out.append(t)

        for xr in self.get_xrefs_from(Address(addr)):
            if xr.type in (XrefType.CALL, XrefType.JUMP):
                continue                           # data ref only, not a branch
            add(int(xr.target))
        try:
            ins = self.disassemble(Address(addr))
        except Exception:
            ins = None
        if ins is not None and not ins.mnemonic.startswith(("call", "j", "ret")):
            for op in ins.operands:
                v = getattr(op, "value", None)
                if isinstance(v, Address):
                    add(int(v))
        return out

    def _scan_wrapper_for_rust_main(self, func_ea: int) -> int | None:
        """Byte-walk the function containing ``func_ea`` for a loaded code pointer
        that leaves the wrapper and resolves to a function start (directly, or by
        following a closure JMP-thunk), followed within 8 instructions by a Rust
        bootstrap call. Returns the resolved target or None. Does not rename.
        """
        program = self._get_actual_program()
        fn = program.getFunctionManager().getFunctionContaining(self._gh_addr(func_ea))
        if fn is None:
            return None
        body = fn.getBody()
        addrs = self._func_insn_addrs(func_ea)
        for i, addr in enumerate(addrs):
            for tgt in self._loaded_code_pointers_at(addr, body):
                cand = self._ghidra_func_at_start(tgt)
                if cand is None:
                    # The loaded pointer may be a closure/JMP-thunk rather than a
                    # promoted function start (32-bit PE: `mov reg,<closure>` where
                    # the closure is a tiny `... ; jmp <main_body>` trampoline).
                    # Resolve it statically by following the unconditional jump.
                    resolved = self._follow_to_function_start(tgt)
                    if resolved is None:
                        continue                   # not a function start nor a thunk
                    tgt = resolved
                    cand = self._ghidra_func_at_start(tgt)
                    if cand is None:
                        continue
                # Reject trivial trampolines (jmp rax, etc.): rust_main has at
                # least 2 basic blocks OR a single block with an outgoing call.
                cand_bbs = list(GhidraFunction(cand, self).basic_blocks)
                if len(cand_bbs) < 2:
                    if not any(xr2.type == XrefType.CALL
                               for xr2 in self.get_xrefs_from(Address(tgt))):
                        continue
                if self._has_following_bootstrap_call(addrs, i, 8):
                    return tgt
        return None

    def _iter_user_callees(self, func_ea: int) -> Iterator[int]:
        """Yield function-start addresses directly called from ``func_ea`` that
        are plausible Rust bootstrap candidates: not external, not thunk, not a
        known CRT helper. Used to descend one level below a PE entry.
        """
        seen: set[int] = set()
        for addr in self._func_insn_addrs(func_ea):
            if not self._is_call_at(addr):
                continue
            for xr in self.get_xrefs_from(Address(addr)):
                if xr.type != XrefType.CALL:
                    continue
                tgt = int(xr.target)
                if tgt in seen:
                    continue
                cand = self._ghidra_func_at_start(tgt)
                if cand is None or cand.isThunk() or cand.isExternal():
                    continue
                nm = (self.get_name_at(Address(tgt)) or "").lstrip("._")
                if self._is_crt_helper_name(nm):
                    continue
                seen.add(tgt)
                yield tgt

    @classmethod
    def _is_crt_helper_name(cls, name: str) -> bool:
        """True for MinGW / MSVCRT helpers we don't want to recurse into.
        Conservative — a false positive only costs a wasted byte-walk.
        """
        if not name:
            return False
        stripped = name.lstrip(".").lstrip("_").split(".")[0].lower()
        # MinGW's static-init helper is ``__main`` -> strips to ``main``; the
        # real Rust bootstrap is unnamed here, so an exact ``main`` is the helper.
        if stripped == "main":
            return True
        return any(p in stripped for p in cls._CRT_HELPER_PATTERNS)

    # rust_main detection tuning.
    _MAIN_MIN_REACH = 16          # the genuine rust_main reaches >= this many funcs
    _MAIN_REACH_CAP = 64          # cap on the reachability probe (relative size only)
    _MAIN_SEARCH_MAX_DEPTH = 4    # BFS depth through the CRT chain
    _MAIN_SEARCH_MAX_FUNCS = 250  # cap on functions scanned during the deep search

    def _follow_to_function_start(self, addr_int: int, max_hops: int = 4) -> int | None:
        """Resolve a loaded code pointer to a real function start.

        If ``addr_int`` is already a function start, return it. Otherwise, if it
        begins a tiny trampoline that ends in an unconditional ``JMP``, follow
        that jump (a few hops) to a function start. Rust passes the user main as
        ``mov reg, <closure>`` where the closure is frequently a ``…; jmp
        <monomorphised body>`` thunk that Ghidra never promotes to a function —
        statically followable without any emulation. Returns the resolved start
        or None.
        """
        program = self._get_actual_program()
        listing = program.getListing()
        cur = addr_int
        for _ in range(max_hops):
            if self._ghidra_func_at_start(cur) is not None:
                return cur
            # Scan a tiny window from ``cur`` for the trampoline's terminating
            # unconditional jump/tail-call. ``getInstructions(start, True)``
            # yields the first DEFINED instruction at-or-after ``cur``, so this
            # works even when the closure entry byte itself isn't disassembled.
            window_end = self._gh_addr(cur + 0x20)
            it = listing.getInstructions(self._gh_addr(cur), True)
            landed = None
            steps = 0
            while it.hasNext() and steps < 4:
                inst = it.next()
                if inst.getAddress().compareTo(window_end) >= 0:
                    break
                ft = inst.getFlowType()
                if (ft.isJump() or ft.isCall()) and ft.isUnConditional():
                    flows = inst.getFlows()
                    if flows:
                        landed = flows[0].getOffset()
                    break
                if ft.isTerminal() or ft.isConditional():
                    break
                steps += 1
            if landed is None:
                return None
            cur = landed
        return None

    def _func_callee_starts(self, func_ea: int) -> set[int]:
        """Function-start addresses called from ``func_ea`` (resolved CALL /
        indirect edges), for the reachability probe."""
        out: set[int] = set()
        program = self._get_actual_program()
        fm = program.getFunctionManager()
        for ia in self._func_insn_addrs(func_ea):
            # Count a CALL edge, or an UNKNOWN/computed edge ONLY when it
            # originates from a call instruction (an indirect/vtable dispatch).
            # An UNKNOWN edge off a non-call instruction is a data-pointer load,
            # not a call, and counting it inflates the reach of runtime stubs.
            is_call_site = self._is_call_at(ia)
            for xr in self.get_xrefs_from(Address(ia)):
                if not (xr.type == XrefType.CALL
                        or (is_call_site and xr.type == XrefType.UNKNOWN)):
                    continue
                f = fm.getFunctionContaining(self._gh_addr(int(xr.target)))
                if f is not None and not f.isExternal():
                    out.add(f.getEntryPoint().getOffset())
        return out

    def _capped_reach(self, start: int, cap: int) -> int:
        """Functions reachable from ``start`` via call edges, capped at ``cap``
        (we only need the relative size to tell a real main from a dead-end)."""
        seen = {start}
        stack = [start]
        while stack and len(seen) < cap:
            x = stack.pop()
            for c in self._func_callee_starts(x):
                if c not in seen:
                    seen.add(c)
                    if len(seen) >= cap:
                        break
                    stack.append(c)
        return len(seen)

    def _search_main_handoffs(self, entry_ea: int) -> Iterator[int]:
        """BFS the CRT call chain from ``entry_ea`` (bounded), yielding every
        resolved rust_main handoff the byte-walk finds at any depth. Used when
        the shallow scan only lands on a dead-end stub — on 32-bit PE the real
        ``mov reg,<closure>; call lang_start`` handoff sits two+ levels below the
        entry, so a one-level recursion never reaches it."""
        from collections import deque
        visited = {entry_ea}
        q = deque([(entry_ea, 0)])
        scanned = 0
        while q and scanned < self._MAIN_SEARCH_MAX_FUNCS:
            fea, depth = q.popleft()
            scanned += 1
            hit = self._scan_wrapper_for_rust_main(fea)
            if hit is not None:
                yield hit
            if depth < self._MAIN_SEARCH_MAX_DEPTH:
                for callee in self._iter_user_callees(fea):
                    if callee not in visited:
                        visited.add(callee)
                        q.append((callee, depth + 1))

    def find_rust_main_candidate(self, main_addr: Address) -> Address | None:
        """Ghidra rust_main detection.

        Walks the CRT call chain from the entry with a single bounded BFS
        (:meth:`_search_main_handoffs`, depth ``<= _MAIN_SEARCH_MAX_DEPTH``,
        ``<= _MAIN_SEARCH_MAX_FUNCS`` functions scanned). The byte-walk at each
        level looks for the ``mov reg, <user-main ptr>; ... ; call <bootstrap>``
        shape, resolving the loaded immediate and following its closure JMP-thunk
        to the monomorphised body. Depth 0 covers the ELF/glibc shape (the
        pointer load sits in the entry itself); deeper levels cover the 32-bit PE
        shape, where the ``mov reg,<closure>; call lang_start`` handoff is a
        statically-recoverable immediate two+ levels below the entry.

        Every handoff found at any depth is a candidate; we pick the
        MOST-CONNECTED one by capped call-graph reach (:meth:`_capped_reach`).
        The genuine user main dominates the user call graph, so taking the max
        reach robustly beats dead-end runtime stubs without depending on scan
        order, and lands on the real main directly rather than leaning on the
        clustering stage's connectivity guard. A candidate must reach at least
        ``_MAIN_MIN_REACH`` functions to be accepted.

        On a hit the function is renamed ``rust_main`` so a later
        ``get_address_for_name("rust_main")`` short-circuits the scan.
        """
        main_ea = int(main_addr)
        # Per-search memo for the listing walk; reset so it can't go stale across
        # calls (e.g. a re-analysis after the program changed).
        self._rustmain_insn_cache = {}

        # Collect every rust_main handoff the byte-walk finds along the CRT chain
        # (entry at depth 0 covers the ELF/glibc shape directly; deeper levels
        # cover the 32-bit PE shape), resolving each loaded immediate and
        # following its closure JMP-thunk. Pick the MOST-CONNECTED candidate: the
        # genuine user main dominates the user call graph, so taking the max reach
        # robustly beats dead-end runtime stubs (whose reach can flicker just over
        # a fixed gate via UNKNOWN edges) without depending on scan order.
        best, best_reach = None, -1
        for cand in self._search_main_handoffs(main_ea):
            r = self._capped_reach(cand, self._MAIN_REACH_CAP)
            if r > best_reach:
                best, best_reach = cand, r
        chosen = best if (best is not None and best_reach >= self._MAIN_MIN_REACH) else None

        if chosen is None:
            return None
        fn = self._ghidra_func_at_start(chosen)
        if fn is not None:
            try:
                from ghidra.program.model.symbol import SourceType
                fn.setName("rust_main", SourceType.USER_DEFINED)
            except Exception as e:
                logging.getLogger(__name__).debug(
                    "Failed to rename rust_main candidate 0x%x: %s", chosen, e)
        return Address(chosen)
