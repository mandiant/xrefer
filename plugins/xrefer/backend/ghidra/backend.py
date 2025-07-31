import logging
from collections.abc import Iterator

from ..base import Address, BackEnd, BackendError, BasicBlock, Function, FunctionType, InvalidAddressError, Section, SectionType, String, StringEncType, Xref, XrefType

# Global reference to getCurrentProgram function - will be set by use_backend.py
getCurrentProgram = None


class GhidraFunction(Function):
    def __init__(self, ghidra_func) -> None:
        """Initialize with Ghidra function object."""
        if ghidra_func is None:
            raise ValueError("Ghidra function cannot be None")
        self._func = ghidra_func
        self._name: str | None = None
        self._function_type: FunctionType | None = None

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
            self._func.setName(value, None)
            self._name = value
        except Exception as e:
            raise BackendError(f"Failed to set function name: {e}") from e

    @property
    def type(self) -> FunctionType:
        """Get function classification."""
        if self._function_type is None:
            # Check if it's a thunk
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
        # Use current program's address factory
        program = getCurrentProgram()
        addr_factory = program.getAddressFactory()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = addr_factory.getAddress(f"{addr_value:x}")
        return self._func.getBody().contains(ghidra_addr)

    @property
    def basic_blocks(self) -> Iterator[BasicBlock]:
        """Iterate over basic blocks in the function."""
        # Get basic blocks using program model
        from ghidra.program.model.block import BasicBlockModel

        program = getCurrentProgram()
        block_model = BasicBlockModel(program)
        blocks = block_model.getCodeBlocksContaining(self._func.getBody(), None)

        while blocks.hasNext():
            block = blocks.next()
            yield BasicBlock(Address(block.getMinAddress().getOffset()),
                           Address(block.getMaxAddress().getOffset() + 1))

    def _is_export(self) -> bool:
        """Return True if the function is exported from the binary."""
        program = getCurrentProgram()
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

        # Check permissions to determine section type
        if self._section.isExecute():
            return SectionType.CODE
        elif not self._section.isInitialized() and self._section.isRead():
            # Uninitialized readable section is typically BSS
            return SectionType.BSS
        elif self._section.isWrite() or self._section.isRead():
            # Writable or readable sections are data
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

    def __init__(self) -> None:
        """Initialize Ghidra backend."""
        super().__init__()
        self._program = None
        self._addr_factory = None

    def _ensure_program_loaded(self):
        """Ensure program is loaded and cached."""
        if self._program is None:
            self._program = getCurrentProgram()
            if self._program is None:
                raise BackendError("No program is currently loaded in Ghidra")
            # Cache address factory for performance
            self._addr_factory = self._program.getAddressFactory()

    @property
    def name(self) -> str:
        """Backend name for language module lookup."""
        return "ghidra"

    @property
    def image_base(self) -> Address:
        """Get image base address where binary is loaded."""
        try:
            self._ensure_program_loaded()
            return Address(self._program.getImageBase().getOffset())
        except Exception as e:
            raise BackendError(f"Failed to get image base: {e}")

    def functions(self) -> Iterator[Function]:
        """Iterate over all functions in the binary."""
        self._ensure_program_loaded()
        function_manager = self._program.getFunctionManager()
        for func in function_manager.getFunctions(True):
            if func is not None:
                yield GhidraFunction(func)

    def get_function_at(self, address: Address) -> Function | None:
        """Get function containing the specified address."""
        self._ensure_program_loaded()
        # Use cached address factory for performance
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")
        function_manager = self._program.getFunctionManager()
        ghidra_func = function_manager.getFunctionContaining(ghidra_addr)
        if ghidra_func:
            return GhidraFunction(ghidra_func)
        return None

    def strings(self, min_length: int = String.MIN_LENGTH) -> Iterator[String]:
        """Iterate over all strings in the binary."""
        self._ensure_program_loaded()
        listing = self._program.getListing()

        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext():
            data = data_iter.next()
            data_type = data.getDataType()

            # Check if it's a string type (call hasStringValue on data, not data_type)
            if data.hasStringValue():
                value = data.getValue()
                if value and isinstance(value, str) and len(value) >= min_length:
                    addr = Address(data.getAddress().getOffset())
                    # Determine encoding
                    if "unicode" in data_type.getName().lower() or "wide" in data_type.getName().lower():
                        encoding = StringEncType.UTF16
                    else:
                        encoding = StringEncType.ASCII

                    yield GhidraString(addr, value, len(value), encoding)

        # Search for additional undefined strings
        memory = self._program.getMemory()
        for block in memory.getBlocks():
            if block.isInitialized() and not block.isVolatile():
                yield from self._search_strings_in_block(block, min_length)

    def _search_strings_in_block(self, block, min_length: int) -> Iterator[String]:
        """Search for strings in a memory block."""

        start = block.getStart()
        end = block.getEnd()

        current = start
        while current.compareTo(end) < 0:
            try:
                listing = self._program.getListing()
                data = listing.getDataAt(current)
                if data and data.hasStringValue():
                    str_data = data.getValue()
                else:
                    str_data = None
                if str_data and len(str_data) >= min_length:
                    yield GhidraString(Address(current.getOffset()), str(str_data), len(str_data), StringEncType.ASCII)
                    current = current.add(len(str_data))
                else:
                    current = current.add(1)
            except Exception:
                # Skip on any error and continue scanning
                current = current.add(1)

    def get_name_at(self, address: Address) -> str:
        """Get symbol name at the specified address."""
        self._ensure_program_loaded()
        # Use program's address factory instead of gl.resolve()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")
        symbol_table = self._program.getSymbolTable()
        symbol = symbol_table.getPrimarySymbol(ghidra_addr)
        return symbol.getName() if symbol else ""

    def get_address_for_name(self, name: str) -> Address | None:
        """Get address for the specified symbol name."""
        self._ensure_program_loaded()
        symbol_table = self._program.getSymbolTable()
        symbols = symbol_table.getSymbols(name)
        if symbols and symbols.hasNext():
            symbol = symbols.next()
            return Address(symbol.getAddress().getOffset())
        return None

    def get_xrefs_to(self, address: Address) -> Iterator[Xref]:
        """Get all references TO the specified address."""
        self._ensure_program_loaded()
        # Use program's reference manager
        ref_manager = self._program.getReferenceManager()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")

        raw_refs = ref_manager.getReferencesTo(ghidra_addr)
        for ref in raw_refs:
            xref_type = self._convert_ref_type(ref.getReferenceType())
            yield GhidraXref(Address(ref.getFromAddress().getOffset()), Address(ref.getToAddress().getOffset()), xref_type)

    def get_xrefs_from(self, address: Address) -> Iterator[Xref]:
        """Get all references FROM the specified address."""
        self._ensure_program_loaded()
        # Use program's reference manager
        ref_manager = self._program.getReferenceManager()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")

        raw_refs = ref_manager.getReferencesFrom(ghidra_addr)
        stack_refs_skipped = 0
        for ref in raw_refs:
            xref_type = self._convert_ref_type(ref.getReferenceType())

            # Skip stack references as they use a different address space and can have negative offsets
            to_addr = ref.getToAddress()
            if to_addr.isStackAddress():
                stack_refs_skipped += 1
                continue

            yield GhidraXref(Address(ref.getFromAddress().getOffset()), Address(to_addr.getOffset()), xref_type)

        # Log summary instead of individual skips
        if stack_refs_skipped > 0:
            logger = logging.getLogger(__name__)
            logger.debug(f"Skipped {stack_refs_skipped} stack references from {address}")

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
        if ghidra_ref_type in (RefType.DATA, RefType.READ):
            return XrefType.DATA_READ
        if ghidra_ref_type == RefType.WRITE:
            return XrefType.DATA_WRITE
        if ghidra_ref_type == RefType.DATA_IND:
            return XrefType.DATA_OFFSET
        return XrefType.UNKNOWN

    def read_bytes(self, address: Address, size: int) -> bytes | None:
        """Read raw bytes from the specified address."""
        self._ensure_program_loaded()
        # Use program's address factory instead of gl.resolve()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")

        # Use FlatProgramAPI for simplified byte reading
        from ghidra.program.flatapi import FlatProgramAPI

        flat_api = FlatProgramAPI(self._program)
        buffer = flat_api.getBytes(ghidra_addr, size)
        return bytes(buffer)

    def instructions(self, start: Address, end: Address) -> Iterator[Address]:
        """Iterate over instruction addresses in the specified range."""
        self._ensure_program_loaded()
        listing = self._program.getListing()
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
        self._ensure_program_loaded()
        memory = self._program.getMemory()
        for block in memory.getBlocks():
            yield GhidraSection(block)

    def get_section_by_name(self, name: str) -> Section | None:
        """Get section by name."""
        self._ensure_program_loaded()
        memory = self._program.getMemory()
        block = memory.getBlock(name)
        if block:
            return GhidraSection(block)
        return None

    def _get_raw_imports(self) -> Iterator[tuple[Address, str, str]]:
        """Get raw import data from backend."""
        self._ensure_program_loaded()
        import ghidra.program.model.symbol

        symbol_table: ghidra.program.model.symbol.SymbolTable = self._program.getSymbolTable()
        em: ghidra.program.model.symbol.ExternalManager = self._program.getExternalManager()

        for symbol in symbol_table.getExternalSymbols():
            symbol: ghidra.program.model.symbol.Symbol
            # Get the external location using the external manager
            external_loc: ghidra.program.model.symbol.ExternalLocation = em.getExternalLocation(symbol)
            function_name = external_loc.getLabel() or ""
            library_name = external_loc.getLibraryName() or ""
            # Find references to this external symbol
            refs = symbol.getReferences()
            if refs:
                for ref in refs:
                    if ref.referenceType.toString() == "DATA":
                        addr = Address(ref.getFromAddress().getOffset())
                        yield (addr, function_name, library_name)

    def get_exports(self) -> Iterator[tuple[str, Address]]:
        """Get all exported symbols from the binary."""
        self._ensure_program_loaded()
        symbol_table = self._program.getSymbolTable()

        # Iterate through all symbols and find exports
        for symbol in symbol_table.getAllSymbols(True):
            if symbol.isExternalEntryPoint():
                name = symbol.getName()
                addr = Address(symbol.getAddress().getOffset())
                yield (name, addr)

    def _add_user_xref_impl(self, source: Address, target: Address) -> None:
        """Backend-specific implementation for adding user cross-references."""
        self._ensure_program_loaded()
        # Import locally to avoid module-level dependency issues
        import ghidra.program.model.symbol as symbol_module

        RefType = symbol_module.RefType
        SourceType = symbol_module.SourceType

        ref_manager = self._program.getReferenceManager()
        source_addr = self._addr_factory.getAddress(f"{source.value:x}")
        target_addr = self._addr_factory.getAddress(f"{target.value:x}")

        ref_manager.addMemoryReference(source_addr, target_addr, RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0)

    def _set_comment_impl(self, address: Address, comment: str) -> None:
        """Backend-specific implementation for setting comments."""
        self._ensure_program_loaded()
        listing = self._program.getListing()
        ghidra_addr = self._addr_factory.getAddress(f"{address.value:x}")
        # Use numeric constant instead of importing the class
        EOL_COMMENT = 0
        listing.setComment(ghidra_addr, EOL_COMMENT, comment)

    def _set_function_comment_impl(self, address: Address, comment: str) -> None:
        """Backend-specific implementation for setting function comments."""
        self._ensure_program_loaded()
        # Use cached address factory
        ghidra_addr = self._addr_factory.getAddress(f"{address.value:x}")
        function_manager = self._program.getFunctionManager()
        func = function_manager.getFunctionContaining(ghidra_addr)
        if func:
            listing = self._program.getListing()
            # Use numeric constant instead of importing the class
            PLATE_COMMENT = 1
            listing.setComment(func.getEntryPoint(), PLATE_COMMENT, comment)
        else:
            raise BackendError("Function not found at specified address")

    def _path_impl(self) -> str:
        """Backend-specific implementation for getting binary path."""
        self._ensure_program_loaded()
        try:
            executable_path = self._program.getExecutablePath()
            if executable_path:
                return executable_path
            # Fallback to program name
            return self._program.getName()
        except Exception as e:
            raise BackendError(f"Failed to get binary path: {e}")

    def _binary_hash_impl(self) -> str:
        """Compute SHA256 hash of the binary file."""
        self._ensure_program_loaded()
        sha256 = self._program.getExecutableSHA256()
        if sha256:
            return sha256
        raise BackendError("Failed to compute binary hash")
