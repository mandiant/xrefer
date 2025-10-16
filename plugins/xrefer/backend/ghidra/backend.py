import logging
from collections.abc import Iterator

from ..base import Address, BackEnd, BackendError, BasicBlock, Function, FunctionType, Instruction, InvalidAddressError, Operand, OperandType, Section, SectionType, String, StringEncType, Xref, XrefType


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
        program = self._get_program()
        addr_factory = program.getAddressFactory()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = addr_factory.getAddress(f"{addr_value:x}")
        return self._func.getBody().contains(ghidra_addr)

    @property
    def basic_blocks(self) -> Iterator[BasicBlock]:
        """Iterate over basic blocks in the function."""
        # Get basic blocks using program model
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

    def __init__(self, program=None) -> None:
        """Initialize Ghidra backend.

        Args:
            program: Optional Ghidra program object.
        """
        super().__init__()
        self._program = program
        self._addr_factory = None

        # Set up address factory if program is provided
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
        # Remove the unpicklable program reference
        state["_program"] = None
        state["_addr_factory"] = None
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

        # Set up address factory if not already done
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

        # 2) Scan readable, initialized, non-executable blocks for raw ASCII/UTF-16LE strings
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

    def get_xrefs_from(self, address: Address) -> Iterator[Xref]:
        """Get all references FROM the specified address."""
        program = self._get_actual_program()
        # Use program's reference manager
        ref_manager = program.getReferenceManager()
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
        program = self._get_actual_program()
        # Use program's address factory instead of gl.resolve()
        addr_value = address.value if isinstance(address, Address) else int(address)
        ghidra_addr = self._addr_factory.getAddress(f"{addr_value:x}")

        # # Use FlatProgramAPI for simplified byte reading
        # from ghidra.program.flatapi import FlatProgramAPI

        # flat_api = FlatProgramAPI(program)
        # buffer = flat_api.getBytes(ghidra_addr, size)
        # return bytes(buffer)
        """ v2 """
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
            fmt = (program.getExecutableFormat() or "").upper()
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

            # Collect references and classify
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
                return executable_path
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
                            val = Address(int(o.getOffset()))
                            break
            elif op_kind == OperandType.IMMEDIATE:
                if has_addr:
                    for o in objs:
                        if isinstance(o, GAddress):
                            val = Address(int(o.getOffset()))
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
                        if to_addr is not None and not to_addr.isStackAddress():
                            val = Address(int(to_addr.getOffset()))
                            break

            operands.append(Operand(type=op_kind, text=op_text, value=val))

        ins = Instruction(
            address=Address(ea),
            mnemonic=mnem,
            operands=tuple(operands),
            text=text
        )
        return ins
