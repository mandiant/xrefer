"""
base classes for backend abstraction.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Tuple


class BackendError(Exception):
    """Base exception for backend operations."""

    ...


class InvalidAddressError(BackendError):
    """Raised when an invalid address is accessed."""

    ...


class UnsupportedOperationError(BackendError):
    """Raised when an operation is not supported by the backend."""

    ...


class FunctionType(Enum):
    """Function classification types."""

    NORMAL = auto()
    THUNK = auto()
    LIBRARY = auto()
    EXTERN = auto()
    IMPORT = auto()
    EXPORT = auto()


class XrefType(Enum):
    """Cross-reference types for different kinds of references."""

    CALL = auto()
    JUMP = auto()
    BRANCH_TRUE = auto()
    BRANCH_FALSE = auto()
    DATA_READ = auto()
    DATA_WRITE = auto()
    DATA_OFFSET = auto()
    STRING_REF = auto()
    UNKNOWN = auto()


class StringEncType(Enum):
    """String encoding types for unified string handling."""

    ASCII = "ascii"
    UTF8 = "utf-8"
    UTF16 = "utf-16"
    UTF32 = "utf-32"


class SectionType(Enum):
    """Segment types for memory classification and analysis."""

    CODE = auto()  # Executable code segments
    DATA = auto()  # Initialized data segments
    BSS = auto()  # Uninitialized data segments
    EXTERN = auto()  # External/import segments
    UNKNOWN = auto()  # Unclassified segments


class Address(int):
    """
    Type-safe address wrapper with validation.

    Provides a strongly-typed address that prevents common errors
    and offers helpful debugging representations.
    """

    def __new__(cls, value: int):
        if value < 0:
            raise ValueError(f"Invalid address: {value}")
        return super().__new__(cls, value)

    def __repr__(self):
        return f"0x{self:x}"

    def __hash__(self):
        return int.__hash__(self)

    @property
    def value(self) -> int:
        """Return the raw integer value of the address."""
        return int(self)

    @classmethod
    def invalid(cls) -> "Address":
        """Return invalid address sentinel."""
        return cls(0xFFFFFFFFFFFFFFFF)

    def is_valid(self) -> bool:
        """Check if this address is valid (not the sentinel value)."""
        return self != self.invalid()


class OperandType(Enum):
    """Canonical operand categories across backends."""
    IMMEDIATE = auto()
    REGISTER  = auto()
    MEMORY    = auto()
    RELATIVE  = auto()   # branch/call rel targets
    OTHER     = auto()

@dataclass(frozen=True)
class MemoryOperand:
    """Structured memory operand (best-effort, tolerant across tools)."""
    base: Optional[str] = None
    index: Optional[str] = None
    scale: Optional[int] = None
    disp: Optional[int] = None
    seg: Optional[str] = None
    addr_size: Optional[int] = None  # in bits if known

@dataclass(frozen=True)
class Operand:
    """Unified operand."""
    type: OperandType
    text: str
    value: Optional[Address]=None
    # reg: Optional[str] = None
    # imm: Optional[int] = None
    # mem: Optional[MemoryOperand] = None

@dataclass
class Instruction:
    address: Address
    # prefixes: Tuple[str, ...]      # e.g., ("lock",) or (). TODO: forget for now
    mnemonic: str                  # canonical, lowercased, NO prefixes
    operands: Tuple[Operand, ...]
    text: str                      # full display text as shown in tool




@dataclass
class BasicBlock:
    """
    Basic block representation with address range.

    Represents a contiguous block of instructions with single entry
    and exit points.
    """

    start: Address
    end: Address

    def contains(self, address: Address) -> bool:
        """Check if address is within the block."""
        return self.start <= address < self.end

    def __contains__(self, address: Address) -> bool:
        """Support 'address in block' syntax."""
        return self.contains(address)

    def __repr__(self):
        return f"BasicBlock(start={self.start}, end={self.end})"


class Function(ABC):
    """
    Abstract function representation.

    Provides a unified interface for function analysis across different
    disassemblers. Implementations should handle backend-specific details.
    """

    def __repr__(self) -> str:
        """Return a helpful string representation for debugging."""
        try:
            nbb = len(list(self.basic_blocks))
        except Exception:
            nbb = 0
        return f"Function(name={self.name!r}, start={self.start!r}, basic_blocks={nbb})"

    def __contains__(self, address: Address) -> bool:
        """Support 'address in function' syntax."""
        return self.contains(address)

    @property
    @abstractmethod
    def start(self) -> Address:
        """Start address of function."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Function name (may be auto-generated)."""

    @name.setter
    @abstractmethod
    def name(self, value: str) -> None:
        """Set the function name."""

    @property
    @abstractmethod
    def type(self) -> FunctionType:
        """Function classification (normal, import, export, etc.)."""

    @property
    @abstractmethod
    def is_thunk(self) -> bool:
        """Check if function is a thunk (jump stub)."""

    @property
    @abstractmethod
    def basic_blocks(self) -> Iterator[BasicBlock]:
        """Iterate over basic blocks in the function."""
        ...

    @abstractmethod
    def contains(self, address: Address) -> bool:
        """Check if address is within function boundaries."""


class String(ABC):
    """
    Abstract string representation.
    """

    MIN_LENGTH = 5  # Minimum length for a string to be considered

    def __len__(self) -> int:
        """Get string length."""
        return self.length

    def __str__(self) -> str:
        """Get string content."""
        return self.content

    def __repr__(self) -> str:
        """String representation for debugging."""
        content_preview = self.content[:50] + "..." if len(self.content) > 50 else self.content
        return f"String(address={self.address}, content={content_preview!r})"

    def __hash__(self) -> int:
        """Hash based on address and content."""
        return hash((self.address, self.content))

    @property
    @abstractmethod
    def address(self) -> Address:
        """Address where string is located."""

    @property
    @abstractmethod
    def content(self) -> str:
        """Decoded string content."""

    @property
    @abstractmethod
    def length(self) -> int:
        """String length in bytes."""

    @property
    @abstractmethod
    def encoding(self) -> StringEncType:
        """String encoding type."""


class Xref(ABC):
    """
    Abstract cross-reference representation.
    """

    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"Xref(source={self.source}, target={self.target}, type={self.type.name})"

    @property
    @abstractmethod
    def source(self) -> Address:
        """Source address of the reference."""

    @property
    @abstractmethod
    def target(self) -> Address:
        """Target address of the reference."""

    @property
    @abstractmethod
    def type(self) -> XrefType:
        """Type of reference (call, jump, data access, etc.)."""


class Section(ABC):
    """
    Abstract memory segment representation.
    """

    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"Segment(name={self.name!r}, start={self.start}, end={self.end})"

    def contains(self, address: Address) -> bool:
        """Check if address is within segment boundaries."""
        return self.start <= address < self.end

    def __contains__(self, address: Address) -> bool:
        """Support 'address in segment' syntax."""
        return self.contains(address)

    @property
    @abstractmethod
    def name(self) -> str:
        """Segment name (e.g., '.text', '.data')."""

    @property
    @abstractmethod
    def start(self) -> Address:
        """Start address of the segment (inclusive)."""

    @property
    @abstractmethod
    def end(self) -> Address:
        """
        End address of the segment (exclusive).

        The end address is the first address NOT included in the segment.
        This follows Python's range convention where [start, end) defines
        the segment boundaries.
        """
        ...

    @property
    def size(self) -> int:
        """
        Size of the segment in bytes.
        """
        return self.end.value - self.start.value

    @property
    @abstractmethod
    def is_readable(self) -> bool:
        """Check if segment is readable."""

    @property
    @abstractmethod
    def type(self) -> SectionType:
        """Get segment type."""

    @property
    @abstractmethod
    def perm(self) -> str:
        """Get segment permissions as string (e.g., 'rwx', 'r--', etc.)."""


#
# Main Backend Interface
#


class BackEnd(ABC):
    """
    Abstract interface for binary analysis operations.

    The backend handles:
    - Function enumeration and analysis
    - String extraction and decoding
    - Cross-reference analysis
    - Symbol resolution
    - Memory access
    - User annotations
    """

    def __init__(self):
        """Initialize backend with caching support."""
        self._path_cache: Optional[str] = None
        self._hash_cache: Optional[str] = None

    def __repr__(self) -> str:
        """String representation for debugging."""
        path = self.path
        image_base = self.image_base
        return f"{self.name}(path={path!r}, image_base={image_base})"

    #
    # Properties
    #
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of the backend (e.g., 'IDA Pro', 'Binary Ninja')."""
        ...

    @property
    def path(self) -> str:
        """Get binary file path (cached for performance)."""
        if self._path_cache is None:
            self._path_cache = self._path_impl()
        return self._path_cache

    @property
    @abstractmethod
    def image_base(self) -> Address:
        """Get image base address where binary is loaded."""

    @property
    @abstractmethod
    def size(self) -> int:
        """Get total size of the binary in bytes."""
        ...

    @property
    def binary_hash(self) -> str:
        """
        Get SHA256 hash of the binary file (cached).

        Returns:
            Hexadecimal SHA256 hash string

        Raises:
            BackendError: If binary file cannot be read
        """
        if self._hash_cache is None:
            self._hash_cache = self._binary_hash_impl()
        return self._hash_cache

    @abstractmethod
    def _binary_hash_impl(self) -> str:
        """Backend-specific implementation to compute binary hash.
        This should return the hash without
        """
        raise NotImplementedError("Backend must implement _binary_hash_impl() to provide binary hash.")

    def is_valid_address(self, address: Address) -> bool:
        """
        Check if address is valid within any segment.

        Args:
            address: Address to validate

        Returns:
            True if address is within a valid segment
        """
        try:
            return any(seg.contains(address) for seg in self.get_sections())
        except Exception:
            return False

    # Function Analysis

    @abstractmethod
    def functions(self) -> Iterator[Function]:
        """
        Iterate over all functions in the binary.

        Yields:
            Function objects for each identified function
        """

    @abstractmethod
    def get_function_at(self, address: Address) -> Optional[Function]:
        """
        Get function containing the specified address.

        Args:
            address: Address to search for

        Returns:
            Function containing the address, or None if not found
        """
        ...

    def get_function_containing(self, address: Address) -> Optional[Function]:
        """Alias for get_function_at for backwards compatibility."""
        return self.get_function_at(address)

    @abstractmethod
    def strings(self, min_length: int = String.MIN_LENGTH) -> Iterator[String]:
        """
        Iterate over all strings in the binary.

        Args:
            min_length: Minimum string length to consider

        Yields:
            String objects for each identified string
        """
        ...

    @abstractmethod
    def get_name_at(self, address: Address) -> str:
        """
        Get symbol name at the specified address.

        Args:
            address: Address to query

        Returns:
            Symbol name, or empty string if none exists
        """
        ...

    @abstractmethod
    def get_address_for_name(self, name: str) -> Optional[Address]:
        """
        Get address for the specified symbol name.

        Args:
            name: Symbol name to look up

        Returns:
            Address of the symbol, or None if not found
        """
        ...

    # Cross-Reference Analysis

    @abstractmethod
    def get_xrefs_to(self, address: Address) -> Iterator[Xref]:
        """
        Get all references TO the specified address.

        Args:
            address: Target address

        Yields:
            Cross-references pointing to the address
        """
        ...

    @abstractmethod
    def get_xrefs_from(self, address: Address) -> Iterator[Xref]:
        """
        Get all references FROM the specified address.

        Args:
            address: Source address

        Yields:
            Cross-references originating from the address
        """
        ...

    # Memory Access

    @abstractmethod
    def read_bytes(self, address: Address, size: int) -> Optional[bytes]:
        """
        Read raw bytes from the specified address.

        Args:
            address: Starting address
            size: Number of bytes to read

        Returns:
            Byte data, or None if unable to read
        """
        ...

    @abstractmethod
    def instructions(self, start: Address, end: Address) -> Iterator[Address]:
        """
        Iterate over instruction addresses in the specified range.

        Args:
            start: Starting address (inclusive)
            end: Ending address (exclusive)

        Yields:
            Address of each instruction in the range
        """
        ...

    def get_sections(self) -> Iterator[Section]:
        """
        Iterate over all memory segments sorted by start address.

        Yields:
            Segment objects for each memory region in address order
        """
        # Collect all sections and sort by start address for consistency
        sections = list(self._get_sections_impl())
        sections.sort(key=lambda s: s.start.value)

        for section in sections:
            yield section

    @abstractmethod
    def _get_sections_impl(self) -> Iterator[Section]:
        """
        Backend-specific implementation for getting memory segments.

        Yields:
            Segment objects for each memory region (unsorted)
        """
        ...

    @abstractmethod
    def get_section_by_name(self, name: str) -> Optional[Section]:
        """
        Get segment by name.

        Args:
            name: Segment name to find

        Returns:
            Segment with the specified name, or None if not found
        """
        ...

    def get_imports(self) -> Iterator[Tuple[Address, str, str]]:
        """
        Get imported functions with unified parsing.

        This method processes raw import data and normalizes it to a
        consistent format across different backends.

        Returns:
            Iterator of (address, full_name, module) tuples where:
            - address: Location of import in binary
            - full_name: "module.function" format
            - module: Normalized module name
        """
        for addr, raw_name, raw_module in self._get_raw_imports():
            # Parse and normalize the import name
            if raw_name:
                module_name, function_name = self.parse_import_name(raw_name)
                # Only use raw_module if we didn't extract a module from versioned symbol
                if raw_module and raw_module != "unknown" and module_name == "unknown":
                    module_name = self.normalize_module_name(raw_module)
            else:
                module_name = self.normalize_module_name(raw_module) if raw_module else "unknown"
                function_name = raw_name or "unknown"
            full_name = f"{module_name}.{function_name}"
            yield (addr, full_name, module_name)

    @abstractmethod
    def _get_raw_imports(self) -> Iterator[Tuple[Address, str, str]]:
        """
        Get raw import data from backend.

        Backend-specific implementation should return unprocessed import data.

        Returns:
            Iterator of (address, function_name, module_name) tuples
        """
        ...

    @staticmethod
    def parse_import_name(name: str) -> Tuple[str, str]:
        """
        Parse import name handling versioned symbols.

        Extracts module and function name from various import formats:
        - "function@@GLIBC_2.17" -> ("glibc", "function")
        - "kernel32.CreateFileA" -> ("kernel32", "CreateFileA")
        - "CreateFileA" -> ("unknown", "CreateFileA")

        Args:
            name: Full import name

        Returns:
            Tuple of (module_name, function_name)
        """
        # Handle versioned symbols (e.g., function@@GLIBC_2.17)
        if "@@" in name:
            parts = name.split("@@", 1)
            function_name = parts[0]
            version_info = parts[1]

            # Extract module name from version info
            if "_" in version_info:
                module_name = "_".join(version_info.split("_")[:-1])
            else:
                module_name = version_info

            return module_name, function_name

        # Handle "module.function" format
        if "." in name:
            parts = name.rsplit(".", 1)
            if len(parts) == 2:
                module_name = parts[0]  # .lower()
                function_name = parts[1]
                return module_name, function_name

        # Default: unknown module
        return "unknown", name

    @staticmethod
    def normalize_module_name(module_name: str) -> str:
        """
        Normalize module names by removing common extensions and paths.

        Args:
            module_name: Raw module name

        Returns:
            Normalized module name in lowercase
        """
        # Remove common file extensions
        for ext in [".so", ".dll", ".dylib", ".exe"]:
            if module_name.lower().endswith(ext):
                module_name = module_name[: -len(ext)]
                break

        # Remove path components (handle both Unix and Windows paths)
        module_name = module_name.split("/")[-1].split("\\")[-1]

        return module_name

    @abstractmethod
    def get_exports(self) -> Iterator[Tuple[str, Address]]:
        """
        Get all exported symbols from the binary.
        Returns:
            Iterator of (name, Address) tuples for each export
        """
        raise NotImplementedError("get_exports() must be implemented by the backend to provide export symbols.")

    #
    # User Annotations
    #

    def add_user_xref(self, source: Address, target: Address) -> bool:
        """
        Add a user-defined code reference.

        Args:
            source: Source address of the reference
            target: Target address of the reference

        Returns:
            True if successfully added, False otherwise
        """
        try:
            self._add_user_xref_impl(source, target)
            return True
        except Exception:
            return False

    def set_comment(self, address: Address, comment: str) -> bool:
        """
        Set a comment at the specified address.

        Args:
            address: Address to set comment at
            comment: Comment text

        Returns:
            True if successfully set, False otherwise
        """
        try:
            self._set_comment_impl(address, comment)
            return True
        except Exception:
            return False

    def set_function_comment(self, address: Address, comment: str) -> bool:
        """
        Set or replace the comment for the function containing the address.

        Args:
            address: Address within the function
            comment: Comment text

        Returns:
            True if successfully set, False otherwise
        """
        try:
            self._set_function_comment_impl(address, comment)
            return True
        except Exception:
            return False

    def disassemble(self, address: Address) -> "Instruction":
        """
        Disassemble a single instruction at `address`.
        """
        return self._get_disassembly_impl(address)

    #
    # Backend-Specific Implementation Methods
    #

    @abstractmethod
    def _add_user_xref_impl(self, source: Address, target: Address) -> None:
        """Backend-specific implementation for adding user cross-references."""
        ...

    @abstractmethod
    def _set_comment_impl(self, address: Address, comment: str) -> None:
        """Backend-specific implementation for setting comments."""
        ...

    @abstractmethod
    def _set_function_comment_impl(self, address: Address, comment: str) -> None:
        """Backend-specific implementation for setting function comments."""
        ...

    @abstractmethod
    def _path_impl(self) -> str:
        """Backend-specific implementation for getting binary path."""
        ...

    @abstractmethod
    def _get_disassembly_impl(self, address: Address) -> Instruction:
        """Backend-specific implementation for getting disassembly at a specific address."""
        ...

    def resolve_file_offset(self, file_offset: int) -> Address | None:
        """Resolve a file offset to a memory address if possible.

        Args:
            file_offset: Raw file offset to resolve

        Returns:
            Resolved Address or None if the offset does not map to memory
        """
        if file_offset < 0:
            raise ValueError("file_offset must be non-negative")
        return self._resolve_file_offset_impl(file_offset)

    @abstractmethod
    def _resolve_file_offset_impl(self, file_offset: int) -> Address | None:
        """Backend-specific implementation for resolving file offsets."""
        ...
