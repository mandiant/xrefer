"""Base classes for backend abstraction."""

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Optional, Tuple

from xrefer.backend.types import Address, FunctionType, XrefType

class Function(ABC):
    """Abstract function representation."""

    @property
    @abstractmethod
    def address(self) -> Address:
        """Start address of function."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Function name."""
        pass

    @property
    @abstractmethod
    def type(self) -> FunctionType:
        """Function type."""
        pass

    @property
    @abstractmethod
    def is_thunk(self) -> bool:
        """Check if function is a thunk."""
        pass

    @abstractmethod
    def contains(self, address: Address) -> bool:
        """Check if address is within function."""
        pass


class String(ABC):
    """Abstract string representation."""

    @property
    @abstractmethod
    def address(self) -> Address:
        """String address."""
        pass

    @property
    @abstractmethod
    def content(self) -> str:
        """String content."""
        pass

    @property
    @abstractmethod
    def encoding(self) -> str:
        """String encoding (utf-8, utf-16, etc)."""
        pass


class Xref(ABC):
    """Abstract cross-reference."""

    @property
    @abstractmethod
    def source(self) -> Address:
        """Source address."""
        pass

    @property
    @abstractmethod
    def target(self) -> Address:
        """Target address."""
        pass

    @property
    @abstractmethod
    def type(self) -> XrefType:
        """Reference type."""
        pass


class Segment(ABC):
    """Abstract memory segment."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Segment name."""
        pass

    @property
    @abstractmethod
    def start(self) -> Address:
        """Start address."""
        pass

    @property
    @abstractmethod
    def end(self) -> Address:
        """End address (exclusive)."""
        pass

    def contains(self, address: Address) -> bool:
        """Check if address is in segment."""
        return self.start <= address < self.end


class BackEnd(ABC):
    """Abstract interface for disassembler operations."""

    @property
    def path(self) -> str:
        """Get binary file path."""
        return self._path_impl()

    # @property
    @abstractmethod
    def image_base(self) -> Address:
        """Get image base address."""
        pass

    def binary_hash(self) -> str:
        """Get SHA256 of binary."""
        sha256 = hashlib.sha256()
        with open(self.path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    # Functions
    @abstractmethod
    def get_functions(self) -> Iterator[Function]:
        """Iterate over all functions."""
        pass

    @abstractmethod
    def get_function_at(self, address: Address) -> Optional[Function]:
        """Get function containing address."""
        pass

    # Strings
    @abstractmethod
    def get_strings(self, min_length: int = 3) -> Iterator[String]:
        """Iterate over all strings."""
        pass

    # Cross-references
    @abstractmethod
    def get_xrefs_to(self, address: Address) -> Iterator[Xref]:
        """Get references to address."""
        pass

    @abstractmethod
    def get_xrefs_from(self, address: Address) -> Iterator[Xref]:
        """Get references from address."""
        pass

    # Instructions
    @abstractmethod
    def is_call_instruction(self, address: Address) -> bool:
        """Check if instruction at address is a call."""
        pass

    @abstractmethod
    def get_instruction_mnemonic(self, address: Address) -> Optional[str]:
        """Get instruction mnemonic at address."""
        pass

    # Memory access
    @abstractmethod
    def read_bytes(self, address: Address, size: int) -> Optional[bytes]:
        """Read bytes from address."""
        pass

    # Segments
    @abstractmethod
    def get_segments(self) -> Iterator[Segment]:
        """Iterate over all segments."""
        pass

    @abstractmethod
    def get_segment_by_name(self, name: str) -> Optional[Segment]:
        """Get segment by name."""
        pass

    @abstractmethod
    def get_imports(self) -> Iterator[Tuple[str, Address]]:
        """Get imported functions as (name, address) pairs."""
        pass

    @abstractmethod
    def _path_impl(self) -> str:
        """Abstract method for `path`."""
        pass
