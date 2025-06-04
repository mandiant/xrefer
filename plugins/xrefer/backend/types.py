"""Common types and enums for backend abstraction."""

from enum import Enum, auto


# enums.ph: SymbolType
class FunctionType(Enum):
    NORMAL = auto()
    THUNK = auto()
    LIBRARY = auto()
    EXTERN = auto()
    IMPORT = auto()
    EXPORT = auto()


# https://github.com/mandiant/xrefer/blob/8bce6a07a2ceeea0cf3e2dbffb9a0f312f3e9c7f/plugins/xrefer/core/analyzer.py#L736
# https://github.com/mandiant/xrefer/blob/8bce6a07a2ceeea0cf3e2dbffb9a0f312f3e9c7f/plugins/xrefer/lang/lang_rust.py#L526
# BN:
# enums.py: BranchType
class XrefType(Enum):
    """Cross-reference types."""

    CALL = auto()
    JUMP = auto()
    BRANCH_TRUE = auto()
    BRANCH_FALSE = auto()
    DATA_READ = auto()
    DATA_WRITE = auto()
    DATA_OFFSET = auto()
    STRING_REF = auto()
    UNKNOWN = auto()


class Address(int):
    """Type-safe address wrapper."""

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
        return self != self.invalid()
