"""backend factory for pythonic backend selection."""

import importlib.util
from abc import ABC, abstractmethod
from typing import Dict, Optional

from .base import BackEnd, BackendError


class BackendFactory(ABC):
    """Abstract factory for creating analysis backends."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this backend is available in the current environment."""
        ...

    @abstractmethod
    def create_backend(self, **kwargs) -> BackEnd:
        """Create and configure a backend instance."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this backend."""
        ...


class IDABackendFactory(BackendFactory):
    """Factory for IDA Pro backend."""

    @property
    def name(self) -> str:
        return "IDA Pro"

    def is_available(self) -> bool:
        """Check if IDA Pro is available."""
        return importlib.util.find_spec("idapro") is not None

    def create_backend(self, **kwargs) -> BackEnd:
        """Create IDA backend instance."""
        from .ida.backend import IDABackend

        return IDABackend()


class BinaryNinjaBackendFactory(BackendFactory):
    """Factory for Binary Ninja backend."""

    @property
    def name(self) -> str:
        return "Binary Ninja"

    def is_available(self) -> bool:
        """Check if Binary Ninja is available."""
        return importlib.util.find_spec("binaryninja") is not None

    def create_backend(self, bv=None, **kwargs) -> BackEnd:
        """Create Binary Ninja backend instance."""
        if bv is None:
            raise BackendError("Binary Ninja backend requires 'bv' parameter")

        from .binaryninja.backend import BNBackend

        return BNBackend(bv)


class GhidraBackendFactory(BackendFactory):
    """Factory for Ghidra backend."""

    @property
    def name(self) -> str:
        return "Ghidra"

    def is_available(self) -> bool:
        """Check if Ghidra is available."""
        return importlib.util.find_spec("pyghidra") is not None

    def create_backend(self, **kwargs) -> BackEnd:
        """Create Ghidra backend instance."""
        from .ghidra.backend import GhidraBackend

        return GhidraBackend()


class BackendManager:
    """Manages available backends and provides unified access."""

    def __init__(self):
        self._factories: Dict[str, BackendFactory] = {
            "ida": IDABackendFactory(),
            "binaryninja": BinaryNinjaBackendFactory(),
            "ghidra": GhidraBackendFactory(),
        }
        self._active_backend: Optional[BackEnd] = None

    def get_available_backends(self) -> Dict[str, str]:
        """Get dict of available backend IDs to names."""
        return {backend_id: factory.name for backend_id, factory in self._factories.items() if factory.is_available()}

    def create_backend(self, backend_id: Optional[str] = None, **kwargs) -> BackEnd:
        """
        Create a backend instance.

        Args:
            backend_id: Specific backend to create, or None for auto-detection
            **kwargs: Backend-specific arguments

        Returns:
            Configured backend instance

        Raises:
            BackendError: If no suitable backend is found
        """
        if backend_id:
            if backend_id not in self._factories:
                raise BackendError(f"Unknown backend: {backend_id}")

            factory = self._factories[backend_id]
            if not factory.is_available():
                raise BackendError(f"Backend '{factory.name}' is not available")

            return factory.create_backend(**kwargs)

        # Auto-detect available backend
        available = self.get_available_backends()
        if not available:
            raise BackendError("No analysis backends are available")

        # Prefer IDA if available, then Binary Ninja, then Ghidra
        for preferred in ["ida", "binaryninja", "ghidra"]:
            if preferred in available:
                return self._factories[preferred].create_backend(**kwargs)

        # Fallback to first available
        first_id = next(iter(available.keys()))
        return self._factories[first_id].create_backend(**kwargs)

    def set_active_backend(self, backend: BackEnd) -> None:
        """Set the currently active backend."""
        self._active_backend = backend

    def get_active_backend(self) -> Optional[BackEnd]:
        """Get the currently active backend."""
        return self._active_backend


# Global backend manager instance
backend_manager = BackendManager()


def get_backend(**kwargs) -> BackEnd:
    """
    Convenience function to get a backend instance.

    Args:
        **kwargs: Backend-specific arguments

    Returns:
        Configured backend instance
    """
    return backend_manager.create_backend(**kwargs)


def list_available_backends() -> Dict[str, str]:
    """List all available backends."""
    return backend_manager.get_available_backends()
