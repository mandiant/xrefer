"""Shared fixtures for integration tests.

This module provides reusable fixtures for backend initialization
and testing utilities that can be used across multiple test modules.
"""

import os
import pathlib
from contextlib import contextmanager

import pytest

from xrefer.backend.factory import backend_manager


@pytest.fixture(scope="session")
def samples_root():
    """Path to the e2e test samples directory."""
    return pathlib.Path("tests/e2e/xrefer-test/samples")


@pytest.fixture(scope="session")
def strict_mode():
    """Check if strict mode is enabled (fail on missing backends)."""
    return os.environ.get("XREFER_BACKEND_STRICT", "0") not in ("", "0", "false", "False")


@pytest.fixture
def available_backends():
    """Get list of available backend IDs."""
    return list(backend_manager.get_available_backends().keys())


@pytest.fixture
def backend_factory():
    """Factory for creating backend instances.

    Returns a function that takes (backend_id, path) and returns
    an initialized backend instance.
    """

    def _create_backend(backend_id: str, path: str):
        if backend_id == "binaryninja":
            return _open_binaryninja(path)
        if backend_id == "ghidra":
            return _open_ghidra(path)
        if backend_id == "ida":
            return _open_ida()
        raise ValueError(f"Unknown backend: {backend_id}")

    return _create_backend


def _open_binaryninja(path: str):
    """Open a binary in Binary Ninja and return BNBackend instance."""
    import binaryninja as bn
    bv = bn.load(path)
    if bv is None:
        raise RuntimeError("Binary Ninja could not open view")
    bn.disable_default_log()
    bv.update_analysis_and_wait()
    from xrefer.backend.binaryninja.backend import BNBackend

    return BNBackend(bv)


def _open_ghidra(path: str):
    """Open a binary in Ghidra and return GhidraBackend instance."""
    try:
        from pyghidra import open_program
    except Exception as e:
        raise RuntimeError(f"pyghidra not usable: {e}")

    program = open_program(path)
    from xrefer.backend.ghidra.backend import GhidraBackend

    return GhidraBackend(program=program)


def _open_ida():
    """Open the current IDA database and return IDABackend instance."""
    import idapro  # noqa: F401
    import idc  # noqa: F401
    from xrefer.backend.ida.backend import IDABackend

    return IDABackend()


@pytest.fixture
@contextmanager
def active_backend():
    """Context manager to temporarily set active backend.

    Usage:
        with active_backend(backend):
            # backend is active here
            ...
    """

    def _active_backend(be):
        prev = backend_manager.get_active_backend()
        backend_manager.set_active_backend(be)
        try:
            yield
        finally:
            backend_manager.set_active_backend(prev)

    return _active_backend


def require_backends(expected: set[str], strict: bool = False):
    """Helper to check backend availability.

    Args:
        expected: Set of required backend IDs
        strict: If True, fail instead of skip when backends missing
    """
    avail = set(backend_manager.get_available_backends().keys())
    missing = expected - avail
    if missing:
        if strict:
            pytest.fail(f"Missing required backends (strict mode): {sorted(missing)}")
        pytest.skip(f"Backends not available: {sorted(missing)}")


def sample_path(samples_root: pathlib.Path, sample_id: str) -> str:
    """Get path to sample binary, skip test if missing.

    Args:
        samples_root: Root directory containing samples
        sample_id: SHA256 hash identifying the sample

    Returns:
        String path to the binary file
    """
    p = samples_root / sample_id / "binary"
    if not p.exists():
        pytest.skip(f"sample missing: {p}")
    return str(p)
