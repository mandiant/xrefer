"""Fast, DRY tests for .size method across all backends.

Tests skip unnecessary analysis - `size` reads file metadata only.
"""

import os
import pathlib
from contextlib import contextmanager

import pytest
pytestmark = pytest.mark.no_cover
from xrefer.backend.factory import backend_manager


SAMPLES_ROOT = pathlib.Path("tests/e2e/xrefer-test/samples")

SAMPLE_BINARIES_SIZE = [
    ("12dfab3f9b0bbec86cf003479b92e1c72959fbe7bfc7ce1b7e46f9366de82a2a", 15840),
    ("0dfa1d01bf75ed5dca0e6c6e5ff19c731d93eedf6b08d513be52f80050718ea5", 311927),
    ("38bab81052ffdbef9b458d2d35baa40a03ff980cd30c8aee8baa3e0d8ca0828a", 4616704),
]


def _sample_path(sample_id: str) -> str:
    p = SAMPLES_ROOT / sample_id / "binary"
    if not p.exists():
        pytest.skip(f"sample missing: {p}")
    return str(p)


def _strict_mode() -> bool:
    return os.environ.get("XREFER_BACKEND_STRICT", "0") not in ("", "0", "false", "False")


def _available_backend_ids() -> list[str]:
    return list(backend_manager.get_available_backends().keys())


def _require_backends(expected: set[str]):
    avail = set(_available_backend_ids())
    missing = expected - avail
    if missing:
        if _strict_mode():
            pytest.fail(f"Missing required backends: {sorted(missing)}")
        pytest.skip(f"Backends not available: {sorted(missing)}")


@contextmanager
def _binaryninja_backend(path: str):
    """Yield BinaryNinja backend without full analysis."""
    import binaryninja as bn

    bn.disable_default_log()
    bv = bn.load(path)
    if bv is None:
        raise RuntimeError("BinaryNinja could not open binary")

    from xrefer.backend.binaryninja.backend import BNBackend

    backend = BNBackend(bv)
    try:
        yield backend
    finally:
        try:
            bv.file.close()
        except Exception:
            pass


@contextmanager
def _ghidra_backend(path: str):
    """Yield Ghidra backend using program context."""
    from pyghidra import open_program
    from xrefer.backend.ghidra.backend import GhidraBackend

    with open_program(path, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        backend = GhidraBackend(program=program)
        yield backend


@contextmanager
def _ida_backend(path: str):
    """Yield IDA backend by temporarily opening database."""
    import idapro
    from xrefer.backend.ida.backend import IDABackend

    idapro.open_database(path, run_auto_analysis=False)
    try:
        yield IDABackend()
    finally:
        idapro.close_database(save=False)


@contextmanager
def _backend_context(backend_id: str, path: str):
    """Factory: yield backend without running full analysis."""
    if backend_id == "binaryninja":
        with _binaryninja_backend(path) as backend:
            yield backend
        return
    if backend_id == "ghidra":
        with _ghidra_backend(path) as backend:
            yield backend
        return
    if backend_id == "ida":
        with _ida_backend(path) as backend:
            yield backend
        return
    raise ValueError(f"Unknown backend: {backend_id}")


@pytest.mark.integration
@pytest.mark.requires_binary
@pytest.mark.parametrize("sample_id,expected_size", SAMPLE_BINARIES_SIZE)
@pytest.mark.parametrize("backend_id", ["binaryninja", "ghidra", "ida"])
def test_backend_size_method(backend_id: str, sample_id: str, expected_size: int):
    """Test backend.size returns correct file size."""
    _require_backends({backend_id})
    path = _sample_path(sample_id)
    with _backend_context(backend_id, path) as backend:
        actual = backend.size
        print(f"{backend_id}.name={backend.name}, {backend.path=}, size={backend.size}, expected={expected_size}")

        assert isinstance(actual, int)
        assert actual > 0
        assert actual == expected_size, f"{backend_id}.size={actual}, expected {expected_size}"
