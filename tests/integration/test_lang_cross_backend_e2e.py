import os
import pathlib
import sys
import types
import importlib
from contextlib import contextmanager

import pytest

from xrefer.backend.factory import backend_manager

pytestmark = pytest.mark.no_cover


SAMPLES_ROOT = pathlib.Path("tests/e2e/xrefer-test/samples")


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
            pytest.fail(f"Missing required backends (strict mode): {sorted(missing)}")
        pytest.skip(f"Backends not available: {sorted(missing)}")


@contextmanager
def _active_backend(be):
    prev = backend_manager.get_active_backend()
    backend_manager.set_active_backend(be)
    try:
        yield
    finally:
        backend_manager.set_active_backend(prev)


@contextmanager
def _binaryninja_backend(path: str):
    import binaryninja as bn
    bv = bn.load(path)
    bv.update_analysis_and_wait()
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
    import pyghidra
    from xrefer.backend.ghidra.backend import GhidraBackend

    program_ctx = pyghidra.open_program(path, analyze=False)
    flat_api = program_ctx.__enter__()
    program = flat_api.getCurrentProgram()
    backend = GhidraBackend(program=program)
    try:
        yield backend
    finally:
        program_ctx.__exit__(None, None, None)


@contextmanager
def _ida_backend(path: str):
    import idapro
    from xrefer.backend.ida.backend import IDABackend

    idapro.open_database(path, run_auto_analysis=True)
    try:
        yield IDABackend()
    finally:
        idapro.close_database(save=False)


@contextmanager
def _backend_context(backend_id: str, path: str):
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


def _ensure_core_analyzer_stubbed():
    # Break circular import: xrefer.core.__init__ imports analyzer which imports xrefer.lang.
    # Pre-insert a stub module so 'from . import analyzer' succeeds without executing the real analyzer.
    if "xrefer.core.analyzer" not in sys.modules:
        sys.modules["xrefer.core.analyzer"] = types.ModuleType("xrefer.core.analyzer")


def _collect_lang_snapshot():
    _ensure_core_analyzer_stubbed()
    get_language_object = importlib.import_module("xrefer.lang.lang_registry").get_language_object
    lang = get_language_object()
    # Normalize result for cross-backend comparison
    result = {
        "lang": type(lang).__name__,
        "entry_point": getattr(lang, "entry_point", None),
        "lib_refs": sorted({str(name) for (_ea, name, _cat, _grp) in getattr(lang, "lib_refs", [])}),
    }
    # Attach rust specifics if present
    if hasattr(lang, "crate_columns"):
        result["crate_columns"] = [list(getattr(lang, "crate_columns")[0]), list(getattr(lang, "crate_columns")[1])]
    return lang, result


def _debug_dump(backend_id: str, snapshot: dict):
    print(f"[DEBUG] backend={backend_id} snapshot={snapshot}")

@pytest.mark.integration
@pytest.mark.requires_binary
@pytest.mark.parametrize(
    "sample_id",
    [
        "e336e4474285d32636eb5b14acd62db5028be29d0602f266dafacd4a6caad999",  # rust
        "ca23d3715faf1c48f3ca1cdf56d996ed031247f14c18ec4a75fb78f612da4f68",  # c hello
        "4bef733c2a02c1776591d77fe320016616ea10dd3f32c45fd786adbe7d014e1f", # rust
        "38bab81052ffdbef9b458d2d35baa40a03ff980cd30c8aee8baa3e0d8ca0828a", # rust
        "e3f6628c1d43da4205b4d0744f7fb44265da2232909e900b523bea8a7c0ecab1", # rust
        "da70e2c87d3f83331b01cd2b3f36ab4b3150ce8ee74506843134b58152109eb5", # c
        "a7384e9286044955b4715ce95d5fa823a92bb8eecc0e691cc499e9f7e930890a", # cpp
        "60ba2914e48b9b9f60b4e50452b83b2e426690833d5e1152e2e19ec470942f4f", # cpp
        "49ed19448b75330414e451bd1bacf197a2316a02217c2aadac17d1fa1c4ea830", # go
        "28afe46a3fabf90f8beb3874265c5879ce6c115ffd316c59aca3cba62f15aceb", # go
    ],
)
def test_lang_consistency_across_real_backends(sample_id):
    # Require at least two backends to make a meaningful comparison
    avail = _available_backend_ids()
    need_any = {"binaryninja", "ghidra", "ida"}
    usable = [b for b in avail if b in need_any]
    if len(usable) < 2:
        _require_backends(need_any)  # will skip or fail fast depending on strict mode
        pytest.skip("Not enough backends available for cross-check")

    path = _sample_path(sample_id)

    snapshots: dict[str, dict] = {}
    for be_id in usable:
        with _backend_context(be_id, path) as backend:
            with _active_backend(backend):
                lang, snap = _collect_lang_snapshot()
                _debug_dump(be_id, snap)
                snapshots[be_id] = snap

    # Reference snapshot
    backends = sorted(snapshots.keys())
    ref = snapshots[backends[0]]
    for be_id in backends[1:]:
        snap = snapshots[be_id]
        # Lang type must match across backends
        assert snap["lang"] == ref["lang"], f"lang mismatch: {be_id}={snap['lang']} ref={ref['lang']}"
        # Entry point must match exactly
        assert snap["entry_point"] == ref["entry_point"], f"entry_point mismatch: {be_id}={snap['entry_point']} ref={ref['entry_point']} (backend: )"
        # Compare crate_columns if present on either side
        if "crate_columns" in ref or "crate_columns" in snap:
            assert snap.get("crate_columns") == ref.get("crate_columns"), f"crate_columns mismatch: {be_id} vs ref"
        # Compare lib_refs strictly (names only)
        assert set(snap["lib_refs"]) == set(ref["lib_refs"]), f"lib_refs mismatch: {be_id} vs ref"
