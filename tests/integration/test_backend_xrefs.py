"""Strict cross-backend reference validation.

The goal is to guarantee that each backend agrees on both the set of
targets and the semantic type of `get_xrefs_from` for carefully curated
addresses drawn from a known C sample binary.
"""

from __future__ import annotations

import pathlib
from contextlib import contextmanager
from dataclasses import dataclass

import pytest

from xrefer.backend.base import Address, XrefType
from xrefer.backend.factory import BackendManager


pytestmark = pytest.mark.no_cover


@dataclass(frozen=True)
class ExpectedXref:
    target: Address
    type: XrefType


SAMPLES = {
    "12dfab3f9b0bbec86cf003479b92e1c72959fbe7bfc7ce1b7e46f9366de82a2a": {
        # Address(0x401004): {ExpectedXref(Address(0x403FE0), XrefType.DATA_READ)},  # .init:0000000000401004 mov     rax, cs:__gmon_start___ptr
        Address(0x40100E): {ExpectedXref(Address(0x401012), XrefType.JUMP)}, # .init:000000000040100E jz      short loc_401012
        Address(0x401030): {
            ExpectedXref(Address(0x404000), XrefType.UNKNOWN), # .plt:0000000000401030 jmp     cs:off_404000; -> .got.plt:0000000000404000 off_404000      dq offset printf
            # ExpectedXref(Address(0x405008), XrefType.UNKNOWN)
        },
        Address(0x401066): {ExpectedXref(Address(0x401040), XrefType.CALL)}, # .text:0000000000401066 call    _strtol -> .plt:0000000000401040 jmp     cs:off_404008
        # Address(0x401076): {ExpectedXref(Address(0x402004), XrefType.DATA_OFFSET)}, # .text:0000000000401076 mov     edi, offset format ; "Fibonacci(%d) = %ld\n" ← TODO: this shouldn't be UNKNOWN
        Address(0x401156): {ExpectedXref(Address(0x404020), XrefType.DATA_WRITE)}, # .text:0000000000401156 C6 05 C3 2E 00 00 01                    mov     cs:__bss_start, 1
        Address(0x4013CF): set(), # .text:00000000004013CF 83 6C 24 10 02                          sub     [rsp+0B8h+var_A8], 2
        # Address(0x4014D9): {ExpectedXref(Address(0x4013CC), XrefType.JUMP)},  # .text:00000000004014D9 jmp     loc_4013CC
    },
}


# STRICT_EXPECTATIONS = {
#     Address(0x401004): {
#         "ghidra": {
#             ExpectedXref(Address(0x403FE0), XrefType.DATA_READ),
#             ExpectedXref(Address(0x405010), XrefType.DATA_READ),
#         },
#         "binaryninja": {
#             ExpectedXref(Address(0x403FE0), XrefType.UNKNOWN),
#         },
#     },
#     Address(0x40100E): {
#         "ghidra": {ExpectedXref(Address(0x401012), XrefType.BRANCH_TRUE)},
#         "binaryninja": {
#             ExpectedXref(Address(0x401010), XrefType.UNKNOWN),
#             ExpectedXref(Address(0x401012), XrefType.UNKNOWN),
#         },
#     },
#     Address(0x401030): {
#         "ghidra": {
#             ExpectedXref(Address(0x404000), XrefType.UNKNOWN),
#             ExpectedXref(Address(0x405008), XrefType.UNKNOWN),
#         },
#         "binaryninja": {
#             ExpectedXref(Address(0x404000), XrefType.CALL),
#         },
#     },
#     Address(0x401066): {
#         "ghidra": {ExpectedXref(Address(0x401040), XrefType.CALL)},
#         "binaryninja": {ExpectedXref(Address(0x401040), XrefType.UNKNOWN)},
#     },
#     Address(0x401076): {
#         "ghidra": {ExpectedXref(Address(0x402004), XrefType.DATA_READ)},
#         "binaryninja": {ExpectedXref(Address(0x402004), XrefType.UNKNOWN)},
#     },
#     Address(0x401156): {
#         "ghidra": {ExpectedXref(Address(0x404020), XrefType.DATA_WRITE)},
#         "binaryninja": {ExpectedXref(Address(0x404020), XrefType.UNKNOWN)},
#     },
#     Address(0x4013CF): {
#         "ghidra": set(),
#         "binaryninja": set(),
#     },
#     Address(0x4014D9): {
#         "ghidra": {ExpectedXref(Address(0x4013CC), XrefType.JUMP)},
#         "binaryninja": {ExpectedXref(Address(0x4013CC), XrefType.UNKNOWN)},
#     },
# }


def _strict_mode() -> bool:
    return True


def _require_path(path: pathlib.Path) -> pathlib.Path:
    if not path.exists():
        pytest.skip(f"missing sample binary: {path}")
    return path


@contextmanager
def _binaryninja_backend(path: pathlib.Path):
    import binaryninja as bn
    from xrefer.backend.binaryninja.backend import BNBackend

    bn.disable_default_log()
    bv = bn.load(str(path))
    if bv is None:
        raise RuntimeError("Binary Ninja could not load sample binary")

    backend = BNBackend(bv)
    try:
        yield backend
    finally:
        try:
            bv.file.close()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass


@contextmanager
def _ghidra_backend(path: pathlib.Path):
    from pyghidra import open_program
    from xrefer.backend.ghidra.backend import GhidraBackend

    with open_program(str(path), analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()
        backend = GhidraBackend(program=program)
        yield backend


@contextmanager
def _ida_backend(path: pathlib.Path):  # pragma: no cover - requires IDA at runtime
    import idapro
    from xrefer.backend.ida.backend import IDABackend

    idapro.open_database(str(path), run_auto_analysis=False)
    try:
        yield IDABackend()
    finally:
        idapro.close_database(save=False)


def _backend_context(backend_id: str, path: pathlib.Path):
    if backend_id == "binaryninja":
        return _binaryninja_backend(path)
    if backend_id == "ghidra":
        return _ghidra_backend(path)
    if backend_id == "ida":
        return _ida_backend(path)
    raise ValueError(f"unknown backend: {backend_id}")


def _available_backends() -> set[str]:
    return set(BackendManager().get_available_backends().keys())


def _require_backend(backend_id: str) -> None:
    if backend_id not in _available_backends():
        message = f"backend not available: {backend_id}"
        if _strict_mode():
            pytest.fail(message)
        pytest.skip(message)


def _collect(backend, address: Address) -> set[ExpectedXref]:
    xrefs = set()
    for ref in backend.get_xrefs_from(address):
        xrefs.add(ExpectedXref(ref.target, ref.type))
    return xrefs


@pytest.mark.integration
@pytest.mark.requires_binary
@pytest.mark.parametrize("hash_id", list(SAMPLES.keys()))
@pytest.mark.parametrize("backend_id", ["binaryninja", "ghidra", "ida"])
def test_strict_xrefs(hash_id: str, backend_id: str):
    expectations = SAMPLES[hash_id]
    base = pathlib.Path("tests/e2e/xrefer-test/samples") / hash_id / "binary"

    _require_backend(backend_id)
    path = _require_path(base)

    # Binary Ninja exposes only a subset of xref types; insist on exact
    # Ghidra matches for now until other backends reach parity.
    # if backend_id != "ghidra":
        # pytest.skip("strict expectations enforced only for ghidra")

    with _backend_context(backend_id, path) as backend:
        for address, expected in expectations.items():
            actual = _collect(backend, address)
            assert actual == expected, (
                f"backend={backend_id} hash={hash_id} addr={address:#x}"
                f" expected={sorted(expected, key=lambda e: e.target)}"
                f" actual={sorted(actual, key=lambda e: e.target)}"
            )
