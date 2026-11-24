# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for segmented address handling in GhidraBackend."""

from unittest.mock import MagicMock, patch
import sys

from xrefer.backend.base import Address, InvalidAddressError, OperandType, XrefType


class _FakeGhidraAddress:
    def __init__(self, text: str, offset: int | None = None) -> None:
        self._text = text
        self._offset = offset

    def toString(self) -> str:
        return self._text

    def getOffset(self) -> int | None:
        return self._offset

    def isStackAddress(self) -> bool:
        return False

    def isMemoryAddress(self) -> bool:
        return True


def test_get_xrefs_from_handles_segmented_addresses():
    from xrefer.backend.ghidra.backend import GhidraBackend

    mock_ref_type = MagicMock()
    mock_ref = MagicMock()
    mock_ref.getReferenceType.return_value = mock_ref_type
    mock_ref.getFromAddress.return_value = _FakeGhidraAddress("1000:0000", 0x10000)
    mock_ref.getToAddress.return_value = _FakeGhidraAddress("1000:0120", 0x10120)

    mock_ref_mgr = MagicMock()
    mock_ref_mgr.getReferencesFrom.return_value = [mock_ref]

    mock_memory = MagicMock()
    mock_memory.getBlock.return_value = MagicMock()

    mock_addr_factory = MagicMock()
    mock_addr_factory.getAddress.return_value = _FakeGhidraAddress("1000:0000", 0x10000)

    mock_program = MagicMock()
    mock_program.getAddressFactory.return_value = mock_addr_factory
    mock_program.getReferenceManager.return_value = mock_ref_mgr
    mock_program.getMemory.return_value = mock_memory

    mock_ghidra = MagicMock()
    mock_ghidra.program.model.symbol.RefType.UNCONDITIONAL_CALL = mock_ref_type

    with patch.dict(
        sys.modules,
        {
            "ghidra": mock_ghidra,
            "ghidra.program.model.symbol": mock_ghidra.program.model.symbol,
        },
    ):
        backend = GhidraBackend(program=mock_program)
        xrefs = list(backend.get_xrefs_from(Address(0x10000)))

    assert len(xrefs) == 1
    assert xrefs[0].source == Address(0x10000)
    assert xrefs[0].target == Address(0x10120)
    assert xrefs[0].type == XrefType.CALL


def test_get_xrefs_from_returns_empty_when_address_unresolvable():
    from xrefer.backend.ghidra.backend import GhidraBackend

    mock_addr_factory = MagicMock()
    mock_addr_factory.getAddress.return_value = None

    mock_program = MagicMock()
    mock_program.getAddressFactory.return_value = mock_addr_factory

    backend = GhidraBackend(program=mock_program)
    assert list(backend.get_xrefs_from(Address(0x10000))) == []


def test_ghidra_address_string_fallback_parses_segmented_and_spaced():
    from xrefer.backend.ghidra.backend import _ghidra_address_to_xrefer_address

    assert _ghidra_address_to_xrefer_address(_FakeGhidraAddress("1000:0000")) == Address(0x10000)
    assert _ghidra_address_to_xrefer_address(_FakeGhidraAddress("ram:1000:0010")) == Address(0x10010)
    assert _ghidra_address_to_xrefer_address(_FakeGhidraAddress("ram:00401000")) == Address(0x401000)

    try:
        _ghidra_address_to_xrefer_address(_FakeGhidraAddress(""))
        raise AssertionError("Expected InvalidAddressError for empty address")
    except InvalidAddressError:
        pass


def test_get_disassembly_impl_handles_segmented_operand_address():
    from xrefer.backend.ghidra.backend import GhidraBackend

    class _FakeGAddress(_FakeGhidraAddress):
        pass

    class _FakeGRegister:
        pass

    class _FakeGScalar:
        pass

    seg_target = _FakeGAddress("1000:0050", 0x10050)
    mock_inst = MagicMock()
    mock_inst.toString.return_value = "CALL 1000:0050"
    mock_inst.getMnemonicString.return_value = "CALL"
    mock_inst.getNumOperands.return_value = 1
    mock_inst.getDefaultOperandRepresentation.return_value = "1000:0050"
    mock_inst.getOpObjects.return_value = [seg_target]
    mock_inst.getReferencesFrom.return_value = []

    mock_listing = MagicMock()
    mock_listing.getInstructionAt.return_value = mock_inst

    mock_addr_factory = MagicMock()
    mock_addr_factory.getAddress.return_value = _FakeGAddress("1000:0000", 0x10000)

    mock_program = MagicMock()
    mock_program.getAddressFactory.return_value = mock_addr_factory
    mock_program.getListing.return_value = mock_listing
    mock_program.getMemory.return_value = MagicMock()

    mock_ghidra = MagicMock()
    mock_ghidra.program.model.address.Address = _FakeGAddress
    mock_ghidra.program.model.lang.Register = _FakeGRegister
    mock_ghidra.program.model.scalar.Scalar = _FakeGScalar

    with patch.dict(
        sys.modules,
        {
            "ghidra": mock_ghidra,
            "ghidra.program.model.scalar": mock_ghidra.program.model.scalar,
            "ghidra.program.model.address": mock_ghidra.program.model.address,
            "ghidra.program.model.lang": mock_ghidra.program.model.lang,
        },
    ):
        backend = GhidraBackend(program=mock_program)
        ins = backend._get_disassembly_impl(Address(0x10000))

    assert len(ins.operands) == 1
    assert ins.operands[0].type == OperandType.IMMEDIATE
    assert ins.operands[0].value == Address(0x10050)
