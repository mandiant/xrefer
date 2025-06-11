from typing import List

from .base import Address, BackEnd


def sample_path() -> str:
    """Return a sample path for the active backend."""
    from . import get_current_backend

    backend = get_current_backend()
    return backend.path


def _dump_indirect_calls_ida():
    import ida_bytes
    import idaapi
    import idautils
    import idc

    indirect_calls = []
    for segea in idautils.Segments():
        for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
            for startea, endea in idautils.Chunks(funcea):
                for head in idautils.Heads(startea, endea):
                    if ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                        if idaapi.is_call_insn(head):
                            insn = idaapi.insn_t()
                            idaapi.decode_insn(insn, head)
                            operand = insn.ops[0]
                            if operand.type in (idaapi.o_phrase, idaapi.o_displ, idaapi.o_reg):
                                # {idc.generate_disasm_line(head, 0)}
                                indirect_calls.append(f"0x{head:x}")
    return indirect_calls


def _dump_indirect_calls_bn(bv):
    from binaryninja import BinaryView, LowLevelILOperation

    indirect_calls = []
    bv: BinaryView = bv

    for func in bv.functions:
        llil = func.low_level_il
        if not llil:
            continue
        for block in llil.basic_blocks:
            for instr in block:
                if instr.operation == LowLevelILOperation.LLIL_CALL:
                    dest = instr.dest
                    if dest.operation not in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR]:
                        addr = instr.address
                        # disasm = bv.get_disassembly(addr)
                        indirect_calls.append(f"0x{addr:x}")
    return indirect_calls


class Mapping:
    """A utility class for mapping addresses to symbols and vice-versa."""

    def __init__(self, backend: BackEnd):
        """
        Initializes the Mapping utility.

        Args:
            backend: An instance of a backend (e.g., IDABackend or BNBackend).
        """
        self._backend = backend

    def addr2sym(self, address: Address) -> List[str]:
        """
        Resolves an address to a list of symbol names.

        Args:
            address: The address to resolve.

        Returns:
            A list of symbol names, which may be empty if no symbols are found.
        """
        symbols = []
        func = self._backend.get_function_at(address)
        if func:
            symbols.append(func.name)

        # In some cases, a name might exist at an address without a function.
        name = self._backend.get_name_at(address)
        if name and name not in symbols:
            symbols.append(name)

        return symbols

    def sym2addr(self, symbol: str) -> List[Address]:
        """
        Resolves a symbol name to a list of addresses.

        Args:
            symbol: The symbol name to resolve.

        Returns:
            A list of addresses, which may be empty if the symbol is not found.
        """
        address = self._backend.get_address_for_name(symbol)
        return [address] if address else []
