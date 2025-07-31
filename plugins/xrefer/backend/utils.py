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
                        # Check if call has a known target (symbol)
                        addr = instr.address
                        refs = list(bv.get_code_refs_from(addr))
                        has_known_target = any(bv.get_symbol_at(ref) for ref in refs)
                        if not has_known_target:
                            indirect_calls.append(f"0x{addr:x}")
    return indirect_calls


def _dump_indirect_calls_ghidra(program):
    """
    Finds and returns the addresses of all indirect call instructions in a Ghidra program.

    This function iterates through all defined functions, inspects the P-Code for each
    instruction, and identifies indirect calls via the `CALLIND` P-Code operation.
    This approach is robust and architecture-agnostic, as it relies on Ghidra's
    semantic representation rather than instruction mnemonics or operand types.

    Args:
        program: The active Ghidra program object (typically the global `currentProgram`).

    Returns:
        A list of strings, with each string representing the hexadecimal address
        of an indirect call instruction (e.g., ["0x401050", "0x4010a2"]).
    """
    from ghidra.program.model.pcode import PcodeOp

    indirect_calls = []
    function_manager = program.getFunctionManager()
    listing = program.getListing()
    symbol_table = program.getSymbolTable()  # Cache symbol table for performance
    
    for func in function_manager.getFunctions(True):
        instructions = listing.getInstructions(func.getBody(), True)
        for instr in instructions:
            for pcode_op in instr.getPcode():
                if pcode_op.getOpcode() == PcodeOp.CALLIND:
                    address = instr.getAddress().getOffset()
                    # Check if this call references any known symbol (exclude GOT/PLT calls)
                    refs = instr.getReferencesFrom()
                    has_symbol_ref = False
                    for ref in refs:
                        symbols = symbol_table.getSymbols(ref.getToAddress())
                        symbol_list = list(symbols)
                        if symbol_list:
                            # If there are any symbols at the target address, it's a direct call
                            has_symbol_ref = True
                            break

                    if not has_symbol_ref:
                        indirect_calls.append(f"0x{address:x}")
                    # Don't break here - continue processing remaining pcode operations

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