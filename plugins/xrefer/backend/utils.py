from typing import List

from . import Backend
from .base import BackEnd
from .types import Address


def sample_path() -> str:
    """Return a sample path for the backend."""
    return Backend().path


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

