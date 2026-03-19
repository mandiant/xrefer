"""IDA backed implementation of the xrefer_new backend contract"""
from __future__ import annotations
import binascii
from typing import Iterator, Optional, Sequence, Set
from .base import BackEnd
from .types import CallSite, Function, ImportEntry, Segment, StringArtifact

try:
    import ida_bytes
    import ida_funcs
    import ida_nalt
    import ida_segment
    import idaapi
    import idautils
    import idc
except ImportError:  # no cover exercised only inside IDA
    ida_bytes = None
    ida_funcs = None
    ida_nalt = None
    ida_segment = None
    idaapi = None
    idautils = None
    idc = None


class IDABackEnd(BackEnd):
    """Reference backend implementation for IDA Pro."""

    def __init__(self) -> None:
        if idaapi is None:  # no cover exercised only inside IDA
            raise RuntimeError("IDABackEnd requires an IDA Python runtime")

    @property
    def name(self) -> str:
        return "ida"

    def get_image_base(self) -> int:
        return idaapi.get_imagebase()

    def get_input_sha256(self) -> Optional[str]:
        sha256_bytes = ida_nalt.retrieve_input_file_sha256()
        if not sha256_bytes:
            return None
        return binascii.hexlify(sha256_bytes).decode("ascii")

    def get_entry_points(self) -> Sequence[int]:
        return tuple(ea for _, _, ea, _ in idautils.Entries())
    def iter_segments(self) -> Iterator[Segment]:
        current = ida_segment.get_first_seg()
        if current is None:
            return

        while current is not None:
            yield Segment(
                name=ida_segment.get_segm_name(current),
                start_ea=current.start_ea,
                end_ea=current.end_ea,
            )
            current = ida_segment.get_next_seg(current.start_ea)

    def iter_functions(self) -> Iterator[Function]:
        for func_ea in idautils.Functions():
            func = self.get_function(func_ea)
            if func is not None:
                yield func

    def get_function(self, ea: int) -> Optional[Function]:
        func = idaapi.get_func(ea)
        if func is None or func.start_ea != ea:
            return None
        return self._to_function(func)

    def get_function_containing(self, ea: int) -> Optional[Function]:
        func = idaapi.get_func(ea)
        if func is None:
            return None
        return self._to_function(func)

    def iter_imports(self) -> Iterator[ImportEntry]:
        for index in range(idaapi.get_import_module_qty()):
            module_name = idaapi.get_import_module_name(index)
            if not module_name:
                continue

            normalized_module = module_name.lower().split("/")[-1]
            entries = []

            def collect_import(ea: int, name: str, ordinal: int) -> bool:
                resolved_module = normalized_module
                resolved_name = name

                if name and "@@" in name:
                    symbol_name, symbol_module = name.split("@@", 1)
                    resolved_name = symbol_name
                    if "_" in symbol_module:
                        resolved_module = "_".join(symbol_module.split("_")[:-1])
                    else:
                        resolved_module = symbol_module

                entries.append(
                    ImportEntry(
                        ea=ea,
                        name=resolved_name,
                        module=resolved_module,
                        ordinal=ordinal,
                    )
                )
                return True

            idaapi.enum_import_names(index, collect_import)
            yield from entries

    def iter_strings(self) -> Iterator[StringArtifact]:
        strings = idautils.Strings(False)
        strings.setup(
            strtypes=[
                ida_nalt.STRTYPE_C,
                ida_nalt.STRTYPE_C_16,
                ida_nalt.STRTYPE_C_32,
            ]
        )

        for string_item in strings:
            str_type = idc.get_str_type(string_item.ea)
            if str_type is None:
                continue

            value = ida_bytes.get_strlit_contents(string_item.ea, -1, str_type)
            if not value:
                continue

            yield StringArtifact(
                ea=string_item.ea,
                value=value.decode("utf-8", errors="replace"),
                encoding=str(str_type),
            )

    def iter_call_sites(self, func_ea: Optional[int] = None) -> Iterator[CallSite]:
        if func_ea is None:
            func_starts = tuple(idautils.Functions())
        else:
            func = idaapi.get_func(func_ea)
            if func is None:
                return
            func_starts = (func.start_ea,)

        seen: Set[tuple[int, int, int]] = set()

        for function_start in func_starts:
            func = idaapi.get_func(function_start)
            if func is None:
                continue

            caller_ea = func.start_ea
            for chunk_start, chunk_end in idautils.Chunks(caller_ea):
                for head in idautils.Heads(chunk_start, chunk_end):
                    if not ida_bytes.is_code(ida_bytes.get_full_flags(head)):
                        continue
                    if not idaapi.is_call_insn(head):
                        continue

                    for xref in idautils.XrefsFrom(head, 0):
                        callee = ida_funcs.get_func(xref.to)
                        if callee is None:
                            continue

                        edge = (caller_ea, head, callee.start_ea)
                        if edge in seen:
                            continue
                        seen.add(edge)

                        yield CallSite(
                            caller_ea=caller_ea,
                            call_ea=head,
                            callee_ea=callee.start_ea,
                            is_direct=True,
                        )

    def _to_function(self, func) -> Function:
        flags = idc.get_func_flags(func.start_ea)
        return Function(
            start_ea=func.start_ea,
            end_ea=func.end_ea,
            name=idc.get_func_name(func.start_ea),
            is_library=bool(flags & idc.FUNC_LIB),
            is_thunk=bool(flags & idc.FUNC_THUNK),
        )
