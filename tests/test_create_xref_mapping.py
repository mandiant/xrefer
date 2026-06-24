# Copyright 2024 Google LLC
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

"""create_xref_mapping: far-only harvest + Python-side chunk containment.

The rewrite must keep func_contains semantics exactly: a reference into a
TAIL CHUNK of the same function is intra-function (skipped), not an
external edge — testing against basic-block bounds instead would have
polluted caller_xrefs_cache with embedded-data/jump-table targets. Also
locks that far_only=True reaches the backend and that backends without
chunk enumeration fall back to the original per-block walk.
"""

from xrefer.backend.base import Address, BasicBlock
from xrefer.core.analyzer import XRefer

MAIN_START, MAIN_END = 0x1000, 0x1100
TAIL_START, TAIL_END = 0x5000, 0x5040
OUTSIDE = 0x9000


class _Ref:
    def __init__(self, source, target):
        self.source = source
        self.target = target


class _ChunkedFunc:
    start = Address(MAIN_START)
    chunk_ranges = [(MAIN_START, MAIN_END), (TAIL_START, TAIL_END)]


class _BlockFunc:
    start = Address(MAIN_START)
    chunk_ranges = None

    @property
    def basic_blocks(self):
        yield BasicBlock(Address(MAIN_START), Address(MAIN_END))

    def __contains__(self, address):
        return MAIN_START <= int(address) < MAIN_END


class _Backend:
    def __init__(self, func, refs_at):
        self._func = func
        self.refs_at = refs_at
        self.far_only_seen = []

    def functions(self):
        yield self._func

    def instructions(self, start, end):
        for addr in sorted(self.refs_at):
            if int(start) <= addr < int(end):
                yield Address(addr)

    def get_xrefs_from(self, address, far_only=False):
        self.far_only_seen.append(far_only)
        return iter(self.refs_at.get(int(address), []))


def _bare_xrefer(backend):
    xr = object.__new__(XRefer)
    xr._backend = backend
    xr.caller_xrefs_cache = {}
    return xr


def test_tail_chunk_targets_are_intra_function():
    refs_at = {
        0x1010: [_Ref(0x1010, TAIL_START + 8)],   # into own tail chunk -> skip
        0x1020: [_Ref(0x1020, MAIN_START + 4)],   # into own main chunk -> skip
        0x1030: [_Ref(0x1030, OUTSIDE)],          # real external edge
        TAIL_START + 4: [_Ref(TAIL_START + 4, OUTSIDE + 0x10)],  # edge FROM the tail chunk
    }
    backend = _Backend(_ChunkedFunc(), refs_at)
    xr = _bare_xrefer(backend)
    xr.create_xref_mapping()
    cache = xr.caller_xrefs_cache
    assert set(cache) == {MAIN_START}
    assert set(cache[MAIN_START]) == {OUTSIDE, OUTSIDE + 0x10}
    assert cache[MAIN_START][OUTSIDE] == {0x1030}
    assert cache[MAIN_START][OUTSIDE + 0x10] == {TAIL_START + 4}


def test_far_only_is_requested_from_the_backend():
    backend = _Backend(_ChunkedFunc(), {0x1010: [_Ref(0x1010, OUTSIDE)]})
    xr = _bare_xrefer(backend)
    xr.create_xref_mapping()
    assert backend.far_only_seen and all(backend.far_only_seen)


def test_no_chunk_info_falls_back_to_block_walk_and_contains():
    refs_at = {
        0x1010: [_Ref(0x1010, MAIN_START + 4)],  # intra -> skip via contains()
        0x1020: [_Ref(0x1020, OUTSIDE)],
    }
    backend = _Backend(_BlockFunc(), refs_at)
    xr = _bare_xrefer(backend)
    xr.create_xref_mapping()
    assert set(xr.caller_xrefs_cache[MAIN_START]) == {OUTSIDE}


def test_multiple_call_sites_accumulate():
    refs_at = {
        0x1010: [_Ref(0x1010, OUTSIDE)],
        0x1020: [_Ref(0x1020, OUTSIDE)],
    }
    backend = _Backend(_ChunkedFunc(), refs_at)
    xr = _bare_xrefer(backend)
    xr.create_xref_mapping()
    assert xr.caller_xrefs_cache[MAIN_START][OUTSIDE] == {0x1010, 0x1020}
