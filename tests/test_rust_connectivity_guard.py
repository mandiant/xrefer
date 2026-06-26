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

"""Rust EP connectivity guard — the bimodal alphv cluster-collapse fix.

Models the topology measured live on rust-alphv 005994 under Ghidra: the
chosen entry point is the CRT stub (0x4014c0), which reaches only a runtime
sliver, while the real user main (rust_main, 0x489e80) is an ORPHAN — zero
incoming call edges, because Ghidra non-deterministically fails to resolve the
indirect Rust bootstrap call (__lang_start_internal(main_ptr, ...)) — yet has
high out-degree and reach. The guard must re-root at that dominant disconnected
island so clustering recovers (6 -> ~106-142 clusters), and must leave
well-connected / genuinely-fragmented binaries untouched.

These tests exercise _connectivity_guarded_ep directly with a synthetic call
graph (no Ghidra), so they are deterministic regardless of analysis variance.
"""

from xrefer.lang.lang_rust import LangRust


class _Fn:
    def __init__(self, start):
        self.start = start


class _Backend:
    """Minimal backend surface used by _connectivity_guarded_ep: functions()
    and the recover_incomplete_call_graph capability flag."""

    def __init__(self, fvas, recover=True):
        self._fvas = list(fvas)
        self.recover_incomplete_call_graph = recover

    def functions(self):
        return [_Fn(f) for f in self._fvas]


def _lang(adjacency, recover=True):
    """A LangRust whose call graph is the supplied adjacency dict.

    _func_callees is replaced with a pure lookup so the guard's reachability /
    out-degree logic runs against the synthetic graph rather than real xrefs.
    """
    fvas = set(adjacency)
    for callees in adjacency.values():
        fvas.update(callees)
    lang = LangRust()
    lang.backend = _Backend(sorted(fvas), recover=recover)

    def _callees(fva, cache, _adj=adjacency):
        if fva in cache:
            return cache[fva]
        out = set(_adj.get(fva, ()))
        cache[fva] = out
        return out

    lang._func_callees = _callees
    return lang


def _fan(root, base, n):
    """root calls n distinct leaves; root reaches n+1 functions total."""
    leaves = [base + i for i in range(n)]
    return {root: set(leaves)}


EP = 0x4014C0      # CRT stub the bimodal collapse roots at
MAIN = 0x489E80    # the orphaned rust_main (the real user main)


def test_reroots_to_orphan_dominant_island():
    """The measured collapse: EP reaches a minority, an orphan main reaches a
    majority. The guard must re-root at the orphan main."""
    adj = {}
    adj.update(_fan(EP, 0x500000, 299))    # EP reaches 300 (a minority)
    adj.update(_fan(MAIN, 0x600000, 599))  # MAIN reaches 600 (a majority); orphan
    lang = _lang(adj)
    # total funcs = 300 + 600 = 900 -> majority = 450; EP(300) < 450 < MAIN(600)
    assert lang._connectivity_guarded_ep(EP) == MAIN


def test_keeps_well_connected_ep():
    """An EP that already reaches a majority is the real root: returned as-is,
    and the expensive island search is never needed."""
    adj = {}
    adj.update(_fan(EP, 0x500000, 600))    # EP reaches 601 (a majority)
    adj.update(_fan(MAIN, 0x600000, 299))  # a smaller island
    lang = _lang(adj)
    # total = 601 + 300 = 901 -> majority 450; EP(601) >= 450 -> kept
    assert lang._connectivity_guarded_ep(EP) == EP


def test_no_reroot_when_no_dominant_island():
    """Genuinely fragmented binary: EP reaches a minority but no other function
    dominates (none reaches a majority or 10x the EP). Must NOT re-root."""
    adj = {}
    adj.update(_fan(EP, 0x500000, 299))    # EP reaches 300
    adj.update(_fan(MAIN, 0x600000, 320))  # 321 < majority and < 10*300
    # pad with isolated funcs so majority is high enough that neither dominates
    pad = {0x700000 + i: set() for i in range(400)}
    adj.update(pad)
    lang = _lang(adj)
    # total = 300 + 321 + 400 = 1021 -> majority 510; EP 300 < 510, but best
    # island 321 < 510 and 321 < 10*300=3000 -> no dominant island -> keep EP
    assert lang._connectivity_guarded_ep(EP) == EP


def test_reroots_fragmented_island_via_dominance_rule():
    """The 052e0fa2 case: a more fragmented binary where the real user main
    reaches only a MINORITY (~31%) — below the majority — yet still dwarfs the
    stuck CRT entry by ~5x. The dominance rule (>=4x EP and >=25% of program)
    must re-root there; the majority/10x rules alone would miss it."""
    adj = {}
    adj.update(_fan(EP, 0x500000, 113))    # EP reaches 114 (a small sliver)
    adj.update(_fan(MAIN, 0x600000, 559))  # MAIN reaches 560 (~31% of program)
    pad = {0x700000 + i: set() for i in range(1126)}  # total ~1800
    adj.update(pad)
    lang = _lang(adj)
    # total = 114 + 560 + 1126 = 1800 -> majority 900; MAIN 560 < 900 and
    # 560 < 10*114=1140, but 560 >= 4*114=456 and 560 >= 1800//4=450 -> re-root
    assert lang._connectivity_guarded_ep(EP) == MAIN


def test_reroots_genuinely_dead_ep_via_10x_rule():
    """The original strict case still works: an essentially-dead EP (reaches
    almost nothing) re-roots at an island dwarfing it by >=10x even when that
    island is below the program majority."""
    adj = {}
    adj.update(_fan(EP, 0x500000, 3))      # EP reaches 4 (dead)
    adj.update(_fan(MAIN, 0x600000, 199))  # MAIN reaches 200
    pad = {0x700000 + i: set() for i in range(600)}  # majority well above 200
    adj.update(pad)
    lang = _lang(adj)
    # total = 4 + 200 + 600 = 804 -> majority 402; MAIN 200 < 402 (not majority)
    # but 200 >= 10*4=40 -> re-root via the dwarf rule
    assert lang._connectivity_guarded_ep(EP) == MAIN
