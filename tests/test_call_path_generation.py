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

"""Regression tests for the call-path BFS in core/analyzer.py.

``generate_simple_call_paths`` answers "which functions reference this one"
from a predecessor map inverted once per run from ``caller_xrefs_cache``
instead of issuing one get_xrefs_to + get_function_at backend round-trip per
path expansion. These tests lock in:

  * the BFS produces the same PATH SET as the original list-based
    enumeration (the oracle below preserves the pre-optimization control
    flow: list buffer, list-membership dedup, fresh refs set per step);
  * cycles terminate and self-recursion edges are skipped;
  * ``generate_all_simple_call_paths_for_ep`` builds the predecessor map
    from ``caller_xrefs_cache`` correctly end-to-end.

No IDA / disassembler: bare XRefer instances via ``object.__new__`` and a
synthetic call graph expressed directly as caller_xrefs_cache.
"""

import random

from xrefer.core.analyzer import XRefer


def _bare_xrefer():
    return object.__new__(XRefer)


def _preds_from_graph(graph):
    """graph: caller -> iterable of callees. Returns target -> {callers}."""
    preds = {}
    for caller, callees in graph.items():
        for callee in callees:
            preds.setdefault(callee, set()).add(caller)
    return preds


def _cache_from_graph(graph):
    """graph -> caller_xrefs_cache shape: caller -> {target: {call sites}}."""
    return {caller: {callee: {caller + 0x10} for callee in callees} for caller, callees in graph.items()}


def _oracle_paths(graph, initial, final, max_limit=10000):
    """The pre-optimization BFS (list buffer, list dedup), kept as the oracle."""
    preds = _preds_from_graph(graph)
    all_paths = []
    path_buffer = [[final]]
    while path_buffer and len(all_paths) < max_limit and len(path_buffer) < max_limit:
        refs = set()
        target = path_buffer[0][-1]
        if len(path_buffer[0]) < max_limit:
            refs = set(preds.get(target, set()))
        if refs:
            current_path = path_buffer.pop(0)
            for ref in refs:
                if ref in current_path:
                    continue
                if ref == initial:
                    candidate = (current_path + [ref])[::-1]
                    if candidate not in all_paths:
                        all_paths.append(candidate)
                else:
                    path_buffer.append(current_path + [ref])
        elif initial not in path_buffer[0]:
            path_buffer.pop(0)
        elif initial in path_buffer[0]:
            candidate = path_buffer.pop(0)[::-1]
            if candidate not in all_paths:
                all_paths.append(candidate)
    return all_paths


def _new_paths(graph, initial, final, max_limit=10000):
    xr = _bare_xrefer()
    return xr.generate_simple_call_paths(initial, final, _preds_from_graph(graph), max_limit)


def _as_path_set(paths):
    return {tuple(p) for p in paths}


EP, A, B, C, D, LEAF = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x9000


def test_diamond_finds_both_paths():
    graph = {EP: [A, B], A: [LEAF], B: [LEAF]}
    paths = _new_paths(graph, EP, LEAF)
    assert _as_path_set(paths) == {(EP, A, LEAF), (EP, B, LEAF)}


def test_unreachable_leaf_returns_empty():
    graph = {EP: [A], B: [LEAF]}
    assert _new_paths(graph, EP, LEAF) == []


def test_cycle_terminates_and_paths_survive():
    # A <-> B mutual recursion on the way; the cycle edge must be skipped,
    # the straight path still found, and the BFS must terminate.
    graph = {EP: [A], A: [B, LEAF], B: [A, LEAF]}
    paths = _new_paths(graph, EP, LEAF)
    assert _as_path_set(paths) == {(EP, A, LEAF), (EP, A, B, LEAF)}


def test_self_recursion_is_skipped():
    graph = {EP: [A], A: [A, LEAF]}
    paths = _new_paths(graph, EP, LEAF)
    assert _as_path_set(paths) == {(EP, A, LEAF)}


def test_no_duplicate_paths():
    graph = {EP: [A, B], A: [C], B: [C], C: [LEAF]}
    paths = _new_paths(graph, EP, LEAF)
    assert len(paths) == len(_as_path_set(paths))


def test_max_limit_matches_oracle():
    # max_limit caps BOTH the result count and the working-buffer size (a
    # fan-out >= max_limit aborts enumeration entirely); lock in oracle
    # equivalence rather than a particular interpretation of the cap.
    mids = [0x6000 + i * 0x100 for i in range(8)]
    wide = {EP: mids}
    wide.update({m: [LEAF] for m in mids})
    mixed = {EP: [LEAF, A, B], A: [LEAF], B: [LEAF]}
    for graph in (wide, mixed):
        for limit in (2, 3, 5, 10000):
            new = _new_paths(graph, EP, LEAF, max_limit=limit)
            assert _as_path_set(new) == _as_path_set(_oracle_paths(graph, EP, LEAF, max_limit=limit))
            assert len(new) <= limit


def test_matches_oracle_on_random_graphs():
    rng = random.Random(0xC0FFEE)
    for _ in range(25):
        n_nodes = rng.randint(4, 14)
        nodes = [0x1000 * (i + 1) for i in range(n_nodes)]
        graph = {}
        for src in nodes:
            fanout = rng.randint(0, min(4, n_nodes - 1))
            graph[src] = rng.sample([n for n in nodes if n != src], fanout)
        initial, final = nodes[0], nodes[-1]
        assert _as_path_set(_new_paths(graph, initial, final)) == _as_path_set(_oracle_paths(graph, initial, final))


class _FakeFn:
    def __init__(self, name):
        self.name = name


class _FakeBackend:
    """get_function_at is only used for log labels in the ep loop."""

    def get_function_at(self, address):
        return _FakeFn(f"sub_{int(address):x}")


def test_ep_loop_builds_predecessor_map_from_cache():
    xr = _bare_xrefer()
    xr._backend = _FakeBackend()
    xr.current_analysis_ep = EP
    xr.paths = {}
    xr.leaf_funcs = {LEAF, D}
    # EP -> A -> LEAF and EP -> B -> LEAF; D is never referenced.
    xr.caller_xrefs_cache = _cache_from_graph({EP: [A, B], A: [LEAF], B: [LEAF]})

    xr.generate_all_simple_call_paths_for_ep()

    assert _as_path_set(xr.paths[EP][LEAF]) == {(EP, A, LEAF), (EP, B, LEAF)}
    # Unreachable leaves get no entry at all (len()==0 paths are not stored).
    assert D not in xr.paths[EP]
