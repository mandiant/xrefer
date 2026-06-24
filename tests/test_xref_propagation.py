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

"""Worklist xref propagation must reach the exact state of the old passes.

propagate_xref_nodes / populate_xref_addrs / fix_thunk_xrefs used to
re-walk every node of every stored path (the same edge recurring across up
to 10k paths per leaf), repeated to fixpoint. The rewrites process each
distinct edge once with re-queue-on-growth. These tests run faithful
oracles of the ORIGINAL algorithms against the same seeded state and
require byte-equal global_xrefs — including the *_ea maps' INSERTION ORDER
(it feeds the INDIRECT table row order) and the create-on-touch entry side
effect for path heads.
"""

import copy
import random

from xrefer.core.analyzer import XRefer

XT = ("libs", "imports", "strings", "capa", "api_trace")
SUFFIX = {"libs": "libs_ea", "imports": "imports_ea", "strings": "strings_ea", "capa": "capa_ea", "api_trace": "api_trace_ea"}
EP = 0x1000


def _template():
    entry = {t: set() for t in XT}
    entry.update({SUFFIX[t]: {} for t in XT})
    return entry


def _bare_xrefer(paths, direct_seed):
    """paths: {leaf: [path, ...]}; direct_seed: {func: {xref_type: {ids}}}."""
    xr = object.__new__(XRefer)
    xr.current_analysis_ep = EP
    xr.paths = {EP: paths}
    xr.entity_suffix_map = dict(SUFFIX)
    xr.global_xrefs = {}
    for func, by_type in direct_seed.items():
        entry = {XRefer.DIRECT_XREFS: _template(), XRefer.INDIRECT_XREFS: _template(), XRefer.COMBINED_XREFS: set()}
        for xref_type, ids in by_type.items():
            entry[XRefer.DIRECT_XREFS][xref_type] = set(ids)
        xr.global_xrefs[func] = entry
    return xr


def _oracle_propagate(xr):
    """The original multi-pass fixpoint, verbatim control flow."""
    modified = True
    while modified:
        modified = False
        for path_group in xr.paths[EP].values():
            for path in path_group:
                child = None
                for func_ea in reversed(path):
                    if child:
                        if xr.merge_xrefs(func_ea, child):
                            modified = True
                    child = func_ea


def _oracle_populate(xr):
    """The original every-node-of-every-path population, verbatim."""
    for path_group in xr.paths[EP].values():
        for path in path_group:
            child = None
            for func_ea in reversed(path):
                parent = xr.ensure_global_xrefs_entry(func_ea)
                for xref_type in XT:
                    for cat in (XRefer.DIRECT_XREFS, XRefer.INDIRECT_XREFS):
                        parent[XRefer.COMBINED_XREFS].update(parent[cat][xref_type])
                        if child is None:
                            continue
                        child_entry = xr.ensure_global_xrefs_entry(child)
                        for xref in child_entry[cat][xref_type]:
                            try:
                                parent[XRefer.INDIRECT_XREFS][SUFFIX[xref_type]][xref].add(child)
                            except KeyError:
                                parent[XRefer.INDIRECT_XREFS][SUFFIX[xref_type]][xref] = {child}
                child = func_ea


def _normalize(global_xrefs):
    """Comparable structure that also captures *_ea key insertion ORDER."""
    out = {}
    for func, entry in global_xrefs.items():
        rec = {}
        for cat in (XRefer.DIRECT_XREFS, XRefer.INDIRECT_XREFS):
            for xref_type in XT:
                rec[(cat, xref_type)] = frozenset(entry[cat][xref_type])
                ea_map = entry[cat][SUFFIX[xref_type]]
                rec[(cat, SUFFIX[xref_type])] = tuple((k, frozenset(v)) for k, v in ea_map.items())
        rec["combined"] = frozenset(entry[XRefer.COMBINED_XREFS])
        out[func] = rec
    return out


def _random_corpus(rng):
    n = rng.randint(4, 9)
    nodes = [0x1000 * (i + 1) for i in range(n)]
    leaves = rng.sample(nodes[1:], rng.randint(1, min(3, n - 1)))
    paths = {}
    for leaf in leaves:
        group = []
        for _ in range(rng.randint(1, 4)):
            mids = rng.sample([x for x in nodes if x not in (EP, leaf)], rng.randint(0, min(3, n - 2)))
            group.append([EP, *mids, leaf])
        paths[leaf] = group
    seed = {}
    eid = 1
    for node in nodes:
        if rng.random() < 0.7:
            by_type = {}
            for xref_type in rng.sample(XT, rng.randint(1, 3)):
                by_type[xref_type] = {eid, eid + 1}
                eid += 2
            seed[node] = by_type
    return paths, seed


def test_propagation_matches_oracle_on_random_corpora():
    rng = random.Random(0x5EED)
    for _ in range(20):
        paths, seed = _random_corpus(rng)
        a = _bare_xrefer(copy.deepcopy(paths), copy.deepcopy(seed))
        b = _bare_xrefer(copy.deepcopy(paths), copy.deepcopy(seed))
        _oracle_propagate(a)
        b.propagate_xref_nodes()
        assert _normalize(a.global_xrefs) == _normalize(b.global_xrefs)
        # Entry side effect: every path node has an entry, path heads included.
        for group in paths.values():
            for path in group:
                for node in path:
                    assert node in b.global_xrefs


def test_populate_matches_oracle_including_row_order():
    rng = random.Random(0xACE)
    for _ in range(20):
        paths, seed = _random_corpus(rng)
        a = _bare_xrefer(copy.deepcopy(paths), copy.deepcopy(seed))
        b = _bare_xrefer(copy.deepcopy(paths), copy.deepcopy(seed))
        _oracle_propagate(a)
        b.propagate_xref_nodes()
        _oracle_populate(a)
        b.populate_xref_addrs()
        assert _normalize(a.global_xrefs) == _normalize(b.global_xrefs)


class _Fn:
    def __init__(self, is_thunk):
        self.is_thunk = is_thunk


class _ThunkBackend:
    def __init__(self, thunks):
        self.thunks = thunks
        self.lookups = []

    def get_function_at(self, ea):
        self.lookups.append(int(ea))
        return _Fn(int(ea) in self.thunks)


def test_fix_thunk_xrefs_matches_original_behavior():
    # EP -> A -> THUNK (leaf, one direct import); many duplicate paths so
    # the old per-path version would redo the same work.
    thunk, a = 0x9000, 0x2000
    paths = {thunk: [[EP, a, thunk]] * 5}
    seed = {thunk: {"imports": {42}}, a: {"strings": {7}}}
    xr = _bare_xrefer(paths, seed)
    xr.propagate_xref_nodes()
    xr._backend = _ThunkBackend({thunk})
    xr.caller_xrefs_cache = {a: {thunk: {0x2010}}}
    xr.entity_xrefs = {42: set()}

    xr.fix_thunk_xrefs()

    direct = xr.global_xrefs[a][XRefer.DIRECT_XREFS]
    assert 42 in direct["imports"]
    assert direct["imports_ea"][42] == {0x2010}
    assert xr.entity_xrefs[42] == {0x2010}
    assert 42 not in xr.global_xrefs[a][XRefer.INDIRECT_XREFS]["imports"]
    # Deduped: the thunk leaf resolved once, not once per stored path.
    assert xr._backend.lookups.count(thunk) == 1
