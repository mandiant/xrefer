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

"""fix_thunk_xrefs must forward a thunk's import onto a caller that has no
global_xrefs entry of its own.

global_xrefs entries are created for artifact-bearing functions, plus — in
FULL mode only — every path node via propagate_xref_nodes(). fix_thunk_xrefs
runs in BOTH modes (see tests/test_light_mode_gating.py), so in light mode it
regularly meets a (caller, thunk-leaf) pair whose CALLER has no entry.
Indexing that caller raised KeyError and aborted the whole analysis before
clustering (observed on a Rust PE via the Ghidra backend: KeyError 6010912 /
0x5bb820).

Skipping such callers is not an acceptable fix either: it would silently drop
the thunk's import from the caller in light mode only, which is exactly the
light-vs-full report divergence test_light_mode_gating.py guards against. The
entry must be CREATED and the import forwarded, matching full-mode semantics.
"""

from xrefer.core.analyzer import XRefer

XT = ("libs", "imports", "strings", "capa", "api_trace")
SUFFIX = {"libs": "libs_ea", "imports": "imports_ea", "strings": "strings_ea", "capa": "capa_ea", "api_trace": "api_trace_ea"}
EP = 0x1000
CALLER = 0x2000       # bears no artifacts -> no global_xrefs entry in light mode
THUNK_LEAF = 0x3000   # artifact-bearing thunk -> has an entry
IMPORT_NODE = 42
CALL_SITE = 0x2010


def _template():
    entry = {t: set() for t in XT}
    entry.update({SUFFIX[t]: {} for t in XT})
    return entry


class _Fn:
    def __init__(self, start, is_thunk):
        self.start = start
        self.is_thunk = is_thunk


class _FakeBackend:
    """Only get_function_at is exercised by fix_thunk_xrefs."""

    def __init__(self, thunks):
        self._thunks = thunks

    def get_function_at(self, ea):
        return _Fn(int(ea), int(ea) in self._thunks)


def _xrefer_with_unseeded_caller():
    """Light-mode state: only the thunk leaf has a global_xrefs entry."""
    xr = object.__new__(XRefer)
    xr.current_analysis_ep = EP
    # One path EP -> CALLER -> THUNK_LEAF, so last_edges == [(CALLER, THUNK_LEAF)]
    xr.paths = {EP: {THUNK_LEAF: [[EP, CALLER, THUNK_LEAF]]}}
    xr.entity_suffix_map = dict(SUFFIX)
    xr._backend = _FakeBackend({THUNK_LEAF})
    xr.caller_xrefs_cache = {CALLER: {THUNK_LEAF: {CALL_SITE}}}
    xr.entity_xrefs = {IMPORT_NODE: set()}

    leaf_entry = {
        XRefer.DIRECT_XREFS: _template(),
        XRefer.INDIRECT_XREFS: _template(),
        XRefer.COMBINED_XREFS: set(),
    }
    leaf_entry[XRefer.DIRECT_XREFS]["imports"] = {IMPORT_NODE}
    xr.global_xrefs = {THUNK_LEAF: leaf_entry}
    return xr


def test_thunk_forwarding_survives_caller_without_global_xrefs_entry():
    """The KeyError regression: must not raise, and must forward the import."""
    xr = _xrefer_with_unseeded_caller()
    assert CALLER not in xr.global_xrefs

    xr.fix_thunk_xrefs()  # used to raise KeyError(CALLER)

    assert CALLER in xr.global_xrefs, "caller entry must be created, not skipped"
    direct = xr.global_xrefs[CALLER][XRefer.DIRECT_XREFS]
    assert IMPORT_NODE in direct["imports"], "thunk import must reach the caller"
    assert direct["imports_ea"][IMPORT_NODE] == {CALL_SITE}
    assert CALL_SITE in xr.entity_xrefs[IMPORT_NODE]


def test_light_mode_forwarding_matches_full_mode():
    """Light mode (caller unseeded) must reach the same caller state as full
    mode, where propagate_xref_nodes() pre-created the entry."""
    light = _xrefer_with_unseeded_caller()
    light.fix_thunk_xrefs()

    full = _xrefer_with_unseeded_caller()
    full.ensure_global_xrefs_entry(CALLER)  # what full mode does beforehand
    full.fix_thunk_xrefs()

    ld = light.global_xrefs[CALLER][XRefer.DIRECT_XREFS]
    fd = full.global_xrefs[CALLER][XRefer.DIRECT_XREFS]
    assert ld["imports"] == fd["imports"]
    assert ld["imports_ea"] == fd["imports_ea"]
    assert light.entity_xrefs[IMPORT_NODE] == full.entity_xrefs[IMPORT_NODE]


def test_non_thunk_leaf_is_left_alone():
    """Guard against over-forwarding: a non-thunk leaf must not create or
    touch a caller entry."""
    xr = _xrefer_with_unseeded_caller()
    xr._backend = _FakeBackend(set())  # leaf is NOT a thunk

    xr.fix_thunk_xrefs()

    assert CALLER not in xr.global_xrefs
    assert xr.entity_xrefs[IMPORT_NODE] == set()


def test_leaf_without_global_xrefs_entry_is_skipped():
    """A leaf with no entry at all must be skipped, not created/indexed."""
    xr = _xrefer_with_unseeded_caller()
    xr.global_xrefs = {}  # neither side seeded

    xr.fix_thunk_xrefs()  # must not raise

    assert xr.global_xrefs == {}
