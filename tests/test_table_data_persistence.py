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

"""table_data is lazy-only: never persisted, rebuilt on demand.

The eagerly-built context tables were a measured ~58% of the saved DB
(23.6MB of 40.9MB on a 2002-function sample), inflating every save and
every IDB-open load, for tables the viewer already builds lazily per
visit. These tests pin: the saved master_struct carries no table_data
key, the rerun sentinel in analyze() keys on real analysis state instead
of the (now lazy) tables, and a wiped table_data is the rebuild trigger
the viewer's lazy path expects.
"""

import gzip
import pickle

from xrefer.core.analyzer import XRefer


class _Backend:
    name = "ida"


def _saveable_xrefer(tmp_path):
    xr = object.__new__(XRefer)
    xr._backend = _Backend()
    xr.settings = {"paths": {"analysis": str(tmp_path / "sample.exe.xrefer")}}
    xr.image_base = 0x400000
    xr.lang = None
    xr.global_xrefs = {0x1000: {}}
    xr.string_index_cache = [1]
    xr.caller_xrefs_cache = {}
    xr.paths = {0x1000: {}}
    xr.entities = ["e"]
    xr.reverse_entity_lookup_index = {}
    xr.entity_xrefs = {}
    xr.graph_cache = {}
    xr.leaf_funcs = set()
    xr.api_trace_data = {}
    xr.string_storage_addrs = {}
    xr.uncategorized_string_indices = set()
    xr.clusters = []
    xr.cluster_analysis = {}
    xr.selected_refs = {0x1000: {0}}
    # The (lazy) tables may exist in memory — they still must not persist.
    xr.table_data = {0x1000: {"big": "table"}}
    return xr


def test_save_omits_table_data(tmp_path):
    xr = _saveable_xrefer(tmp_path)
    xr.save_analysis()
    with gzip.open(xr.settings["paths"]["analysis"], "rb") as infile:
        metadata = pickle.load(infile)
        master_struct = pickle.load(infile)
    assert metadata["__xrefer_metadata__"] is True
    assert "table_data" not in master_struct
    assert master_struct["paths"] == {0x1000: {}}


def test_analyze_rerun_sentinel_keys_on_analysis_state():
    xr = object.__new__(XRefer)
    xr.global_xrefs = {0x1000: {}}  # analysis already ran this session
    xr.table_data = {}
    called = []
    xr.load_categories = lambda: called.append("load_categories")
    assert xr.analyze() is None
    assert called == []  # early-returned before any pipeline step


def test_old_format_load_assignment_tolerates_both_shapes():
    # The load path reads master_struct.get("table_data", {}) — old DBs keep
    # their persisted tables, new DBs default to empty.
    old_struct = {"table_data": {0x1: {"t": 1}}}
    new_struct = {}
    assert old_struct.get("table_data", {}) == {0x1: {"t": 1}}
    assert new_struct.get("table_data", {}) == {}
