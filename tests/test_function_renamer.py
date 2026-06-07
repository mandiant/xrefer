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

"""Tests for XRefer.rename_cluster_functions — the improved cluster renamer.

Verifies it: only touches auto-named functions (never FLIRT/user names); skips
library + unclustered functions; names cluster members ``<prefix>_<addr>`` and
shared functions ``xutil_<addr>``; folds single-bridged intermediates into
their cluster's prefix (Option A); and re-prefixes names xrefer assigned on an
earlier run. Stub XRefer + fake backend; the real find_cluster_analysis drives
the prefix lookup (so cluster_analysis carries real keys).
"""

from xrefer.backend import FunctionType
from xrefer.core.analyzer import XRefer


class _Func:
    def __init__(self, start, ftype=FunctionType.NORMAL, is_thunk=False, name=None, default=True):
        self.start = start
        self.type = ftype
        self.is_thunk = is_thunk
        self._name = name if name is not None else f"sub_{start:x}"
        self.has_default_name = default

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value


class _Cluster:
    def __init__(self, cid, nodes, is_library=False, parent_cluster_id=None, subclusters=None,
                 root_node=None, cluster_refs=None, intermediate_paths=None):
        self.id = cid
        self.nodes = set(nodes)
        self.is_library = is_library
        self.parent_cluster_id = parent_cluster_id
        self.subclusters = subclusters or []
        self.root_node = root_node if root_node is not None else (min(nodes) if nodes else 0)
        self.cluster_refs = cluster_refs or {}
        self.intermediate_paths = intermediate_paths or {}


class _Backend:
    def __init__(self, funcs):
        self._funcs = {f.start: f for f in funcs}

    def functions(self):
        return list(self._funcs.values())

    def get_function_at(self, addr):
        return self._funcs.get(int(getattr(addr, "value", addr)))


# Real cluster-analysis shape: cluster 1 -> "netc2", cluster 2 -> "fileenc".
_CA = {"clusters": {"1": {"function_prefix": "netc2"}, "2": {"function_prefix": "fileenc"}}}


def _xrefer(clusters, funcs, cluster_analysis=_CA, simple_thunks=(), artifact_functions=None):
    o = object.__new__(XRefer)
    o.clusters = clusters
    o.cluster_analysis = cluster_analysis
    o._backend = _Backend(funcs)
    o.is_simple_api_thunk = lambda ea: ea in set(simple_thunks)
    o.artifact_functions = set(artifact_functions or ())
    return o


def test_single_cluster_node_gets_cluster_prefix():
    f = _Func(0x1000)
    _xrefer([_Cluster(1, nodes={0x1000})], [f]).rename_cluster_functions()
    assert f.name == "netc2_1000"


def test_func_lib_is_not_renamed():
    f = _Func(0x1000, ftype=FunctionType.LIBRARY)
    _xrefer([_Cluster(1, nodes={0x1000})], [f]).rename_cluster_functions()
    assert f.name == "sub_1000"


def test_already_named_function_is_not_clobbered():
    # has_default_name=False (FLIRT/user name) -> never renamed, even in a cluster.
    f = _Func(0x1000, name="memcpy", default=False)
    _xrefer([_Cluster(1, nodes={0x1000})], [f]).rename_cluster_functions()
    assert f.name == "memcpy"


def test_multi_cluster_node_gets_shared_prefix():
    f = _Func(0x1000)
    _xrefer([_Cluster(1, nodes={0x1000}), _Cluster(2, nodes={0x1000})], [f]).rename_cluster_functions()
    assert f.name == "xutil_1000"


def test_unclustered_function_is_not_renamed():
    other = _Func(0x9000)
    _xrefer([_Cluster(1, nodes={0x1000})], [_Func(0x1000), other]).rename_cluster_functions()
    assert other.name == "sub_9000"


def test_single_bridged_intermediate_gets_cluster_prefix():
    glue = _Func(0x6000)
    c = _Cluster(1, nodes={0x1000, 0x1100},
                 intermediate_paths={(0x1000, 0x1100): {(0x1000, 0x6000, 0x1100)}})
    _xrefer([c], [_Func(0x1000), _Func(0x1100), glue]).rename_cluster_functions()
    assert glue.name == "netc2_6000"


def test_rerun_reprefixes_xrefer_named_function():
    # xrefer named this netc2_1000 earlier (no longer "default"); the function
    # now belongs to cluster 2 -> re-run re-applies the new prefix.
    f = _Func(0x1000, name="netc2_1000", default=False)
    _xrefer([_Cluster(2, nodes={0x1000})], [f]).rename_cluster_functions()
    assert f.name == "fileenc_1000"


def test_cluster_without_prefix_is_skipped():
    f = _Func(0x1000)
    _xrefer([_Cluster(7, nodes={0x1000})], [f]).rename_cluster_functions()
    assert f.name == "sub_1000"


def test_no_cluster_analysis_is_a_noop():
    f = _Func(0x1000)
    _xrefer([_Cluster(1, nodes={0x1000})], [f], cluster_analysis={}).rename_cluster_functions()
    assert f.name == "sub_1000"
