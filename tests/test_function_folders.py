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

"""Tests for XRefer.compute_function_folders — the per-function origin verdict
(library vs user) that drives the IDA folder organization. Pure selection
logic, exercised on a stub XRefer (object.__new__) with fake clusters + a fake
backend, so no IDA / disassembler is needed. find_cluster_analysis is
monkeypatched so folder names are deterministic ("NNNN C<id>").

Verdict precedence under test: FUNC_LIB/thunk -> Library (overrides cluster);
single library cluster -> /Library/<path>; single user cluster ->
/User/<path>; multi-cluster -> User unless ALL clusters are library
(fail-open); intermediate/unclustered/simple-thunk -> omitted (root).
"""

import pytest

from xrefer.backend import FunctionType
from xrefer.core import analyzer as analyzer_mod
from xrefer.core.analyzer import XRefer


class _Func:
    def __init__(self, start, ftype=FunctionType.NORMAL, is_thunk=False, name=None):
        self.start = start
        self.type = ftype
        self.is_thunk = is_thunk
        self.name = name if name is not None else f"sub_{start:x}"


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

    def get_function_at(self, addr):  # unused by core, present for parity
        return self._funcs.get(int(getattr(addr, "value", addr)))


@pytest.fixture(autouse=True)
def _deterministic_labels(monkeypatch):
    monkeypatch.setattr(analyzer_mod, "find_cluster_analysis",
                        lambda ca, cid: {"label": f"C{cid}"})


def _xrefer(clusters, funcs, simple_thunks=(), artifact_functions=None):
    o = object.__new__(XRefer)
    o.clusters = clusters
    o.cluster_analysis = {}
    o._backend = _Backend(funcs)
    o.is_simple_api_thunk = lambda ea: ea in set(simple_thunks)
    o.artifact_functions = set(artifact_functions or ())
    return o


def test_single_user_cluster():
    c = _Cluster(1, nodes={0x1000}, is_library=False)
    out = _xrefer([c], [_Func(0x1000)]).compute_function_folders()
    assert out[0x1000] == ["User", "0001 C1"]


def test_single_library_cluster():
    c = _Cluster(42, nodes={0x2000}, is_library=True)
    out = _xrefer([c], [_Func(0x2000)]).compute_function_folders()
    assert out[0x2000] == ["Library", "0042 C42"]


def test_func_lib_overrides_cluster_membership():
    # 0x1000 is a node of a USER cluster, but FUNC_LIB -> Library (flat).
    c = _Cluster(1, nodes={0x1000}, is_library=False)
    out = _xrefer([c], [_Func(0x1000, ftype=FunctionType.LIBRARY)]).compute_function_folders()
    assert out[0x1000] == ["Library"]


def test_thunk_goes_to_library_flat():
    out = _xrefer([], [_Func(0x1000, is_thunk=True)]).compute_function_folders()
    assert out[0x1000] == ["Library"]


def test_simple_api_thunk_is_skipped():
    # Even though FUNC_LIB, a simple API thunk is left at root (not in dict).
    f = _Func(0x1000, ftype=FunctionType.LIBRARY)
    out = _xrefer([], [f], simple_thunks={0x1000}).compute_function_folders()
    assert 0x1000 not in out


def test_multi_cluster_any_user_is_user_bare():
    # node of a user cluster AND a library cluster -> User (fail-open), bare root.
    c1 = _Cluster(1, nodes={0x3000}, is_library=False)
    c2 = _Cluster(2, nodes={0x3000}, is_library=True)
    out = _xrefer([c1, c2], [_Func(0x3000)]).compute_function_folders()
    assert out[0x3000] == ["User"]


def test_multi_cluster_all_library_is_library_bare():
    c1 = _Cluster(1, nodes={0x3000}, is_library=True)
    c2 = _Cluster(2, nodes={0x3000}, is_library=True)
    out = _xrefer([c1, c2], [_Func(0x3000)]).compute_function_folders()
    assert out[0x3000] == ["Library"]


def test_nested_subcluster_path():
    # 0x5000 is a node of subcluster C7, child of top-level C1 (both user).
    c7 = _Cluster(7, nodes={0x5000}, is_library=False, parent_cluster_id=1)
    c1 = _Cluster(1, nodes={0x4000}, is_library=False, subclusters=[c7])
    out = _xrefer([c1], [_Func(0x4000), _Func(0x5000)]).compute_function_folders()
    assert out[0x4000] == ["User", "0001 C1"]
    assert out[0x5000] == ["User", "0001 C1", "0007 C7"]


def test_unclustered_non_lib_is_omitted():
    # No cluster membership, not FUNC_LIB -> left at root (absent from dict).
    out = _xrefer([], [_Func(0x9000)]).compute_function_folders()
    assert 0x9000 not in out


def test_mixed_population_end_to_end():
    c7 = _Cluster(7, nodes={0x5000}, is_library=False, parent_cluster_id=2)
    c1 = _Cluster(1, nodes={0x1000}, is_library=False)               # user
    c2 = _Cluster(2, nodes={0x2000}, is_library=False, subclusters=[c7])  # user + nested
    c42 = _Cluster(42, nodes={0x4000}, is_library=True)              # library
    funcs = [
        _Func(0x1000),                                  # user single -> /User/0001 C1
        _Func(0x2000),                                  # user single -> /User/0002 C2
        _Func(0x5000),                                  # user nested -> /User/0002 C2/0007 C7
        _Func(0x4000),                                  # lib cluster -> /Library/0042 C42
        _Func(0x6000, ftype=FunctionType.LIBRARY),      # FUNC_LIB    -> /Library
        _Func(0x9000),                                  # unclustered -> omitted
    ]
    # 0x1000 also belongs to c42 to exercise multi-cluster (user wins).
    c42.nodes.add(0x1000)
    out = _xrefer([c1, c2, c42], funcs).compute_function_folders()
    assert out[0x1000] == ["User"]                      # multi-cluster, fail-open
    assert out[0x2000] == ["User", "0002 C2"]
    assert out[0x5000] == ["User", "0002 C2", "0007 C7"]
    assert out[0x4000] == ["Library", "0042 C42"]
    assert out[0x6000] == ["Library"]
    assert 0x9000 not in out


# -- intermediates: Option A (fold into the bridged cluster) ----------------


def test_single_bridged_intermediate_folds_into_cluster():
    # 0x6000 is a pure connector on C1's intermediate_paths (not a node) -> it
    # folds into C1, same place as C1's nodes.
    c = _Cluster(1, nodes={0x1000, 0x1100}, is_library=False,
                 intermediate_paths={(0x1000, 0x1100): {(0x1000, 0x6000, 0x1100)}})
    out = _xrefer([c], [_Func(0x1000), _Func(0x1100), _Func(0x6000)]).compute_function_folders()
    assert out[0x6000] == ["User", "0001 C1"]


def test_multi_bridged_intermediate_is_shared():
    # 0x6000 bridges two clusters -> no single home -> shared (bare /User).
    c1 = _Cluster(1, nodes={0x1000, 0x1100},
                  intermediate_paths={(0x1000, 0x1100): {(0x1000, 0x6000, 0x1100)}})
    c2 = _Cluster(2, nodes={0x2000, 0x2100},
                  intermediate_paths={(0x2000, 0x2100): {(0x2000, 0x6000, 0x2100)}})
    funcs = [_Func(0x6000), _Func(0x1000), _Func(0x1100), _Func(0x2000), _Func(0x2100)]
    out = _xrefer([c1, c2], funcs).compute_function_folders()
    assert out[0x6000] == ["User"]


def test_node_membership_beats_intermediate():
    # 0x6000 is a node of C2 AND on C1's intermediate_paths -> node wins.
    c1 = _Cluster(1, nodes={0x1000, 0x1100},
                  intermediate_paths={(0x1000, 0x1100): {(0x1000, 0x6000, 0x1100)}})
    c2 = _Cluster(2, nodes={0x6000}, is_library=False)
    out = _xrefer([c1, c2], [_Func(0x6000), _Func(0x1000), _Func(0x1100)]).compute_function_folders()
    assert out[0x6000] == ["User", "0002 C2"]


def test_artifact_bearing_path_node_is_not_an_intermediate():
    # A function on a path but in artifact_functions is not a "true
    # intermediate" -> no verdict -> left at root.
    c = _Cluster(1, nodes={0x1000, 0x1100},
                 intermediate_paths={(0x1000, 0x1100): {(0x1000, 0x6000, 0x1100)}})
    out = _xrefer([c], [_Func(0x1000), _Func(0x1100), _Func(0x6000)],
                  artifact_functions={0x6000}).compute_function_folders()
    assert 0x6000 not in out


def test_intermediate_inherits_library_origin():
    # Intermediate bridging a single LIBRARY cluster -> /Library/<cluster>.
    c = _Cluster(42, nodes={0x4000, 0x4100}, is_library=True,
                 intermediate_paths={(0x4000, 0x4100): {(0x4000, 0x6000, 0x4100)}})
    out = _xrefer([c], [_Func(0x4000), _Func(0x4100), _Func(0x6000)]).compute_function_folders()
    assert out[0x6000] == ["Library", "0042 C42"]
