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

"""Behavioral tests for FunctionalCluster.to_graph.

to_graph resolves "real intermediate" membership once per build and memoizes
node labels (each backend name lookup happens at most once per node) instead
of re-scanning intermediate_paths and re-querying the backend per edge
endpoint. These tests lock the rendered graph itself — node labels and edge
set, with and without intermediate nodes — and the at-most-once lookup
guarantee, so the caching cannot drift from the original behavior.
"""

from xrefer.core.clusters import FunctionalCluster

ROOT, A, B, MID, REF = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000
REF_CLUSTER_ID = 77


class CountingBackend:
    """Names functions and counts lookups (one SWIG crossing each in IDA)."""

    def __init__(self):
        self.lookups = []

    def get_name_at(self, address):
        self.lookups.append(int(address))
        return f"sub_{int(address):x}"


def _build_cluster(backend):
    FunctionalCluster.reset_id_counter()
    c = FunctionalCluster(ROOT, backend=backend)
    c.add_edge(ROOT, A)
    c.add_edge(ROOT, B)
    # A reaches a replaced node (cluster reference) through MID, a pure
    # intermediate hop that only exists on the path.
    c.replace_node_with_cluster(REF, REF_CLUSTER_ID)
    c.intermediate_paths[(A, REF)] = [[A, MID, REF]]
    return c


def _analysis():
    return {
        "clusters": {
            f"cluster.id.{1:04d}": {"label": "Root Cluster"},
            f"cluster.id.{REF_CLUSTER_ID:04d}": {"label": "Referenced Cluster"},
        }
    }


def test_simplified_graph_hides_real_intermediates():
    c = _build_cluster(CountingBackend())
    g = c.to_graph(cluster_analysis=_analysis(), include_intermediate=False)
    joined = "||".join(g.nodes())
    assert "0x2000" in joined and "0x3000" in joined
    assert "0x4000" not in joined  # MID is a pure intermediate
    # The cluster ref still shows up — as an isolated candidate node — but
    # the path edges through MID must not.
    assert not any(f"cluster.id.{REF_CLUSTER_ID:04d}" in t for _, t in g.edges())


def test_full_graph_includes_intermediates_with_marker():
    c = _build_cluster(CountingBackend())
    g = c.to_graph(cluster_analysis=_analysis(), include_intermediate=True)
    mid_nodes = [n for n in g.nodes() if "0x4000" in n]
    assert len(mid_nodes) == 1
    assert "(i)" in mid_nodes[0]  # true-intermediate marker preserved
    ref_nodes = [n for n in g.nodes() if f"cluster.id.{REF_CLUSTER_ID:04d}" in n]
    assert len(ref_nodes) == 1
    assert "Referenced Cluster" in ref_nodes[0]
    # Path edges A -> MID -> REF made it in.
    edges = {(s, t) for s, t in g.edges()}
    a_node = next(n for n in g.nodes() if "0x2000" in n)
    assert any(s == a_node and "0x4000" in t for s, t in edges)
    assert any("0x4000" in s and f"cluster.id.{REF_CLUSTER_ID:04d}" in t for s, t in edges)


def test_member_nodes_are_never_treated_as_intermediate():
    # A member that also appears inside an intermediate path keeps its plain
    # label (no "(i)" marker) — membership wins over path presence.
    backend = CountingBackend()
    c = _build_cluster(backend)
    c.intermediate_paths[(B, REF)] = [[B, A, REF]]  # A is a member on a path
    g = c.to_graph(cluster_analysis=_analysis(), include_intermediate=True)
    a_nodes = [n for n in g.nodes() if "0x2000" in n]
    assert len(a_nodes) == 1
    assert "(i)" not in a_nodes[0]


def test_backend_name_lookup_at_most_once_per_node():
    backend = CountingBackend()
    c = _build_cluster(backend)
    # Repeat the same intermediate path from another origin so MID appears as
    # an edge endpoint many times.
    c.intermediate_paths[(B, REF)] = [[B, MID, REF]]
    c.to_graph(cluster_analysis=_analysis(), include_intermediate=True)
    assert len(backend.lookups) == len(set(backend.lookups))


def test_is_real_intermediate_public_api_unchanged():
    c = _build_cluster(CountingBackend())
    assert c.is_real_intermediate(MID) is True
    assert c.is_real_intermediate(A) is False  # member
    assert c.is_real_intermediate(REF) is False  # cluster ref
    assert c.is_real_intermediate(ROOT) is False  # root
