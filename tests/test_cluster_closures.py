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

"""Tests for cluster closure partitioning (core/clusters.compute_closures).

Stub clusters carry only .id / .subclusters / .cluster_refs — the fields the
graph builder reads. No IDA / backend needed.
"""

from xrefer.core.clusters import cluster_ids, compute_closures


class _C:
    def __init__(self, cid, subclusters=None, cluster_refs=None):
        self.id = cid
        self.subclusters = subclusters or []
        self.cluster_refs = cluster_refs or {}  # node -> referenced cluster id


def _shape(closures):
    return [sorted(c.id for c in cl) for cl in closures]


def test_isolated_clusters_are_singletons():
    assert _shape(compute_closures([_C(1), _C(2), _C(3)])) == [[1], [2], [3]]


def test_ref_joins_two_clusters():
    cs = [_C(1, cluster_refs={0x1000: 2}), _C(2), _C(3)]
    assert _shape(compute_closures(cs)) == [[1, 2], [3]]


def test_transitive_chain_is_one_closure():
    cs = [_C(1, cluster_refs={0x1: 2}), _C(2, cluster_refs={0x2: 3}), _C(3), _C(4)]
    assert _shape(compute_closures(cs)) == [[1, 2, 3], [4]]


def test_shared_cluster_fuses_components():
    # 1->4, 2->4, 3->4 — all fused through the shared cluster 4.
    cs = [_C(1, cluster_refs={0xa: 4}), _C(2, cluster_refs={0xb: 4}),
          _C(3, cluster_refs={0xc: 4}), _C(4)]
    assert _shape(compute_closures(cs)) == [[1, 2, 3, 4]]


def test_subcluster_ref_pulls_its_top_level_parent():
    # A subcluster of 1 references cluster 2 -> top-levels 1 and 2 are linked,
    # and the closure lists the TOP-LEVEL clusters (subcluster stays nested).
    cs = [_C(1, subclusters=[_C(5, cluster_refs={0xd: 2})]), _C(2), _C(3)]
    assert _shape(compute_closures(cs)) == [[1, 2], [3]]


def test_ref_to_a_subcluster_maps_to_its_root():
    cs = [_C(1, cluster_refs={0xe: 6}), _C(2, subclusters=[_C(6)]), _C(3)]
    assert _shape(compute_closures(cs)) == [[1, 2], [3]]


def test_dangling_ref_is_ignored():
    cs = [_C(1, cluster_refs={0xf: 999}), _C(2)]
    assert _shape(compute_closures(cs)) == [[1], [2]]


def test_cluster_ids_includes_subclusters():
    assert cluster_ids([_C(1, subclusters=[_C(5), _C(6)]), _C(2)]) == {1, 5, 6, 2}
