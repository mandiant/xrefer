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

"""Unit tests for ClusterManager.coarsen_library_clusters.

Covers the two merge rules (single-child library chains, tiny library leaves)
and the central safety invariant: a non-library (behavior-carrying) cluster is
never absorbed and is never used as a merge sink.
"""

from xrefer.core.clusters import ClusterManager, FunctionalCluster


def make(root, lib, nodes=None, parent_id=None):
    c = FunctionalCluster(root, parent_cluster_id=parent_id, backend=None)
    if nodes:
        c.nodes.update(nodes)
    c.is_library = lib
    return c


def all_ids(clusters):
    out = set()

    def walk(c):
        out.add(c.id)
        for sc in c.subclusters:
            walk(sc)
    for c in clusters:
        walk(c)
    return out


def _node_arts(cluster):
    # tie artifacts to nodes so overlap/distinctness are controllable in tests
    return {("n", x) for x in cluster.nodes}


SIB_KW = dict(overlap_frac=0.75, max_private_nodes=1, min_distinct_artifacts=2)


def test_redundant_siblings_absorbed_into_parent():
    # subA and subB are near-duplicate fragments (share 4/5 nodes, 1 distinct);
    # subC is genuinely distinct. A and B should fold into the parent, C stays.
    root = make(0x1, False, set())
    a = make(0x10, False, {0x10, 0x11, 0x12, 0x13, 0x14})
    b = make(0x20, False, {0x10, 0x11, 0x12, 0x13, 0x15})
    c = make(0x30, False, {0x20, 0x21, 0x22, 0x23, 0x24})
    root.subclusters = [a, b, c]
    for s in root.subclusters:
        s.parent_cluster_id = root.id

    merged = ClusterManager.coarsen_redundant_siblings(
        [root], artifact_fn=_node_arts, **SIB_KW)

    assert merged == 2
    assert root.subclusters == [c]
    assert {0x14, 0x15}.issubset(root.nodes)  # absorbed fragment nodes


def test_distinct_siblings_preserved():
    # no node overlap -> nothing is redundant -> all three survive.
    root = make(0x1, False, set())
    a = make(0x10, False, {0x10, 0x11})
    b = make(0x20, False, {0x20, 0x21})
    c = make(0x30, False, {0x30, 0x31})
    root.subclusters = [a, b, c]
    for s in root.subclusters:
        s.parent_cluster_id = root.id

    merged = ClusterManager.coarsen_redundant_siblings(
        [root], artifact_fn=_node_arts, **SIB_KW)

    assert merged == 0
    assert len(root.subclusters) == 3


def test_all_redundant_keeps_one_representative():
    # all three siblings are identical -> every one is redundant -> keep exactly
    # one representative, merge the other two (never collapse the level entirely).
    # (note: make() folds root_node into nodes, so equal sets need equal members)
    root = make(0x1, False, set())
    a = make(0x10, False, {0x11, 0x12, 0x13, 0x14})  # -> {0x10,0x11,0x12,0x13,0x14}
    b = make(0x11, False, {0x10, 0x12, 0x13, 0x14})  # -> same set
    c = make(0x12, False, {0x10, 0x11, 0x13, 0x14})  # -> same set
    root.subclusters = [a, b, c]
    for s in root.subclusters:
        s.parent_cluster_id = root.id

    merged = ClusterManager.coarsen_redundant_siblings(
        [root], artifact_fn=_node_arts, **SIB_KW)

    assert merged == 2
    assert len(root.subclusters) == 1  # one representative kept


def test_rich_distinct_siblings_not_merged_despite_overlap():
    # siblings overlap on nodes but each carries many distinct artifacts ->
    # the artifact test protects them (mirrors c6b727d7 behavior clusters).
    root = make(0x1, False, set())
    a = make(0x10, False, {0x10, 0x11, 0x12, 0x13, 0x14})
    b = make(0x20, False, {0x10, 0x11, 0x12, 0x13, 0x15})
    root.subclusters = [a, b]
    for s in root.subclusters:
        s.parent_cluster_id = root.id

    # artifact_fn gives each cluster many unique artifacts regardless of nodes
    arts = {a.id: {("x", i) for i in range(10)} | {("u", "a")},
            b.id: {("x", i) for i in range(10)} | {("u", "b")}}
    # 1 distinct each is < min_distinct(2); bump so they read as rich
    arts[a.id] |= {("ua", i) for i in range(5)}
    arts[b.id] |= {("ub", i) for i in range(5)}

    merged = ClusterManager.coarsen_redundant_siblings(
        [root], artifact_fn=lambda c: arts[c.id], **SIB_KW)

    assert merged == 0
    assert len(root.subclusters) == 2


def test_single_child_library_chain_collapses():
    # root(lib) -> mid(lib) -> leaf(lib), each a single child -> collapse to root.
    leaf = make(0x30, True, {0x31})
    mid = make(0x20, True, {0x21})
    mid.subclusters = [leaf]
    leaf.parent_cluster_id = mid.id
    root = make(0x10, True, {0x11})
    root.subclusters = [mid]
    mid.parent_cluster_id = root.id

    merged = ClusterManager.coarsen_library_clusters([root])

    assert merged == 2
    assert root.subclusters == []
    # absorbed nodes rolled up into the surviving root
    assert {0x11, 0x20, 0x21, 0x30, 0x31}.issubset(root.nodes)


def test_tiny_library_leaf_absorbed_only_under_library_parent():
    # libparent(lib) has two tiny library leaves -> both absorbed (not single child,
    # so the tiny-leaf rule is what fires).
    leaf_a = make(0x40, True, {0x41})
    leaf_b = make(0x50, True, {0x51})
    libparent = make(0x10, True, {0x11})
    libparent.subclusters = [leaf_a, leaf_b]
    for sc in libparent.subclusters:
        sc.parent_cluster_id = libparent.id

    merged = ClusterManager.coarsen_library_clusters([libparent])
    assert merged == 2
    assert libparent.subclusters == []


def test_non_library_parent_is_never_a_merge_sink():
    # behavior(lib=False) parent with a tiny library leaf -> leaf must survive,
    # because absorbing it would alter a behavior-carrying cluster.
    tiny_lib = make(0x40, True, {0x41})
    behavior = make(0x10, False, {0x11})
    behavior.subclusters = [tiny_lib]
    tiny_lib.parent_cluster_id = behavior.id

    merged = ClusterManager.coarsen_library_clusters([behavior])
    assert merged == 0
    assert behavior.subclusters == [tiny_lib]


def test_non_library_child_never_absorbed():
    # library parent, single non-library child -> child is protected, not merged.
    behavior_child = make(0x40, False, {0x41})
    libparent = make(0x10, True, {0x11})
    libparent.subclusters = [behavior_child]
    behavior_child.parent_cluster_id = libparent.id

    merged = ClusterManager.coarsen_library_clusters([libparent])
    assert merged == 0
    assert libparent.subclusters == [behavior_child]


def test_cluster_refs_redirected_after_merge():
    # A sibling holds a cluster_ref to a leaf that gets absorbed; the ref must be
    # redirected to the surviving parent so it does not dangle.
    leaf = make(0x30, True, {0x31})
    mid = make(0x20, True, {0x21})
    mid.subclusters = [leaf]
    leaf.parent_cluster_id = mid.id
    root = make(0x10, True, {0x11})
    root.subclusters = [mid]
    mid.parent_cluster_id = root.id
    # someone referenced the leaf by id
    referrer = make(0x80, False, {0x81})
    referrer_node = 0x82
    referrer = referrer  # noqa (keep name explicit below)
    referrer.cluster_refs[referrer_node] = leaf.id

    leaf_id = leaf.id
    mid_id = mid.id
    ClusterManager.coarsen_library_clusters([root, referrer])

    # leaf and mid both absorbed into root -> ref should resolve to root.id
    assert referrer.cluster_refs[referrer_node] == root.id
    assert leaf_id not in all_ids([root, referrer])
    assert mid_id not in all_ids([root, referrer])
