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


# ── collapse_pure_library_subtrees ─────────────────────────────────────────

def _make_tree(root, children):
    """Attach children (FunctionalClusters) to root, setting parent ids."""
    root.subclusters = list(children)
    for c in children:
        c.parent_cluster_id = root.id
    return root


def test_bushy_pure_library_subtree_collapses_to_one():
    # A behavior root with one bushy fully-library child subtree:
    #   beh(root) -> lib_a(lib) -> {lib_b(lib), lib_c(lib) -> lib_d(lib)}
    # The maximal pure-library subtree is lib_a; it folds to a single node.
    lib_d = make(0x50, True, {0x51})
    lib_c = _make_tree(make(0x40, True, {0x41}), [lib_d])
    lib_b = make(0x30, True, {0x31})
    lib_a = _make_tree(make(0x20, True, {0x21}), [lib_b, lib_c])
    root = _make_tree(make(0x10, False, {0x11}), [lib_a])

    removed = ClusterManager.collapse_pure_library_subtrees([root])

    assert removed == 3                       # b, c, d folded into a
    assert root.subclusters == [lib_a]        # behavior root + lib root kept
    assert lib_a.subclusters == []            # flattened to a leaf
    # every node is preserved (rolled up into the surviving subtree root)
    assert {0x21, 0x30, 0x31, 0x40, 0x41, 0x50, 0x51}.issubset(lib_a.nodes)


def test_subtree_with_behavior_descendant_not_collapsed():
    # lib parent whose subtree contains a behavior cluster is NOT pure-library,
    # so nothing in that subtree is collapsed (behavior must be reachable).
    behavior_leaf = make(0x50, False, {0x51})
    lib_mid = _make_tree(make(0x40, True, {0x41}), [behavior_leaf])
    lib_root = _make_tree(make(0x20, True, {0x21}), [lib_mid])

    removed = ClusterManager.collapse_pure_library_subtrees([lib_root])

    assert removed == 0
    assert lib_root.subclusters == [lib_mid]
    assert lib_mid.subclusters == [behavior_leaf]


def test_mixed_behavior_parent_collapses_only_pure_library_siblings():
    # beh_root -> { pure_lib_subtree, behavior_child(with lib grandchild) }
    # Only the pure-library sibling collapses; the behavior child and its
    # (mixed) subtree are untouched.
    pure_gc = make(0x60, True, {0x61})
    pure_lib = _make_tree(make(0x50, True, {0x51}), [pure_gc])          # pure
    lib_under_beh = make(0x40, True, {0x41})
    beh_child = _make_tree(make(0x30, False, {0x31}), [lib_under_beh])  # mixed
    root = _make_tree(make(0x10, False, {0x11}), [pure_lib, beh_child])

    removed = ClusterManager.collapse_pure_library_subtrees([root])

    assert removed == 1                        # only pure_gc folds into pure_lib
    assert pure_lib.subclusters == []
    assert beh_child.subclusters == [lib_under_beh]   # behavior subtree intact
    assert {0x61}.issubset(pure_lib.nodes)


def test_no_library_subtree_is_a_noop():
    # C/C++-like shape: behavior clusters with at most isolated library leaves
    # that are already maximal (no descendants) -> nothing to fold.
    lib_leaf = make(0x30, True, {0x31})          # pure but childless -> no-op
    beh = make(0x20, False, {0x21})
    root = _make_tree(make(0x10, False, {0x11}), [beh, lib_leaf])

    removed = ClusterManager.collapse_pure_library_subtrees([root])

    assert removed == 0
    assert root.subclusters == [beh, lib_leaf]


def test_top_level_pure_library_root_collapses():
    # A top-level fully-library tree collapses to its root (parent is None).
    gc = make(0x30, True, {0x31})
    child = _make_tree(make(0x20, True, {0x21}), [gc])
    top = _make_tree(make(0x10, True, {0x11}), [child])

    removed = ClusterManager.collapse_pure_library_subtrees([top])

    assert removed == 2
    assert top.subclusters == []
    assert {0x21, 0x30, 0x31}.issubset(top.nodes)


def test_cluster_refs_redirected_after_subtree_collapse():
    # A behavior cluster references a node inside a folded library subtree;
    # the ref must redirect to the surviving subtree root.
    gc = make(0x30, True, {0x31})
    lib_root = _make_tree(make(0x20, True, {0x21}), [gc])
    root = _make_tree(make(0x10, False, {0x11}), [lib_root])
    referrer = make(0x80, False, {0x81})
    referrer.cluster_refs[0x82] = gc.id
    root.subclusters.append(referrer)
    referrer.parent_cluster_id = root.id

    gc_id = gc.id
    ClusterManager.collapse_pure_library_subtrees([root])

    assert referrer.cluster_refs[0x82] == lib_root.id
    assert gc_id not in all_ids([root])
