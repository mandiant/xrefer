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

"""Block-level cluster filter (S in the clusters-table view).

The cluster table renders multi-line blocks (tree glyphs + wrapped
descriptions), so the per-view filter keeps/drops whole blocks:
``cluster_filter_match_ids`` decides which clusters match the typed
text, ``cluster_subtree_matches`` keeps ancestors of matches so the
tree stays rooted. Both are pure and run headless; the renderer's
pruning in gui/helpers is a two-line application of the second.
"""

from xrefer.core.clusters import (
    FunctionalCluster,
    cluster_filter_match_ids,
    cluster_subtree_matches,
)

ROOT_EA, CHILD_EA, GRAND_EA, SIB_EA, OTHER_EA = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000


def _tree():
    """root(1) -> [child(2) -> grand(3), sib(4)]; other(5) top-level."""
    FunctionalCluster.reset_id_counter()
    root = FunctionalCluster(ROOT_EA)
    child = FunctionalCluster(CHILD_EA, parent_cluster_id=root.id)
    grand = FunctionalCluster(GRAND_EA, parent_cluster_id=child.id)
    sib = FunctionalCluster(SIB_EA, parent_cluster_id=root.id)
    other = FunctionalCluster(OTHER_EA)
    child.subclusters.append(grand)
    root.subclusters.extend([child, sib])
    return [root, other]


_ANALYSIS = {
    "clusters": {
        "cluster_0001": {"label": "Network Comms", "description": "Sends beacons upstream", "relationships": ""},
        "cluster_0002": {"label": "Crypto", "description": "RC4 key schedule", "relationships": "feeds cluster.id.0001"},
        "cluster_0003": {"label": "Persistence", "description": "Registry run key", "relationships": ""},
        "cluster_0004": {"label": "Disk IO", "description": "", "relationships": ""},
        "cluster_0005": {"label": "Loader", "description": "", "relationships": ""},
    }
}


def test_matches_label_description_and_relationships():
    clusters = _tree()
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "crypto") == {2}
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "registry run") == {3}
    # Relationships text is rendered in the block, so it is searchable —
    # and the cluster.id token inside it also matches the referenced form.
    assert 2 in cluster_filter_match_ids(clusters, _ANALYSIS, "feeds cluster.id.0001")


def test_matches_rendered_id_token_and_node_address():
    clusters = _tree()
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "cluster.id.0004") == {4}
    assert cluster_filter_match_ids(clusters, _ANALYSIS, f"0x{OTHER_EA:x}") == {5}


def test_match_is_case_insensitive_and_empty_filter_matches_nothing():
    clusters = _tree()
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "CRYPTO") == {2}
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "") == set()
    assert cluster_filter_match_ids(clusters, None, "crypto") == set()


def test_function_names_match_only_through_the_resolver():
    clusters = _tree()
    resolver = {GRAND_EA: "decrypt_strings"}.get
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "decrypt_str") == set()
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "decrypt_str", name_resolver=resolver) == {3}


def test_subtree_matches_keeps_ancestors_and_drops_unrelated():
    root, other = _tree()
    child, sib = root.subclusters
    grand = child.subclusters[0]
    match_ids = {grand.id}
    # Ancestors of the match survive (the block stays rooted) …
    assert cluster_subtree_matches(root, match_ids)
    assert cluster_subtree_matches(child, match_ids)
    assert cluster_subtree_matches(grand, match_ids)
    # … unrelated branches and trees do not.
    assert not cluster_subtree_matches(sib, match_ids)
    assert not cluster_subtree_matches(other, match_ids)


def test_parent_match_does_not_keep_children_blocks():
    root, other = _tree()
    child, sib = root.subclusters
    match_ids = cluster_filter_match_ids([root, other], _ANALYSIS, "network comms")
    assert match_ids == {root.id}
    # The renderer keeps a subcluster only when ITS subtree matches:
    # a parent-only match renders the parent block alone.
    assert not cluster_subtree_matches(child, match_ids)
    assert not cluster_subtree_matches(sib, match_ids)


def test_excluded_ids_suppress_own_text_but_keep_descendants_searchable():
    clusters = _tree()
    # 'crypto' lives in cluster 2's analysis text. When the renderer is
    # trimming cluster 2 (hidden library block), a hit in its invisible
    # text must not keep its ancestors …
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "crypto", excluded_ids={2}) == set()
    # … but its descendants still render (lifted), so they stay matchable.
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "registry run", excluded_ids={2}) == {3}


def test_rendered_bracket_id_form_matches():
    clusters = _tree()
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "[0004]") == {4}


def test_constant_token_prefix_does_not_match_every_block():
    clusters = _tree()
    # Substrings of the invisible 'cluster.id.' constant must not match
    # all blocks — only text the table actually renders counts (here,
    # cluster 2's relationships cite 'cluster.id.0001').
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "cluster") == {2}
    # The full discriminating token still works.
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "cluster.id.0004") == {4}


def test_truncated_rendered_function_name_matches():
    clusters = _tree()
    resolver = {GRAND_EA: "decrypt_strings_inplace"}.get
    # The table renders long names as name[:11] + '..' — typing the
    # on-screen form must match the same cluster as the full name.
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "decrypt_str..", name_resolver=resolver) == {3}
    assert cluster_filter_match_ids(clusters, _ANALYSIS, "decrypt_strings_inplace", name_resolver=resolver) == {3}
