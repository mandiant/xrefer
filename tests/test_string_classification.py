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

"""Tests for XRefer.collect_strings — the classification backing the
right-click "Copy ... strings to clipboard" actions. Uses a stub
instance (object.__new__) so the pure selection logic is exercised
without an IDA backend. The orphan category delegates to
collect_orphan_entities (backend-dependent) and is not covered here.

String categorization has two independent sources, both modelled here:
  * language module  -> strings[0] (plain) vs strings[1] (typed);
  * grep.app lookup  -> entity[0] is the repo name, or 'UNCATEGORIZED'.
A string is "uncategorized" only when BOTH say so.
"""

from xrefer.core.analyzer import XRefer, EntityType


class _Ref:
    def __init__(self, i):
        self.entity_index = i


def _make_obj(exclusions=False, excluded=None):
    o = object.__new__(XRefer)
    # entity[0] = grep.app repo name OR 'UNCATEGORIZED'; entity[6] = full
    # string when enriched, else entity[1] (truncated) is used.
    o.entities = [
        ("repoA", "alpha", EntityType.STRING, 0, 0, 0, "alpha_full"),          # 0 grep-categorized
        ("UNCATEGORIZED", "beta", EntityType.STRING),                          # 1 grep-uncat, truncated
        ("g", "CreateFileW", EntityType.IMPORT),                               # 2 not a string
        ("repoB", "gamma", EntityType.STRING, 0, 0, 0, "gamma_full"),          # 3 grep-categorized
        ("UNCATEGORIZED", "delta", EntityType.STRING, 0, 0, 0, "delta_full"),  # 4 grep-uncat
    ]
    o.string_index_cache = [0, 1, 3, 4]
    o.DIRECT_XREFS = 0
    o.INDIRECT_XREFS = 1
    o.global_xrefs = {
        0x1000: {0: {"strings": {0}}, 1: {"strings": {1}}},
        0x2000: {0: {"strings": {4}}, 1: {"strings": set()}},
    }
    o.strings = [[], []]                       # empty live bucket -> persisted fallback
    # language-"plain" indices (strings[0]); alpha(0) and delta(4) are
    # language-typed, so they are NOT here.
    o.uncategorized_string_indices = {1, 3}
    o.settings = {"enable_exclusions": exclusions}
    o.excluded_entities = set(excluded or [])
    return o


def test_all_strings():
    assert _make_obj().collect_strings("all") == ["alpha_full", "beta", "gamma_full", "delta_full"]


def test_directly_referenced():
    assert _make_obj().collect_strings("direct") == ["alpha_full", "delta_full"]


def test_directly_and_indirectly_referenced():
    # direct {0,4} ∪ indirect {1}
    assert _make_obj().collect_strings("direct_indirect") == ["alpha_full", "beta", "delta_full"]


def test_full_string_preferred_over_truncated():
    out = _make_obj().collect_strings("all")
    assert "alpha_full" in out   # entity[6]
    assert "beta" in out         # idx1 has no entity[6] -> truncated entity[1]


# -- uncategorized: must satisfy BOTH sources -----------------------------


def test_uncategorized_requires_both_sources():
    # plain+UNCATEGORIZED -> beta(1). gamma(3) is plain but grep-categorized
    # (repoB); delta(4) is grep-uncat but language-typed. Both excluded.
    assert _make_obj().collect_strings("uncategorized") == ["beta"]


def test_uncategorized_excludes_grep_categorized_plain_string():
    o = _make_obj()
    o.uncategorized_string_indices = {3}   # gamma: plain, but entity[0]='repoB'
    assert o.collect_strings("uncategorized") == []


def test_uncategorized_excludes_language_typed_even_if_grep_uncat():
    o = _make_obj()
    o.uncategorized_string_indices = set()  # delta(4) is grep-uncat but NOT plain
    assert o.collect_strings("uncategorized") == []


def test_uncategorized_prefers_live_bucket_over_persisted():
    o = _make_obj()
    o.uncategorized_string_indices = {4}    # persisted would yield delta_full
    o.strings = [[_Ref(1), _Ref(3)], []]    # live bucket wins -> {1,3}
    # of {1,3}, only beta(1) is also grep-UNCATEGORIZED
    assert o.collect_strings("uncategorized") == ["beta"]


# -- exclusions + misc ----------------------------------------------------


def test_exclusions_filter_when_enabled():
    out = _make_obj(exclusions=True, excluded=[4]).collect_strings("all")
    assert "delta_full" not in out
    assert out == ["alpha_full", "beta", "gamma_full"]


def test_exclusions_ignored_when_disabled():
    assert "delta_full" in _make_obj(exclusions=False, excluded=[4]).collect_strings("all")


def test_unknown_category_returns_empty():
    assert _make_obj().collect_strings("bogus") == []


def test_dedupes_repeated_content():
    o = _make_obj()
    o.entities.append(("repoA", "alpha", EntityType.STRING, 0, 0, 0, "alpha_full"))  # idx 5 dup
    o.global_xrefs[0x3000] = {0: {"strings": {5}}, 1: {"strings": set()}}
    assert o.collect_strings("direct").count("alpha_full") == 1


def test_lib_ified_or_non_string_index_is_dropped():
    # idx 2 is CreateFileW (an IMPORT, i.e. a lib-ified / non-string
    # entity). Even if it leaks into a string source set it must never
    # be emitted as a string.
    o = _make_obj()
    o.string_index_cache = [0, 1, 2, 3, 4]                 # idx 2 = IMPORT
    o.global_xrefs[0x4000] = {0: {"strings": {2}}, 1: {"strings": set()}}
    all_out = o.collect_strings("all")
    direct_out = o.collect_strings("direct")
    assert "CreateFileW" not in all_out
    assert "CreateFileW" not in direct_out
    assert all_out == ["alpha_full", "beta", "gamma_full", "delta_full"]
