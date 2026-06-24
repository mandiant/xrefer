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

"""Stage-1 batches must share a byte-identical prompt prefix.

The full stage-1 path resends the same corpus every batch; provider
implicit prompt caching (OpenAI/Gemini/DeepSeek) only covers the shared
part if requests are byte-identical up to the first difference. The
batch-varying ID directive therefore lives in the tail ps_note, after the
corpus. These tests pin that property so a future prompt edit cannot
silently re-break caching.
"""

from xrefer.core.clusters import FunctionalCluster as FC
from xrefer.llm.cluster_analyzer import ClusterAnalyzer


class _Obj:
    def __init__(self):
        self.settings = {"enable_exclusions": False}
        self._backend = type("_B", (), {"filetype": lambda self: "PE"})()

    def get_apis_for_function(self, n):
        return []

    def get_libs_for_function(self, n):
        return []

    def get_strings_for_function(self, n):
        return []

    def get_capa_for_function(self, n):
        return []

    def get_direct_calls(self, a, n):
        return []


def _clusters(n):
    FC.reset_id_counter()
    out = []
    for i in range(n):
        c = FC(0x1000 * (i + 1))
        c.nodes = {0x1000 * (i + 1)}
        out.append(c)
    return out


def _common_prefix_len(a: str, b: str) -> int:
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n


def test_consecutive_batches_share_prefix_through_the_corpus():
    clusters = _clusters(4)
    obj = _Obj()
    ids = sorted(c.id for c in clusters)
    batch1 = ClusterAnalyzer.format_cluster_data(clusters, obj, respond_for_ids=set(ids[:2]))
    batch2 = ClusterAnalyzer.format_cluster_data(clusters, obj, respond_for_ids=set(ids[2:]))
    # Identical up to (at least) the end of the corpus block: the only
    # divergence allowed is in the tail ps_note.
    corpus_end = batch1.rindex("</CLUSTER>") + len("</CLUSTER>")
    assert batch1[:corpus_end] == batch2[:corpus_end]
    # And the batch-specific ID lists really are in the tails.
    assert ",".join(map(str, ids[:2])) in batch1[corpus_end:]
    assert ",".join(map(str, ids[2:])) in batch2[corpus_end:]


def test_subset_exclusion_directive_lives_in_the_tail():
    clusters = _clusters(3)
    obj = _Obj()
    ids = sorted(c.id for c in clusters)
    text = ClusterAnalyzer.format_cluster_data(clusters, obj, respond_for_ids={ids[0]})
    corpus_end = text.rindex("</CLUSTER>")
    tail = text[corpus_end:]
    assert "do NOT provide analysis" in tail
    # The pre-corpus note must not contain any batch-varying ID list.
    head = text[:corpus_end]
    assert f"IDs {ids[0]}" not in head


def test_full_set_run_is_unchanged_shape():
    clusters = _clusters(2)
    obj = _Obj()
    ids = {c.id for c in clusters}
    text = ClusterAnalyzer.format_cluster_data(clusters, obj, respond_for_ids=ids)
    # No subset note at the head, plain ps_note at the tail.
    assert "context only" not in text
    assert "Enumerate and ensure you return results" in text
