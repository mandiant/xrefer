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

"""Categorizer chunking: output-cap-safe sequential batches.

The single giant call overflowed small output caps on first-run Rust/Go
binaries and aborted analysis before the category cache was saved. The
chunked replacement is locked here: chunk boundaries and index rebasing,
the wrapped result shape, Others-fill ONLY within successful chunks
(failed chunks stay uncached so transient 429s are never cached
permanently), and the order-preserving dedup in Categorizer.categorize.
"""

import pytest

from xrefer.llm.base import PromptType
from xrefer.llm.categorizer import CATEGORIES, Categorizer
from xrefer.llm.processor import LLMProcessor, ProcessConfig


def _processor(chunk_results):
    """LLMProcessor whose _process_single is replayed from a list."""
    p = LLMProcessor()
    p._chunks_seen = []
    results = list(chunk_results)

    def _fake_single(items, prompt_type, config=None):
        assert prompt_type == PromptType.CATEGORIZER
        p._chunks_seen.append(list(items))
        return results.pop(0)

    p._process_single = _fake_single
    return p


def _config():
    return ProcessConfig(categories=list(CATEGORIES), item_type="api")


def test_single_chunk_wrapped_shape():
    p = _processor([{"category_assignments": {"0": 3, "1": 5}}])
    out = p._categorize_in_chunks(["a", "b"], _config())
    assert out == {"category_assignments": {"0": 3, "1": 5}}
    assert len(p._chunks_seen) == 1


def test_chunk_boundaries_and_index_rebasing(monkeypatch):
    monkeypatch.setattr(LLMProcessor, "_CATEGORIZER_CHUNK_SIZE", 2)
    p = _processor([
        {"category_assignments": {"0": 1, "1": 2}},
        {"category_assignments": {"0": 3, "1": 4}},
        {"category_assignments": {"0": 5}},
    ])
    out = p._categorize_in_chunks(["a", "b", "c", "d", "e"], _config())
    assert out["category_assignments"] == {"0": 1, "1": 2, "2": 3, "3": 4, "4": 5}
    assert [len(c) for c in p._chunks_seen] == [2, 2, 1]


def test_missed_items_filled_only_in_successful_chunks(monkeypatch):
    monkeypatch.setattr(LLMProcessor, "_CATEGORIZER_CHUNK_SIZE", 2)
    others = CATEGORIES.index("Others")
    p = _processor([
        {"category_assignments": {"0": 1}},  # success, omitted item 1 -> Others
        {},                                   # FAILED chunk -> stays uncached
    ])
    out = p._categorize_in_chunks(["a", "b", "c", "d"], _config())
    assignments = out["category_assignments"]
    assert assignments["0"] == 1
    assert assignments["1"] == others  # model saw it and skipped it
    assert "2" not in assignments and "3" not in assignments  # not cached as Others


def test_categorize_dedups_preserving_order():
    seen = {}

    class _FakeProcessor:
        def validate_api_key(self):
            return True

        def process_items(self, items, **kwargs):
            seen["items"] = list(items)
            return {"category_assignments": {str(i): 0 for i in range(len(items))}}

    saved = Categorizer._processor
    try:
        Categorizer._processor = _FakeProcessor()
        items, _ = Categorizer.categorize(["b", "a", "b", "c", "a"], {})
    finally:
        Categorizer._processor = saved
    assert seen["items"] == ["b", "a", "c"]
    assert set(items) == {"a", "b", "c"}


def test_unsupported_prompt_type_raises():
    p = LLMProcessor()
    p.lm = object()
    p._preflight_connectivity = lambda: None
    with pytest.raises(ValueError):
        p.process_items(["x"], prompt_type="bogus")
