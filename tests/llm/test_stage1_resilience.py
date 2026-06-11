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

"""Stage-1 resilient calls: retry keyed on MISSING IDS, not exceptions.

The processor absorbs rate limits and returns {} without raising, and a
model can silently drop requested cluster ids — so a try/except-only
retry misses both. _resilient_stage1_call's contract is locked here:
completeness check on cluster_<id> keys, cache-bypassed retry, merge
across attempts, and a partial-failure note (skipped ids) when the retry
still comes back short.
"""

from contextlib import contextmanager

from xrefer.llm.cluster_analyzer import ClusterAnalyzer


class _Obj:
    cluster_analysis_failure = None


class _StubProcessor:
    """Replays scripted outcomes; records which attempt contexts ran."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def process_items(self, *a, **k):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _ctx_recorder(record):
    @contextmanager
    def make_ctx(attempt):
        record.append(attempt)
        yield

    return make_ctx


def test_complete_first_attempt_makes_one_call():
    p = _StubProcessor([{"clusters": {"cluster_1": {"label": "a"}, "cluster_2": {"label": "b"}}}])
    attempts = []
    out = ClusterAnalyzer._resilient_stage1_call(p, "data", {1, 2}, _Obj(), _ctx_recorder(attempts))
    assert set(out) == {"cluster_1", "cluster_2"}
    assert p.calls == 1 and attempts == [0]


def test_rate_limited_empty_result_triggers_cache_bypassed_retry():
    p = _StubProcessor([{}, {"clusters": {"cluster_1": {}, "cluster_2": {}}}])
    attempts = []
    out = ClusterAnalyzer._resilient_stage1_call(p, "data", {1, 2}, _Obj(), _ctx_recorder(attempts))
    assert set(out) == {"cluster_1", "cluster_2"}
    assert attempts == [0, 1]  # retry ran under the cache-bypassed context


def test_partial_attempts_merge():
    p = _StubProcessor([
        {"clusters": {"cluster_1": {"label": "from-first"}}},
        {"clusters": {"cluster_2": {"label": "from-retry"}}},
    ])
    out = ClusterAnalyzer._resilient_stage1_call(p, "data", {1, 2}, _Obj(), _ctx_recorder([]))
    assert out["cluster_1"]["label"] == "from-first"
    assert out["cluster_2"]["label"] == "from-retry"


def test_exception_then_success():
    p = _StubProcessor([RuntimeError("validation"), {"clusters": {"cluster_1": {}}}])
    out = ClusterAnalyzer._resilient_stage1_call(p, "data", {1}, _Obj(), _ctx_recorder([]))
    assert set(out) == {"cluster_1"}


def test_still_missing_after_retry_records_skip_note():
    obj = _Obj()
    p = _StubProcessor([
        {"clusters": {"cluster_1": {}}},
        {"clusters": {}},
    ])
    out = ClusterAnalyzer._resilient_stage1_call(p, "data", {1, 2, 3}, obj, _ctx_recorder([]))
    assert set(out) == {"cluster_1"}  # partial work preserved
    note = obj.cluster_analysis_failure
    assert note and note["severity"] == "partial"
    assert note["skipped_cluster_ids"] == [2, 3]


def test_ids_present_parses_and_tolerates_garbage():
    present = ClusterAnalyzer._stage1_ids_present(
        {"cluster_7": {}, "cluster_0012": {}, "weird": {}, "cluster_x": {}}
    )
    assert present == {7, 12}
