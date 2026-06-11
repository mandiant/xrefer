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

"""Failed / partial cluster runs must be reported, not swallowed.

The core layer records what happened on ``xrefer_obj.cluster_analysis_failure``
(same consume-and-clear contract as ``cluster_token_budget_exceeded``); the
GUI shows a dialog and stops announcing "complete" for runs that were not.
These tests lock the flag-setting logic headlessly:

  * empty stage-1 result -> total failure flag (suppressed when the in-run
    budget gate already set its own flag — no double-reporting);
  * an exception during the LLM run -> total failure flag with the error;
  * partial notes (skipped stage-1 calls, stage-2 fallback) merge instead
    of overwriting each other.
"""

import pytest

from xrefer.core.analyzer import XRefer
from xrefer.llm.cluster_analyzer import ClusterAnalyzer


class _FakeFn:
    name = "sub_2000"


class _FakeBackend:
    def get_function_at(self, address):
        return _FakeFn()


def _bare_xrefer():
    xr = object.__new__(XRefer)
    xr._backend = _FakeBackend()
    xr.current_analysis_ep = 0x1000
    xr.paths = {}
    xr.clusters = None
    xr.cluster_analysis = None
    xr.cluster_token_budget_exceeded = None
    xr.cluster_analysis_failure = None
    xr.analysis_warnings = []
    xr.artifact_functions = {}
    xr.settings = {}
    # One artifact-bearing candidate so the degenerate-cluster fallback fires
    # and the flow reaches the LLM call.
    xr._group_interesting_artifacts = lambda entities: ({0x2000: []}, {}, None)
    return xr


@pytest.fixture(autouse=True)
def _skip_budget_gate(monkeypatch):
    # The pre-flight gate needs a configured model; skipping it (estimate
    # raising) is the no-model headless behavior.
    monkeypatch.setattr(
        ClusterAnalyzer, "estimate_cluster_request",
        classmethod(lambda cls, clusters, xr: (_ for _ in ()).throw(RuntimeError("no model"))),
    )


def test_empty_result_sets_total_failure(monkeypatch):
    monkeypatch.setattr(ClusterAnalyzer, "analyze_clusters", classmethod(lambda cls, *a, **k: {}))
    xr = _bare_xrefer()
    xr.analyze_clusters([1])
    failure = xr.cluster_analysis_failure
    assert failure and failure["severity"] == "total"
    assert failure["error"] == "EmptyResult"


def test_empty_result_suppressed_when_budget_blocked(monkeypatch):
    def _blocked(cls, clusters, xrefer_obj, **kwargs):
        xrefer_obj.cluster_token_budget_exceeded = object()  # in-run gate fired
        return {}

    monkeypatch.setattr(ClusterAnalyzer, "analyze_clusters", classmethod(_blocked))
    xr = _bare_xrefer()
    xr.analyze_clusters([1])
    assert xr.cluster_analysis_failure is None  # budget dialog owns this case


def test_llm_exception_sets_total_failure(monkeypatch):
    def _boom(cls, *a, **k):
        raise RuntimeError("auth failed")

    monkeypatch.setattr(ClusterAnalyzer, "analyze_clusters", classmethod(_boom))
    xr = _bare_xrefer()
    xr.analyze_clusters([1])
    failure = xr.cluster_analysis_failure
    assert failure and failure["severity"] == "total"
    assert failure["error"] == "RuntimeError"
    assert "auth failed" in failure["message"]


def test_clean_run_leaves_no_failure(monkeypatch):
    result = {"clusters": {"cluster_1": {}}, "binary_description": "d", "binary_category": "Tool"}
    monkeypatch.setattr(ClusterAnalyzer, "analyze_clusters", classmethod(lambda cls, *a, **k: dict(result)))
    xr = _bare_xrefer()
    xr.analyze_clusters([1])
    assert xr.cluster_analysis_failure is None
    assert xr.cluster_analysis["binary_category"] == "Tool"


def test_partial_notes_merge():
    class _Obj:
        cluster_analysis_failure = None

    obj = _Obj()
    ClusterAnalyzer._note_partial_failure(obj, stage="stage 1", skipped_cluster_ids={3, 1})
    ClusterAnalyzer._note_partial_failure(obj, stage="stage 1", skipped_cluster_ids={5})
    ClusterAnalyzer._note_partial_failure(obj, stage="stage 2", stage2_failed=True, partial_cluster_count=7)
    note = obj.cluster_analysis_failure
    assert note["severity"] == "partial"
    assert note["skipped_cluster_ids"] == [1, 3, 5]
    assert note["stage2_failed"] is True
    assert note["partial_cluster_count"] == 7
