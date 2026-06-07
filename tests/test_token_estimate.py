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

"""Tests for the pre-flight cluster-analysis token estimate.

Covers the TokenEstimate value object (total / utilization / warn,
including overflow and unknown-window) and ClusterAnalyzer.estimate_cluster_request's
assembly + graceful-degradation branches. The heavy pieces (cluster
formatting, DSPy message rendering, litellm counting / model-info) are
monkeypatched so the logic is exercised without a disassembler, an LLM,
or network access. No IDA imports.
"""

from xrefer.llm.cluster_analyzer import (
    ClusterAnalyzer,
    EstimateContext,
    TokenEstimate,
    _MAX_RESPONSE_TOKENS_CAP,
    exceeds_context_window,
)
from xrefer.llm.processor import LLMProcessor


class _C:
    """Minimal cluster stub: id + subclusters + cluster_refs — the fields the
    closure partitioner and counter read. Each instance auto-gets a unique id."""

    _counter = 0

    def __init__(self, subclusters=None, cluster_refs=None):
        _C._counter += 1
        self.id = _C._counter
        self.subclusters = subclusters or []
        self.cluster_refs = cluster_refs or {}


class _Obj:
    """Minimal XRefer stub: a settings dict + clusters list."""

    def __init__(self, settings):
        self.settings = settings
        self.clusters = []


# -- TokenEstimate value object ---------------------------------------------


def test_total_tokens_sums_request_and_response():
    assert TokenEstimate("m", 100, 50, 1000, 1, 1, True).total_tokens == 150


def test_response_none_counts_as_zero():
    assert TokenEstimate("m", 1200, None, 2000, 1, 1, True).total_tokens == 1200


def test_utilization_below_threshold_does_not_warn():
    e = TokenEstimate("m", 800, 100, 1000, 1, 1, True)  # 0.90
    assert abs(e.utilization - 0.90) < 1e-9
    assert e.warn is False


def test_warn_fires_at_threshold():
    e = TokenEstimate("m", 900, 50, 1000, 1, 1, True)  # 0.95 exactly
    assert e.warn is True


def test_overflow_utilization_exceeds_one_and_warns():
    e = TokenEstimate("m", 1200, 400, 1000, 1, 1, True)  # 1.60
    assert e.utilization > 1.0
    assert e.warn is True


def test_unknown_window_yields_none_utilization_and_no_warn():
    e = TokenEstimate("m", 1200, 400, None, 1, 1, True)
    assert e.utilization is None
    assert e.warn is False
    assert e.total_tokens == 1600


# -- estimate_cluster_request assembly --------------------------------------


def test_estimate_assembles_rendered_count(monkeypatch):
    monkeypatch.setattr(ClusterAnalyzer, "current_config", None)
    monkeypatch.setattr(ClusterAnalyzer, "format_cluster_data",
                        staticmethod(lambda *a, **k: "PAYLOAD"))
    monkeypatch.setattr(LLMProcessor, "render_request_messages",
                        lambda self, pt, item, model_id=None: [{"role": "user", "content": item}])
    monkeypatch.setattr("litellm.token_counter", lambda model, **kw: 12345)
    monkeypatch.setattr("litellm.get_model_info",
                        lambda m: {"max_input_tokens": 100000,
                                   "max_output_tokens": 8000, "max_tokens": 8000})

    clusters = [_C(subclusters=[_C(), _C()]), _C()]  # 4 total
    obj = _Obj({"llm_model_id": "gemini/x", "analysis_options": {"cluster_batch_size": 2}})
    est = ClusterAnalyzer.estimate_cluster_request(clusters, obj)

    assert est.model_id == "gemini/x"
    assert est.rendered is True
    assert est.request_tokens == 12345
    assert est.max_response_tokens == 8000      # from _build_lm_kwargs via model info
    assert est.context_window == 100000
    assert est.cluster_count == 4
    assert est.num_closures == 2                 # two independent top-level groups
    assert est.num_calls == 3                    # group1 (3 clusters, batch 2)=2 + group2=1
    assert est.warn is False                     # (12345+8000)/100000 ~= 0.20


def test_build_context_fuses_linked_clusters(monkeypatch):
    # Two top-level clusters linked by a cluster_ref -> ONE closure -> ONE call.
    monkeypatch.setattr(ClusterAnalyzer, "current_config", None)
    monkeypatch.setattr(ClusterAnalyzer, "format_cluster_data",
                        staticmethod(lambda *a, **k: "PAYLOAD"))
    monkeypatch.setattr(LLMProcessor, "render_request_messages",
                        lambda self, pt, item, model_id=None: [{"role": "user", "content": item}])
    monkeypatch.setattr("litellm.token_counter", lambda model, **kw: 100)
    monkeypatch.setattr("litellm.get_model_info",
                        lambda m: {"max_input_tokens": 100000, "max_output_tokens": 8000})

    a, b = _C(), _C()
    a.cluster_refs = {0x1000: b.id}   # a references b -> linked into one group
    obj = _Obj({"llm_model_id": "gemini/x", "analysis_options": {"cluster_batch_size": 30}})
    est = ClusterAnalyzer.estimate_cluster_request([a, b], obj)

    assert est.num_closures == 1      # fused
    assert est.cluster_count == 2
    assert est.num_calls == 1         # 2 clusters <= batch 30 -> single call


def test_estimate_without_model_uses_char_fallback(monkeypatch):
    monkeypatch.setattr(ClusterAnalyzer, "current_config", None)
    monkeypatch.setattr(ClusterAnalyzer, "format_cluster_data",
                        staticmethod(lambda *a, **k: "X" * 4000))

    est = ClusterAnalyzer.estimate_cluster_request([_C()], _Obj({}))

    assert est.model_id is None
    assert est.rendered is False
    assert est.request_tokens == 1000            # 4000 // 4
    assert est.context_window is None
    assert est.max_response_tokens is None
    assert est.utilization is None
    assert "No LLM model configured" in est.note


def test_estimate_render_failure_falls_back_to_payload_text(monkeypatch):
    monkeypatch.setattr(ClusterAnalyzer, "current_config", None)
    monkeypatch.setattr(ClusterAnalyzer, "format_cluster_data",
                        staticmethod(lambda *a, **k: "PAYLOAD"))

    def boom(self, pt, item):
        raise RuntimeError("render exploded")

    monkeypatch.setattr(LLMProcessor, "render_request_messages", boom)

    seen = {}

    def fake_counter(model, **kw):
        seen.update(kw)
        return 7

    monkeypatch.setattr("litellm.token_counter", fake_counter)
    monkeypatch.setattr("litellm.get_model_info",
                        lambda m: {"max_input_tokens": 1000, "max_output_tokens": 100})

    est = ClusterAnalyzer.estimate_cluster_request([_C()], _Obj({"llm_model_id": "openai/x"}))

    assert est.rendered is False
    assert est.request_tokens == 7
    assert seen.get("text") == "PAYLOAD"         # fell back to the text= path
    # Render failure is signalled by rendered=False: build_estimate_context
    # sets messages=None silently, then estimate_for_model counts the payload.


# -- estimate_for_model: response cap + per-model estimate -------------------


def _ctx(cluster_data="PAYLOAD"):
    return EstimateContext(cluster_data, [{"role": "user", "content": "x"}], True, 3, 1)


def test_estimate_caps_huge_response_to_ceiling(monkeypatch):
    monkeypatch.setattr("litellm.token_counter", lambda model, **kw: 1000)
    monkeypatch.setattr("litellm.get_model_info",
                        lambda m: {"max_input_tokens": 2_000_000,
                                   "max_output_tokens": 256_000, "max_tokens": 256_000})
    est = ClusterAnalyzer.estimate_for_model(_ctx(), "xai/grok-4")
    assert est.max_response_tokens == _MAX_RESPONSE_TOKENS_CAP   # 256k clamped
    assert est.response_capped is True
    assert est.request_tokens == 1000
    assert est.context_window == 2_000_000


def test_estimate_keeps_response_when_below_cap(monkeypatch):
    monkeypatch.setattr("litellm.token_counter", lambda model, **kw: 1000)
    monkeypatch.setattr("litellm.get_model_info",
                        lambda m: {"max_input_tokens": 1_000_000,
                                   "max_output_tokens": 8192, "max_tokens": 8192})
    est = ClusterAnalyzer.estimate_for_model(_ctx(), "gemini/x")
    assert est.max_response_tokens == 8192
    assert est.response_capped is False


# -- estimate_for_model: Ollama (local) branch ------------------------------


def test_estimate_for_ollama_uses_server_context(monkeypatch):
    monkeypatch.setattr("litellm.token_counter", lambda model, **kw: 5000)
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 131072)
    ctx = EstimateContext("PAYLOAD", [{"role": "user", "content": "x"}], True, 3, 1,
                          api_base="http://localhost:11434")
    est = ClusterAnalyzer.estimate_for_model(ctx, "ollama_chat/llama3.1")
    assert est.context_window == 131072
    assert est.request_tokens == 5000
    # Ollama is shared-budget: reserve window // 4 for the response, capped.
    assert est.max_response_tokens == min(_MAX_RESPONSE_TOKENS_CAP, 131072 // 4)  # 32768


def test_estimate_for_ollama_unknown_context_notes_it(monkeypatch):
    monkeypatch.setattr("litellm.token_counter", lambda model, **kw: 5000)
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: None)
    ctx = EstimateContext("PAYLOAD", [{"role": "user", "content": "x"}], True, 3, 1, api_base=None)
    est = ClusterAnalyzer.estimate_for_model(ctx, "ollama_chat/llama3.1")
    assert est.context_window is None
    assert est.max_response_tokens == _MAX_RESPONSE_TOKENS_CAP
    assert "Ollama server reachable" in est.note


# -- exceeds_context_window: the run-time gate's block predicate ------------


def test_exceeds_when_total_over_window():
    # request 200k + response 60k = 260k > 250k window -> block.
    assert exceeds_context_window(TokenEstimate("m", 200_000, 60_000, 250_000, 1, 1, True)) is True


def test_not_exceeds_when_total_within_window():
    assert exceeds_context_window(TokenEstimate("m", 180_000, 60_000, 250_000, 1, 1, True)) is False


def test_not_exceeds_at_exactly_window():
    # 190k + 60k == 250k; gate blocks only on strict overflow (>), not ==.
    assert exceeds_context_window(TokenEstimate("m", 190_000, 60_000, 250_000, 1, 1, True)) is False


def test_unknown_window_never_blocks():
    # context_window None -> can't prove overflow -> never block.
    assert exceeds_context_window(TokenEstimate("m", 9_000_000, 60_000, None, 1, 1, True)) is False


def test_response_none_treated_as_zero_in_block_check():
    # request 240k + response None(=0) = 240k < 250k -> no block.
    assert exceeds_context_window(TokenEstimate("m", 240_000, None, 250_000, 1, 1, True)) is False
