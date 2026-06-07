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

"""Tests for hierarchical (bottom-up) stage-1 cluster analysis.

Covers the four moving parts that make a big binary fit a small/local model:
the leaves-first ``bottomup_waves`` scheduler, the summary-aware
``format_cluster_data`` shape, the budget/count packer, the mode-aware
estimate (so the pre-flight gate blocks on the real plan, not the full corpus),
and the ``_run_bottomup_stage1`` driver (coverage + summary propagation +
num_ctx capping). litellm / DSPy / the Ollama REST API are monkeypatched, so no
disassembler, LLM, or network is touched. No IDA imports.
"""

import re
from contextlib import contextmanager

from xrefer.core.clusters import FunctionalCluster as FC
from xrefer.core.clusters import bottomup_waves, cluster_ids
from xrefer.llm.cluster_analyzer import (
    _HIER_RESPONSE_RESERVE,
    ClusterAnalyzer,
    resolve_cluster_context_mode,
)
from xrefer.llm.processor import LLMProcessor


# -- tiny cluster builders --------------------------------------------------


def _leaf(root):
    c = FC(root)
    c.nodes = {root}
    return c


def _parent(root, children):
    c = FC(root)
    c.nodes = {root}
    c.subclusters = list(children)
    for ch in children:
        c.replace_node_with_cluster(ch.root_node, ch.id)
        c.edges.append((root, ch.root_node))
    return c


class _Obj:
    """Minimal XRefer stub: settings + the per-function artifact getters
    ``format_cluster_data`` reads (all empty unless a test overrides one)."""

    def __init__(self, mode="auto", budget=32768):
        self.settings = {
            "enable_exclusions": True,
            "api_base": "http://localhost:11434",
            "llm_model_id": "gemini/gemini-2.5-pro",
            "analysis_options": {
                "cluster_batch_size": 30,
                "local_max_call_tokens": budget,
                "cluster_context_mode": mode,
            },
        }
        self.cluster_token_budget_exceeded = None
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


def _patch_litellm(monkeypatch, window=200000, out=8192):
    monkeypatch.setattr(
        "litellm.token_counter",
        lambda model=None, **kw: (len(kw["text"]) // 4 if "text" in kw else 5000),
    )
    monkeypatch.setattr(
        "litellm.get_model_info",
        lambda m: {"max_input_tokens": window, "max_output_tokens": out, "max_tokens": out},
    )
    monkeypatch.setattr(
        LLMProcessor, "render_request_messages",
        lambda self, pt, item: [{"role": "user", "content": item}],
    )


# -- bottomup_waves ---------------------------------------------------------


def test_waves_leaves_first_and_children_before_parents():
    FC.reset_id_counter()
    a, b = _leaf(0x10), _leaf(0x20)
    p = _parent(0x100, [a, b])
    root = _parent(0x1000, [p])
    waves = bottomup_waves([root])
    pos = {c.id: i for i, w in enumerate(waves) for c in w}
    assert pos[a.id] == 0 and pos[b.id] == 0
    assert pos[a.id] < pos[p.id] < pos[root.id]


def test_waves_shared_subcluster_appears_once():
    FC.reset_id_counter()
    shared = _leaf(0x10)
    p1 = _parent(0x100, [shared])
    p2 = _parent(0x200, [shared])
    root = _parent(0x1000, [p1, p2])
    waves = bottomup_waves([root])
    flat = [c.id for w in waves for c in w]
    assert flat.count(shared.id) == 1
    assert sorted(set(flat)) == sorted(cluster_ids([root]))


def test_waves_within_wave_ordered_by_id():
    FC.reset_id_counter()
    leaves = [_leaf(0x10 + i) for i in range(3)]
    p = _parent(0x100, leaves)
    waves = bottomup_waves([p])
    assert [c.id for c in waves[0]] == sorted(c.id for c in leaves)


# -- resolve_cluster_context_mode -------------------------------------------


def test_mode_resolution_table():
    r = resolve_cluster_context_mode
    # auto: local ALWAYS hierarchical (fit != hardware-comfort)
    assert r("auto", "ollama_chat/llama3", True) == "hierarchical"
    assert r("auto", "ollama_chat/llama3", False) == "hierarchical"
    # auto: commercial fit-triggered
    assert r("auto", "gemini/x", True) == "full"
    assert r("auto", "gemini/x", False) == "hierarchical"
    # forced overrides win regardless of fit/model
    assert r("full", "ollama_chat/llama3", False) == "full"
    assert r("hierarchical", "gemini/x", True) == "hierarchical"
    # default + case-insensitive
    assert r(None, "gemini/x", True) == "full"
    assert r("AUTO", "gemini/x", True) == "full"


# -- format_cluster_data: full vs hierarchical shape ------------------------


def test_hier_format_summarises_children_and_hides_detail():
    FC.reset_id_counter()
    leaf = _leaf(0x10)
    leaf.nodes = {0x10, 0x11}
    parent = _parent(0x100, [leaf])
    obj = _Obj()
    obj.get_strings_for_function = lambda n: ["LEAFSECRET"] if n in (0x10, 0x11) else []
    summaries = {leaf.id: {"label": "Leaf Worker", "description": "does leaf work", "library_or_runtime": 1}}
    out = ClusterAnalyzer.format_cluster_data([parent], obj, respond_for_ids={parent.id}, summaries=summaries)
    assert "Leaf Worker" in out and "does leaf work" in out
    assert f"Subcomponent cluster {leaf.id}" in out
    assert "library/runtime" in out          # leaf marked lib in its summary
    assert "black box" in out.lower()         # the orchestration instruction
    assert "LEAFSECRET" not in out            # child detail must NOT leak


def test_full_format_expands_children_unchanged():
    FC.reset_id_counter()
    leaf = _leaf(0x10)
    leaf.nodes = {0x10}
    parent = _parent(0x100, [leaf])
    obj = _Obj()
    obj.get_strings_for_function = lambda n: ["LEAFSECRET"] if n == 0x10 else []
    out = ClusterAnalyzer.format_cluster_data([parent], obj)
    assert "Subclusters:" in out and "LEAFSECRET" in out
    assert "Subcomponent" not in out


# -- _pack_waves ------------------------------------------------------------


def _ids(calls):
    return [[c.id for c in call] for call in calls]


def _stub(cid):
    """A bare object with just an ``id`` — all ``_pack_waves`` reads."""
    return type("X", (), {"id": cid})()


def test_pack_respects_budget_and_never_mixes_waves():
    waves = [[_stub(1), _stub(2), _stub(3)], [_stub(4)]]
    calls = ClusterAnalyzer._pack_waves(waves, lambda c: 100, 250, 30)
    assert _ids(calls) == [[1, 2], [3], [4]]   # 2 per call by budget; wave 2 separate


def test_pack_respects_batch_size():
    waves = [[_stub(1), _stub(2), _stub(3)]]
    calls = ClusterAnalyzer._pack_waves(waves, lambda c: 1, 10 ** 9, 2)
    assert _ids(calls) == [[1, 2], [3]]


def test_pack_oversized_single_cluster_gets_own_call():
    waves = [[_stub(1), _stub(2)]]
    calls = ClusterAnalyzer._pack_waves(waves, lambda c: 99999, 100, 30)
    assert _ids(calls) == [[1], [2]]


# -- hierarchical estimate --------------------------------------------------


def test_build_hier_context_tags_mode_and_counts(monkeypatch):
    monkeypatch.setattr(ClusterAnalyzer, "current_config", None)
    _patch_litellm(monkeypatch)
    FC.reset_id_counter()
    leaves = [_leaf(0x10 + i) for i in range(4)]
    parent = _parent(0x100, leaves)
    ctx = ClusterAnalyzer.build_hier_estimate_context([parent], _Obj())
    assert ctx.mode == "hierarchical"
    assert ctx.cluster_count == 5          # parent + 4 leaves
    assert ctx.num_calls >= 1


def test_hier_estimate_fixed_response_reserve_commercial(monkeypatch):
    _patch_litellm(monkeypatch, window=1_000_000, out=65535)
    FC.reset_id_counter()
    p = _parent(0x100, [_leaf(0x10)])
    ctx = ClusterAnalyzer.build_hier_estimate_context([p], _Obj())
    est = ClusterAnalyzer.estimate_for_model(ctx, "gemini/x")
    assert est.mode == "hierarchical"
    assert est.max_response_tokens == _HIER_RESPONSE_RESERVE   # not window // 4
    assert est.run_num_ctx is None                              # commercial: n/a


def test_hier_estimate_ollama_num_ctx_clamped(monkeypatch):
    _patch_litellm(monkeypatch)
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 131072)
    FC.reset_id_counter()
    p = _parent(0x100, [_leaf(0x10)])
    ctx = ClusterAnalyzer.build_hier_estimate_context([p], _Obj(budget=32768))
    est = ClusterAnalyzer.estimate_for_model(ctx, "ollama_chat/gemma3")
    assert est.context_window == 131072
    assert 32768 <= est.run_num_ctx <= 131072


def test_estimate_cluster_request_mode_aware(monkeypatch):
    monkeypatch.setattr(ClusterAnalyzer, "current_config", None)
    _patch_litellm(monkeypatch, window=1_000_000)
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 131072)
    FC.reset_id_counter()
    p = _parent(0x100, [_leaf(0x10)])
    obj = _Obj()
    assert ClusterAnalyzer.estimate_cluster_request([p], obj, model_id="ollama_chat/g").mode == "hierarchical"
    assert ClusterAnalyzer.estimate_cluster_request([p], obj, model_id="gemini/x").mode == "full"


def test_estimate_commercial_overflow_falls_to_hierarchical(monkeypatch):
    # A tiny window makes the FULL corpus overflow -> auto picks hierarchical.
    monkeypatch.setattr(ClusterAnalyzer, "current_config", None)
    _patch_litellm(monkeypatch, window=100)
    monkeypatch.setattr("litellm.token_counter", lambda model=None, **kw: 999999)
    FC.reset_id_counter()
    p = _parent(0x100, [_leaf(0x10), _leaf(0x20)])
    est = ClusterAnalyzer.estimate_cluster_request([p], _Obj(), model_id="gemini/x")
    assert est.mode == "hierarchical"


# -- _run_bottomup_stage1: coverage + propagation + num_ctx -----------------


class _FakeProc:
    """Stand-in LLMProcessor: records payloads + LM overrides, and answers a
    stage-1 result for exactly the cluster ids named in the payload's scoping
    note (mirroring how the real LLM is told which ids to return)."""

    def __init__(self, model_id="ollama_chat/x"):
        self.config = type("C", (), {"model_id": model_id})()
        self.payloads = []
        self.overrides = []

    @contextmanager
    def override_lm(self, **kw):
        self.overrides.append(kw)
        yield

    def process_items(self, cluster_data, prompt_type=None, ignore_token_limit=False):
        self.payloads.append(cluster_data)
        m = re.search(r"IDs ([\d,]+)", cluster_data)
        ids = [int(x) for x in m.group(1).split(",")] if m else []
        return {"clusters": {
            f"cluster_{i}": {"label": f"L{i}", "description": f"D{i}", "library_or_runtime": 0}
            for i in ids
        }}


def test_bottomup_covers_every_cluster_and_propagates_summaries(monkeypatch):
    monkeypatch.setattr("litellm.token_counter", lambda model=None, **kw: 100)
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 131072)
    FC.reset_id_counter()
    a, b = _leaf(0x10), _leaf(0x20)
    p = _parent(0x100, [a, b])
    root = _parent(0x1000, [p])
    proc = _FakeProc("ollama_chat/x")
    out = ClusterAnalyzer._run_bottomup_stage1([root], _Obj(), proc, 30, False, "ollama_chat/x")

    # Every cluster (leaves, intermediate, root) produced exactly one entry.
    assert set(out.keys()) == {f"cluster_{i}" for i in cluster_ids([root])}

    # Local model -> every call pinned num_ctx (bounded KV memory).
    assert proc.overrides and all("num_ctx" in o for o in proc.overrides)

    # Propagation: only the parent's call renders BOTH child summaries, proving
    # leaf results flowed up into the parent's payload as summaries.
    parent_call = [pl for pl in proc.payloads if f"L{a.id}" in pl and f"L{b.id}" in pl]
    assert len(parent_call) == 1
    assert "LEAFSECRET" not in parent_call[0]  # (no real detail; sanity)


def test_bottomup_commercial_sets_no_num_ctx(monkeypatch):
    monkeypatch.setattr("litellm.token_counter", lambda model=None, **kw: 100)
    FC.reset_id_counter()
    p = _parent(0x100, [_leaf(0x10)])
    proc = _FakeProc("gemini/x")
    ClusterAnalyzer._run_bottomup_stage1([p], _Obj(), proc, 30, False, "gemini/x")
    assert all("num_ctx" not in o for o in proc.overrides)


def test_bottomup_force_no_cache_sets_cache_off(monkeypatch):
    monkeypatch.setattr("litellm.token_counter", lambda model=None, **kw: 100)
    FC.reset_id_counter()
    p = _parent(0x100, [_leaf(0x10)])
    proc = _FakeProc("gemini/x")
    ClusterAnalyzer._run_bottomup_stage1([p], _Obj(), proc, 30, True, "gemini/x")
    assert proc.overrides and all(o.get("cache") is False for o in proc.overrides)


# -- full analyze_clusters dispatch (both stages, both modes) ----------------


class _DispatchProc(_FakeProc):
    """Extends _FakeProc with the stage-2 synthesis reply + uncached_lm, so the
    whole two-stage analyze_clusters flow runs against it."""

    @contextmanager
    def uncached_lm(self):
        yield

    def render_request_messages(self, pt, item):
        return [{"role": "user", "content": item}]

    def process_items(self, cluster_data, prompt_type=None, ignore_token_limit=False):
        from xrefer.llm.base import PromptType
        if prompt_type == PromptType.BINARY_SYNTHESIZER:
            return {"binary_description": "A test binary.", "binary_category": "Utility",
                    "binary_report": "Stage-2 report body."}
        return super().process_items(cluster_data, prompt_type, ignore_token_limit)


def _run_dispatch(monkeypatch, mode, model):
    monkeypatch.setattr("litellm.token_counter", lambda model=None, **kw: 500)
    monkeypatch.setattr("litellm.get_model_info",
                        lambda m: {"max_input_tokens": 1_000_000, "max_output_tokens": 8192, "max_tokens": 8192})
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 131072)
    FC.reset_id_counter()
    a, b = _leaf(0x10), _leaf(0x20)
    p = _parent(0x100, [a, b])
    root = _parent(0x1000, [p])
    obj = _Obj(mode=mode)
    proc = _DispatchProc(model)
    monkeypatch.setattr(ClusterAnalyzer, "current_config", type("C", (), {"model_id": model})())
    monkeypatch.setattr(ClusterAnalyzer, "_processor", proc)
    res = ClusterAnalyzer.analyze_clusters([root], obj, batch_size=30)
    return res, cluster_ids([root])


def test_dispatch_full_runs_both_stages(monkeypatch):
    res, ids = _run_dispatch(monkeypatch, "full", "gemini/x")
    assert set(res["clusters"].keys()) == {f"cluster_{i}" for i in ids}
    assert res["binary_description"] and res["binary_category"] and res["binary_report"]


def test_dispatch_hierarchical_commercial_runs_both_stages(monkeypatch):
    res, ids = _run_dispatch(monkeypatch, "hierarchical", "gemini/x")
    assert set(res["clusters"].keys()) == {f"cluster_{i}" for i in ids}
    assert res["binary_description"]


def test_dispatch_auto_local_runs_hierarchical(monkeypatch):
    # auto + ollama -> hierarchical; full coverage + stage 2 still complete.
    res, ids = _run_dispatch(monkeypatch, "auto", "ollama_chat/gemma3")
    assert set(res["clusters"].keys()) == {f"cluster_{i}" for i in ids}
    assert res["binary_category"]


class _Stage2FailProc(_DispatchProc):
    """Stage 1 succeeds; the stage-2 synthesis call always raises (mimics a
    small model omitting a required binary-level field)."""

    def process_items(self, cluster_data, prompt_type=None, ignore_token_limit=False):
        from xrefer.llm.base import PromptType
        if prompt_type == PromptType.BINARY_SYNTHESIZER:
            raise ValueError("simulated BinarySynthesisResponse validation error")
        return super().process_items(cluster_data, prompt_type, ignore_token_limit)


def test_dispatch_preserves_stage1_when_stage2_fails(monkeypatch):
    # A stage-2 failure must NOT discard the (expensive) stage-1 per-cluster
    # analyses — the run is saved with placeholder binary-level fields.
    monkeypatch.setattr("litellm.token_counter", lambda model=None, **kw: 500)
    monkeypatch.setattr("litellm.get_model_info",
                        lambda m: {"max_input_tokens": 1_000_000, "max_output_tokens": 8192, "max_tokens": 8192})
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 131072)
    FC.reset_id_counter()
    a, b = _leaf(0x10), _leaf(0x20)
    p = _parent(0x100, [a, b])
    root = _parent(0x1000, [p])
    obj = _Obj(mode="hierarchical")
    proc = _Stage2FailProc("ollama_chat/x")
    monkeypatch.setattr(ClusterAnalyzer, "current_config", type("C", (), {"model_id": "ollama_chat/x"})())
    monkeypatch.setattr(ClusterAnalyzer, "_processor", proc)
    res = ClusterAnalyzer.analyze_clusters([root], obj, batch_size=30)
    # stage-1 coverage preserved despite stage-2 blowing up
    assert set(res["clusters"].keys()) == {f"cluster_{i}" for i in cluster_ids([root])}
    assert res["binary_description"] == ""             # placeholder, not a crash
    assert res["binary_category"] == "Undetermined"


# -- token-accurate sizing (the num_ctx-overflow regression) ----------------


def test_bottomup_num_ctx_bumps_to_cover_large_prompt(monkeypatch):
    # A big per-payload token count makes the call's need exceed the budget, so
    # num_ctx must BUMP above it (clamped to the window) — never sit below the
    # prompt size, which was the bug that ran a 42k prompt under num_ctx=32768.
    monkeypatch.setattr("litellm.token_counter", lambda model=None, **kw: 30000)
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 131072)
    FC.reset_id_counter()
    p = _parent(0x100, [_leaf(0x10)])
    proc = _DispatchProc("ollama_chat/x")
    ClusterAnalyzer._run_bottomup_stage1([p], _Obj(budget=32768), proc, 30, False, "ollama_chat/x")
    assert proc.overrides
    for ov in proc.overrides:
        assert "num_ctx" in ov and ov["num_ctx"] <= 131072   # never exceeds the window
    assert any(ov["num_ctx"] > 32768 for ov in proc.overrides)  # bumped past the budget


def test_bottomup_ollama_drops_cache_seed_on_force_no_cache(monkeypatch):
    # force_no_cache on a LOCAL model must NOT add cache_seed (Ollama warns).
    monkeypatch.setattr("litellm.token_counter", lambda model=None, **kw: 100)
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 131072)
    FC.reset_id_counter()
    p = _parent(0x100, [_leaf(0x10)])
    proc = _DispatchProc("ollama_chat/x")
    ClusterAnalyzer._run_bottomup_stage1([p], _Obj(), proc, 30, True, "ollama_chat/x")
    assert proc.overrides
    assert all(ov.get("cache") is False for ov in proc.overrides)
    assert all("cache_seed" not in ov for ov in proc.overrides)


# -- resilience: one bad call must NOT abort the whole run ------------------


class _FlakyProc(_DispatchProc):
    """Raises on any call whose answerable set intersects ``fail_ids`` (mimics
    a small model emitting output that fails Pydantic validation)."""

    def __init__(self, fail_ids, model_id="ollama_chat/x"):
        super().__init__(model_id)
        self.fail_ids = set(fail_ids)
        self.attempts_on_failing = 0

    def process_items(self, cluster_data, prompt_type=None, ignore_token_limit=False):
        m = re.search(r"IDs ([\d,]+)", cluster_data)
        ids = {int(x) for x in m.group(1).split(",")} if m else set()
        if self.fail_ids & ids:
            self.attempts_on_failing += 1
            raise ValueError("simulated ClusterAnalysisResponse validation error")
        return super().process_items(cluster_data, prompt_type, ignore_token_limit)


def test_bottomup_skips_failing_call_and_completes_rest(monkeypatch):
    monkeypatch.setattr("litellm.token_counter", lambda model=None, **kw: 100)
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 131072)
    FC.reset_id_counter()
    a, b = _leaf(0x10), _leaf(0x20)
    p = _parent(0x100, [a, b])
    root = _parent(0x1000, [p])
    proc = _FlakyProc(fail_ids={a.id})  # the leaf call (a+b packed) always fails
    out = ClusterAnalyzer._run_bottomup_stage1([root], _Obj(), proc, 30, False, "ollama_chat/x")

    assert proc.attempts_on_failing == 2          # tried, retried once, then gave up
    assert f"cluster_{a.id}" not in out           # failing call's clusters skipped
    assert f"cluster_{b.id}" not in out           # (b was packed with a)
    assert f"cluster_{p.id}" in out               # but the run CONTINUED
    assert f"cluster_{root.id}" in out            # all the way to the root


def test_mitre_entry_tolerates_missing_descriptive_fields():
    # A small model that omits tactic/name/rationale must still validate (id is
    # the only required anchor) — otherwise one entry aborts the whole batch.
    from xrefer.llm.dspy_modules import MitreAttackTechnique
    m = MitreAttackTechnique(id="T1083")
    assert m.id == "T1083"
    assert m.tactic == "" and m.name == "" and m.rationale == ""


def test_cluster_analysis_coerces_dict_relationships():
    # Gemma e2b returns `relationships` as a {cluster: cluster} dict ~half the
    # time; coerce it to a readable string instead of failing validation.
    from xrefer.llm.dspy_modules import ClusterAnalysisItem
    item = ClusterAnalysisItem(cluster_id="cluster_1", label="X", description="d",
                               relationships={"cluster_1.0x10": "cluster_2.0x20"},
                               function_prefix="p")
    assert isinstance(item.relationships, str)
    assert "cluster_1.0x10 -> cluster_2.0x20" in item.relationships


def test_cluster_analysis_tolerates_missing_prose_fields():
    # A small model that omits prose fields entirely must still validate
    # (cluster_id is the only required anchor) so one cluster doesn't abort the
    # whole call's batch of clusters.
    from xrefer.llm.dspy_modules import ClusterAnalysisItem
    item = ClusterAnalysisItem(cluster_id="cluster_1")
    assert item.label == "" and item.description == ""
    assert item.relationships == "" and item.function_prefix == ""
