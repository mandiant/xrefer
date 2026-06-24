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

"""Tests for the dual-model feature: a HEAVY model for cluster analysis and an
optional LIGHT model for categorization.

Two layers:
  * ``resolve_model_configs(settings)`` — the pure routing logic (which model /
    key / base each role gets, incl. same-key reuse, separate key, local mix,
    and back-compat for old settings that lack the light-* keys).
  * ``LLMProcessor._process_single`` — re-asserts THIS processor's own
    lm+adapter per call via ``dspy.context`` (so the two models never clobber
    each other through DSPy's global config). No real LLM / IDA.
"""

import xrefer.llm.processor as P
from xrefer.llm.base import ModelConfig, resolve_model_configs


# --------------------------------------------------------------------------- #
# resolve_model_configs — routing logic
# --------------------------------------------------------------------------- #
_PRIMARY = {"llm_model_id": "gemini/gemini-2.5-pro", "api_key": "PRIMARY_KEY", "api_base": ""}


def test_default_one_model_for_both():
    """No light model → categorization reuses the primary model (the #9 case)."""
    heavy, light = resolve_model_configs(dict(_PRIMARY))
    assert heavy.model_id == light.model_id == "gemini/gemini-2.5-pro"
    assert heavy.api_key == light.api_key == "PRIMARY_KEY"
    assert heavy.ignore_token_limit is True
    assert light.ignore_token_limit is False  # categorizer never ignores limits


def test_backcompat_old_settings_without_light_keys():
    """Settings from before the feature (no light_* keys) behave as 'off'."""
    heavy, light = resolve_model_configs({"llm_model_id": "openai/gpt-4o", "api_key": "K"})
    assert light.model_id == heavy.model_id == "openai/gpt-4o"
    assert light.api_key == "K"


def test_enabled_but_blank_light_model_falls_back():
    """Toggle on but no light model id → still mirrors the primary."""
    s = dict(_PRIMARY, use_light_model=True, light_model_id="")
    heavy, light = resolve_model_configs(s)
    assert light.model_id == heavy.model_id


def test_separate_light_same_key():
    """#5 — different model, reuse the primary key (same provider, cheaper tier)."""
    s = dict(_PRIMARY, use_light_model=True, light_model_id="gemini/gemini-2.5-flash",
             light_use_primary_key=True, light_api_key="")
    heavy, light = resolve_model_configs(s)
    assert heavy.model_id == "gemini/gemini-2.5-pro"
    assert light.model_id == "gemini/gemini-2.5-flash"
    assert light.api_key == "PRIMARY_KEY"  # reused


def test_separate_light_different_key():
    """#5 — different model AND its own distinct key."""
    s = dict(_PRIMARY, use_light_model=True, light_model_id="openai/gpt-4o-mini",
             light_use_primary_key=False, light_api_key="LIGHT_KEY")
    heavy, light = resolve_model_configs(s)
    assert light.model_id == "openai/gpt-4o-mini"
    assert light.api_key == "LIGHT_KEY"
    assert heavy.api_key == "PRIMARY_KEY"  # primary untouched


def test_light_local_ollama_no_key():
    """#6 — hosted heavy + local Ollama light (no key, its own base url)."""
    s = dict(_PRIMARY, use_light_model=True, light_model_id="ollama_chat/llama3.1:8b",
             light_use_primary_key=False, light_api_key="", light_api_base="http://localhost:11434")
    heavy, light = resolve_model_configs(s)
    assert heavy.model_id == "gemini/gemini-2.5-pro" and heavy.api_base is None
    assert light.model_id == "ollama_chat/llama3.1:8b"
    assert light.api_base == "http://localhost:11434"
    assert light.api_key == ""  # local needs none; no primary-key fallback


def test_light_hosted_missing_key_falls_back_to_primary():
    """A hosted light model with an empty own-key falls back to the primary key."""
    s = dict(_PRIMARY, use_light_model=True, light_model_id="xai/grok-4",
             light_use_primary_key=False, light_api_key="")
    _, light = resolve_model_configs(s)
    assert light.api_key == "PRIMARY_KEY"


def test_local_primary_hosted_light_no_key_is_empty():
    """Edge case (documented): a LOCAL primary (no key) + a separate HOSTED light
    model with its own-key blank → light gets an empty key (no primary key to
    borrow). resolve_model_configs produces it; configure_llm_and_lookups warns
    at runtime so categorization's failure is explained, not silent."""
    s = {"llm_model_id": "ollama_chat/llama3.1:8b", "api_key": "", "api_base": "http://localhost:11434",
         "use_light_model": True, "light_model_id": "openai/gpt-4o-mini",
         "light_use_primary_key": False, "light_api_key": ""}
    heavy, light = resolve_model_configs(s)
    assert heavy.model_id == "ollama_chat/llama3.1:8b"
    assert light.model_id == "openai/gpt-4o-mini"
    assert light.api_key == ""  # nothing to borrow → empty (runtime warn covers it)


def test_local_primary_api_base_flows_to_heavy():
    s = {"llm_model_id": "ollama_chat/qwen2.5:7b", "api_key": "", "api_base": "http://host:11434"}
    heavy, light = resolve_model_configs(s)
    assert heavy.api_base == light.api_base == "http://host:11434"


# --------------------------------------------------------------------------- #
# _process_single — per-call routing to this processor's own lm/adapter
# --------------------------------------------------------------------------- #
class _FakeResp:
    def model_dump(self):
        return {"ok": True}


def _patch_dspy_context(monkeypatch):
    captured = {}

    class _Ctx:
        def __init__(self, **kw):
            captured.clear()
            captured.update(kw)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(P.dspy, "context", lambda **kw: _Ctx(**kw))
    return captured


def test_process_single_categorizer_uses_own_lm(monkeypatch):
    captured = _patch_dspy_context(monkeypatch)
    monkeypatch.setattr(P, "CategorizerModule", lambda: (lambda **kw: _FakeResp()))

    proc = P.LLMProcessor()
    proc.lm = object()
    proc.adapter = object()
    out = proc._process_single(["api"], P.PromptType.CATEGORIZER, P.ProcessConfig(categories=["x"], item_type="api"))

    assert out == {"ok": True}
    assert captured["lm"] is proc.lm
    assert captured["adapter"] is proc.adapter


def test_render_request_messages_picks_own_adapter(monkeypatch):
    """Token-estimate rendering must use THIS processor's adapter (not the
    global dspy.settings.adapter, which in dual-model reflects whichever model
    was configured last) — else the heavy estimate is rendered with the light
    model's adapter. When unconfigured, it derives the adapter from model_id."""
    import dspy
    import dspy.adapters as DA
    import xrefer.llm.dspy_modules as DM

    class _FakeChat:
        def format(self, sig, demos, inputs):
            return [{"role": "user", "content": "chat"}]

    class _FakeJSON:
        def format(self, sig, demos, inputs):
            return [{"role": "user", "content": "json"}]

    class _Pred:
        signature = "SIG"

    class _FakeClusterMod:
        def __init__(self):
            self.predictor = _Pred()

    monkeypatch.setattr(DA, "ChatAdapter", _FakeChat)
    monkeypatch.setattr(dspy, "JSONAdapter", _FakeJSON, raising=False)
    monkeypatch.setattr(DM, "ClusterAnalyzerModule", _FakeClusterMod)

    # (a) configured processor → uses its own stored adapter
    proc = P.LLMProcessor()
    proc.adapter = _FakeChat()
    assert proc.render_request_messages(P.PromptType.CLUSTER_ANALYZER, "blob") == [{"role": "user", "content": "chat"}]

    # (b) unconfigured + an Ollama model id → JSONAdapter
    assert P.LLMProcessor().render_request_messages(
        P.PromptType.CLUSTER_ANALYZER, "blob", model_id="ollama_chat/x") == [{"role": "user", "content": "json"}]

    # (c) unconfigured + a hosted model id → ChatAdapter
    assert P.LLMProcessor().render_request_messages(
        P.PromptType.CLUSTER_ANALYZER, "blob", model_id="openai/gpt-4o") == [{"role": "user", "content": "chat"}]


def test_process_single_cluster_uses_own_lm(monkeypatch):
    captured = _patch_dspy_context(monkeypatch)
    monkeypatch.setattr(P, "ClusterAnalyzerModule", lambda: (lambda **kw: _FakeResp()))

    proc = P.LLMProcessor()
    proc.lm = object()
    proc.adapter = None  # adapter omitted → only lm in the context
    out = proc._process_single(["cluster_blob"], P.PromptType.CLUSTER_ANALYZER)

    assert out == {"ok": True}
    assert captured["lm"] is proc.lm
    assert "adapter" not in captured
