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

"""Local-model (Ollama) LM configuration: the latency fixes proven against a
live Ollama. Two changes, both gated to local models so hosted models are
untouched:

  * ``think=False`` — thinking models (Gemma) otherwise spend the bulk of each
    call generating reasoning tokens before the JSON (~134s vs ~54s for a
    1-cluster call, measured).
  * ``JSONAdapter`` — local models emit raw JSON, not DSPy's ChatAdapter
    ``[[ ## field ## ]]`` markers, so ChatAdapter fails to parse and DSPy
    silently retries with a fallback adapter, doubling every call. JSONAdapter
    parses their native JSON on the first try.

Offline: ``dspy.LM`` constructs without a network call, and the Ollama context
probe is monkeypatched. No IDA imports.
"""

import dspy

from xrefer.llm.base import ModelConfig
from xrefer.llm.processor import LLMProcessor


def test_ollama_lm_kwargs_disable_thinking(monkeypatch):
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length", lambda *a, **k: 8192)
    kw = LLMProcessor()._build_lm_kwargs(
        ModelConfig(model_id="ollama_chat/gemma4:e4b", api_key="", api_base="http://localhost:11434"))
    assert kw.get("think") is False          # no chain-of-thought
    assert "cache_seed" not in kw            # Ollama warns on this option
    assert kw.get("num_ctx") == 8192         # from the /api/show probe
    assert kw.get("timeout")                 # generous local timeout (not 600s default)


def test_commercial_lm_kwargs_have_no_local_options():
    kw = LLMProcessor()._build_lm_kwargs(ModelConfig(model_id="gemini/gemini-2.5-pro", api_key="k"))
    assert "think" not in kw                 # thinking control is local-only
    assert "num_ctx" not in kw
    assert "api_base" not in kw


def test_ollama_selects_json_adapter_and_resets(monkeypatch):
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length", lambda *a, **k: 8192)
    p = LLMProcessor()
    p.set_model_config(ModelConfig(model_id="ollama_chat/gemma4:e4b", api_key="", api_base="http://localhost:11434"))
    assert isinstance(dspy.settings.adapter, dspy.JSONAdapter)
    # Switching to a hosted model mid-session must reset to ChatAdapter.
    p.set_model_config(ModelConfig(model_id="gemini/gemini-2.5-pro", api_key="k"))
    assert isinstance(dspy.settings.adapter, dspy.ChatAdapter)
