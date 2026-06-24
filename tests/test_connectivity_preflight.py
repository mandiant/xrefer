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

"""The LLM connectivity preflight must never gate local models on internet.

Air-gapped Ollama is a supported headline use case, and TLS-intercepting
proxies false-fail the raw-IP internet probe even when API access works.
These tests lock the routing in _preflight_connectivity:

  * Ollama model ids probe the Ollama server (actionable error), never the
    internet;
  * any other explicit api_base skips probing entirely;
  * hosted models keep the internet probe, memoized so back-to-back batch
    calls don't re-pay its timeouts.
"""

import pytest

import xrefer.llm.processor as processor_mod
from xrefer.llm.base import ModelConfig
from xrefer.llm.processor import LLMProcessor


@pytest.fixture(autouse=True)
def _reset_probe_memo():
    processor_mod._internet_probe = None
    yield
    processor_mod._internet_probe = None


def _processor(model_id, api_base=None):
    p = LLMProcessor()
    p.config = ModelConfig(model_id=model_id, api_key="k", api_base=api_base)
    return p


def _forbid_internet_probe(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("internet probe must not run for local configs")

    monkeypatch.setattr(processor_mod, "check_internet_connectivity", _boom)


def test_ollama_model_skips_internet_probe(monkeypatch):
    _forbid_internet_probe(monkeypatch)
    import xrefer.llm.ollama as ollama_mod

    monkeypatch.setattr(ollama_mod, "server_reachable", lambda api_base=None, timeout=3.0: True)
    _processor("ollama_chat/gemma3:4b")._preflight_connectivity()


def test_ollama_unreachable_raises_actionable_error(monkeypatch):
    _forbid_internet_probe(monkeypatch)
    import xrefer.llm.ollama as ollama_mod

    monkeypatch.setattr(ollama_mod, "server_reachable", lambda api_base=None, timeout=3.0: False)
    with pytest.raises(ConnectionError) as exc:
        _processor("ollama_chat/gemma3:4b", api_base="http://10.0.0.5:11434")._preflight_connectivity()
    assert "10.0.0.5:11434" in str(exc.value)
    with pytest.raises(ConnectionError) as exc:
        _processor("ollama_chat/gemma3:4b")._preflight_connectivity()
    assert "localhost:11434" in str(exc.value)  # default base named


def test_custom_api_base_skips_all_probes(monkeypatch):
    _forbid_internet_probe(monkeypatch)
    # An OpenAI-compatible local server (vllm, llama.cpp) — not Ollama, so no
    # /api probe either; the real call surfaces any failure.
    _processor("openai/local-model", api_base="http://127.0.0.1:8000/v1")._preflight_connectivity()


def test_hosted_model_probes_and_memoizes(monkeypatch):
    calls = []

    def _probe(*a, **k):
        calls.append(1)
        return True

    monkeypatch.setattr(processor_mod, "check_internet_connectivity", _probe)
    p = _processor("gemini/gemini-2.5-flash")
    p._preflight_connectivity()
    p._preflight_connectivity()
    p._preflight_connectivity()
    assert len(calls) == 1  # memoized within the TTL window


def test_hosted_model_offline_raises(monkeypatch):
    monkeypatch.setattr(processor_mod, "check_internet_connectivity", lambda *a, **k: False)
    with pytest.raises(ConnectionError):
        _processor("gemini/gemini-2.5-flash")._preflight_connectivity()
