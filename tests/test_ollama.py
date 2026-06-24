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

"""Tests for the Ollama local-model helpers (httpx patched — no live server)
and their integration into _build_lm_kwargs. No IDA imports."""

import httpx

from xrefer.llm import ollama
from xrefer.llm.base import ModelConfig
from xrefer.llm.processor import LLMProcessor


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


# -- is_ollama_model --------------------------------------------------------


def test_is_ollama_model():
    assert ollama.is_ollama_model("ollama_chat/llama3.1")
    assert ollama.is_ollama_model("ollama/llama3")
    assert not ollama.is_ollama_model("gemini/gemini-2.5-pro")
    assert not ollama.is_ollama_model("")
    assert not ollama.is_ollama_model(None)


# -- list_models (GET /api/tags) --------------------------------------------


def test_list_models_parses_tags(monkeypatch):
    payload = {"models": [{"name": "llama3.1:8b"}, {"name": "qwen2.5:latest"}, {"model": "mistral:7b"}]}
    monkeypatch.setattr(httpx, "get", lambda url, timeout=3.0: _Resp(payload))
    assert ollama.list_models("http://localhost:11434") == [
        "ollama_chat/llama3.1:8b", "ollama_chat/mistral:7b", "ollama_chat/qwen2.5:latest",
    ]


def test_list_models_empty_on_connection_error(monkeypatch):
    def boom(url, timeout=3.0):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(httpx, "get", boom)
    assert ollama.list_models() == []


def test_list_models_normalizes_bare_host(monkeypatch):
    seen = {}
    monkeypatch.setattr(httpx, "get",
                        lambda url, timeout=3.0: seen.setdefault("url", url) or _Resp({"models": []}))
    ollama.list_models("localhost:11434")
    assert seen["url"] == "http://localhost:11434/api/tags"


# -- model_context_length (POST /api/show) ----------------------------------


def test_context_length_from_arch_key(monkeypatch):
    payload = {"model_info": {"general.architecture": "llama", "llama.context_length": 131072}}
    monkeypatch.setattr(httpx, "post", lambda url, json=None, timeout=3.0: _Resp(payload))
    assert ollama.model_context_length("http://localhost:11434", "ollama_chat/llama3.1") == 131072


def test_context_length_scans_when_no_arch(monkeypatch):
    payload = {"model_info": {"qwen2.context_length": 32768}}
    monkeypatch.setattr(httpx, "post", lambda url, json=None, timeout=3.0: _Resp(payload))
    assert ollama.model_context_length(None, "ollama_chat/qwen2.5") == 32768


def test_context_length_none_on_error(monkeypatch):
    def boom(url, json=None, timeout=3.0):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(httpx, "post", boom)
    assert ollama.model_context_length("http://x", "ollama_chat/llama3.1") is None


def test_context_length_none_when_field_absent(monkeypatch):
    payload = {"model_info": {"general.architecture": "llama"}}  # no .context_length
    monkeypatch.setattr(httpx, "post", lambda url, json=None, timeout=3.0: _Resp(payload))
    assert ollama.model_context_length("http://x", "ollama_chat/llama3.1") is None


def test_context_length_strips_provider_prefix(monkeypatch):
    seen = {}
    monkeypatch.setattr(httpx, "post",
                        lambda url, json=None, timeout=3.0: seen.update(json or {}) or _Resp({"model_info": {}}))
    ollama.model_context_length("http://x", "ollama_chat/llama3.1:8b")
    assert seen.get("name") == "llama3.1:8b"  # provider prefix stripped for /api/show


# -- _build_lm_kwargs Ollama branch -----------------------------------------


def test_build_lm_kwargs_ollama_sets_api_base_and_num_ctx(monkeypatch):
    monkeypatch.setattr("xrefer.llm.ollama.model_context_length",
                        lambda api_base, model_id, **kw: 65536)
    kwargs = LLMProcessor()._build_lm_kwargs(
        ModelConfig(model_id="ollama_chat/llama3.1", api_key="", api_base="http://localhost:11434"))
    assert kwargs["model"] == "ollama_chat/llama3.1"
    assert kwargs["api_base"] == "http://localhost:11434"
    assert kwargs["num_ctx"] == 65536
    # Early return — the hosted-model branches don't run.
    assert "max_tokens" not in kwargs
    assert "extra_headers" not in kwargs
