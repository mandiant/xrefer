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

"""Tests for the Anthropic 1M-context beta-header injection in
``LLMProcessor._build_lm_kwargs``.

Claude's 1M input window is beta-gated: the request must carry
``anthropic-beta: context-1m-2025-08-07``. litellm forwards that header
when we pass it via ``extra_headers`` but never adds it on its own, so
xrefer attaches it — and ONLY for Anthropic models whose catalog entry
advertises >=1M input (never a 200k Claude, never another provider).

``litellm.get_model_info`` is monkeypatched with a fixed mini-catalog so
the gating logic is exercised deterministically, independent of whatever
model table the installed litellm version happens to ship.
"""

import litellm
import pytest

from xrefer.llm.base import ModelConfig
from xrefer.llm.processor import LLMProcessor

BETA = {"anthropic-beta": "context-1m-2025-08-07"}

# model id -> catalog info dict (as litellm.get_model_info would return)
_FAKE_CATALOG = {
    "anthropic/claude-opus-4-8": {
        "litellm_provider": "anthropic", "max_input_tokens": 1_000_000, "max_output_tokens": 128_000},
    "anthropic/claude-opus-4-7": {
        "litellm_provider": "anthropic", "max_input_tokens": 1_000_000, "max_output_tokens": 128_000},
    "anthropic/claude-3-haiku-20240307": {
        "litellm_provider": "anthropic", "max_input_tokens": 200_000, "max_output_tokens": 4_096},
    "openai/gpt-4.1": {
        "litellm_provider": "openai", "max_input_tokens": 1_000_000, "max_output_tokens": 32_000},
    "gemini/gemini-2.5-pro": {
        "litellm_provider": "gemini", "max_input_tokens": 1_048_576, "max_output_tokens": 65_535},
}


@pytest.fixture
def fixed_catalog(monkeypatch):
    def fake_get_model_info(model_id):
        if model_id not in _FAKE_CATALOG:
            raise ValueError(f"unknown model: {model_id}")
        return _FAKE_CATALOG[model_id]

    monkeypatch.setattr(litellm, "get_model_info", fake_get_model_info)


def _kwargs(model):
    return LLMProcessor()._build_lm_kwargs(ModelConfig(model_id=model, api_key="sk-test"))


def test_1m_anthropic_gets_beta_header(fixed_catalog):
    assert _kwargs("anthropic/claude-opus-4-8").get("extra_headers") == BETA
    assert _kwargs("anthropic/claude-opus-4-7").get("extra_headers") == BETA


def test_sub_1m_anthropic_gets_no_header(fixed_catalog):
    # 200k Claude: provider matches but it does not advertise 1M, so the
    # header (which Anthropic would 400 on) must NOT be attached.
    assert "extra_headers" not in _kwargs("anthropic/claude-3-haiku-20240307")


def test_non_anthropic_1m_gets_no_header(fixed_catalog):
    # OpenAI/Gemini at 1M+ are unrelated to the anthropic-beta header.
    assert "extra_headers" not in _kwargs("openai/gpt-4.1")
    assert "extra_headers" not in _kwargs("gemini/gemini-2.5-pro")


def test_unknown_model_no_header_no_crash(fixed_catalog):
    # get_model_info raises -> info falls back to {} -> no header, no error.
    assert "extra_headers" not in _kwargs("custom/some-local-model")


def test_output_cap_still_wired_from_same_lookup(fixed_catalog):
    # The hoisted info lookup must still feed max_tokens for non-reasoning
    # models (regression guard for the refactor that added the header).
    assert _kwargs("gemini/gemini-2.5-pro").get("max_tokens") == 65_535
