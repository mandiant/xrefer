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

"""Auth pre-flight: settle a wrong key in seconds, never veto on noise.

A rejected key used to burn the whole multi-minute cluster run (the full
path died mid-corpus; the hierarchical path retried-and-skipped every wave
into an empty "success"). _preflight_auth issues one tiny completion for
hosted models and blocks ONLY on a definitive AuthenticationError —
local/api_base configs are exempt, and any other probe hiccup passes
through so an unrelated failure can't veto a run the real calls might
survive.
"""

import litellm
import pytest

from xrefer.llm.cluster_analyzer import ClusterAnalyzer


class _Cfg:
    def __init__(self, model_id, api_key="k", api_base=None):
        self.model_id = model_id
        self.api_key = api_key
        self.api_base = api_base


class _Proc:
    def __init__(self, cfg):
        self.config = cfg


class _Obj:
    cluster_analysis_failure = None


def _auth_error():
    return litellm.exceptions.AuthenticationError(
        message="invalid api key", llm_provider="gemini", model="gemini/x"
    )


def test_local_model_skips_probe(monkeypatch):
    def _boom(**kwargs):
        raise AssertionError("probe must not run for local models")

    monkeypatch.setattr(litellm, "completion", _boom)
    assert ClusterAnalyzer._preflight_auth(_Proc(_Cfg("ollama_chat/gemma3:4b")), _Obj()) is True


def test_api_base_config_skips_probe(monkeypatch):
    def _boom(**kwargs):
        raise AssertionError("probe must not run for api_base configs")

    monkeypatch.setattr(litellm, "completion", _boom)
    assert ClusterAnalyzer._preflight_auth(_Proc(_Cfg("openai/local", api_base="http://127.0.0.1:8000")), _Obj()) is True


def test_auth_failure_blocks_and_sets_flag(monkeypatch):
    def _reject(**kwargs):
        raise _auth_error()

    monkeypatch.setattr(litellm, "completion", _reject)
    obj = _Obj()
    assert ClusterAnalyzer._preflight_auth(_Proc(_Cfg("gemini/gemini-2.5-flash")), obj) is False
    failure = obj.cluster_analysis_failure
    assert failure and failure["severity"] == "total"
    assert failure["error"] == "AuthenticationError"
    assert "Configure" in failure["message"]


def test_transient_probe_failure_does_not_block(monkeypatch):
    def _flaky(**kwargs):
        raise RuntimeError("connection reset")

    monkeypatch.setattr(litellm, "completion", _flaky)
    obj = _Obj()
    assert ClusterAnalyzer._preflight_auth(_Proc(_Cfg("gemini/gemini-2.5-flash")), obj) is True
    assert obj.cluster_analysis_failure is None


def test_valid_key_passes(monkeypatch):
    monkeypatch.setattr(litellm, "completion", lambda **kwargs: {"choices": []})
    assert ClusterAnalyzer._preflight_auth(_Proc(_Cfg("openai/gpt-5")), _Obj()) is True
