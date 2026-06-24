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

"""Tests for the headless CLI settings-override surface.

Covers the three pure pieces that let CLI flags override settings.json for a
run: ``deep_merge_settings`` (the merge), ``build_settings_overrides`` (flags ->
override dict), and the env-aware ``_missing_llm_fields`` (so an exported
provider key satisfies the LLM gate without prompting). No IDA / LLM / network.
"""

import types

import xrefer.cli as climod
from xrefer.cli import build_settings_overrides, _missing_llm_fields
from xrefer.core.settings import deep_merge_settings


def _args(**kw):
    base = dict(
        model=None, api_key=None, api_base=None, llm=None,
        git_lookups=None, capa=None, trace=None, user_xrefs=None,
        light_model=None, light_api_key=None,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


# -- deep_merge_settings ----------------------------------------------------


def test_deep_merge_preserves_sibling_keys():
    base = {"analysis_options": {"cluster_batch_size": 30, "cluster_context_mode": "auto"}}
    deep_merge_settings(base, {"analysis_options": {"cluster_batch_size": 10}})
    assert base["analysis_options"] == {"cluster_batch_size": 10, "cluster_context_mode": "auto"}


def test_deep_merge_replaces_scalars_and_adds_keys():
    base = {"llm_lookups": True, "paths": {"capa": "/a"}}
    deep_merge_settings(base, {"llm_lookups": False, "paths": {"trace": "/t"}, "api_key": "k"})
    assert base["llm_lookups"] is False
    assert base["paths"] == {"capa": "/a", "trace": "/t"}
    assert base["api_key"] == "k"


def test_deep_merge_returns_base():
    base = {}
    assert deep_merge_settings(base, {"x": 1}) is base


# -- build_settings_overrides ----------------------------------------------


def test_no_flags_yields_empty_overrides():
    assert build_settings_overrides(_args()) == {}


def test_model_key_and_base_overrides_and_collapse():
    # A single --model collapses the heavy/light split so categorization uses it too.
    o = build_settings_overrides(_args(model="openai/gpt-5", api_key="sk-x", api_base="http://h:1"))
    assert o == {
        "llm_model_id": "openai/gpt-5",
        "api_key": "sk-x",
        "api_base": "http://h:1",
        "use_light_model": False,
    }


def test_dual_model_with_separate_light():
    o = build_settings_overrides(_args(model="anthropic/claude-opus-4-5", light_model="ollama_chat/llama3.1"))
    assert o == {
        "llm_model_id": "anthropic/claude-opus-4-5",
        "use_light_model": True,
        "light_model_id": "ollama_chat/llama3.1",
        "light_use_primary_key": True,
    }


def test_dual_model_with_light_api_key():
    o = build_settings_overrides(
        _args(model="gemini/gemini-flash-latest", light_model="openai/gpt-4o-mini", light_api_key="sk-o")
    )
    assert o["light_model_id"] == "openai/gpt-4o-mini"
    assert o["light_api_key"] == "sk-o"
    assert o["light_use_primary_key"] is False
    assert o["use_light_model"] is True


def test_light_model_alone_leaves_heavy_untouched():
    o = build_settings_overrides(_args(light_model="ollama_chat/llama3.1"))
    assert "llm_model_id" not in o            # heavy comes from settings/default
    assert o == {
        "use_light_model": True,
        "light_model_id": "ollama_chat/llama3.1",
        "light_use_primary_key": True,
    }


def test_light_api_key_without_light_model_is_ignored():
    # No --light-model -> --light-api-key has nothing to attach to.
    o = build_settings_overrides(_args(model="gemini/x", light_api_key="sk-stray"))
    assert "light_api_key" not in o
    assert o["use_light_model"] is False      # --model alone still collapses


def test_llm_disabled_records_false_not_dropped():
    # --no-llm -> args.llm is False; must be recorded (not treated as "unset").
    assert build_settings_overrides(_args(llm=False)) == {"llm_lookups": False}


def test_llm_enabled_and_git_lookups_true():
    assert build_settings_overrides(_args(llm=True)) == {"llm_lookups": True}
    assert build_settings_overrides(_args(git_lookups=True)) == {"git_lookups": True}


def test_path_overrides_resolved_absolute(tmp_path):
    capa = tmp_path / "c.json"
    capa.write_text("{}")
    trace = tmp_path / "t.zip"
    trace.write_text("")
    o = build_settings_overrides(_args(capa=str(capa), trace=str(trace), user_xrefs="x.txt"))
    assert o["paths"]["capa"] == str(capa.resolve())
    assert o["paths"]["trace"] == str(trace.resolve())
    # user-xrefs maps to the "xrefs" path key
    assert o["paths"]["xrefs"].endswith("x.txt")
    assert "llm_model_id" not in o  # only path keys present


# -- _missing_llm_fields (env-aware gate) -----------------------------------


def test_env_key_satisfies_missing_api_key(monkeypatch):
    monkeypatch.setattr(climod, "_env_has_provider_key", lambda m: True)
    assert _missing_llm_fields({"llm_model_id": "gemini/x", "api_key": ""}) == []


def test_no_key_and_no_env_flags_api_key(monkeypatch):
    monkeypatch.setattr(climod, "_env_has_provider_key", lambda m: False)
    assert _missing_llm_fields({"llm_model_id": "gemini/x", "api_key": ""}) == ["api_key"]


def test_local_model_needs_no_key(monkeypatch):
    monkeypatch.setattr(climod, "_env_has_provider_key", lambda m: False)
    assert _missing_llm_fields({"llm_model_id": "ollama_chat/llama3.1", "api_key": ""}) == []


def test_missing_model_id_flagged(monkeypatch):
    monkeypatch.setattr(climod, "_env_has_provider_key", lambda m: False)
    assert _missing_llm_fields({"llm_model_id": "", "api_key": "k"}) == ["llm_model_id"]


def test_saved_key_satisfies_without_env(monkeypatch):
    # An explicit saved api_key means we never even consult the environment.
    called = {"env": False}

    def _spy(_m):
        called["env"] = True
        return False

    monkeypatch.setattr(climod, "_env_has_provider_key", _spy)
    assert _missing_llm_fields({"llm_model_id": "gemini/x", "api_key": "saved"}) == []
    assert called["env"] is False
