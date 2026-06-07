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

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple


class PromptType(Enum):
    CATEGORIZER = "categorizer"
    CLUSTER_ANALYZER = "cluster_analyzer"
    BINARY_SYNTHESIZER = "binary_synthesizer"


@dataclass
class ModelConfig:
    """
    Configuration for LLM model.

    Temperature and reasoning-effort are deliberately NOT exposed here.
    We let the provider's API defaults apply for both — that's the
    calibrated configuration for hybrid reasoning models (e.g. Gemini 3
    uses temperature=1.0 and a dynamic thinking budget by default, and
    Google warns that setting < 1.0 can cause infinite loops and
    degraded reasoning). The only special case is OpenAI reasoning
    models, which require temperature=1.0 — that's enforced in
    ``_build_lm_kwargs`` based on the model id.

    Attributes:
        model_id (str): Fully qualified model identifier (e.g. "openai/gpt-4o-mini")
        api_key (str): API key for authentication
        ignore_token_limit (bool): Whether to ignore token limits
        api_base (Optional[str]): Base URL for local / self-hosted models
            (Ollama). None/empty for hosted providers; applied only to
            ollama_* model ids by ``_build_lm_kwargs``.
    """
    model_id: str
    api_key: str
    ignore_token_limit: bool = False
    api_base: Optional[str] = None


def resolve_model_configs(settings: Dict[str, Any]) -> Tuple[ModelConfig, ModelConfig]:
    """Build the (heavy, light) model configs from the settings dict.

    Two roles, each with its own LM (routed per-task in ``LLMProcessor``):

    * **heavy** — cluster analysis (stage-1 per-cluster + stage-2 synthesis).
      Always the primary model (``llm_model_id`` / ``api_key`` / ``api_base``);
      ``ignore_token_limit=True``.
    * **light** — categorization (bulk API/library tagging). The primary model
      by default (so "one model for everything" is the default and back-compat
      for old saved settings), OR a separate, independently-configured model
      when ``use_light_model`` is on and ``light_model_id`` is set.

    Mix-and-match is fully supported: the light model can be a different hosted
    model (same key via ``light_use_primary_key``, or its own ``light_api_key``)
    or a local Ollama model (``light_api_base``, no key needed). Pure (no IDA);
    unit-tested in tests/test_dual_model_config.py.
    """
    from xrefer.llm.ollama import is_ollama_model

    model_id = (settings.get("llm_model_id") or "").strip()
    api_key = settings.get("api_key", "") or ""
    api_base = (settings.get("api_base", "") or "") or None

    heavy = ModelConfig(model_id=model_id, api_key=api_key, ignore_token_limit=True, api_base=api_base)

    use_light = bool(settings.get("use_light_model", False))
    light_model_id = (settings.get("light_model_id") or "").strip()
    if not (use_light and light_model_id):
        # No separate light model → categorization uses the primary model.
        light = ModelConfig(model_id=model_id, api_key=api_key, ignore_token_limit=False, api_base=api_base)
        return heavy, light

    light_local = is_ollama_model(light_model_id)
    light_api_base = (settings.get("light_api_base", "") or "") or None
    if settings.get("light_use_primary_key", True):
        light_key = api_key
    else:
        light_key = settings.get("light_api_key", "") or ""
    # A hosted light model with no usable key falls back to the primary key
    # (best-effort) rather than silently breaking categorization.
    if not light_key and not light_local:
        light_key = api_key

    light = ModelConfig(model_id=light_model_id, api_key=light_key, ignore_token_limit=False, api_base=light_api_base)
    return heavy, light
