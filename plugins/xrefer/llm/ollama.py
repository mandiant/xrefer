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

"""Local-model (Ollama) helpers.

LiteLLM/DSPy can *call* Ollama (``ollama_chat/<model>`` + ``api_base``) but
neither can enumerate locally-installed models or report a local model's real
context window — LiteLLM's static catalog has no usable value for them. Both of
those come from Ollama's own REST API, which this module wraps:

  * ``list_models``          -> GET  {base}/api/tags   (installed models)
  * ``model_context_length`` -> POST {base}/api/show   (a model's max context)

Pure network helpers (httpx only) — backend-agnostic, no IDA/Qt — so they're
safe to import from the llm/core layers and easy to unit-test by patching httpx.
Every call degrades gracefully (empty list / None) when the server is
unreachable, so a missing or stopped Ollama never breaks the surrounding flow.
"""

from typing import List, Optional

import httpx

# Ollama's default local endpoint. A blank api_base resolves to this so a
# vanilla local install works with no configuration.
DEFAULT_API_BASE = "http://localhost:11434"

# We surface local models under the ollama_chat provider (DSPy's documented
# path — the /api/chat endpoint, with native JSON-schema structured output).
_PROVIDER_PREFIX = "ollama_chat/"


def is_ollama_model(model_id: Optional[str]) -> bool:
    """True for an Ollama model id (either provider prefix)."""
    return bool(model_id) and (model_id.startswith("ollama_chat/") or model_id.startswith("ollama/"))


def _normalize_base(api_base: Optional[str]) -> str:
    base = (api_base or DEFAULT_API_BASE).strip().rstrip("/")
    if not base:
        base = DEFAULT_API_BASE
    if not base.startswith(("http://", "https://")):
        base = "http://" + base
    return base


def _bare_name(model_id: str) -> str:
    """Strip the provider prefix: 'ollama_chat/llama3.1:8b' -> 'llama3.1:8b'."""
    return model_id.split("/", 1)[1] if "/" in model_id else model_id


def list_models(api_base: Optional[str] = None, timeout: float = 3.0) -> List[str]:
    """Return installed Ollama models as ``ollama_chat/<name>`` ids.

    GETs ``{base}/api/tags``. Returns ``[]`` on any failure (server down, bad
    URL, malformed response) so the caller can merge an empty list without
    special-casing a missing Ollama.
    """
    base = _normalize_base(api_base)
    try:
        resp = httpx.get(f"{base}/api/tags", timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return []
    out: List[str] = []
    for entry in (data.get("models") or []):
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("model")
        if name:
            out.append(f"{_PROVIDER_PREFIX}{name}")
    return sorted(set(out))


def model_context_length(api_base: Optional[str], model_id: str, timeout: float = 3.0) -> Optional[int]:
    """Return a model's max context length (tokens) from ``{base}/api/show``.

    This is the value to use both as the estimate's context window AND as the
    ``num_ctx`` we pass at call time — Ollama otherwise defaults num_ctx to a
    tiny 2048, far too small for cluster prompts. Returns ``None`` on any
    failure or if the field is absent.
    """
    base = _normalize_base(api_base)
    try:
        resp = httpx.post(f"{base}/api/show", json={"name": _bare_name(model_id)}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None
    info = data.get("model_info") or {}
    if not isinstance(info, dict):
        return None
    # The context-length key is "<arch>.context_length" (e.g. llama.context_length).
    arch = info.get("general.architecture")
    if arch:
        val = info.get(f"{arch}.context_length")
        if val is not None:
            try:
                return int(val)
            except (TypeError, ValueError):
                pass
    for key, val in info.items():
        if isinstance(key, str) and key.endswith(".context_length"):
            try:
                return int(val)
            except (TypeError, ValueError):
                return None
    return None
