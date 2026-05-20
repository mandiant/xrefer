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

"""
DSPy-native LLM processor with Pydantic validation.
"""

import re
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

import dspy
import litellm
import httpx

from xrefer.core.helpers import check_internet_connectivity, log
from xrefer.llm.base import ModelConfig, PromptType
from xrefer.llm.dspy_modules import ArtifactAnalysisResponse, ArtifactAnalyzerModule, BinarySynthesisResponse, BinarySynthesizerModule, CategorizationResponse, CategorizerModule, ClusterAnalysisResponse, ClusterAnalyzerModule


# Tracks whether the LiteLLM success callback below has been
# registered. We register it lazily on the first ``set_model_config``
# call (rather than at import time) so that test-only / read-only
# code paths that touch this module don't accidentally activate a
# live LLM logging side-effect.
_LLM_IO_CALLBACK_REGISTERED: bool = False


def _log_llm_io(kwargs, completion_response, start_time, end_time) -> None:
    """LiteLLM success-callback fired after every successful LLM call.

    Logs provider-reported prompt and completion token counts so the
    analyst can see exactly how many tokens each call consumed —
    regardless of which prompt type (categorizer, artifact_analyzer,
    cluster_analyzer, binary_synthesizer, or any future addition)
    originated the call. The counts come from the provider's own
    response.usage block, so they're authoritative (not a local
    tokenizer estimate).

    THREAD-SAFETY NOTE: this callback is dispatched by litellm via
    ``executor.submit(...)`` (see litellm/utils.py around line
    1654-1661) — it runs on a litellm-owned background thread, NOT
    the thread that originated the LLM call. That means we MUST NOT
    call into IDA UI APIs here. xrefer's ``log()`` helper (in
    plugins/xrefer/gui/helpers.py) calls
    ``idaapi.replace_wait_box(...)`` which is NOT thread-safe and
    deadlocks IDA when invoked from a worker thread. We use plain
    ``print()`` instead — that goes to IDA's Output window via
    stdout redirection and is safe from any thread. The trade-off
    is that the wait-box message doesn't update, but that's correct
    behaviour — the callback fires AFTER the LLM call has already
    returned, so updating the wait box at that point is pointless
    anyway (the wait box belongs to the call that just finished).

    Defensive: every step is wrapped in try/except so a malformed
    response object (or a provider that omits usage data) never
    breaks the LLM call path. Failures here are silent — the
    primary LLM-call error handling lives elsewhere.
    """
    try:
        # Pull usage block from either object-style (litellm
        # ModelResponse) or dict-style completion responses.
        usage = None
        if hasattr(completion_response, "usage"):
            usage = completion_response.usage
        elif isinstance(completion_response, dict):
            usage = completion_response.get("usage")

        if usage is None:
            return

        def _get(key: str) -> int:
            if hasattr(usage, key):
                v = getattr(usage, key)
            elif isinstance(usage, dict):
                v = usage.get(key)
            else:
                v = None
            try:
                return int(v) if v is not None else 0
            except (TypeError, ValueError):
                return 0

        prompt_tokens = _get("prompt_tokens")
        completion_tokens = _get("completion_tokens")
        total_tokens = _get("total_tokens") or (prompt_tokens + completion_tokens)

        model = (kwargs or {}).get("model", "?")

        try:
            elapsed_s = (end_time - start_time).total_seconds()
        except Exception:
            elapsed_s = 0.0
        elapsed_str = (
            f"{elapsed_s:.1f}s" if elapsed_s >= 1 else f"{int(elapsed_s * 1000)}ms"
        )

        # Use sys.stdout.write — NOT print() and NOT log() — so this
        # is safe from the litellm background thread.
        #
        # Why not print(): builtin print() makes TWO separate write
        # calls (one for the message, one for the trailing newline).
        # Each call is individually thread-safe at the io.TextIOWrapper
        # level, but the sequence isn't — another thread's print can
        # interleave between the message and its newline, producing
        # mashed-together output like
        #   "[XRefer] Stage 1: ...[XRefer] [LLM] ...\n\n"
        # See THREAD-SAFETY NOTE above for the background-thread
        # context.
        #
        # sys.stdout.write(msg + "\n") is ONE write call holding the
        # TextIOWrapper lock for the entire message-plus-newline, so
        # concurrent main-thread print()s can't tear our line in half.
        import sys
        sys.stdout.write(
            f"[XRefer] [LLM] {model}: prompt={prompt_tokens} tok, "
            f"response={completion_tokens} tok, total={total_tokens} tok, "
            f"elapsed={elapsed_str}\n"
        )
    except Exception:
        # Logging must never break the analysis flow.
        pass


def _ensure_llm_io_callback_registered() -> None:
    """Register the IO-logging callback exactly once per process.

    Called from ``LLMProcessor.set_model_config`` so the side-effect
    only activates when real LLM use is configured. The callback is
    process-global (LiteLLM's success_callback list is module-level)
    so repeated calls would otherwise duplicate the log line.
    """
    global _LLM_IO_CALLBACK_REGISTERED
    if _LLM_IO_CALLBACK_REGISTERED:
        return
    try:
        if _log_llm_io not in litellm.success_callback:
            litellm.success_callback.append(_log_llm_io)
    except Exception:
        # If litellm's surface changes in a future version, fall back
        # silently — the existing _measure logs in cluster_analyzer
        # still give pre-call size estimates.
        pass
    _LLM_IO_CALLBACK_REGISTERED = True


@dataclass
class ProcessConfig:
    """Type-safe configuration for processing."""
    categories: List[str] = field(default_factory=list)
    item_type: str = "api"


class LLMProcessor:
    """
    DSPy-native processor for LLM operations.
    """

    def __init__(self):
        self.lm: Optional[dspy.LM] = None
        self.config: Optional[ModelConfig] = None
        # lm_kwargs is the kwargs dict used to build self.lm. Captured
        # so uncached_lm() can rebuild a parallel LM with cache disabled
        # for force-analyze runs without affecting the main LM.
        self._lm_kwargs: Dict[str, Any] = {}

    def _build_lm_kwargs(self, config: ModelConfig) -> Dict[str, Any]:
        """Compute the dspy.LM kwargs dict from a ModelConfig.

        We deliberately do NOT pass ``temperature`` or
        ``reasoning_effort`` for non-OpenAI-reasoning models — omitting
        them lets each provider apply its calibrated API-side default
        (e.g. Gemini 3 uses temperature=1.0 + dynamic thinking budget,
        which Google specifically warns should not be overridden below
        1.0). The only special case is OpenAI reasoning models, which
        require temperature=1.0 and DSPy enforces this on its own
        side; we mirror that constraint here so the value is set
        before DSPy ever sees the request.

        Factored out so set_model_config and uncached_lm both produce
        identical model configuration apart from the cache settings.
        """
        lm_kwargs: Dict[str, Any] = {
            "model": config.model_id,
            "api_key": config.api_key,
            "cache_seed": 0x72616e64306d,
        }

        # ── Hard-constrained branch: OpenAI reasoning models ─────────
        # These models require temperature=1.0 and max_tokens >= 16000;
        # DSPy enforces this on its own side via a regex (see
        # https://github.com/stanfordnlp/dspy/blob/1df5984007b7fd9bb56f3a8fba7a68b5517efb69/dspy/clients/lm.py#L92).
        # We mirror DSPy's regex so we set the right values before
        # DSPy ever sees the request.
        is_openai_reasoning = bool(re.search(
            r'openai\/(?:o[1345]|gpt-5(?:\.\d+)?)(?:-(?:mini|nano|codex))?',
            config.model_id,
        ))
        if is_openai_reasoning:
            lm_kwargs["temperature"] = 1.0
            lm_kwargs["max_tokens"] = 16000

        # ── Max output tokens, from the model's own declared cap ─────
        # OpenAI reasoning branch already set this above. For other
        # models, read the catalog's declared output cap so a Gemini
        # model gets 65535, a gpt-4.1 gets ~16384, a Claude gets its
        # appropriate value, etc. Falls back to leaving max_tokens
        # unset (provider default applies) if the lookup fails.
        if "max_tokens" not in lm_kwargs:
            try:
                info = litellm.get_model_info(config.model_id)
                cap = info.get("max_output_tokens") or info.get("max_tokens")
                if cap:
                    lm_kwargs["max_tokens"] = int(cap)
            except Exception:
                pass

        return lm_kwargs

    def set_model_config(self, config: ModelConfig) -> None:
        """
        Configure DSPy with the specified LLM.

        Args:
            config: Model configuration
        """
        self.config = config
        self._lm_kwargs = self._build_lm_kwargs(config)
        self.lm = dspy.LM(**self._lm_kwargs)
        dspy.settings.configure(lm=self.lm)
        # Lazy registration of the LiteLLM success callback so every
        # subsequent LLM call (categorizer, artifact_analyzer,
        # cluster_analyzer, binary_synthesizer, the API-key validation
        # call, anything else) logs its provider-reported prompt and
        # response token counts.
        _ensure_llm_io_callback_registered()

    @contextmanager
    def uncached_lm(self) -> Iterator[None]:
        """Temporarily swap the configured LM with one that bypasses
        DSPy's response cache for the duration of the ``with`` block.

        Used by the "force re-analyze" UI flow so the analyst can
        re-run cluster / artifact analysis and be guaranteed fresh LLM
        responses, even when a prior identical request is still in
        the LiteLLM cache for this process.

        Implementation: builds a parallel ``dspy.LM`` with
        ``cache=False`` AND a randomized ``cache_seed`` (belt-and-
        braces — different DSPy versions read different flags), swaps
        it into ``dspy.settings`` and ``self.lm`` for the duration of
        the block, then restores the original. If no model is
        configured yet, the context manager is a no-op.
        """
        if self.config is None or self.lm is None:
            yield
            return

        prior_lm = self.lm
        fresh_kwargs = dict(self._lm_kwargs)
        # cache=False disables DSPy's response cache; the randomized
        # cache_seed defeats LiteLLM's deterministic-cache layer in
        # case cache=False isn't honoured by the active adapter.
        fresh_kwargs["cache"] = False
        fresh_kwargs["cache_seed"] = secrets.randbits(64)
        try:
            uncached = dspy.LM(**fresh_kwargs)
        except TypeError:
            # Older dspy.LM may not accept `cache=`; the randomized
            # cache_seed alone is enough to bypass the cache.
            fresh_kwargs.pop("cache", None)
            uncached = dspy.LM(**fresh_kwargs)

        self.lm = uncached
        dspy.settings.configure(lm=uncached)
        try:
            yield
        finally:
            self.lm = prior_lm
            dspy.settings.configure(lm=prior_lm)

    def validate_api_key(self) -> bool:
        """Validate API key with a test call."""
        if not self.lm:
            raise ValueError("Model not configured")
        try:
            self.lm("Say 'valid'")
            return True
        except Exception as e:
            log(f"API validation failed: {e}")
            return False

    def _create_artifacts_dict(self, items: List[Dict[str, Any]]) -> Dict[str, Dict[int, str]]:
        """Convert artifacts list to structured dict."""
        artifacts = {"Strings": {}, "APIs": {}, "CAPA": {}, "Libraries": {}}
        type_map = {"string": "Strings", "api": "APIs", "capa": "CAPA", "lib": "Libraries"}

        for item in items:
            category = type_map.get(item["type"])
            if category:
                artifacts[category][item["index"]] = item["content"]

        return artifacts

    def _process_single(self, items: List[Any], prompt_type: PromptType, config: Optional[ProcessConfig]=None) -> Dict[str, Any]:
        """
        Process items using DSPy module.
        """
        try:
            if prompt_type == PromptType.CATEGORIZER:
                response: "CategorizationResponse" = CategorizerModule()(items=items, categories=config.categories, item_type=config.item_type)
                return response.model_dump()
            elif prompt_type == PromptType.ARTIFACT_ANALYZER:
                artifacts = self._create_artifacts_dict(items)
                response: "ArtifactAnalysisResponse" = ArtifactAnalyzerModule()(artifacts=artifacts)
                return set(response.interesting_indexes)
            elif prompt_type == PromptType.CLUSTER_ANALYZER:
                response: "ClusterAnalysisResponse" = ClusterAnalyzerModule()(cluster_data=items[0])
                return response.model_dump()
            elif prompt_type == PromptType.BINARY_SYNTHESIZER:
                response: "BinarySynthesisResponse" = BinarySynthesizerModule()(synthesis_input=items[0])
                return response.model_dump()
            else:
                raise ValueError(f"Unsupported prompt type: {prompt_type}")
        except (litellm.exceptions.RateLimitError, httpx.HTTPStatusError) as e:
            log(f'''{e.__class__.__name__} was raised during LLM processing:

You can:
  a. Wait a few minutes and retry
  b. Check API quota/billing
  c. Use a cheaper model
''')
            # Return empty result instead of raising - let caller handle gracefully
            if prompt_type == PromptType.CATEGORIZER:
                return {}
            elif prompt_type == PromptType.ARTIFACT_ANALYZER:
                return set()
            elif prompt_type == PromptType.CLUSTER_ANALYZER:
                return {}
            elif prompt_type == PromptType.BINARY_SYNTHESIZER:
                return {}
            else:
                raise ValueError(f"Unsupported prompt type: {prompt_type}")


    def _process_parallel(self, items: List[Any], prompt_type: PromptType, batch_size: int, config: Optional[ProcessConfig]=None) -> Dict[int, Any]:
        """Process items in parallel batches."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        import os
        max_workers = min(os.cpu_count() * 4, 20, len(items) // batch_size + 1)

        results = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}

            for i in range(0, len(items), batch_size):
                chunk = items[i:i + batch_size]
                future = executor.submit(self._process_single, chunk, prompt_type, config)
                futures[future] = i

            for future in as_completed(futures):
                chunk_result = future.result()
                chunk_start = futures[future]

                # Adjust indices for categorizer (use int consistently)
                if prompt_type == PromptType.CATEGORIZER:
                    for idx, cat_idx in chunk_result.items():
                        original_idx = int(idx) + chunk_start
                        results[original_idx] = cat_idx
                else:
                    results.update(chunk_result)

        return results

    def _process_sequential(self, items: List[Any], prompt_type: PromptType, batch_size: int, config: ProcessConfig) -> Dict[int, Any]:
        """Process items sequentially in batches."""
        results = {}
        total_chunks = (len(items) + batch_size - 1) // batch_size

        for i in range(0, len(items), batch_size):
            chunk = items[i:i + batch_size]
            chunk_num = i // batch_size + 1
            log(f"[+]Processing chunk {chunk_num}/{total_chunks}")

            chunk_result = self._process_single(chunk, prompt_type, config)

            # Adjust indices for categorizer
            if prompt_type == PromptType.CATEGORIZER:
                for idx, cat_idx in chunk_result.items():
                    original_idx = int(idx) + i
                    results[original_idx] = cat_idx
            else:
                results.update(chunk_result)

        return results

    def process_items(
        self,
        items: List[Any],
        prompt_type: PromptType,
        ignore_token_limit: bool = False,
        categories: Optional[List[str]] = None,
        type: str = "api"
    ) -> Dict[str, Any]:
        """
        Process items with automatic batching.

        DSPy/LiteLLM automatically handles:

        Args:
            items: Items to process
            prompt_type: Type of processing
            ignore_token_limit: If True, process all items at once
            categories: List of categories (for categorizer)
            type: Item type "api" or "lib" (for categorizer)

        Returns:
            Processed results
        """
        if not self.lm:
            raise ValueError("Model not configured")
        if not items:
            raise ValueError("No items to process")
        if not check_internet_connectivity():
            raise ConnectionError("No internet connectivity")

        if prompt_type == PromptType.CLUSTER_ANALYZER:
            return self._process_single([items], prompt_type)
        if prompt_type == PromptType.BINARY_SYNTHESIZER:
            return self._process_single([items], prompt_type)
        config = None
        if prompt_type == PromptType.CATEGORIZER:
            config = ProcessConfig(categories=categories or [], item_type=type)
            return self._process_single(items, prompt_type, config)

        if ignore_token_limit:
            log(f"[+] Processing all {len(items)} items in single batch")
            results = self._process_single(items, prompt_type, config)
            # Convert to str keys for backward compatibility
            if prompt_type == PromptType.CATEGORIZER:
                return {str(k): v for k, v in results.items()}
            return results

        # Batched processing
        # Simple heuristic: 50 items per batch (conservative, no token counting needed)
        batch_size = 50
        log(f"[+] Processing {len(items)} items in batches of {batch_size}")
        # NOTE: In a perfect world, dspy would support **native** batch processing (/v1/batches)
        # https://docs.litellm.ai/docs/batches
        # unfortunately, we live in a imperfect world...

        use_parallel = True

        if use_parallel:
            results = self._process_parallel(items, prompt_type, batch_size, config)
        else:
            results = self._process_sequential(items, prompt_type, batch_size, config)

        # Fill in missed items for categorizer
        if prompt_type == PromptType.CATEGORIZER:
            all_indices = set(range(len(items)))
            processed_indices = set(results.keys())
            missed_indices = all_indices - processed_indices

            if missed_indices:
                log(f"[*] Found {len(missed_indices)} missed items, assigning to Others")
                others_idx = config.categories.index("Others") if "Others" in config.categories else 0
                for idx in missed_indices:
                    results[idx] = others_idx

            # Convert to str keys for backward compatibility
            return {str(k): v for k, v in results.items()}

        return results
