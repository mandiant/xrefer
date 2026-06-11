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
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from time import monotonic
from typing import Any, Dict, Iterator, List, Optional, Tuple

import dspy
import litellm
import httpx

from xrefer.core.helpers import check_internet_connectivity, log
from xrefer.llm.base import ModelConfig, PromptType
from xrefer.llm.dspy_modules import BinarySynthesisResponse, BinarySynthesizerModule, CategorizationResponse, CategorizerModule, ClusterAnalysisResponse, ClusterAnalyzerModule


# Tracks whether the LiteLLM success callback below has been
# registered. We register it lazily on the first ``set_model_config``
# call (rather than at import time) so that test-only / read-only
# code paths that touch this module don't accidentally activate a
# live LLM logging side-effect.
_LLM_IO_CALLBACK_REGISTERED: bool = False

# Request timeout (seconds) for local Ollama calls. litellm's default is 600s
# (10 min), which a laptop-local model blows past on a large cluster prompt —
# the server then logs a 500 at ~10m0s and the run fails. Local generations are
# inherently slow, so give them a generous ceiling. (Hosted models keep
# litellm's default; their latency is bounded.)
_OLLAMA_REQUEST_TIMEOUT_S = 1800

# Memo for the hosted-model internet preflight. Batched runs call
# process_items many times back-to-back, and every probe miss costs up to
# two 3-second raw-IP timeouts. All LLM calls are main-thread synchronous,
# so a plain module global needs no locking.
_INTERNET_PROBE_TTL_S = 60.0
_internet_probe: Optional[Tuple[float, bool]] = None


def _internet_reachable() -> bool:
    """check_internet_connectivity, memoized for a short TTL."""
    global _internet_probe
    now = monotonic()
    if _internet_probe is not None and now - _internet_probe[0] < _INTERNET_PROBE_TTL_S:
        return _internet_probe[1]
    ok = check_internet_connectivity()
    _internet_probe = (now, ok)
    return ok


def _log_llm_io(kwargs, completion_response, start_time, end_time) -> None:
    """LiteLLM success-callback fired after every successful LLM call.

    Logs provider-reported prompt and completion token counts so the
    analyst can see exactly how many tokens each call consumed —
    regardless of which prompt type (categorizer, cluster_analyzer,
    binary_synthesizer, or any future addition) originated the call.
    The counts come from the provider's own
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
        # The DSPy adapter chosen for this model (JSONAdapter for Ollama,
        # ChatAdapter for hosted). Stored so each call can re-assert THIS
        # processor's lm+adapter via dspy.context() — see _process_single.
        self.adapter: Optional[Any] = None

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
            "cache_seed": 0x72616e64306d,
        }
        # Pass the key explicitly only when we actually have one. Leaving it
        # unset lets litellm resolve the provider key from the environment
        # (e.g. GEMINI_API_KEY / OPENAI_API_KEY), which is how zero-config /
        # env-based auth works for headless runs.
        if config.api_key:
            lm_kwargs["api_key"] = config.api_key

        # ── Local models via Ollama ──────────────────────────────────
        # ollama_chat/<model> + api_base. Crucially, set num_ctx to the model's
        # real context length (from /api/show) — Ollama defaults num_ctx to
        # 2048, far too small for cluster prompts, and silently truncates
        # beyond it. The hosted-model branches below (OpenAI reasoning,
        # Anthropic 1M, catalog output cap) don't apply to local models.
        from xrefer.llm.ollama import is_ollama_model, model_context_length
        if is_ollama_model(config.model_id):
            # Ollama doesn't understand litellm's cache_seed and logs
            # "invalid option provided"; drop it for local models.
            lm_kwargs.pop("cache_seed", None)
            if config.api_base:
                lm_kwargs["api_base"] = config.api_base
            num_ctx = model_context_length(config.api_base, config.model_id)
            if num_ctx:
                lm_kwargs["num_ctx"] = num_ctx
            # Local generations are slow; raise the request timeout well above
            # litellm's 600s default so a long cluster call isn't killed at
            # ~10m0s (see _OLLAMA_REQUEST_TIMEOUT_S).
            lm_kwargs["timeout"] = _OLLAMA_REQUEST_TIMEOUT_S
            # Disable chain-of-thought. Thinking models (e.g. Gemma) spend the
            # bulk of each call emitting reasoning tokens before the JSON, which
            # makes cluster analysis unusably slow locally — a 1-cluster call
            # measured ~134s with thinking vs ~54s without. The structured
            # cluster output doesn't need visible CoT. (Ignored by models that
            # don't support thinking.)
            lm_kwargs["think"] = False
            return lm_kwargs

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

        # ── Model catalog info (best-effort) ─────────────────────────
        # Reused for both the output-token cap and the Anthropic 1M
        # beta-header decision below. Empty dict for unknown/custom ids.
        try:
            info = litellm.get_model_info(config.model_id)
        except Exception:
            info = {}

        # ── Max output tokens, from the model's own declared cap ─────
        # OpenAI reasoning branch already set this above. For other
        # models, read the catalog's declared output cap so a Gemini
        # model gets 65535, a gpt-4.1 gets ~16384, a Claude gets its
        # appropriate value, etc. Falls back to leaving max_tokens
        # unset (provider default applies) if the lookup fails.
        if "max_tokens" not in lm_kwargs:
            try:
                cap = info.get("max_output_tokens") or info.get("max_tokens")
                if cap:
                    lm_kwargs["max_tokens"] = int(cap)
            except Exception:
                pass

        # ── Anthropic 1M context window (beta-gated) ─────────────────
        # Claude's 1M input window requires the request to carry the
        # `anthropic-beta: context-1m-2025-08-07` header AND an API key
        # at tier 4+. litellm forwards anthropic-beta values passed via
        # extra_headers but does NOT auto-add this one, so we send it
        # ourselves — only for Anthropic models whose catalog entry
        # actually advertises >=1M input. That avoids attaching it to a
        # 200k Claude (Anthropic would 400) or to a non-Anthropic
        # provider. Tier 4+ stays the user's responsibility; a lower-
        # tier key is rejected by Anthropic for 1M requests.
        try:
            if (info.get("litellm_provider") == "anthropic"
                    and int(info.get("max_input_tokens") or 0) >= 1_000_000):
                lm_kwargs["extra_headers"] = {"anthropic-beta": "context-1m-2025-08-07"}
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
        # Adapter choice. Local (Ollama) models emit raw JSON, NOT DSPy's
        # ChatAdapter "[[ ## field ## ]]" marker format — so ChatAdapter fails
        # to parse and DSPy silently retries with a fallback adapter, DOUBLING
        # every call (measured: 2 model calls per cluster). JSONAdapter parses
        # their native JSON on the first attempt (and drives Ollama's
        # constrained `format` output, which is more reliable). Hosted models
        # keep the default ChatAdapter they're tuned and tested against. Setting
        # it explicitly each time also resets correctly when the user switches
        # between a local and a hosted model mid-session.
        from xrefer.llm.ollama import is_ollama_model
        try:
            adapter = dspy.JSONAdapter() if is_ollama_model(config.model_id) else dspy.ChatAdapter()
            self.adapter = adapter
            dspy.settings.configure(lm=self.lm, adapter=adapter)
        except Exception:
            # If the adapter classes ever move/rename, don't break LLM setup —
            # fall back to DSPy's default adapter.
            self.adapter = None
            dspy.settings.configure(lm=self.lm)
        # Lazy registration of the LiteLLM success callback so every
        # subsequent LLM call (categorizer, cluster_analyzer,
        # binary_synthesizer, the API-key validation call, anything
        # else) logs its provider-reported prompt and
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

    @contextmanager
    def override_lm(self, **extra_kwargs) -> Iterator[None]:
        """Temporarily rebuild the active LM with ``extra_kwargs`` merged
        over the configured kwargs, for the duration of the ``with`` block.

        Generalises ``uncached_lm``: the hierarchical stage-1 path uses it to
        pin a smaller ``num_ctx`` (so Ollama allocates a bounded KV cache on a
        laptop instead of the model's full advertised window) and, when the
        force-re-analyze flow is active, to also disable the response cache —
        both in a single rebuilt LM so they compose. No-op when no model is
        configured or ``extra_kwargs`` is empty.
        """
        if self.config is None or self.lm is None or not extra_kwargs:
            yield
            return

        prior_lm = self.lm
        kwargs = dict(self._lm_kwargs)
        kwargs.update(extra_kwargs)
        try:
            new_lm = dspy.LM(**kwargs)
        except TypeError:
            # Older dspy.LM may reject some kwargs (e.g. cache=); drop the
            # cache flag and retry — a randomized cache_seed (if supplied)
            # still bypasses the cache.
            kwargs.pop("cache", None)
            new_lm = dspy.LM(**kwargs)

        self.lm = new_lm
        dspy.settings.configure(lm=new_lm)
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

    def render_request_messages(self, prompt_type: PromptType, item: str, model_id: Optional[str] = None) -> List[Dict[str, str]]:
        """Render the exact chat messages DSPy would send for a single
        ``item`` under ``prompt_type`` — WITHOUT calling the LLM.

        Uses the same Predict signature and adapter DSPy uses at call
        time (``ChatAdapter`` unless an adapter is configured on
        ``dspy.settings``). The rendered messages therefore include the
        signature instructions AND the Pydantic output-model JSON schema
        — the prompt scaffolding that a raw count of ``item`` alone
        misses, and usually the larger share of a small request. Returned
        as ``[{"role", "content"}, ...]`` ready for
        ``litellm.token_counter(messages=...)``.

        Side-effect free: constructing the module builds a ``dspy.Predict``
        but never invokes it, so no API key or network access is needed.
        Raises ``ValueError`` for prompt types without a single string
        input field; callers wanting a soft fallback should catch and
        count the raw ``item`` text instead.
        """
        import dspy
        from dspy.adapters import ChatAdapter
        from xrefer.llm.dspy_modules import BinarySynthesizerModule, ClusterAnalyzerModule

        # Use THIS processor's adapter (set in set_model_config), NOT the global
        # dspy.settings.adapter — in a dual-model setup the global reflects
        # whichever model was configured last (e.g. the light Ollama model's
        # JSONAdapter), which would mis-render the heavy model's estimate. When
        # this processor is unconfigured (the fresh-LLMProcessor estimate path),
        # derive the adapter from the model_id being estimated, else ChatAdapter.
        adapter = self.adapter
        if adapter is None:
            _mid = model_id or (self.config.model_id if self.config else None)
            if _mid:
                from xrefer.llm.ollama import is_ollama_model
                adapter = dspy.JSONAdapter() if is_ollama_model(_mid) else ChatAdapter()
        if adapter is None:
            adapter = ChatAdapter()
        if prompt_type == PromptType.CLUSTER_ANALYZER:
            signature = ClusterAnalyzerModule().predictor.signature
            inputs = {"cluster_data": item}
        elif prompt_type == PromptType.BINARY_SYNTHESIZER:
            signature = BinarySynthesizerModule().predictor.signature
            inputs = {"synthesis_input": item}
        else:
            raise ValueError(f"render_request_messages: unsupported prompt type {prompt_type!r}")
        # ChatAdapter.format(signature, demos, inputs); no few-shot demos
        # are configured for these modules, matching the live call path.
        return adapter.format(signature, [], inputs)

    def _process_single(self, items: List[Any], prompt_type: PromptType, config: Optional[ProcessConfig]=None) -> Dict[str, Any]:
        """
        Process items using DSPy module.

        Dual-model routing: each role (cluster analysis vs categorization) runs
        on its OWN ``LLMProcessor`` instance with its own ``self.lm``/``adapter``.
        Because ``dspy.settings`` is GLOBAL (last ``configure`` wins) and these
        run as separate phases that can interleave / re-run, we re-assert THIS
        processor's lm+adapter per call via ``dspy.context`` (thread-local, so
        it is also safe under ``_process_parallel`` workers). ``override_lm`` /
        ``uncached_lm`` mutate ``self.lm``, so the context picks those up too.
        """
        try:
            ctx_kwargs: Dict[str, Any] = {}
            if self.lm is not None:
                ctx_kwargs["lm"] = self.lm
            if self.adapter is not None:
                ctx_kwargs["adapter"] = self.adapter
            ctx = dspy.context(**ctx_kwargs) if ctx_kwargs else nullcontext()
            with ctx:
                if prompt_type == PromptType.CATEGORIZER:
                    response: "CategorizationResponse" = CategorizerModule()(items=items, categories=config.categories, item_type=config.item_type)
                    return response.model_dump()
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

    def _preflight_connectivity(self) -> None:
        """Fail fast with an actionable error before issuing LLM calls.

        Local backends must not require internet: a fully-offline Ollama
        setup (the headline air-gapped use case) would otherwise hard-fail,
        and TLS-intercepting proxies false-fail a raw-IP probe even with
        working API access. Routing:

          * Ollama model -> probe the Ollama server itself, so failure says
            "Ollama server unreachable at <base>" instead of a wrong
            internet diagnosis.
          * any other explicit api_base (vllm, llama.cpp, gateways) -> no
            probe; the real call surfaces a specific error.
          * hosted models -> the internet probe, memoized briefly so
            back-to-back batch calls don't re-pay its timeouts.
        """
        from xrefer.llm.ollama import DEFAULT_API_BASE, is_ollama_model, server_reachable

        model_id = self.config.model_id if self.config else None
        api_base = (self.config.api_base if self.config else None) or None
        if is_ollama_model(model_id):
            if not server_reachable(api_base):
                base = api_base or DEFAULT_API_BASE
                raise ConnectionError(f"Ollama server unreachable at {base} — is `ollama serve` running?")
            return
        if api_base:
            return
        if not _internet_reachable():
            raise ConnectionError("No internet connectivity")

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
        self._preflight_connectivity()

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
