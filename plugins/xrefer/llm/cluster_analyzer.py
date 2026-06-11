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

from __future__ import annotations

import re
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Set

from xrefer.core.helpers import cancellable_phase, check_cancelled, log
from xrefer.llm.base import ModelConfig, PromptType


def _llm_processor_cls():
    """Lazy import of LLMProcessor. Its module pulls dspy/litellm — a
    measured ~4s import chain that must not be paid at IDA plugin load
    (xrefer.llm is imported by core/analyzer, which loads at plugin scan
    time). First LLM use pays it once, behind a wait box."""
    from xrefer.llm.processor import LLMProcessor
    return LLMProcessor


# Realistic upper bound on response tokens for ESTIMATE math. Some models
# advertise enormous output caps (grok-4: 256k, grok-4-fast: 2M) we'd never
# approach for cluster analysis; using them verbatim would falsely inflate the
# projected total and trip the overflow gate. We cap at Gemini Flash's output
# ceiling (65535); a model whose own cap is already <= this keeps its real value.
_MAX_RESPONSE_TOKENS_CAP = 65535

# ── Hierarchical (bottom-up) stage-1 tuning ──────────────────────────────────
# Default per-call token budget for hierarchical/local runs. Doubles as the
# Ollama num_ctx cap, so it bounds KV-cache memory (~32k ≈ ~2 GB KV F16 for a
# 12B model). Overridable via analysis_options.local_max_call_tokens.
_DEFAULT_LOCAL_MAX_CALL_TOKENS = 32768
# Tokens reserved within a hierarchical call for the model's response. Per-
# cluster stage-1 JSON is small, so a fixed modest slice is plenty (unlike the
# full path, which reserves window // 4). Also the headroom used when deciding
# whether a single cluster's call can fit.
_HIER_RESPONSE_RESERVE = 8192
# Floor for the derived Ollama num_ctx so a tiny budget setting never asks for
# an absurdly small context.
_HIER_MIN_NUM_CTX = 8192
# Per-cluster OUTPUT allowance (tokens) reserved inside a hierarchical call's
# window — the stage-1 JSON for one cluster (label / description / relationships
# / prefix / mitre). Prompt AND response share the Ollama num_ctx, so output is
# budgeted per cluster. Measured ~200-400 tok/cluster on real runs; 400 is a
# safe ceiling.
_PER_CLUSTER_RESPONSE_TOKENS = 400
# Safety margin applied to litellm.token_counter when SIZING local-model calls.
# litellm has no NATIVE tokenizer for Ollama models, so token_counter uses a
# generic GPT tokenizer — an approximation. Measured against Gemma's real
# prompt_eval_count on dense cluster data, token_counter came out ~1.18x high
# (it OVER-counts — the safe direction). This margin covers cross-model
# tokenizer variance on top of that; num_ctx = max(budget, need) is the actual
# overflow backstop, so a small margin is plenty. (An earlier char-ratio
# heuristic here was an over-correction from misreading Ollama's char-valued
# server-log field as tokens; token_counter is the proper, far closer measure.)
_LOCAL_TOKEN_SAFETY = 1.2
# Stand-in child summary used ONLY when sizing a hierarchical request before any
# LLM call (real summaries don't exist yet). ~600 chars ≈ a generous typical
# stage-1 description, so the pre-flight estimate doesn't undercount.
_HIER_PLACEHOLDER_SUMMARY = {
    "label": "Representative sub-component",
    "description": "x" * 600,
    "library_or_runtime": 0,
}


@dataclass
class TokenEstimate:
    """Pre-flight token-budget estimate for one cluster-analysis request.

    Produced by ``ClusterAnalyzer.estimate_cluster_request`` and consumed
    by the GUI budget-bar dialog. All token figures are estimates: the
    request count comes from a local tokenizer (provider-aware where
    litellm ships one, generic tiktoken otherwise), and ``max_response_tokens``
    is the output cap that will be *requested*, not a prediction of the
    actual response length.
    """
    model_id: Optional[str]
    request_tokens: int
    max_response_tokens: Optional[int]
    context_window: Optional[int]
    cluster_count: int
    num_calls: int
    rendered: bool
    note: str = ""
    # True when the model's advertised output cap was clamped to
    # _MAX_RESPONSE_TOKENS_CAP for this estimate (so the GUI can say so).
    response_capped: bool = False
    # Number of independent cluster closures (groups). With closure
    # partitioning, stage-1 runs one closure per call; the GUI surfaces this.
    num_closures: int = 1
    # Stage-1 context strategy this estimate was sized for: "full" (whole
    # corpus / largest closure) or "hierarchical" (largest bottom-up call).
    mode: str = "full"
    # For hierarchical/local runs: the Ollama num_ctx we'll actually use (==
    # KV-cache size). None for the full path and for commercial models.
    run_num_ctx: Optional[int] = None

    @property
    def total_tokens(self) -> int:
        return int(self.request_tokens) + int(self.max_response_tokens or 0)

    @property
    def utilization(self) -> Optional[float]:
        """total / context_window, or None when the window is unknown."""
        if not self.context_window:
            return None
        return self.total_tokens / self.context_window

    @property
    def warn(self) -> bool:
        """True when projected usage is at/above 95% of the window."""
        u = self.utilization
        return u is not None and u >= 0.95


def exceeds_context_window(estimate: "TokenEstimate") -> bool:
    """The pre-flight gate's block condition: True when the estimate's
    request + max-response overflows the model's context window (the bar's
    red zone). False when the window is unknown — we never block on a model
    litellm can't size, since we can't prove it would overflow.
    """
    cw = estimate.context_window
    return bool(cw) and estimate.total_tokens > cw


def resolve_cluster_context_mode(mode_setting: Optional[str], model_id: Optional[str],
                                 full_fits: bool) -> str:
    """Resolve the stage-1 context strategy to ``"full"`` or ``"hierarchical"``.

    - ``"full"`` / ``"hierarchical"``: honoured verbatim (the A/B overrides).
    - ``"auto"`` (default): LOCAL (Ollama) models ALWAYS go hierarchical — on a
      laptop, "fits the window" is not the same as "the hardware copes," so we
      always shrink per-call payloads regardless of the advertised window.
      COMMERCIAL models send the full corpus when it fits (``full_fits``) and
      fall back to hierarchical only when it doesn't.
    """
    mode = (mode_setting or "auto").strip().lower()
    if mode in ("full", "hierarchical"):
        return mode
    from xrefer.llm.ollama import is_ollama_model
    if is_ollama_model(model_id):
        return "hierarchical"
    return "full" if full_fits else "hierarchical"


@dataclass(frozen=True)
class EstimateContext:
    """Model-independent inputs for a token estimate, built once by
    ``ClusterAnalyzer.build_estimate_context`` so the GUI can re-estimate
    across models cheaply (``estimate_for_model``) without re-formatting the
    cluster payload or re-rendering the DSPy messages — only the tokenizer and
    the model's limits change per model.
    """
    cluster_data: str
    messages: Optional[List[Dict[str, str]]]
    rendered: bool
    cluster_count: int
    num_calls: int
    # Ollama server URL (for local models); None for hosted. Used by
    # estimate_for_model to read a local model's context via /api/show.
    api_base: Optional[str] = None
    # Number of independent cluster closures (groups) this run partitions into.
    num_closures: int = 1
    # Which strategy this context was built for: "full" or "hierarchical".
    mode: str = "full"
    # Hierarchical per-call token budget (also the Ollama num_ctx cap). Carried
    # so estimate_for_model can derive run_num_ctx without re-reading settings.
    local_max_call_tokens: int = _DEFAULT_LOCAL_MAX_CALL_TOKENS


@contextmanager
def _null_context() -> Iterator[None]:
    """A no-op context manager — paired with ``LLMProcessor.uncached_lm``
    so call-sites can write ``with cache_ctx:`` without branching on
    whether force-no-cache is on. Python 3.7+ has ``contextlib.nullcontext``
    for this; we define a local equivalent to keep the import minimal
    and avoid version-skew issues with the rest of the file's style.
    """
    yield


def _measure(text: str, model: Optional[str]) -> str:
    """Return a short, honest size string for ``text`` for inline logs.

    This is a lightweight progress readout for the cluster payload, NOT a
    full-prompt count: it measures only the formatted cluster/synthesis
    string, excluding the DSPy signature instructions and Pydantic output
    schema that wrap it on the wire. For the accurate request-vs-window
    figure (rendered prompt + max response), use
    ``ClusterAnalyzer.estimate_cluster_request`` / the "Estimate Analysis
    Token Usage" context-menu action.

    ``litellm.token_counter`` is model-aware only where a tokenizer ships
    for the provider — exact for OpenAI (tiktoken); for providers without
    a bundled tokenizer it returns a generic tiktoken-based approximation
    rather than raising. We therefore label the result "input only" and
    drop the earlier "(model: X)" suffix, which overstated how provider-
    specific the number is. The character fallback fires only when no
    model is known or the counter genuinely errors out.
    """
    if model:
        try:
            import litellm
            n = litellm.token_counter(model=model, text=text)
            if isinstance(n, int) and n > 0:
                return f"~{n:,} tokens, input only"
        except Exception:
            # Hard failure (transient import / internal error) -> char count.
            pass
    return f"{len(text):,} chars, input only"


if TYPE_CHECKING:
    from xrefer.core.clusters import FunctionalCluster
    from xrefer.core.analyzer import XRefer
    from xrefer.llm.processor import LLMProcessor


class ClusterAnalyzer:
    """Main interface for analyzing function clusters"""

    current_config: ModelConfig = None
    _processor: LLMProcessor = None

    @classmethod
    def _get_processor(cls) -> LLMProcessor:
        """Get or create LLM processor with current config."""
        if not cls._processor:
            if not cls.current_config:
                raise ValueError("Model configuration not set. Use set_model_config() first.")
            cls._processor = _llm_processor_cls()()
            cls._processor.set_model_config(cls.current_config)
        return cls._processor

    @classmethod
    def set_model_config(cls, config: ModelConfig):
        """Set LLM configuration for analysis."""
        cls.current_config = config
        cls._processor = None  # Force new processor with new config

    @staticmethod
    def _stage1_ids_present(stage1_clusters: Dict[str, Any]) -> Set[int]:
        """Cluster ids already answered for, parsed from 'cluster_<id>' keys
        (unparseable keys from a misbehaving model are ignored)."""
        present: Set[int] = set()
        for key in stage1_clusters:
            try:
                present.add(int(str(key).rsplit("_", 1)[1]))
            except (IndexError, ValueError):
                continue
        return present

    @classmethod
    def _resilient_stage1_call(cls, processor: LLMProcessor, cluster_data: str,
                               respond_ids: Set[int], xrefer_obj, make_ctx) -> Dict[str, Any]:
        """One stage-1 call with retry-on-incomplete and skip-on-repeat.

        The success condition is "the response carries cluster_<id> for
        every requested id" — NOT "no exception": the processor absorbs
        rate limits and returns {} without raising, and a model can
        silently drop ids, so keying on exceptions alone misses both.
        ``make_ctx(attempt)`` supplies the LM context per attempt; the
        retry attempt must bypass the response cache, or a cached
        bad/partial response just replays. A still-incomplete second
        attempt keeps whatever DID come back (attempts merge), records
        the gap for the failure dialog, and lets the run continue —
        stage 2 already tolerates missing entries.
        """
        wanted = {f"cluster_{cid}" for cid in respond_ids}
        merged: Dict[str, Any] = {}
        for _attempt in range(2):
            error_name = None
            try:
                with make_ctx(_attempt):
                    results = dict(processor.process_items(
                        cluster_data,
                        prompt_type=PromptType.CLUSTER_ANALYZER,
                        ignore_token_limit=True,
                    ))
                merged.update(results.get("clusters", {}) or {})
            except Exception as e:
                error_name = e.__class__.__name__
            missing = wanted - set(merged)
            if not missing:
                return merged
            missing_ids = sorted(respond_ids - cls._stage1_ids_present(merged))
            if _attempt == 0:
                reason = error_name or f"{len(missing_ids)} cluster id(s) missing from the response"
                log(f"[!] Stage 1: call for clusters {sorted(respond_ids)} incomplete "
                    f"({reason}); retrying once with the cache bypassed.")
            else:
                log(f"[!] Stage 1: clusters {missing_ids} still missing after retry; "
                    "skipping them and continuing.")
                cls._note_partial_failure(
                    xrefer_obj,
                    stage="stage 1",
                    error=error_name or "IncompleteResponse",
                    message="Some stage-1 cluster calls stayed incomplete after a retry; the affected clusters were skipped.",
                    skipped_cluster_ids=set(missing_ids),
                )
        return merged

    @staticmethod
    def _note_partial_failure(xrefer_obj, **fields) -> None:
        """Record a partial-failure note on the analyzer object.

        The GUI consumes (and clears) ``cluster_analysis_failure`` after the
        run to show what went wrong instead of announcing success —
        precedent: ``cluster_token_budget_exceeded`` is written from here
        the same way. Notes merge, so stage-1 skips and a stage-2 fallback
        within one run are both reported; ``skipped_cluster_ids``
        accumulates. Never raises (reporting must not break the run).
        """
        try:
            note = getattr(xrefer_obj, "cluster_analysis_failure", None) or {}
            note.setdefault("severity", "partial")
            for key, value in fields.items():
                if key == "skipped_cluster_ids":
                    note[key] = sorted(set(note.get(key, [])) | set(value))
                else:
                    note[key] = value
            xrefer_obj.cluster_analysis_failure = note
        except Exception:
            pass

    @classmethod
    def analyze_clusters(
        cls,
        clusters: List["FunctionalCluster"],
        xrefer_obj,
        batch_size: int = 30,
        force_no_cache: bool = False,
    ) -> Dict[str, Any]:
        """
        Analyze cluster hierarchy using a two-stage LLM flow.

        Stage 1 — per-cluster analysis (always, possibly batched):
            Each batch produces label / description / relationships /
            function_prefix / library_or_runtime / mitre_attack for its
            subset of clusters. The full cluster_data is shown in every
            batch so cross-cluster context is available, but the LLM is
            told to only fully respond for the focal subset. No binary-
            level fields are requested here.

        Stage 2 — binary-level synthesis (always, single call):
            The stage-1 per-cluster outputs plus aggregated raw
            artifacts (all strings, libraries, CAPA hits, APIs per
            cluster) are fed to a dedicated synthesizer that produces
            binary_description, binary_category, and the structured
            binary_report. Stage 2 sees the WHOLE binary in one view,
            so its synthesis isn't biased by which batch the
            high-signal clusters happened to fall in.

        The two-stage split also eliminates the prior flow's wasted
        work: the single-stage prompt asked the LLM to produce
        binary_description / binary_category on every batch (only the
        final batch's values were kept) and binary_report on the final
        batch only (earlier batches produced a discard-bound stub).

        Args:
            force_no_cache: when True, bypass DSPy/LiteLLM response
                cache for every call in this run. Both stages wrap
                their LLM calls in ``processor.uncached_lm()`` so the
                temporary cache=False / randomized-cache_seed LM is
                in effect for the duration of each call. Used by the
                "force re-analyze" UI flow.
        """
        processor = cls._get_processor()

        cluster_count = 0

        def count_clusters(cluster):
            nonlocal cluster_count
            cluster_count += 1
            for subcluster in cluster.subclusters:
                count_clusters(subcluster)

        for cluster in clusters:
            count_clusters(cluster)

        if cluster_count == 0:
            return {}

        if force_no_cache:
            log("Force re-analyze: bypassing DSPy / LiteLLM response cache for this run.")

        def cache_ctx():
            return processor.uncached_lm() if force_no_cache else _null_context()

        # Model identifier for token counting. Pull from the active
        # processor's ModelConfig so the count is provider-specific
        # (gpt tokenizer for openai/, gemini tokenizer for gemini/,
        # etc.). Falls back to char count inside ``_measure`` when
        # litellm doesn't ship the tokenizer for this model.
        model_id = processor.config.model_id if processor.config else None

        # ── Resolve stage-1 context strategy (full vs hierarchical) ──
        # auto: local (Ollama) models always summarise bottom-up (small per-call
        # payloads keep laptop memory bounded); commercial models use the full
        # corpus when it fits, else fall back to hierarchical. "full" /
        # "hierarchical" force the choice (and are the A/B lever).
        try:
            mode_setting = xrefer_obj.settings.get("analysis_options", {}).get("cluster_context_mode", "auto")
        except Exception:
            mode_setting = "auto"
        _ms = (mode_setting or "auto").strip().lower()
        if _ms in ("full", "hierarchical"):
            mode = _ms
        else:
            from xrefer.llm.ollama import is_ollama_model as _is_ollama
            if _is_ollama(model_id):
                mode = "hierarchical"
            else:
                # Only the commercial auto case needs the full-corpus fit probe.
                try:
                    _full_est = cls.estimate_for_model(cls.build_estimate_context(clusters, xrefer_obj), model_id)
                    _full_fits = not exceeds_context_window(_full_est)
                except Exception:
                    _full_fits = True
                mode = "full" if _full_fits else "hierarchical"
        log(f"Stage 1 context mode: {mode} (setting: {mode_setting})")

        stage1_clusters: Dict[str, Any] = {}
        # Stage 1 is many independent calls — the one phase where Cancel can
        # take effect between units of work (an in-flight synchronous LLM
        # call itself cannot be interrupted).
        with cancellable_phase():
            if mode == "hierarchical":
                # ── Hierarchical bottom-up: leaves-first, children as summaries ──
                stage1_clusters = cls._run_bottomup_stage1(
                    clusters, xrefer_obj, processor, batch_size, force_no_cache, model_id,
                )
            else:
                # ── Full path: send the whole corpus, answer in batches ──────
                # Each call sends the full cluster corpus (so cross-cluster context
                # is always available) but asks the model to return analysis for only
                # a batch_size-sized subset at a time, for per-cluster richness.
                # Independent closures (groups) are the outer loop; for the common
                # single-component binary there is just one. (Anything too big to fit
                # the window is caught by the pre-flight gate before we get here.)
                from xrefer.core.clusters import cluster_ids as _cluster_ids
                from xrefer.core.clusters import compute_closures as _compute_closures

                closures = _compute_closures(clusters)
                total_batches = sum(
                    max(1, (len(_cluster_ids(cl)) + batch_size - 1) // batch_size) for cl in closures
                )
                log(f"Stage 1 (full): {cluster_count} clusters in {len(closures)} group(s); "
                    f"{total_batches} batch(es) of up to {batch_size}, full corpus sent each call")

                def _full_ctx(attempt: int):
                    # Attempt 0 honors the force-no-cache run setting; the
                    # retry attempt always bypasses the cache.
                    return processor.uncached_lm() if (force_no_cache or attempt == 1) else cache_ctx()

                done = 0
                batch_no = 0
                cancelled = False
                for closure in closures:
                    if cancelled:
                        break
                    closure_ids = sorted(_cluster_ids(closure))
                    for bstart in range(0, len(closure_ids), batch_size):
                        if check_cancelled():
                            cancelled = True
                            break
                        respond_ids = set(closure_ids[bstart:bstart + batch_size])
                        cluster_data = cls.format_cluster_data(closure, xrefer_obj, respond_for_ids=respond_ids)
                        batch_no += 1
                        done += len(respond_ids)
                        log(
                            f"Stage 1 (full): batch {batch_no}/{total_batches}, "
                            f"{len(respond_ids)} cluster(s) [{done}/{cluster_count}] "
                            f"(full corpus {_measure(cluster_data, model_id)})"
                        )
                        # Resilient: a failure on batch 9/10 used to
                        # propagate out and discard the nine completed
                        # batches; now it costs at most this batch.
                        stage1_clusters.update(cls._resilient_stage1_call(
                            processor, cluster_data, respond_ids, xrefer_obj, _full_ctx,
                        ))

                    # One follow-up re-ask per closure for ids the batch
                    # loop didn't land (rate-limited or model-dropped) —
                    # bounded extra cost, and far cheaper than letting them
                    # silently become stage-2 placeholders.
                    if not cancelled and not check_cancelled():
                        still_missing = set(closure_ids) - cls._stage1_ids_present(stage1_clusters)
                        if still_missing:
                            log(f"Stage 1 (full): follow-up call for {len(still_missing)} "
                                f"cluster(s) missed across batches: {sorted(still_missing)}")
                            cluster_data = cls.format_cluster_data(closure, xrefer_obj, respond_for_ids=still_missing)
                            stage1_clusters.update(cls._resilient_stage1_call(
                                processor, cluster_data, still_missing, xrefer_obj, _full_ctx,
                            ))

        if not stage1_clusters:
            log("[-] Error: No cluster data received after stage 1")
            return {}

        if check_cancelled():
            # Cancel pressed mid-stage-1: whatever was gathered is real work.
            # Mirror the stage-2-failure fall-through instead of discarding
            # it — the analyst can re-run later to fill in the rest.
            log("[!] Cluster analysis cancelled — saving the per-cluster analyses "
                "gathered so far with placeholder binary fields.")
            cls._note_partial_failure(
                xrefer_obj,
                stage="stage 1",
                cancelled=True,
                message="Cancelled by user; the per-cluster analyses gathered so far were kept.",
                partial_cluster_count=len(stage1_clusters),
            )
            return {
                "clusters": stage1_clusters,
                "binary_description": "",
                "binary_category": "Undetermined",
            }

        # ── Stage 2: binary-level synthesis ──────────────────────────
        log("Stage 2: synthesising binary-level analysis from per-cluster results")
        synthesis_input = cls.format_synthesis_input(clusters, xrefer_obj, stage1_clusters)
        log(f"Stage 2: generated synthesis input ({_measure(synthesis_input, model_id)})")
        # Stage-2 fit gate: it is one combined call by nature; if it overflows
        # the window there is no lossless way to split it, so block the run
        # (per policy) and surface the estimate to the GUI.
        if model_id:
            try:
                _s2_api_base = xrefer_obj.settings.get("api_base") or None
            except Exception:
                _s2_api_base = None
            try:
                _s2_msgs = processor.render_request_messages(PromptType.BINARY_SYNTHESIZER, synthesis_input)
                # Stage 2 is a single synthesis call regardless of how stage 1
                # was partitioned, so num_closures is 1 here (and `closures` may
                # not exist on the hierarchical path).
                _s2_est = cls.estimate_for_model(
                    EstimateContext(synthesis_input, _s2_msgs, True, cluster_count, 1, _s2_api_base, 1),
                    model_id,
                )
                if exceeds_context_window(_s2_est):
                    log("[!] Stage 2 synthesis exceeds the model's context window — blocking the run.")
                    try:
                        xrefer_obj.cluster_token_budget_exceeded = _s2_est
                    except Exception:
                        pass
                    return {}
            except Exception:
                pass
        # Resilient stage 2. Stage 1's per-cluster analyses are the bulk of the
        # work and valuable on their own, so a stage-2 hiccup must NOT discard
        # them — a single missing field used to abort the entire run AFTER all of
        # stage 1 succeeded. Retry once with a fresh generation; if synthesis
        # still fails, keep the stage-1 results and fall through to placeholders
        # so the run is saved and the analyst can re-synthesise later.
        synthesis: Dict[str, Any] = {}
        for _attempt in range(2):
            try:
                ctx = cache_ctx() if _attempt == 0 else processor.uncached_lm()
                with ctx:
                    synthesis = dict(processor.process_items(
                        synthesis_input,
                        prompt_type=PromptType.BINARY_SYNTHESIZER,
                        ignore_token_limit=True,
                    ))
                break
            except Exception as e:
                if _attempt == 0:
                    log(f"[!] Stage 2 synthesis failed ({e.__class__.__name__}: {str(e)[:140]}); retrying once.")
                else:
                    log(f"[!] Stage 2 synthesis failed again ({e.__class__.__name__}); keeping the "
                        "per-cluster (stage 1) results without binary-level synthesis.")
                    synthesis = {}

        binary_description = synthesis.get("binary_description")
        binary_category = synthesis.get("binary_category")
        binary_report = synthesis.get("binary_report")

        if binary_description is None or binary_category is None:
            # Stage 2 produced nothing usable — but stage 1 did real work, so
            # never throw it away. Save the per-cluster analyses with placeholder
            # binary-level fields rather than returning {} (a total loss of the
            # whole run).
            log("[!] Stage 2 produced no binary-level synthesis; saving the "
                "per-cluster analyses with placeholder binary fields.")
            cls._note_partial_failure(
                xrefer_obj,
                stage="stage 2",
                stage2_failed=True,
                message="Binary-level synthesis failed; the per-cluster analyses were kept with placeholder binary fields.",
                partial_cluster_count=len(stage1_clusters),
            )
            return {
                "clusters": stage1_clusters,
                "binary_description": binary_description or "",
                "binary_category": binary_category or "Undetermined",
            }

        final_result: Dict[str, Any] = {
            "clusters": stage1_clusters,
            "binary_description": binary_description,
            "binary_category": binary_category,
        }
        if binary_report is not None:
            final_result["binary_report"] = binary_report
            # Walk the full cluster tree (top-level + subclusters) to
            # build the valid-ID set for the citation-resolution
            # warning. synthesis_input contained every cluster, so a
            # citation against any of them is legitimate; anything
            # else is a hallucination.
            valid_ids: Set[int] = set()

            def _collect_ids(cs: List["FunctionalCluster"]) -> None:
                for c in cs:
                    valid_ids.add(c.id)
                    _collect_ids(c.subclusters)

            _collect_ids(clusters)
            cls._warn_on_sparse_binary_report(
                binary_report,
                valid_cluster_ids=valid_ids,
                binary_description=binary_description,
            )

        return final_result


    # Regex for the citation token forms documented in
    # BinaryReport.details (e.g. `[c5]`, `[c4, c6]`, `[c4, c6, c7]`).
    # Comma is required between IDs; whitespace after the comma is
    # tolerated. Matches the whole bracketed group so the caller can
    # extract individual `c<N>` tokens from match.group(0).
    _CITATION_GROUP_RE = re.compile(r"\[c\d+(?:\s*,\s*c\d+)*\]")
    _CITATION_ID_RE = re.compile(r"c(\d+)")

    @staticmethod
    def _warn_on_sparse_binary_report(
        binary_report: Any,
        valid_cluster_ids: Optional[Set[int]] = None,
        binary_description: Optional[str] = None,
    ) -> None:
        """Soft post-hoc checks on the final binary_report markdown
        string and (optionally) the standalone ``binary_description``
        summary. Logs non-fatal warnings for length out-of-band,
        marketing-adjective / cluster-id-leak token usage, and
        cluster citations that don't resolve to any cluster in this
        binary.

        None of these are validated by Pydantic — Pydantic
        constraints aren't reflected in the JSON schema the LLM
        sees, so the model can't reliably aim for them. Earlier
        iterations enforced length and banned tokens as hard
        validators and caused real analyses to abort on small
        slips. Prompt guidance now does the heavy lifting; these
        warnings surface anomalies so the analyst can decide
        whether to re-run.

        ``binary_report`` is the already-rendered markdown string —
        the stage-2 ``BinarySynthesisResponse`` serializer flattens
        the structured form via ``to_markdown()`` before this
        function sees it.

        Args:
            binary_report: the rendered markdown string.
            valid_cluster_ids: set of cluster IDs that exist in
                this binary's cluster tree. When provided, the
                citation-resolution check fires for any `[c<N>]`
                whose N isn't in the set. When None, the citation
                check is skipped (used when the caller doesn't
                have the cluster tree handy).
            binary_description: the standalone summary field. When
                provided, the marketing-adjective scan also runs
                against this string — historically the marquee
                line that surfaces in the HTML report and the IDA
                cluster header, so puffery there is especially
                visible. The cluster-id-leak token doesn't apply
                here (cluster.id. never appears in
                binary_description by construction).
        """
        if not isinstance(binary_report, str) or not binary_report:
            return
        try:
            from xrefer.llm.dspy_modules import BinaryReport, BANNED_TOKENS_SOFT
            soft_min = BinaryReport.SOFT_MIN_LENGTH
            soft_max = BinaryReport.SOFT_MAX_LENGTH
            banned = BANNED_TOKENS_SOFT
        except Exception:
            soft_min, soft_max = 1500, 4500
            banned = ()

        # Length band warning.
        n = len(binary_report)
        if n < soft_min:
            log(
                f"[!] binary_report is sparse: {n} chars rendered "
                f"(target: {soft_min}-{soft_max}). Analysis "
                "succeeded but the report may lack detail. This is "
                "fine for small/simple binaries; for larger ones, "
                "re-running cluster analysis usually produces a "
                "richer report."
            )
        elif n > soft_max:
            log(
                f"[!] binary_report is long: {n} chars rendered "
                f"(target: {soft_min}-{soft_max}). Analysis "
                "succeeded but the report may be verbose. The HTML "
                "renderer handles long reports, but a more concise "
                "report is usually easier to triage."
            )

        # Banned-token warnings — marketing adjectives + cluster.id.
        # leak. Case-insensitive substring search; one log per token
        # found.
        lower = binary_report.lower()
        for tok in banned:
            if tok.lower() in lower:
                if tok == "cluster.id.":
                    log(
                        "[!] binary_report contains a `cluster.id.` "
                        "reference. The verbose long form is "
                        "forbidden in binary_report — use the short "
                        "`[c<N>]` citation form instead. Cluster "
                        "cross-references in their long form belong "
                        "in per-cluster `relationships`. Re-running "
                        "cluster analysis usually fixes this."
                    )
                else:
                    log(
                        f"[!] binary_report uses marketing adjective "
                        f"'{tok}' — concrete facts ('32 file "
                        "extensions') are more useful than vague "
                        "qualifiers ('comprehensive list'). The "
                        "report still rendered; this is a style note "
                        "only."
                    )

        # Marketing-adjective scan on binary_description. This is
        # the standalone summary field — historically the marquee
        # analyst-facing line — and the prompt does include an
        # anti-puffery rule for it, but the field has its own LLM
        # output path so slips need their own surface. The cluster-
        # id-leak token is intentionally skipped here (it can't
        # appear in binary_description by construction).
        if isinstance(binary_description, str) and binary_description:
            desc_lower = binary_description.lower()
            for tok in banned:
                if tok == "cluster.id.":
                    continue
                if tok.lower() in desc_lower:
                    log(
                        f"[!] binary_description uses marketing "
                        f"adjective '{tok}' — binary_description "
                        "is the marquee summary; concrete claims "
                        "('encrypts files using ChaCha20-Poly1305') "
                        "are more useful than vague qualifiers "
                        "('sophisticated cryptographic primitives'). "
                        "The description still rendered; this is a "
                        "style note only."
                    )

        # Citation-resolution warning. Only runs when the caller
        # supplied the set of valid cluster IDs. Surfaces any
        # `[c<N>]` whose N doesn't match a cluster in this binary —
        # typically caused by the LLM hallucinating an ID that
        # wasn't in synthesis_input. The web UI / HTML renderer is
        # expected to degrade gracefully (render as a non-link
        # chip with a "missing" tooltip), so this is informational
        # rather than fatal.
        if valid_cluster_ids is not None:
            unresolved: Set[int] = set()
            for bracket in ClusterAnalyzer._CITATION_GROUP_RE.finditer(binary_report):
                for inner in ClusterAnalyzer._CITATION_ID_RE.finditer(bracket.group(0)):
                    cid = int(inner.group(1))
                    if cid not in valid_cluster_ids:
                        unresolved.add(cid)
            if unresolved:
                joined = ", ".join(f"c{i}" for i in sorted(unresolved))
                log(
                    f"[!] binary_report cites cluster IDs not present "
                    f"in this binary's cluster set: {joined}. The "
                    "renderer will treat these as broken-link chips. "
                    "Re-running cluster analysis usually fixes this."
                )


    @classmethod
    def build_estimate_context(cls, clusters: List["FunctionalCluster"], xrefer_obj: "XRefer") -> "EstimateContext":
        """Build the MODEL-INDEPENDENT inputs for a stage-1 token estimate
        once: the formatted cluster payload, the rendered DSPy messages (or
        None on render failure), the cluster count, and the number of stage-1
        calls. The GUI re-estimates across models cheaply by feeding this into
        ``estimate_for_model`` — the prompt content is identical across
        models, only the tokenizer and the model's limits differ.

        Stage 1 now sends one independent **closure** per call, so the binding
        fit constraint is the **largest closure** — not the whole corpus. We
        size that one (render its messages); the GUI re-estimates it across
        models via ``estimate_for_model``. Also reports the number of closures
        and the total stage-1 call count.
        """
        from xrefer.core.clusters import cluster_ids as _cluster_ids
        from xrefer.core.clusters import compute_closures as _compute_closures

        closures = _compute_closures(clusters)

        try:
            batch_size = int(xrefer_obj.settings.get("analysis_options", {}).get("cluster_batch_size", 30)) or 30
        except Exception:
            batch_size = 30

        cluster_count = len(_cluster_ids(clusters))
        # Each closure is >=1 stage-1 call (response-batched by batch_size for
        # output quality when it has many clusters).
        num_calls = 0
        for closure in closures:
            n = len(_cluster_ids(closure))
            num_calls += max(1, (n + batch_size - 1) // batch_size)
        num_closures = len(closures)

        # Size the largest closure. Format each (cheap string build) and pick
        # the longest by characters — a faithful proxy for the token-heaviest —
        # then render only that one.
        cluster_data = max(
            (cls.format_cluster_data(closure, xrefer_obj) for closure in closures),
            key=len,
            default="",
        )

        messages: Optional[List[Dict[str, str]]] = None
        rendered = False
        try:
            # Pass the heavy (cluster-analysis) model id so this fresh, unconfigured
            # processor renders with the right adapter (JSONAdapter for Ollama,
            # ChatAdapter for hosted) — the estimate is for this model, not for
            # whatever model was configured globally last.
            messages = _llm_processor_cls()().render_request_messages(
                PromptType.CLUSTER_ANALYZER, cluster_data,
                model_id=xrefer_obj.settings.get("llm_model_id"))
            rendered = True
        except Exception:
            messages = None
            rendered = False

        try:
            api_base = xrefer_obj.settings.get("api_base", "") or None
        except Exception:
            api_base = None

        return EstimateContext(
            cluster_data=cluster_data,
            messages=messages,
            rendered=rendered,
            cluster_count=cluster_count,
            num_calls=num_calls,
            api_base=api_base,
            num_closures=num_closures,
            mode="full",
        )

    @classmethod
    def build_hier_estimate_context(cls, clusters: List["FunctionalCluster"],
                                    xrefer_obj: "XRefer") -> "EstimateContext":
        """Build the model-independent inputs for a HIERARCHICAL (bottom-up)
        stage-1 estimate. Unlike the full-path context (which sizes the largest
        closure), the binding fit constraint here is the **largest single
        bottom-up call** — one cluster's own detail plus its children rendered as
        short summaries. The real child summaries don't exist before the run, so
        we size with a generous placeholder summary; the result is an upper-ish
        bound, accurate enough for the overflow gate and the budget bar.

        Also reports the projected stage-1 call count (the wave-packed count
        under the configured per-call token budget) and tags the context
        ``mode="hierarchical"`` so ``estimate_for_model`` reserves a small fixed
        response slice and derives the run's Ollama num_ctx.
        """
        from xrefer.core.clusters import bottomup_waves
        from xrefer.core.clusters import cluster_ids as _cluster_ids

        try:
            batch_size = int(xrefer_obj.settings.get("analysis_options", {}).get("cluster_batch_size", 30)) or 30
        except Exception:
            batch_size = 30
        try:
            budget_tokens = int(xrefer_obj.settings.get("analysis_options", {}).get(
                "local_max_call_tokens", _DEFAULT_LOCAL_MAX_CALL_TOKENS)) or _DEFAULT_LOCAL_MAX_CALL_TOKENS
        except Exception:
            budget_tokens = _DEFAULT_LOCAL_MAX_CALL_TOKENS

        # Placeholder summaries for every cluster id, so a focal cluster's
        # children render at a realistic size during sizing.
        placeholder = {cid: _HIER_PLACEHOLDER_SUMMARY for cid in _cluster_ids(clusters)}

        def size_fn(c):
            return len(cls.format_cluster_data([c], xrefer_obj, summaries=placeholder))

        waves = bottomup_waves(clusters)
        payload_budget_chars = max(4096, (budget_tokens - _HIER_RESPONSE_RESERVE) * 4)
        calls = cls._pack_waves(waves, size_fn, payload_budget_chars, batch_size)
        num_calls = len(calls) or 1

        # The largest call by characters is the binding one. Render it as a real
        # bottom-up call (its focal clusters + placeholder child summaries).
        largest = max(calls, key=lambda call: sum(size_fn(c) for c in call), default=[])
        if largest:
            cluster_data = cls.format_cluster_data(
                largest, xrefer_obj, respond_for_ids={c.id for c in largest}, summaries=placeholder,
            )
        else:
            cluster_data = ""

        messages: Optional[List[Dict[str, str]]] = None
        rendered = False
        try:
            # Pass the heavy (cluster-analysis) model id so this fresh, unconfigured
            # processor renders with the right adapter (JSONAdapter for Ollama,
            # ChatAdapter for hosted) — the estimate is for this model, not for
            # whatever model was configured globally last.
            messages = _llm_processor_cls()().render_request_messages(
                PromptType.CLUSTER_ANALYZER, cluster_data,
                model_id=xrefer_obj.settings.get("llm_model_id"))
            rendered = True
        except Exception:
            messages = None
            rendered = False

        try:
            api_base = xrefer_obj.settings.get("api_base", "") or None
        except Exception:
            api_base = None

        return EstimateContext(
            cluster_data=cluster_data,
            messages=messages,
            rendered=rendered,
            cluster_count=len(_cluster_ids(clusters)),
            num_calls=num_calls,
            api_base=api_base,
            num_closures=1,
            mode="hierarchical",
            local_max_call_tokens=budget_tokens,
        )

    @staticmethod
    def _pack_waves(waves, size_fn, budget_chars, batch_size):
        """Greedily pack each wave's ready clusters into calls. A cluster is
        added to the current call until adding it would exceed the char budget
        OR the batch_size count; a single oversized cluster forms its own call.
        Clusters from different waves are NEVER mixed (a parent must read its
        children's summaries from an EARLIER call). Returns a flat, leaves-first
        list of calls, each a list of FunctionalCluster.
        """
        calls = []
        for wave in waves:
            cur, cur_sz = [], 0
            for cluster in wave:
                sz = size_fn(cluster)
                if cur and (len(cur) >= batch_size or cur_sz + sz > budget_chars):
                    calls.append(cur)
                    cur, cur_sz = [], 0
                cur.append(cluster)
                cur_sz += sz
            if cur:
                calls.append(cur)
        return calls

    @classmethod
    def _run_bottomup_stage1(cls, clusters: List["FunctionalCluster"], xrefer_obj: "XRefer",
                             processor, batch_size: int, force_no_cache: bool,
                             model_id: Optional[str]) -> Dict[str, Any]:
        """Hierarchical bottom-up stage 1.

        Walk the subcluster containment hierarchy leaves-first
        (``bottomup_waves``), analysing each cluster with full detail for its OWN
        functions plus its already-analysed children rendered as short summaries.
        Each wave's ready clusters are packed into calls under the per-call token
        budget (``local_max_call_tokens``), so every call stays small regardless
        of the binary's size. For local (Ollama) models the call's num_ctx — i.e.
        the KV-cache memory — is pinned to that budget (bumped only for an
        unusually large single cluster, clamped to the model's window),
        decoupling memory from the model's advertised window.

        Returns the ``{cluster_<id> -> stage-1 result}`` map (same shape the full
        path produces), with one entry per cluster, ready for stage 2.
        """
        from xrefer.core.clusters import bottomup_waves
        from xrefer.llm.ollama import is_ollama_model, model_context_length

        import litellm

        try:
            budget_tokens = int(xrefer_obj.settings.get("analysis_options", {}).get(
                "local_max_call_tokens", _DEFAULT_LOCAL_MAX_CALL_TOKENS)) or _DEFAULT_LOCAL_MAX_CALL_TOKENS
        except Exception:
            budget_tokens = _DEFAULT_LOCAL_MAX_CALL_TOKENS

        local = is_ollama_model(model_id)
        api_base = None
        model_window = None
        if local:
            try:
                api_base = xrefer_obj.settings.get("api_base") or None
            except Exception:
                api_base = None
            model_window = model_context_length(api_base, model_id)

        # Token-accurate sizing. Each call = scaffolding (the DSPy signature +
        # Pydantic JSON schema wrapping every payload, measured once) + the
        # payload + the per-cluster response; all three share the one Ollama
        # window. Counting uses litellm.token_counter — the proper tokenizer.
        # litellm has no NATIVE tokenizer for local models so it falls back to a
        # generic GPT tokenizer, but that measured ~1.18x Gemma's real count on
        # dense cluster data (it over-counts, the safe direction);
        # _LOCAL_TOKEN_SAFETY adds margin for cross-model variance, and
        # num_ctx = max(budget, need) is the real overflow backstop.
        def _tok(text: str) -> int:
            try:
                return int(litellm.token_counter(model=model_id, text=text) * _LOCAL_TOKEN_SAFETY)
            except Exception:
                # No tokenizer at all: conservative char fallback that
                # over-counts (≈2.5 chars/tok) so we still can't overflow.
                return int(len(text) / 2.5 * _LOCAL_TOKEN_SAFETY) + 1

        try:
            _scaffold_msgs = processor.render_request_messages(PromptType.CLUSTER_ANALYZER, "")
            scaffold_tokens = int(litellm.token_counter(model=model_id, messages=_scaffold_msgs) * _LOCAL_TOKEN_SAFETY)
        except Exception:
            scaffold_tokens = 4000
        # Room left for payload + output after the fixed scaffolding (output is
        # charged per cluster inside cost_fn, so it is already accounted for).
        call_budget_tokens = max(2048, budget_tokens - scaffold_tokens)

        waves = bottomup_waves(clusters)
        total = sum(len(w) for w in waves)
        log(f"Stage 1 (hierarchical): {total} clusters in {len(waves)} bottom-up level(s); "
            f"per-call budget ~{budget_tokens:,} tok (scaffold ~{scaffold_tokens:,})"
            + (" — caps num_ctx" if local else ""))

        summaries: Dict[int, Any] = {}
        stage1_clusters: Dict[str, Any] = {}

        def cost_fn(c):
            # Per-cluster cost = payload tokens + the output the cluster will
            # generate. Both share the window, so both are charged.
            payload = cls.format_cluster_data([c], xrefer_obj, summaries=summaries)
            return _tok(payload) + _PER_CLUSTER_RESPONSE_TOKENS

        done_count = 0
        for wi, wave in enumerate(waves, 1):
            calls = cls._pack_waves([wave], cost_fn, call_budget_tokens, batch_size)
            for call in calls:
                if check_cancelled():
                    log("[!] Stage 1 cancelled — keeping the per-cluster results gathered so far.")
                    return stage1_clusters
                respond_ids = {c.id for c in call}
                cluster_data = cls.format_cluster_data(
                    call, xrefer_obj, respond_for_ids=respond_ids, summaries=summaries,
                )
                done_count += len(call)

                # Real per-call need in the shared window: scaffolding + this
                # payload (+ margin) + per-cluster output room. num_ctx is set
                # from THIS so the prompt can never overflow the window we ask
                # for; it stays at the budget for normal calls and only bumps
                # (clamped to the model window) for an unusually large cluster.
                prompt_need = scaffold_tokens + _tok(cluster_data)
                response_need = len(call) * _PER_CLUSTER_RESPONSE_TOKENS
                need = prompt_need + response_need

                lm_overrides: Dict[str, Any] = {}
                if force_no_cache:
                    lm_overrides["cache"] = False
                    if not local:
                        # Ollama logs "invalid option provided: cache_seed";
                        # cache=False alone bypasses the DSPy cache for it.
                        lm_overrides["cache_seed"] = secrets.randbits(64)
                num_ctx_used = None
                if local:
                    rnc = max(budget_tokens, need, _HIER_MIN_NUM_CTX)
                    if model_window:
                        if need > model_window:
                            # A single cluster's call is bigger than the model's
                            # own window — clamping means llama.cpp will truncate
                            # the prompt. Surface it rather than silently dropping
                            # context. (The pre-flight gate normally blocks this.)
                            log(f"[!] A cluster call needs ~{need:,} tok but the model window is only "
                                f"{model_window:,}; the prompt will be TRUNCATED. Use a larger-window "
                                "model or reduce scope.")
                        rnc = min(rnc, model_window)
                    lm_overrides["num_ctx"] = rnc
                    num_ctx_used = rnc

                log(f"Stage 1 (hierarchical): level {wi}/{len(waves)}, "
                    f"{len(call)} cluster(s) [{done_count}/{total}], ~{need:,} tok needed"
                    + (f", num_ctx={num_ctx_used:,}" if num_ctx_used else "")
                    + (" [over budget — large cluster]"
                       if num_ctx_used and num_ctx_used > budget_tokens else ""))
                # Resilient call (shared helper). A small local model
                # occasionally emits output that fails Pydantic validation
                # or errors outright; the helper also treats a response
                # MISSING requested ids (rate-limited {} or model-dropped)
                # as incomplete. Retry once with the cache bypassed (a
                # fresh generation often validates); whatever is still
                # missing is skipped and recorded — stage 2 tolerates gaps.
                def _hier_ctx(attempt: int, _ov=lm_overrides):
                    overrides = dict(_ov)
                    if attempt == 1:
                        overrides["cache"] = False  # force a fresh generation
                    return processor.override_lm(**overrides)

                got = cls._resilient_stage1_call(processor, cluster_data, respond_ids, xrefer_obj, _hier_ctx)
                stage1_clusters.update(got)
                for c in call:
                    s = got.get(f"cluster_{c.id}")
                    if s:
                        summaries[c.id] = s

        return stage1_clusters

    @classmethod
    def estimate_for_model(cls, context: "EstimateContext", model_id: Optional[str]) -> "TokenEstimate":
        """Token estimate for ``model_id`` from a prebuilt ``EstimateContext``
        — cheap enough to call on every dropdown change. Counts the rendered
        messages with the model's tokenizer, reads the model's context window,
        and caps the response bound to a realistic ceiling (see
        ``_MAX_RESPONSE_TOKENS_CAP``). Degrades gracefully: unknown model ->
        limits unknown; render failure -> payload-only count; no model ->
        char-based estimate.
        """
        request_tokens: Optional[int] = None
        rendered = context.rendered
        note = ""
        if model_id and context.messages is not None:
            try:
                import litellm
                request_tokens = int(litellm.token_counter(model=model_id, messages=context.messages))
            except Exception as e:
                note = f"Full-prompt count failed ({e.__class__.__name__}); counted the payload only."
                request_tokens = None
        if request_tokens is None:
            rendered = False
            try:
                import litellm
                request_tokens = (
                    int(litellm.token_counter(model=model_id, text=context.cluster_data))
                    if model_id else len(context.cluster_data) // 4
                )
            except Exception:
                request_tokens = len(context.cluster_data) // 4

        context_window: Optional[int] = None
        max_response: Optional[int] = None
        response_capped = False
        from xrefer.llm.ollama import is_ollama_model
        if model_id and is_ollama_model(model_id):
            # Local model: litellm's catalog has no usable context for these, so
            # read the model's real max context from the Ollama server (the same
            # value we set as num_ctx at call time). Ollama is a SHARED budget —
            # input and output both live in num_ctx — so reserve a realistic
            # slice for the response (a quarter of the window, capped at the
            # ceiling) and let the overflow gate handle the rest.
            from xrefer.llm.ollama import model_context_length
            context_window = model_context_length(context.api_base, model_id)
            if context_window:
                max_response = max(1024, min(_MAX_RESPONSE_TOKENS_CAP, context_window // 4))
            else:
                max_response = _MAX_RESPONSE_TOKENS_CAP
                if not note:
                    note = ("Local model context unknown — is the Ollama server reachable at "
                            f"{context.api_base or 'http://localhost:11434'}?")
        elif model_id:
            info: Dict[str, Any] = {}
            try:
                import litellm
                info = litellm.get_model_info(model_id) or {}
            except Exception:
                info = {}
            context_window = info.get("max_input_tokens") or info.get("max_tokens") or None
            try:
                kwargs = _llm_processor_cls()()._build_lm_kwargs(ModelConfig(model_id=model_id, api_key=""))
                max_response = kwargs.get("max_tokens")
            except Exception:
                max_response = None
            if not max_response:
                max_response = info.get("max_output_tokens") or info.get("max_tokens") or None
            # Cap the response bound to a realistic ceiling (see constant).
            if max_response:
                raw = int(max_response)
                max_response = min(raw, _MAX_RESPONSE_TOKENS_CAP)
                response_capped = raw > _MAX_RESPONSE_TOKENS_CAP
        elif not note:
            note = "No LLM model configured — set one in Settings for a provider-accurate count."

        # Hierarchical sizing: per-cluster responses are small, so reserve a
        # fixed modest slice instead of window // 4, and (for local models)
        # derive the Ollama num_ctx — the user's per-call budget, bumped only if
        # this (largest) call needs more, clamped to the real window. That
        # num_ctx is the KV-cache we actually allocate, decoupled from the
        # model's advertised window so a 256k local model doesn't reserve ~16 GB.
        run_num_ctx: Optional[int] = None
        if context.mode == "hierarchical":
            max_response = min(_HIER_RESPONSE_RESERVE, max_response or _HIER_RESPONSE_RESERVE)
            response_capped = False
            if model_id and is_ollama_model(model_id):
                need = int(request_tokens) + _HIER_RESPONSE_RESERVE
                rnc = max(int(context.local_max_call_tokens or _DEFAULT_LOCAL_MAX_CALL_TOKENS),
                          need, _HIER_MIN_NUM_CTX)
                if context_window:
                    rnc = min(rnc, context_window)
                run_num_ctx = rnc

        return TokenEstimate(
            model_id=model_id,
            request_tokens=int(request_tokens),
            max_response_tokens=max_response,
            context_window=context_window,
            cluster_count=context.cluster_count,
            num_calls=context.num_calls,
            rendered=rendered,
            note=note,
            response_capped=response_capped,
            num_closures=context.num_closures,
            mode=context.mode,
            run_num_ctx=run_num_ctx,
        )

    @classmethod
    def estimate_cluster_request(cls, clusters: List["FunctionalCluster"], xrefer_obj: "XRefer",
                                 model_id: Optional[str] = None) -> "TokenEstimate":
        """Pre-flight token estimate for the cluster-analysis (stage-1)
        request, sized against ``model_id``'s context window (defaults to the
        configured model). Thin wrapper over ``build_estimate_context`` +
        ``estimate_for_model``; the GUI uses those two directly so it can
        re-estimate across models without rebuilding the request. Resolves the
        model from ``current_config`` when set, else ``settings['llm_model_id']``
        — so it runs after clustering and before any LLM call, no API key
        required.
        """
        if model_id is None:
            if cls.current_config is not None and getattr(cls.current_config, "model_id", None):
                model_id = cls.current_config.model_id
            else:
                try:
                    model_id = xrefer_obj.settings.get("llm_model_id") or None
                except Exception:
                    model_id = None
        # Resolve the strategy this model would actually run under, then size
        # the matching request: the full corpus (largest closure) for the full
        # path, or the largest bottom-up call for the hierarchical path. The
        # pre-flight gate blocks on THIS, so it must reflect the real plan — else
        # a local model would be blocked on a full-corpus size it never sends.
        try:
            mode_setting = xrefer_obj.settings.get("analysis_options", {}).get("cluster_context_mode", "auto")
        except Exception:
            mode_setting = "auto"
        ms = (mode_setting or "auto").strip().lower()
        from xrefer.llm.ollama import is_ollama_model
        # Hierarchical without needing the full-corpus probe (avoids formatting
        # the whole binary just to discard it): forced hierarchical, or
        # auto + local (local always summarises).
        if ms == "hierarchical" or (ms == "auto" and is_ollama_model(model_id)):
            return cls.estimate_for_model(cls.build_hier_estimate_context(clusters, xrefer_obj), model_id)
        full_est = cls.estimate_for_model(cls.build_estimate_context(clusters, xrefer_obj), model_id)
        if ms == "full":
            return full_est
        # auto + commercial: full when it fits the window, else hierarchical.
        if exceeds_context_window(full_est):
            return cls.estimate_for_model(cls.build_hier_estimate_context(clusters, xrefer_obj), model_id)
        return full_est

    @staticmethod
    def format_cluster_data(clusters: List["FunctionalCluster"], xrefer_obj: 'XRefer',
                            respond_for_ids: Optional[Set[int]] = None,
                            summaries: Optional[Dict[int, Any]] = None) -> str:
        """
        Format a cluster group for LLM analysis.

        Two shapes, selected by ``summaries``:

        * ``summaries is None`` (FULL path): ``clusters`` is a closure's
          top-level clusters and every subcluster is expanded inline with full
          detail — the whole corpus in one payload.
        * ``summaries`` provided (HIERARCHICAL / bottom-up path): ``clusters``
          are the FOCAL clusters for this call (at any depth). Each is rendered
          with full detail for its OWN functions, but its child subclusters are
          rendered only as short summaries pulled from ``summaries`` (no
          recursion) — so the payload is bounded by local fan-out, not the whole
          binary. The answerable set is exactly the focal clusters.

        Args:
            clusters: the clusters that form this call's context (top-level
                closure for the full path; focal clusters for the bottom-up
                path).
            xrefer_obj: XRefer instance containing artifact getter methods.
            respond_for_ids: explicit set of cluster ids the model must return
                results for. ``None`` = respond for every focal cluster present.
                A strict subset (full path, a big closure response-batched) shows
                the rest for context only.
            summaries: when provided, ``{cluster_id -> stage-1 result dict}`` for
                already-analysed child clusters; selects the bottom-up shape and
                supplies each child's ``label`` / ``description`` summary.

        Returns:
            str: Formatted cluster hierarchy with a trailing instruction scoping
                which cluster ids to answer for.
        """
        from xrefer.core.clusters import cluster_ids as _cluster_ids
        if summaries is not None:
            # Bottom-up: only the focal clusters are answerable; their children
            # are summarised, not expanded, so they are NOT in the respond set.
            all_ids = {c.id for c in clusters}
        else:
            all_ids = _cluster_ids(clusters)
        respond_for_ids = set(all_ids) if respond_for_ids is None else set(respond_for_ids)

        # Store original exclusions state
        original_exclusion_state = xrefer_obj.settings["enable_exclusions"]

        try:
            # Temporarily disable exclusions for cluster data collection
            xrefer_obj.settings["enable_exclusions"] = False

            def format_cluster(cluster: "FunctionalCluster", depth: int = 0) -> str:
                indent = "  " * depth
                formatted = [f"{indent}Cluster {cluster.id}:",
                             f"{indent}Type: {'Primary' if cluster.parent_cluster_id is None else f'Subcluster of {cluster.parent_cluster_id}'}",
                             f"{indent}Root: {cluster.root_node:#x}",
                             '',
                             f"{indent}Functions:"]
                for node in cluster.nodes:
                    if node not in cluster.cluster_refs:
                        formatted.append(f"{indent}- Function {node:#x}:")
                        # Get APIs
                        if apis := xrefer_obj.get_apis_for_function(node):
                            formatted.append(f"{indent}  APIs:")
                            for api in apis:
                                formatted.append(f"{indent}    API: {api}")
                                # Get top 10 calls
                                if calls := xrefer_obj.get_direct_calls(api, node):
                                    sorted_calls = sorted(calls, key=lambda x: x[1], reverse=True)[:10]
                                    for call_str, count in sorted_calls:
                                        formatted.append(f"{indent}      Call: {call_str} (called {count} times)")

                        for label, data in [
                            ('Libraries', xrefer_obj.get_libs_for_function(node)),
                            ('Strings', xrefer_obj.get_strings_for_function(node)),
                            ('CAPA', xrefer_obj.get_capa_for_function(node)),
                        ]:
                            if data:
                                formatted.append(f"{indent}  {label}: {', '.join(data)}")
                # Add call flow
                if cluster.edges:
                    formatted.append(f"\n{indent}Call Flow:")
                    for source, target in cluster.edges:
                        source_label = f"{source:#x}"
                        if target in cluster.cluster_refs:
                            target_label = f"Cluster {cluster.cluster_refs[target]}"
                        else:
                            target_label = f"{target:#x}"
                        formatted.append(f"{indent}- {source_label} -> {target_label}")

                # Add cluster references. In the bottom-up shape, refs that point
                # at this cluster's OWN subclusters are skipped here (they're
                # rendered as summaries below); only genuine cross-cluster refs
                # remain. In the full shape, sub_ids is empty so behaviour is
                # unchanged.
                if cluster.cluster_refs:
                    sub_ids = {s.id for s in cluster.subclusters} if summaries is not None else set()
                    cross_refs = [(n, cid) for n, cid in cluster.cluster_refs.items() if cid not in sub_ids]
                    if cross_refs:
                        formatted.append(f"\n{indent}References to Other Clusters:")
                        for node, cluster_id in cross_refs:
                            formatted.append(f"{indent}- Node {node:#x} replaced by Cluster {cluster_id}")

                # Subclusters: expand inline (full path) or render as a short
                # summary the parent treats as a black box (bottom-up path).
                if cluster.subclusters:
                    if summaries is not None:
                        formatted.append(f"\n{indent}Subcomponents (already analysed — treat each as a black box):")
                        for sub in cluster.subclusters:
                            s = summaries.get(sub.id) or {}
                            label = (s.get("label") or "").strip() or f"cluster {sub.id}"
                            desc = (s.get("description") or "").strip()
                            tag = "library/runtime" if s.get("library_or_runtime", 0) else "application"
                            formatted.append(f"{indent}- Subcomponent cluster {sub.id} ({tag}): {label}")
                            if desc:
                                formatted.append(f"{indent}    {desc}")
                    else:
                        formatted.append(f"\n{indent}Subclusters:")
                        for subcluster in cluster.subclusters:
                            formatted.append("\n" + format_cluster(subcluster, depth + 1))

                return "\n".join(formatted)

            # Start building the formatted output
            # If we are analyzing a subset, add a note clarifying that the LLM must analyze all clusters
            # but only fully respond for the given subset.
            ids_csv = ','.join(map(str, sorted(respond_for_ids)))
            ps_note = f"IMPORTANT: Enumerate and ensure you return results for all clusters with IDs {ids_csv}"
            if respond_for_ids != all_ids:
                # The subset directive lives here at the TAIL on purpose:
                # the full stage-1 path sends a byte-identical corpus every
                # batch, and keeping everything batch-varying after the
                # corpus makes the shared prefix eligible for provider
                # implicit prompt caching (OpenAI/Gemini/DeepSeek) — batches
                # 2..N stop re-prefilling a multi-hundred-k corpus while the
                # IDA main thread blocks on them.
                ps_note += (
                    ". For clusters outside this ID list, do NOT provide analysis — "
                    "they appear above for cross-cluster context only."
                )
            note = ""
            if summaries is not None:
                # Bottom-up: children are pre-analysed summaries; only the focal
                # clusters are answered for. Tell the model to use the summaries
                # as black-box sub-components when reasoning about orchestration.
                note = (
                    "NOTE: Each cluster below shows FULL detail for its own functions, but its "
                    "child sub-components have already been analysed and appear only as short "
                    "summaries (label + description). Treat every such summary as a black-box "
                    "sub-component: use it to understand what this cluster delegates to its "
                    "children and how it orchestrates them, and let the cluster's description "
                    "account for that delegated functionality. Provide cluster-level analysis "
                    "(label, description, relationships, function_prefix, library_or_runtime, "
                    f"mitre_attack) for the cluster IDs {ids_csv}."
                )
            elif respond_for_ids != all_ids:
                # A big closure split across calls for output quality: the whole
                # closure is shown for context, but only this subset is answered
                # for. (Stage 2 produces the binary-level fields separately, so
                # there is no binary-level instruction to thread through here.)
                # STATIC text only — the batch-varying ID list lives in the
                # tail ps_note so consecutive batches share a byte-identical
                # prefix (see the prompt-caching note above).
                note = (
                    "NOTE: All clusters below are provided for cross-cluster context. "
                    "This call answers for only a subset of them; the answerable "
                    "cluster IDs are listed after the cluster data. ONLY provide "
                    "cluster-level analysis (label, description, relationships, "
                    "function_prefix, library_or_runtime, mitre_attack) for that "
                    "subset — other clusters appear below for context only."
                )

            formatted = '''Structure is organized hierarchically with primary clusters and their subclusters.
Each cluster shows its functions, artifacts (APIs, strings, etc.), and call flows.
References to subclusters indicate where complex behavior is encapsulated.

{note}

<CLUSTER>
{formatted_clusters}
</CLUSTER>

{ps_note}
'''.format(
    note=note,
    formatted_clusters='\n\n'.join(format_cluster(c) for c in clusters),
    ps_note=ps_note)
            return formatted

        finally:
            # Restore original exclusions state
            xrefer_obj.settings["enable_exclusions"] = original_exclusion_state

    @staticmethod
    def format_synthesis_input(
        clusters: List["FunctionalCluster"],
        xrefer_obj: "XRefer",
        stage1_clusters: Dict[str, Any],
    ) -> str:
        """Format the input for the stage-2 binary synthesizer call.

        Stage 2 receives:
          - A short binary-level header (total cluster count).
          - One block per cluster (recursing through subclusters)
            containing:
              * stage-1 fields (label, library_or_runtime,
                description, relationships, mitre_attack) — the
                LLM's own per-cluster synthesis from stage 1.
              * All raw artifacts (strings, libraries, CAPA
                capabilities, APIs) attributed to that cluster's
                OWN nodes (subcluster nodes are emitted in the
                subcluster's own block, so the union is exact
                with no duplication).

        Rationale for sending all artifacts (no interestingness
        filter): the artifact-analyzer's "interesting indexes"
        filter is itself LLM-generated and misses items. Sending
        all strings / libs / CAPA / APIs keeps stage 2 free of
        upstream LLM-judgement filtering. Function addresses,
        per-function attribution, call flows, and caller-count
        rankings are stage-1 concerns and are NOT sent — that
        function-level wiring is the bulk of stage 1's cluster_data
        token cost, and stage 2 doesn't need it for binary-level
        synthesis.

        Args:
            clusters: Top-level cluster list (subclusters are walked
                recursively, one block per cluster).
            xrefer_obj: XRefer instance providing the per-function
                artifact getters (get_apis_for_function, etc.).
            stage1_clusters: The stage-1 cluster map keyed by
                ``cluster_<id>`` strings, as returned by
                ``ClusterAnalysisResponse.model_dump()['clusters']``.

        Returns:
            str: The full prompt input for the stage-2 LLM call.
        """
        # Mirrors format_cluster_data: temporarily disable exclusions
        # so the artifact aggregation sees everything.
        original_exclusion_state = xrefer_obj.settings["enable_exclusions"]
        try:
            xrefer_obj.settings["enable_exclusions"] = False

            def aggregate_artifacts(cluster: "FunctionalCluster") -> Dict[str, List[str]]:
                """Collect all artifacts for cluster's OWN nodes
                (excluding nodes that are subcluster-refs — those
                contribute to their subcluster's own block).
                Deduplicates while preserving insertion order.
                """
                apis: Dict[str, None] = {}
                libs: Dict[str, None] = {}
                strings: Dict[str, None] = {}
                capa: Dict[str, None] = {}
                for node in cluster.nodes:
                    if node in cluster.cluster_refs:
                        continue
                    for a in (xrefer_obj.get_apis_for_function(node) or []):
                        apis[a] = None
                    for lib in (xrefer_obj.get_libs_for_function(node) or []):
                        libs[lib] = None
                    for s in (xrefer_obj.get_strings_for_function(node) or []):
                        strings[s] = None
                    for c in (xrefer_obj.get_capa_for_function(node) or []):
                        capa[c] = None
                return {
                    "strings": list(strings),
                    "libraries": list(libs),
                    "capa": list(capa),
                    "apis": list(apis),
                }

            def format_cluster_block(cluster: "FunctionalCluster") -> List[str]:
                lines: List[str] = []
                lines.append(f"=== cluster.id.{cluster.id} ===")

                stage1 = stage1_clusters.get(f"cluster_{cluster.id}")
                if stage1 is None:
                    # Stage 1 didn't produce an entry for this
                    # cluster (LLM dropped it from its batch).
                    # Emit a placeholder so stage 2 still sees the
                    # cluster's artifacts even without per-cluster
                    # synthesis.
                    lines.append("Label: (stage 1 did not return a label for this cluster)")
                    lines.append("Library/Runtime: 0")
                    lines.append("Description: (stage 1 did not return a description)")
                    lines.append("Relationships: (stage 1 did not return relationships)")
                else:
                    label = stage1.get("label", "")
                    description = stage1.get("description", "")
                    relationships = stage1.get("relationships", "")
                    library_or_runtime = stage1.get("library_or_runtime", 0)
                    mitre = stage1.get("mitre_attack", []) or []

                    lines.append(f"Label: {label}")
                    lines.append(f"Library/Runtime: {library_or_runtime}")
                    lines.append(f"Description: {description}")
                    lines.append(f"Relationships: {relationships}")
                    if mitre:
                        lines.append("MITRE:")
                        for m in mitre:
                            if not isinstance(m, dict):
                                continue
                            mid = m.get("id", "?")
                            tactic = m.get("tactic", "?")
                            mname = m.get("name", "?")
                            rationale = m.get("rationale", "")
                            lines.append(
                                f"  - {mid} ({tactic}) {mname} — {rationale}"
                            )

                artifacts = aggregate_artifacts(cluster)
                for key, label_name in [
                    ("strings", "Strings"),
                    ("libraries", "Libraries"),
                    ("capa", "CAPA"),
                    ("apis", "APIs"),
                ]:
                    values = artifacts[key]
                    if values:
                        lines.append(f"{label_name}:")
                        for v in values:
                            lines.append(f"  - {v}")
                lines.append("")
                return lines

            def walk(cluster: "FunctionalCluster", acc: List[str]) -> None:
                acc.extend(format_cluster_block(cluster))
                for sub in cluster.subclusters:
                    walk(sub, acc)

            def total_cluster_count(cs: List["FunctionalCluster"]) -> int:
                count = 0
                stack: List["FunctionalCluster"] = list(cs)
                while stack:
                    c = stack.pop()
                    count += 1
                    stack.extend(c.subclusters)
                return count

            # File-format string from the backend (e.g. "Portable
            # executable for AMD64 (PE)"). Stage 2's prompt treats
            # this as ground truth for runtime target, so the LLM
            # doesn't infer cross-platform behaviour from inert
            # strings that survive in single-platform builds of
            # cross-platform malware families.
            file_format = ""
            try:
                file_format = xrefer_obj._backend.filetype() or ""
            except Exception:
                # Backend missing or filetype() unimplemented — fall
                # back to omitting the header line rather than
                # aborting synthesis.
                file_format = ""

            header_lines: List[str] = ["=== BINARY ==="]
            if file_format:
                header_lines.append(f"File format: {file_format}")
            header_lines.append(f"Total clusters: {total_cluster_count(clusters)}")
            header_lines.append("")
            body: List[str] = []
            for cluster in clusters:
                walk(cluster, body)

            return "\n".join(header_lines + body)
        finally:
            xrefer_obj.settings["enable_exclusions"] = original_exclusion_state

    @staticmethod
    def populate_dummy_cluster_analysis(clusters: List["FunctionalCluster"]) -> Dict[str, Any]:
        """
        Create a dummy cluster analysis dictionary with fake, unique data for each cluster and subcluster.
        Useful for testing and debugging issues without calling the LLM.
        """

        # A recursive helper to handle subclusters
        def recurse_clusters(c: "FunctionalCluster", analysis: Dict[str, Any], prefix: str):
            cluster_id_str = f"cluster_{c.id}"
            analysis["clusters"][cluster_id_str] = {
                "label": f"Dummy Label {prefix}{c.id}",
                "description": f"This is a dummy description for {prefix}{c.id}.",
                "relationships": f"Dummy relationships for {prefix}{c.id}.",
                "function_prefix": f"dummy_{prefix}{c.id}",
                # Synthetic MITRE entries so the HTML report's MITRE
                # ATT&CK tab renders visibly during dev / debug paths
                # that bypass the real LLM. Two techniques across two
                # tactics exercises both the grouping and the rationale
                # rendering.
                "mitre_attack": [
                    {
                        "id": "T1059.003",
                        "tactic": "Execution",
                        "name": "Command and Scripting Interpreter: Windows Command Shell",
                        "rationale": (
                            f"Dummy rationale for cluster {prefix}{c.id} — pretend a cmd.exe invocation pattern "
                            "was observed in this cluster's strings."
                        ),
                    },
                    {
                        "id": "T1027",
                        "tactic": "Defense Evasion",
                        "name": "Obfuscated Files or Information",
                        "rationale": (
                            f"Dummy rationale for cluster {prefix}{c.id} — pretend a base64-like decoding loop "
                            "appears alongside the cluster's CAPA hits."
                        ),
                    },
                ],
            }

            for sc in c.subclusters:
                recurse_clusters(sc, analysis, prefix + f"{c.id}_")

        analysis = {"clusters": {}}
        for c in clusters:
            recurse_clusters(c, analysis, "")

        # Add global fields to mimic the structure returned by LLM
        analysis["binary_description"] = "Dummy binary description for testing."
        analysis["binary_category"] = "Dummy category"
        # Optionally add "binary_report"
        analysis["binary_report"] = "Dummy binary report"

        return analysis
