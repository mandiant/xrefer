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

import re
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Set

from xrefer.core.helpers import log
from xrefer.llm.base import ModelConfig, PromptType
from xrefer.llm.processor import LLMProcessor


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
    """Return a short human-readable size string for ``text``.

    Prefers a provider-specific token count via ``litellm.token_counter``
    when a model is known and the call succeeds. Falls back to a
    character count when the model is unknown OR the tokenizer for the
    provider isn't shipped with the installed litellm version (some
    less-common providers fall through to a generic estimator that
    litellm itself logs warnings about).
    """
    if model:
        try:
            import litellm
            n = litellm.token_counter(model=model, text=text)
            if isinstance(n, int) and n > 0:
                return f"{n} tokens (model: {model})"
        except Exception:
            # Any failure (missing tokenizer, transient import issue,
            # network call internally) falls through to char count.
            pass
    return f"{len(text)} chars"


if TYPE_CHECKING:
    from xrefer.core.clusters import FunctionalCluster
    from xrefer.core.analyzer import XRefer


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
            cls._processor = LLMProcessor()
            cls._processor.set_model_config(cls.current_config)
        return cls._processor

    @classmethod
    def set_model_config(cls, config: ModelConfig):
        """Set LLM configuration for analysis."""
        cls.current_config = config
        cls._processor = None  # Force new processor with new config

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

        # ── Stage 1: per-cluster analyses ────────────────────────────
        stage1_clusters: Dict[str, Any] = {}

        if cluster_count <= batch_size:
            cluster_data = cls.format_cluster_data(clusters, xrefer_obj, start_idx=0, end_idx=cluster_count)
            log(f"Stage 1: generated cluster data ({_measure(cluster_data, model_id)})")
            with cache_ctx():
                results = processor.process_items(
                    cluster_data,
                    prompt_type=PromptType.CLUSTER_ANALYZER,
                    ignore_token_limit=True,
                )
            results = dict(results)
            stage1_clusters.update(results.get("clusters", {}))
        else:
            log(
                f"Stage 1: going to process {cluster_count} clusters through "
                "the LLM. This will take some time..."
            )
            for start in range(0, cluster_count, batch_size):
                end = min(start + batch_size, cluster_count)
                log(f"Stage 1: processing clusters {start + 1} to {end} in this batch")

                cluster_data = cls.format_cluster_data(
                    clusters, xrefer_obj, start_idx=start, end_idx=end
                )
                log(f"Stage 1: generated cluster data ({_measure(cluster_data, model_id)})")
                with cache_ctx():
                    results = processor.process_items(
                        cluster_data,
                        prompt_type=PromptType.CLUSTER_ANALYZER,
                        ignore_token_limit=True,
                    )
                results = dict(results)
                stage1_clusters.update(results.get("clusters", {}))

        if not stage1_clusters:
            log("[-] Error: No cluster data received after stage 1")
            return {}

        # ── Stage 2: binary-level synthesis ──────────────────────────
        log("Stage 2: synthesising binary-level analysis from per-cluster results")
        synthesis_input = cls.format_synthesis_input(clusters, xrefer_obj, stage1_clusters)
        log(f"Stage 2: generated synthesis input ({_measure(synthesis_input, model_id)})")
        with cache_ctx():
            synthesis = processor.process_items(
                synthesis_input,
                prompt_type=PromptType.BINARY_SYNTHESIZER,
                ignore_token_limit=True,
            )
        synthesis = dict(synthesis)

        binary_description = synthesis.get("binary_description")
        binary_category = synthesis.get("binary_category")
        binary_report = synthesis.get("binary_report")

        if binary_description is None or binary_category is None:
            log(
                "[-] Error: Missing binary_description or binary_category after "
                "stage 2 synthesis"
            )
            return {}

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


    @staticmethod
    def format_cluster_data(clusters: List["FunctionalCluster"], xrefer_obj: 'XRefer', start_idx: int = 0, end_idx: int = None) -> str:
        """
        Format cluster hierarchy for LLM analysis.

        Args:
            clusters: List of clusters to analyze
            xrefer_obj: XRefer instance containing artifact getter methods
            start_idx: Start index (0-based) of the cluster subset for which full response is needed
            end_idx: End index (non-inclusive) of the cluster subset. If None, use all clusters.

        Returns:
            str: Formatted string describing cluster hierarchy. If the entire range of clusters
                is requested (i.e., start_idx=0 and end_idx=len(clusters)), then no partial instructions
                are added. If a subset is requested (because of batching), a note is added instructing
                the model to analyze all clusters for understanding but only fully respond with
                detailed cluster-level analysis for the given subset.
        """
        if end_idx is None:
            end_idx = len(clusters)

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

                # Add cluster references
                if cluster.cluster_refs:
                    formatted.append(f"\n{indent}References to Other Clusters:")
                    for node, cluster_id in cluster.cluster_refs.items():
                        formatted.append(f"{indent}- Node {node:#x} replaced by Cluster {cluster_id}")

                # Recursively add subclusters
                if cluster.subclusters:
                    formatted.append(f"\n{indent}Subclusters:")
                    for subcluster in cluster.subclusters:
                        formatted.append("\n" + format_cluster(subcluster, depth + 1))

                return "\n".join(formatted)

            # Start building the formatted output
            # If we are analyzing a subset, add a note clarifying that the LLM must analyze all clusters
            # but only fully respond for the given subset.
            note = ""
            ps_note = f"IMPORTANT: Enumerate and ensure you return results for all clusters with IDs {','.join(map(str, range(start_idx + 1, end_idx + 1)))}"
            full_range = start_idx == 0 and end_idx == len(clusters)
            if not full_range:
                # Stage 1 produces per-cluster outputs only — the
                # binary-level fields (binary_description /
                # binary_category / binary_report) are produced by
                # the separate stage-2 synthesizer call in
                # analyze_clusters. So the partial-batch note here
                # only needs to scope cluster-level work; there is
                # no longer any binary-level instruction to thread
                # through.
                note = (
                    f"NOTE: All clusters are provided below for cross-cluster context. "
                    f"When producing the response, ONLY provide cluster-level analysis "
                    f"(label, description, relationships, function_prefix, library_or_runtime, mitre_attack) "
                    f"for clusters with indices in the range [{start_idx + 1}, {end_idx}]. "
                    f"For clusters outside this subset, do NOT provide analysis — they appear below for context only."
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
