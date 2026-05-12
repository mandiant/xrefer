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

from typing import TYPE_CHECKING, Any, Dict, List

from xrefer.core.helpers import log
from xrefer.llm.base import ModelConfig, PromptType
from xrefer.llm.processor import LLMProcessor


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
    def analyze_clusters(cls, clusters: List["FunctionalCluster"], xrefer_obj, batch_size = 30) -> Dict[str, Any]:
        """
        Analyze cluster hierarchy using LLM.

        If the cluster count is larger than 50, we split the analysis into multiple
        batches (each with up to 50 clusters). Each batch includes all clusters for context,
        but the LLM is instructed to fully respond only for the subset in that batch.
        The binary_description, binary_category, and binary_report fields are requested each time.

        If the cluster count is <= 50, we request all at once with no partial instructions.
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
            # No clusters to analyze
            return {}

        if cluster_count <= batch_size:
            # Single request scenario, no partial instructions
            cluster_data = cls.format_cluster_data(clusters, xrefer_obj, start_idx=0, end_idx=cluster_count)
            log(f"Generated cluster data ({len(cluster_data)} chars)")
            results = processor.process_items(cluster_data, prompt_type=PromptType.CLUSTER_ANALYZER, ignore_token_limit=True)
            results = dict(results)  # Ensure it's a dict # TODO: Drop dict across the codebase for better developer experience.
            cls._warn_on_sparse_binary_report(results.get("binary_report"))
            return results
        else:
            # Multiple batch scenario
            all_clusters_result = {}
            binary_description = None
            binary_category = None
            binary_report = None
            log(f"Going to process {cluster_count} clusters through the LLM. This will take some time...")

            # Process clusters in batches of batch_size
            for start in range(0, cluster_count, batch_size):
                end = min(start + batch_size, cluster_count)
                log(f"Processing clusters {start + 1} to {end} in this batch")

                cluster_data = cls.format_cluster_data(clusters, xrefer_obj, start_idx=start, end_idx=end)
                log(f"Generated cluster data ({len(cluster_data)} chars)")
                results = processor.process_items(cluster_data, prompt_type=PromptType.CLUSTER_ANALYZER, ignore_token_limit=True)
                results = dict(results)  # Ensure it's a dict

                # Extract clusters from partial result
                partial_clusters = results.get("clusters", {})
                # Merge cluster analyses
                for cid, cdata in partial_clusters.items():
                    all_clusters_result[cid] = cdata

                # Update binary fields from the latest batch.
                # binary_description / binary_category are updated each
                # batch (the LLM sees the same context, so later
                # batches generally give a slightly-refined value).
                if "binary_description" in results:
                    binary_description = results["binary_description"]
                if "binary_category" in results:
                    binary_category = results["binary_category"]
                # binary_report is only kept from the FINAL batch.
                # Earlier batches were told (via the partial-batch
                # note in format_cluster_data) that their binary_report
                # is a discard-bound placeholder; gating the assignment
                # here makes that contract explicit on the consumer
                # side so a non-compliant LLM that still emits a real
                # report on a partial batch can't leak it through.
                if "binary_report" in results and end == cluster_count:
                    binary_report = results["binary_report"]

            # After processing all batches, ensure required fields are present
            if not all_clusters_result:
                log("[-] Error: No cluster data received after all batches")
                return {}

            if binary_description is None or binary_category is None:
                log("[-] Error: Missing binary_description or binary_category after batched analysis")
                return {}

            final_result = {"clusters": all_clusters_result, "binary_description": binary_description, "binary_category": binary_category}
            if binary_report is not None:
                final_result["binary_report"] = binary_report
                cls._warn_on_sparse_binary_report(binary_report)

            return final_result


    @staticmethod
    def _warn_on_sparse_binary_report(binary_report: Any) -> None:
        """Soft length check on the final binary_report markdown string.

        The hard length validator on ``BinaryReport`` was relaxed to a
        ceiling-only check because the Pydantic model-validator
        constraint isn't visible in the JSON schema the LLM sees, so
        the model can't aim for a minimum it doesn't know exists, and
        a hard floor would fail entire analyses on sparse-but-valid
        reports. The LLM-visible target (1500-4500 chars) lives in
        ``ClusterAnalyzerSignature``'s docstring; this function logs
        a non-fatal warning when the produced report falls under
        ``BinaryReport.SOFT_MIN_LENGTH`` so the analyst knows the
        report is sparse but the analysis still succeeds.

        ``binary_report`` is the already-rendered markdown string —
        the outer ``ClusterAnalysisResponse`` serializer flattens the
        structured form via ``to_markdown()`` before this function
        sees it.
        """
        if not isinstance(binary_report, str):
            return
        try:
            from xrefer.llm.dspy_modules import BinaryReport
            soft_min = BinaryReport.SOFT_MIN_LENGTH
        except Exception:
            soft_min = 1500
        n = len(binary_report)
        if n and n < soft_min:
            log(
                f"[!] binary_report is sparse: {n} chars rendered "
                f"(target: {soft_min}-4500). Analysis succeeded but "
                "the report may lack detail for analyst triage. "
                "Re-running cluster analysis usually produces a "
                "richer report."
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
                # For partial batches we tell the LLM that
                # binary_report is going to be discarded (the final
                # batch produces the kept report). The schema still
                # requires a valid BinaryReport here — the consumer
                # gates the assignment, so even a non-compliant LLM
                # that emits a real report can't leak it through.
                is_final_batch = end_idx == len(clusters)
                if is_final_batch:
                    binary_report_instruction = (
                        "This is the FINAL batch — produce the kept "
                        "binary_report here. Apply every BinaryReport "
                        "field description as written; this is the "
                        "report the analyst sees."
                    )
                else:
                    binary_report_instruction = (
                        "binary_report from this batch WILL BE "
                        "DISCARDED — the report is produced by the "
                        "final batch only. Return a minimal "
                        "BinaryReport that still satisfies every "
                        "field description (overview opens with 'The "
                        "binary is' or 'This binary is' and fits the "
                        "length/structure rules, at least one "
                        "behavior section with an evidence-descriptive "
                        "heading, empty observed_artifacts is fine). "
                        "Do not invest effort in this batch's "
                        "binary_report — describe the binary's "
                        "overall shape at a high level only."
                    )
                note = (
                    f"NOTE: Analyze ALL clusters to understand overall functionality and relationships. "
                    f"However, when producing the final JSON response, ONLY provide the full cluster-level analysis "
                    f"(label, description, relationships, function_prefix, library_or_runtime, mitre_attack) for clusters "
                    f"with indices in the range [{start_idx + 1}, {end_idx}]. For all other clusters outside this subset, "
                    f"do NOT provide their full analysis. Still, as instructed, provide binary_description and "
                    f"binary_category for the entire binary. "
                    f"{binary_report_instruction} "
                    f"All clusters are provided below for context. "
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
