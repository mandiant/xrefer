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
from xrefer.llm.base import ModelConfig
from xrefer.llm.processor import LLMProcessor
from xrefer.llm.prompts import PromptType

if TYPE_CHECKING:
    from xrefer.core.clusters import FunctionalCluster


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
    def analyze_clusters(cls, clusters: List["FunctionalCluster"], xrefer_obj) -> Dict[str, Any]:
        """
        Analyze cluster hierarchy using LLM.

        If the cluster count is larger than 50, we split the analysis into multiple
        batches (each with up to 50 clusters). Each batch includes all clusters for context,
        but the LLM is instructed to fully respond only for the subset in that batch.
        The binary_description, binary_category, and binary_report fields are requested each time.

        If the cluster count is <= 50, we request all at once with no partial instructions.
        """
        processor = cls._get_processor()

        # try:
        cluster_count = 0
        batch_size = 20

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
            results = dict(results)  # Ensure it's a dict
            # TODO: Drop dict across the codebase for better developer experience.

            if not isinstance(results, dict):
                log("[-] Error: LLM returned invalid format")
                return {}

            required_keys = {"clusters", "binary_description", "binary_category"}
            if not all(key in results for key in required_keys):
                log("[-] Error: Missing required keys in LLM response")
                log(f"Found keys: {list(results.keys())}")
                return {}

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


                # if not isinstance(results, dict) or not results:
                #     log("[-] Error: LLM returned erroneous response, please re-start cluster analysis")
                #     break

                # Extract clusters from partial result
                partial_clusters = results.get("clusters", {})
                # Merge cluster analyses
                for cid, cdata in partial_clusters.items():
                    all_clusters_result[cid] = cdata

                # Update binary fields from the latest batch
                if "binary_description" in results:
                    binary_description = results["binary_description"]
                if "binary_category" in results:
                    binary_category = results["binary_category"]
                if "binary_report" in results:
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

            return final_result

        # except Exception as e:
        #     import traceback
        #     traceback.print_exc()
        #     log(f"[-] Error analyzing clusters: {str(e)}")
        #     return {}

    @staticmethod
    def format_cluster_data(clusters: List["FunctionalCluster"], xrefer_obj, start_idx: int = 0, end_idx: int = None) -> str:
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

                formatted = f"{indent}Cluster {cluster.id}:\n"
                formatted += f"{indent}Type: {'Primary' if cluster.parent_cluster_id is None else f'Subcluster of {cluster.parent_cluster_id}'}\n"
                formatted += f"{indent}Root: 0x{cluster.root_node:x}\n\n"

                # Add nodes and their artifacts
                formatted += f"{indent}Functions:\n"
                for node in cluster.nodes:
                    if node not in cluster.cluster_refs:
                        formatted += f"{indent}- Function 0x{node:x}:\n"
                        try:
                            # Get APIs
                            apis = xrefer_obj.get_apis_for_function(node)
                            if apis:
                                formatted += f"{indent}  APIs:\n"
                                for api in apis:
                                    formatted += f"{indent}    {api}\n"
                                    # Get top 10 calls
                                    calls = xrefer_obj.get_direct_calls(api, node, colorized=False)
                                    if calls:
                                        sorted_calls = sorted(calls, key=lambda x: x[1], reverse=True)[:10]
                                        for call_str, count in sorted_calls:
                                            formatted += f"{indent}      Call: {call_str} (called {count} times)\n"

                            # Get libraries
                            libs = xrefer_obj.get_libs_for_function(node)
                            if libs:
                                formatted += f"{indent}  Libraries: {', '.join(libs)}\n"

                            # Get strings
                            strings = xrefer_obj.get_strings_for_function(node)
                            if strings:
                                formatted += f"{indent}  Strings: {', '.join(strings)}\n"

                            # Get CAPA matches
                            capa = xrefer_obj.get_capa_for_function(node)
                            if capa:
                                formatted += f"{indent}  CAPA: {', '.join(capa)}\n"

                        except Exception as e:
                            log(f"[-] Error getting artifacts for function 0x{node:x}: {str(e)}")
                            continue

                # Add call flow
                if cluster.edges:
                    formatted += f"\n{indent}Call Flow:\n"
                    for source, target in cluster.edges:
                        source_label = f"0x{source:x}"
                        if target in cluster.cluster_refs:
                            target_label = f"Cluster {cluster.cluster_refs[target]}"
                        else:
                            target_label = f"0x{target:x}"
                        formatted += f"{indent}- {source_label} -> {target_label}\n"

                # Add cluster references
                if cluster.cluster_refs:
                    formatted += f"\n{indent}References to Other Clusters:\n"
                    for node, cluster_id in cluster.cluster_refs.items():
                        formatted += f"{indent}- Node 0x{node:x} replaced by Cluster {cluster_id}\n"

                # Recursively add subclusters
                if cluster.subclusters:
                    formatted += f"\n{indent}Subclusters:\n"
                    for subcluster in cluster.subclusters:
                        formatted += "\n" + format_cluster(subcluster, depth + 1)

                return formatted

            # Start building the formatted output
            # If we are analyzing a subset, add a note clarifying that the LLM must analyze all clusters
            # but only fully respond for the given subset.
            note = ""
            ps_note = f"IMPORTANT: Enumerate and ensure you return results for all clusters with IDs {','.join(map(str, range(start_idx + 1, end_idx + 1)))}"
            full_range = start_idx == 0 and end_idx == len(clusters)
            if not full_range:
                note = (
                    f"NOTE: Analyze ALL clusters to understand overall functionality and relationships. "
                    f"However, when producing the final JSON response, ONLY provide the full cluster-level analysis "
                    f"(label, description, relationships, function_prefix) for clusters with indices in the range "
                    f"[{start_idx + 1}, {end_idx}]. For all other clusters outside this subset, do NOT provide their "
                    f"full analysis. Still, as instructed, provide binary_description, binary_category, and binary_report "
                    f"for the entire binary. All clusters are provided below for context. "
                )

            formatted = "Binary Analysis Clusters\n=====================\n\n"
            formatted += "Structure is organized hierarchically with primary clusters and their subclusters.\n"
            formatted += "Each cluster shows its functions, artifacts (APIs, strings, etc.), and call flows.\n"
            formatted += "References to subclusters indicate where complex behavior is encapsulated.\n\n"
            formatted += note

            for cluster in clusters:
                formatted += format_cluster(cluster) + "\n\n"

            formatted += ps_note
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
