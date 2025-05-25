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

from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import idc
import networkx as nx
from networkx import NetworkXError
from xrefer.core.helpers import find_cluster_analysis, log


class FunctionalCluster:
    """
    Represents a cluster of related interesting functions.

    Each cluster has a root node that may have high branching factor,
    but all immediate children within the cluster must have ≤2 children
    or be replaced with cluster references.
    """

    # Class variable to track next available ID
    _next_id = 1

    def __init__(self, root_node: int, parent_cluster_id: Optional[int] = None):
        # Get next ID and increment counter
        self.id = FunctionalCluster._next_id
        FunctionalCluster._next_id = (FunctionalCluster._next_id % 9999) + 1

        # Convert ID to padded string format
        self.id_str = f"{self.id:04d}"

        self.root_node = root_node  # Function that forms the root of this cluster
        self.nodes = set([root_node])  # All interesting functions in this cluster
        self.edges = []  # (source, target) pairs representing calls between interesting nodes
        self.subclusters = []  # Child clusters split off from this one
        self.parent_cluster_id = parent_cluster_id  # ID of parent cluster if any
        self.cluster_refs = {}  # Maps node -> cluster_id for replaced nodes
        self.intermediate_paths = {}  # Maps (source, target) -> set of intermediate paths

    @classmethod
    def reset_id_counter(cls):
        """Reset the ID counter back to 1. Useful between analysis runs."""
        cls._next_id = 1

    def add_edge(self, source: int, target: int) -> None:
        """Add an edge between two functions in the cluster."""
        self.nodes.add(source)
        self.nodes.add(target)
        self.edges.append((source, target))

    def get_direct_children(self, node: int) -> List[int]:
        """Get immediate child nodes of the given node."""
        return [target for source, target in self.edges if source == node]

    def replace_node_with_cluster(self, node: int, cluster_id: int) -> None:
        """
        Replace node with cluster reference while preserving edge structure.
        Critical: Only removes from nodes set, preserves edges.
        """
        # Remove from nodes but preserve edge structure
        if node in self.nodes:
            self.nodes.remove(node)
        # Add cluster reference
        self.cluster_refs[node] = cluster_id

    def _format_root_node_label(self, cluster_analysis: Dict = None, max_label_length: int = 50) -> str:
        """Format the root node label."""
        cluster_id = f"cluster.id.{self.id_str}"
        root_addr = f"0x{self.root_node:x}"
        cluster_id_and_root = f"{cluster_id} - {root_addr}"

        if cluster_analysis:
            data = find_cluster_analysis(cluster_analysis, self.id)
            if data and data.get("label"):
                label = data["label"]
                if len(label) > max_label_length:
                    label = label[: max_label_length - 2] + ".."

                # Center align all components
                max_width = max(len(cluster_id_and_root), len(label), len(root_addr))
                return f"{cluster_id_and_root:^{max_width}}\n{label:^{max_width}}"

        # If no analysis data, just show ID and root address
        max_width = max(len(cluster_id_and_root), len(root_addr))
        return f"{cluster_id_and_root:^{max_width}}"

    def is_real_intermediate(self, node: int) -> bool:
        """
        Determine if a node is truly intermediate (no artifacts).

        Args:
            node: Node to check

        Returns:
            bool: True if node is purely intermediate (no artifacts), False if it's a normal node
        """
        # Not intermediate if it's in nodes set (has artifacts or is root/direct child)
        if node in self.nodes:
            return False

        # Not intermediate if it's a cluster reference
        if node in self.cluster_refs:
            return False

        # Not intermediate if it's the root node
        if node == self.root_node:
            return False

        # At this point, if it's in any intermediate path, it's a true intermediate
        for _, paths in self.intermediate_paths.items():
            for path in paths:
                if node in path:
                    return True

        return False

    def to_graph(self, cluster_analysis: Dict = None, include_intermediate: bool = False, max_label_length: int = 50) -> nx.DiGraph:
        """
        Convert cluster to NetworkX graph for visualization.

        Args:
            cluster_analysis: Analysis data for clusters
            include_intermediate: Whether to include intermediate nodes in the graph.
            max_label_length: Maximum length for cluster labels before truncation

        Returns:
            nx.DiGraph: Graph ready for ASCII visualization
        """

        def truncate_label(label: str) -> str:
            """Truncate label if it exceeds max length."""
            if len(label) > max_label_length:
                return label[: max_label_length - 2] + ".."
            return label

        def center_text(text: str, width: int) -> str:
            """Center text in given width."""
            return f"{text:^{width}}"

        def format_function_label(addr: int, max_name_length: int = 25) -> str:
            """
            Format function address and name with center alignment.
            """
            addr_str = f"0x{addr:x}"
            name = idc.get_func_name(addr)

            if len(name) > max_name_length:
                name = name[: max_name_length - 2] + ".."

            width = max(len(addr_str), len(name))

            centered_addr = center_text(addr_str, width)
            centered_name = center_text(name, width)

            return f"{centered_addr}\n{centered_name}"

        def format_node_label(node: int) -> str:
            """
            Format label for a node, handling cluster references and function nodes.
            """
            # Handle cluster references
            if node in self.cluster_refs:
                ref_cluster_id = self.cluster_refs[node]

                analysis_data = find_cluster_analysis(cluster_analysis, ref_cluster_id)
                label = analysis_data.get("label", "") if analysis_data else ""

                first_line = f"cluster.id.{ref_cluster_id:04d}"

                if label:
                    label = truncate_label(label.strip())
                    width = max(len(first_line), len(label))
                    centered_id = center_text(first_line, width)
                    centered_label = center_text(label, width)
                    return f"{centered_id}\n{centered_label}"

                return first_line

            # Handle root node
            if node == self.root_node:
                return self._format_root_node_label(cluster_analysis, max_label_length)

            # Format basic function label
            label = format_function_label(node)

            # Add intermediate marker only for true intermediates
            if self.is_real_intermediate(node):
                lines = label.split("\n")
                width = max(len(line) for line in lines)
                marker = center_text("(i)", width)
                label = f"{label}\n{marker}"

            return label

        g = nx.DiGraph()

        # Add direct edges between interesting nodes/clusters only
        for source, target in self.edges:
            source_label = format_node_label(source)
            target_label = format_node_label(target)
            g.add_edge(source_label, target_label)

        # Track processed edges to avoid duplicates
        processed_edges = set((source, target) for source, target in self.edges)

        # Add edges from intermediate paths
        # Only add them if they connect nodes that should be visible.
        # If include_intermediate is False, we skip edges that introduce real intermediate nodes.
        for (source, target), paths in self.intermediate_paths.items():
            for path in paths:
                for i in range(len(path) - 1):
                    curr = path[i]
                    next_node = path[i + 1]

                    # Check if these nodes qualify for display:
                    # Either node is interesting (in self.nodes), a cluster reference, or root node.
                    if curr in self.nodes or next_node in self.nodes or curr == self.root_node or next_node == self.root_node or curr in self.cluster_refs or next_node in self.cluster_refs:
                        # If intermediate nodes are not included, skip edges that introduce real intermediates
                        if not include_intermediate:
                            # If either node is a real intermediate node, skip this edge
                            if self.is_real_intermediate(curr) or self.is_real_intermediate(next_node):
                                continue

                        # Skip if we've already processed this edge
                        if (curr, next_node) in processed_edges:
                            continue

                        source_label = format_node_label(curr)
                        target_label = format_node_label(next_node)
                        g.add_edge(source_label, target_label)
                        processed_edges.add((curr, next_node))

        # Add isolated nodes if they are not already in the graph
        # We consider root_node, nodes, and cluster_refs.
        candidate_nodes = set(self.nodes)
        candidate_nodes.add(self.root_node)
        candidate_nodes.update(self.cluster_refs.keys())

        for node in candidate_nodes:
            if not include_intermediate and self.is_real_intermediate(node):
                # Skip intermediate nodes if not including them
                continue
            node_label = format_node_label(node)
            if node_label not in g:
                g.add_node(node_label)

        return g


class ClusterManager:
    """
    Manages decomposition of paths into hierarchical clusters.
    """

    @staticmethod
    def simplify_path_with_intermediates(path: List[int], interesting_funcs: Set[int]) -> Tuple[Optional[List[int]], Dict]:
        """
        Simplify path while preserving intermediate nodes between interesting functions.

        Args:
            path: Original path through functions
            interesting_funcs: Set of functions marked as interesting

        Returns:
            Tuple of:
            - Optional[List[int]]: Simplified path containing only interesting functions, or None
            - Dict: Mapping of (source, target) pairs to shortest intermediate paths
        """
        simplified = []
        interesting_count = 0
        intermediates_map = {}

        # First collect interesting nodes and their positions
        interesting_positions = []
        for i, node in enumerate(path):
            if node in interesting_funcs:
                interesting_positions.append((i, node))
                interesting_count += 1

        # If insufficient interesting nodes, return None
        if interesting_count < 2:
            return None, {}

        # Build simplified path and collect intermediates
        for i in range(len(interesting_positions)):
            curr_pos, curr_node = interesting_positions[i]
            simplified.append(curr_node)

            # If not last node, store intermediates to next interesting node
            if i < len(interesting_positions) - 1:
                next_pos, next_node = interesting_positions[i + 1]
                # Get intermediate path including endpoints
                intermediate_path = tuple(path[curr_pos : next_pos + 1])
                key = (curr_node, next_node)

                # Update intermediates map if this is a shorter path
                if key not in intermediates_map or len(intermediate_path) < len(intermediates_map[key]):
                    intermediates_map[key] = intermediate_path

        return simplified, intermediates_map

    @staticmethod
    def establish_cluster_relationships(clusters: List[FunctionalCluster]) -> None:
        """
        Post-process to ensure all cluster relationships are properly established.
        Check all terminating nodes in call flows to see if they are root nodes of other clusters.
        """
        # First build complete map of all root nodes to their clusters
        root_to_cluster = {}  # root_node -> cluster

        def map_cluster(cluster):
            """Map cluster and all its subclusters."""
            root_to_cluster[cluster.root_node] = cluster
            for subcluster in cluster.subclusters:
                map_cluster(subcluster)

        # Build complete mapping including all subclusters
        for cluster in clusters:
            map_cluster(cluster)

        def process_cluster(cluster):
            """Process a cluster and all its subclusters."""
            # Check all edges
            for source, target in list(cluster.edges):  # Create list copy since we might modify edges
                if target in root_to_cluster and target != cluster.root_node:
                    target_cluster = root_to_cluster[target]
                    # Don't create reference to self or own subcluster
                    if target_cluster.id != cluster.id and target_cluster.parent_cluster_id != cluster.id and target_cluster.root_node != cluster.root_node:
                        cluster.replace_node_with_cluster(target, target_cluster.id)
                        # log(f"Replacing node 0x{target:x} with Cluster {target_cluster.id} in cluster {cluster.id}")

            # Process subclusters
            for subcluster in cluster.subclusters:
                process_cluster(subcluster)

        # Process all clusters
        for cluster in clusters:
            process_cluster(cluster)

    @staticmethod
    def cleanup_frequent_nodes(clusters: List["FunctionalCluster"], frequency_threshold: int = 5, min_cluster_size: int = 2) -> None:
        """
        Remove nodes that appear too frequently across clusters and subclusters,
        while preserving small clusters that would become too small after cleanup.

        Args:
            clusters: List of clusters to process
            frequency_threshold: Maximum number of times a node can appear before being removed
            min_cluster_size: Minimum number of nodes (including root) a cluster must maintain
        """
        node_frequencies = defaultdict(int)
        cluster_map = {}

        def count_node_frequencies(cluster: "FunctionalCluster") -> None:
            cluster_map[cluster.id] = cluster
            for node in cluster.nodes:
                node_frequencies[node] += 1
            for subcluster in cluster.subclusters:
                count_node_frequencies(subcluster)

        for cluster in clusters:
            count_node_frequencies(cluster)

        nodes_to_remove = {node for node, freq in node_frequencies.items() if freq > frequency_threshold}

        if not nodes_to_remove:
            log("No nodes found exceeding frequency threshold")
            return

        log(f"Found {len(nodes_to_remove)} nodes appearing in >{frequency_threshold} clusters:")
        log(f"Frequent nodes: {', '.join(f'0x{node:x}' for node in sorted(nodes_to_remove))}\n")

        def clean_cluster(cluster: "FunctionalCluster", depth: int = 0) -> None:
            """
            Clean frequent nodes from a cluster and update its structure.

            Args:
                cluster: Cluster to clean
                depth: Current depth in cluster hierarchy for logging indentation
            """
            indent = "  " * depth
            nodes_to_remove_here = nodes_to_remove.intersection(cluster.nodes)
            original_size = len(cluster.nodes)
            remaining_size = original_size - len(nodes_to_remove_here)
            cluster_type = "Cluster" if depth == 0 else "Subcluster"

            if remaining_size < min_cluster_size:
                log(f"{indent}{cluster_type} {cluster.id} preserved - would have only {remaining_size} nodes (current: {original_size})")
            else:
                # Store pre-cleanup state
                pre_cleanup_nodes = set(cluster.nodes)
                pre_cleanup_root = cluster.root_node

                # Perform cleanup
                cluster.nodes.difference_update(nodes_to_remove)

                # Update edges
                new_edges = []
                for source, target in cluster.edges:
                    if source not in nodes_to_remove and target not in nodes_to_remove:
                        new_edges.append((source, target))
                cluster.edges = new_edges

                # Update cluster_refs
                cluster.cluster_refs = {node: ref_id for node, ref_id in cluster.cluster_refs.items() if node not in nodes_to_remove}

                # Handle root node if needed
                root_changed = False
                if cluster.root_node in nodes_to_remove:
                    old_root = cluster.root_node
                    remaining_nodes = cluster.nodes - set(target for _, target in cluster.edges)
                    if remaining_nodes:
                        cluster.root_node = min(remaining_nodes)
                    elif cluster.nodes:
                        cluster.root_node = min(cluster.nodes)
                    else:
                        cluster.marked_for_removal = True
                    root_changed = True

                # Log changes
                final_size = len(cluster.nodes)
                removed_nodes = pre_cleanup_nodes - cluster.nodes

                log(f"{indent}{cluster_type} {cluster.id}:")
                log(f"{indent}  Nodes: {original_size} → {final_size} ({len(removed_nodes)} removed)")
                log(f"{indent}  Removed nodes: {', '.join(f'0x{n:x}' for n in sorted(removed_nodes))}")

                if root_changed:
                    log(f"{indent}  Root node changed: 0x{old_root:x} → 0x{cluster.root_node:x}")

                if hasattr(cluster, "marked_for_removal"):
                    log(f"{indent}  ⚠️ Cluster marked for removal - no valid nodes remain")

                log("")  # Empty line for readability

            # Process subclusters
            if cluster.subclusters:
                log(f"{indent}Processing {len(cluster.subclusters)} subclusters of {cluster_type} {cluster.id}:")

            for subcluster in cluster.subclusters:
                clean_cluster(subcluster, depth + 1)

            # Remove empty subclusters
            original_subcluster_count = len(cluster.subclusters)
            cluster.subclusters = [sub for sub in cluster.subclusters if not hasattr(sub, "marked_for_removal")]

            if original_subcluster_count != len(cluster.subclusters):
                log(f"{indent}Removed {original_subcluster_count - len(cluster.subclusters)} empty subclusters from {cluster_type} {cluster.id}")

        log("\nStarting cluster cleanup:")
        log("=" * 50)

        # Clean all clusters
        original_cluster_count = len(clusters)
        for cluster in clusters[:]:
            clean_cluster(cluster)

        # Remove empty root clusters
        clusters[:] = [cluster for cluster in clusters if not hasattr(cluster, "marked_for_removal")]

        log("\nCleanup Summary:")
        log("=" * 50)
        log(f"Original clusters: {original_cluster_count}")
        log(f"Final clusters: {len(clusters)}")
        log(f"Clusters removed: {original_cluster_count - len(clusters)}")

    @staticmethod
    def decompose_into_clusters(
        paths: List[List[int]],
        intermediate_paths_map: Dict[Tuple[int, int], Tuple[int, ...]],
        root_nodes: Set[int],
        artifact_functions: Set[int],
        branching_threshold: int = 2,
        frequency_threshold: int = 5,
        min_cluster_size: int = 2,
    ) -> List[FunctionalCluster]:
        """
        Create clusters based on interesting nodes first, using only shortest intermediate paths.

        Args:
            paths: Call paths to decompose (already simplified)
            intermediate_paths_map: Mapping of node pairs to their shortest intermediate paths
            root_nodes: Set of root nodes to start clustering from
            branching_threshold: Max children before creating subcluster
            frequency_threshold: Maximum times a node can appear before being removed
            min_cluster_size: Minimum nodes a cluster must maintain

        Returns:
            List[FunctionalCluster]: List of clusters representing the hierarchy
        """
        log(f"Creating initial graph with {len(paths)} paths")

        # Create initial graph using simplified paths
        initial_graph = nx.DiGraph()
        for path in paths:
            for i in range(len(path) - 1):
                initial_graph.add_edge(path[i], path[i + 1])

        log(f"Initial graph has {len(initial_graph.nodes())} nodes and {len(initial_graph.edges())} edges")

        # Track processed nodes to avoid duplicates
        processed = set()
        subcluster_cache = {}  # Maps node -> (cluster, parent_id)

        def is_node_interesting(node: int, cluster: FunctionalCluster) -> bool:
            """Check if a node should be included in cluster nodes."""
            # Root nodes and direct children are always interesting
            if node == cluster.root_node:
                return True

            # Check successors count (branching factor)
            try:
                successors = list(initial_graph.successors(node))
                if len(successors) > branching_threshold:
                    return True
            except NetworkXError:
                pass

            if node in artifact_functions:
                return True

            return False

        def extract_cluster(graph: nx.DiGraph, root: int, parent_id: Optional[int] = None) -> FunctionalCluster:
            """Extract cluster rooted at given node, recursively creating subclusters."""
            cluster = FunctionalCluster(root, parent_id)

            try:
                children = list(graph.successors(root))
                # log(f"Root 0x{root:x} has {len(children)} children")
            except NetworkXError:
                return cluster

            processed.add(root)

            # Process all direct children first
            for child in children:
                # Add edge regardless of node classification
                cluster.add_edge(root, child)
                # Store intermediate path if it exists
                if (root, child) in intermediate_paths_map:
                    cluster.intermediate_paths[(root, child)] = {intermediate_paths_map[(root, child)]}

                    # Check each intermediate node for artifacts
                    for intermediate_node in intermediate_paths_map[(root, child)]:
                        if is_node_interesting(intermediate_node, cluster):
                            cluster.nodes.add(intermediate_node)

                # log(f"Added edge: 0x{root:x} -> 0x{child:x}")

                # Skip if already processed
                if child in processed:
                    continue

                try:
                    child_successors = list(graph.successors(child))
                    # log(f"Child 0x{child:x} has {len(child_successors)} successors")

                    # Determine if child should be a subcluster root
                    should_subcluster = len(child_successors) > branching_threshold and child not in root_nodes

                    if should_subcluster:
                        # log(f"Adding subcluster for node 0x{child:x}")
                        if child in subcluster_cache:
                            existing_subcluster, _ = subcluster_cache[child]
                            cluster.subclusters.append(existing_subcluster)
                            cluster.replace_node_with_cluster(child, existing_subcluster.id)
                            # Copy intermediate paths from subcluster
                            for k, v in existing_subcluster.intermediate_paths.items():
                                cluster.intermediate_paths[k] = v
                        else:
                            subcluster = extract_cluster(graph, child, cluster.id)
                            cluster.subclusters.append(subcluster)
                            cluster.replace_node_with_cluster(child, subcluster.id)
                            # Copy intermediate paths from new subcluster
                            for k, v in subcluster.intermediate_paths.items():
                                cluster.intermediate_paths[k] = v
                            subcluster_cache[child] = (subcluster, cluster.id)
                    else:
                        # Check if child should be included in cluster nodes
                        if is_node_interesting(child, cluster):
                            cluster.nodes.add(child)
                        processed.add(child)

                        # Process child's successors
                        for grandchild in child_successors:
                            if grandchild not in processed:
                                if is_node_interesting(grandchild, cluster):
                                    cluster.add_edge(child, grandchild)
                                    # Store intermediate path if it exists
                                    if (child, grandchild) in intermediate_paths_map:
                                        path_tuple = intermediate_paths_map[(child, grandchild)]
                                        cluster.intermediate_paths[(child, grandchild)] = {path_tuple}

                                        # Check intermediates for artifacts
                                        for intermediate_node in path_tuple:
                                            if is_node_interesting(intermediate_node, cluster):
                                                cluster.nodes.add(intermediate_node)

                                processed.add(grandchild)

                except NetworkXError:
                    log(f"Error: Child 0x{child:x} not found in graph")
                    continue

            return cluster

        # Create clusters from root nodes
        clusters = []
        for root in root_nodes:
            if root in processed or not initial_graph.has_node(root):
                continue

            cluster = extract_cluster(initial_graph, root)
            clusters.append(cluster)

        # Post-process to establish all cluster relationships
        log("Establishing cluster relationships...")
        ClusterManager.establish_cluster_relationships(clusters)
        return clusters
