#!/usr/bin/env python

import argparse
import gzip
import os
import pickle
import sys
from collections import defaultdict
from datetime import datetime, timezone
from importlib.util import find_spec
from pathlib import Path
from pprint import pprint
from typing import Any, Dict

import idapro

PROJECT_DIR = Path(os.environ.get("PROJECT"))  # should be "pathto/xrefer/plugins"
assert PROJECT_DIR.exists(), f"PROJECT_DIR does not exist: {PROJECT_DIR}"
sys.path.insert(0, str(PROJECT_DIR.absolute()))


class DBAnalyzer:
    """Analyzes XRefer database structure and metrics."""

    def __init__(self, db_path: str, verbose: bool = False):
        self.db_path = Path(db_path)
        self.verbose = verbose
        self.data = self._load_db()

        dateiso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        print(f"{'.'.join(map(str, idapro.get_library_version()[:-1]))}\n{dateiso}")

        pkg_path = Path(find_spec("xrefer").origin).resolve().parent
        rel_pkg_path = os.path.relpath(pkg_path, start=os.getcwd())
        print(f"XRefer path: {rel_pkg_path}")

        self.metrics = self._calculate_metrics()

    def _load_db(self) -> Dict[str, Any]:
        """Load gzipped pickle database."""
        try:
            with gzip.open(self.db_path, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            raise ValueError(f"Failed to load {self.db_path}: {e}")

    def _calculate_metrics(self) -> Dict[str, Any]:
        """Calculate key database metrics."""
        metrics = {}
        if self.verbose:
            pprint(self.data, width=800, compact=True)

        # Basic info
        metrics["image_base"] = self.data.get("image_base", 0)
        metrics["entry_point"] = getattr(self.data.get("lang"), "entry_point", 0) if self.data.get("lang") else 0

        # Cross-references
        global_xrefs = self.data.get("global_xrefs", {})
        metrics["total_functions"] = len(global_xrefs)

        # Count edges in cross-references
        edge_count = 0
        ref_types = ["libs", "imports", "strings", "capa", "api_trace"]

        for func_ea, xrefs in global_xrefs.items():
            for xref_category in ["DIRECT_XREFS", "INDIRECT_XREFS"]:
                if isinstance(xrefs, dict) and xref_category in xrefs:
                    for ref_type in ref_types:
                        if ref_type in xrefs[xref_category]:
                            edge_count += len(xrefs[xref_category][ref_type])

        metrics["total_edges"] = edge_count

        entities = self.data.get("entities", [])
        metrics["total_entities"] = len(entities)
        # entity type:
        # 1: lib type
        # 2: api type
        # 3: string type
        # 4: capa type
        entity_counts = defaultdict(int)
        for entity in entities:
            if len(entity) >= 3:
                entity_type = entity[2]
                entity_counts[entity_type] += 1

        metrics["entity_counts"] = dict(entity_counts)

        # Paths
        paths = self.data.get("paths", {})
        metrics["entry_points"] = len(paths)
        metrics["total_paths"] = sum(len(path_list) for func_paths in paths.values() for path_list in func_paths.values())

        # Clusters
        # Clusters - check both the cluster objects and cluster_analysis
        cluster_objects = self.data.get("clusters", [])
        cluster_analysis = self.data.get("cluster_analysis", {})

        # Count from cluster_analysis (which matches log output)
        if isinstance(cluster_analysis, dict) and "clusters" in cluster_analysis:
            metrics["total_clusters"] = len(cluster_analysis["clusters"])
        else:
            metrics["total_clusters"] = 0

        # Also track actual cluster objects
        metrics["cluster_objects"] = len(cluster_objects)

        if cluster_objects:
            cluster_nodes = 0
            cluster_edges = 0

            def count_cluster_data(cluster_list):
                nonlocal cluster_nodes, cluster_edges
                for cluster in cluster_list:
                    cluster_nodes += len(getattr(cluster, "nodes", set()))
                    cluster_edges += len(getattr(cluster, "edges", []))
                    # Recursively count subclusters
                    if hasattr(cluster, "subclusters"):
                        count_cluster_data(cluster.subclusters)

            count_cluster_data(cluster_objects)
            metrics["cluster_nodes"] = cluster_nodes
            metrics["cluster_edges"] = cluster_edges
        else:
            metrics["cluster_nodes"] = 0
            metrics["cluster_edges"] = 0
        # Other structures
        metrics["string_cache_size"] = len(self.data.get("string_index_cache", []))
        metrics["caller_xrefs_size"] = len(self.data.get("caller_xrefs_cache", {}))
        metrics["entity_xrefs_size"] = len(self.data.get("entity_xrefs", {}))
        metrics["leaf_functions"] = len(self.data.get("leaf_funcs", set()))
        metrics["api_trace_functions"] = len(self.data.get("api_trace_data", {}))
        metrics["interesting_artifacts"] = len(self.data.get("interesting_artifacts", set()))

        return metrics

    def summary(self):
        """Print database summary."""
        print(f"\nDatabase Analysis: {self.db_path.name}")
        print(f"Image Base: {self.metrics['image_base']:#x}")
        print(f"Entry Point: {self.metrics['entry_point']:#x}")
        print(f"\nStructure Counts:")
        print(f"  Functions: {self.metrics['total_functions']}")
        print(f"  Edges: {self.metrics['total_edges']}")
        print(f"  Entities: {self.metrics['total_entities']}")
        print(f"  Entry Points: {self.metrics['entry_points']}")
        print(f"  Paths: {self.metrics['total_paths']}")
        print(f"  Clusters: {self.metrics['total_clusters']}")
        print(f"  Cluster Nodes: {self.metrics['cluster_nodes']}")
        print(f"  Cluster Edges: {self.metrics['cluster_edges']}")

        print(f"\nEntity Types:")
        for etype, count in self.metrics["entity_counts"].items():
            print(f"  Type {etype}: {count}")

        print(f"\nCache Sizes:")
        print(f"  String Cache: {self.metrics['string_cache_size']}")
        print(f"  Caller XRefs: {self.metrics['caller_xrefs_size']}")
        print(f"  Entity XRefs: {self.metrics['entity_xrefs_size']}")
        print(f"  Leaf Functions: {self.metrics['leaf_functions']}")
        print(f"  API Trace Functions: {self.metrics['api_trace_functions']}")
        print(f"  Interesting Artifacts: {self.metrics['interesting_artifacts']}")


def compare_databases(db1_path: str, db2_path: str):
    """Compare two databases and show differences."""
    print("Loading databases...")
    db1 = DBAnalyzer(db1_path)
    db2 = DBAnalyzer(db2_path)

    print(f"\n# Comparison: {Path(db1_path).name} vs {Path(db2_path).name}")

    differences = []
    for key in db1.metrics:
        val1 = db1.metrics[key]
        val2 = db2.metrics.get(key, 0)

        if val1 != val2:
            if isinstance(val1, dict) and isinstance(val2, dict):
                for subkey in set(val1.keys()) | set(val2.keys()):
                    v1 = val1.get(subkey, 0)
                    v2 = val2.get(subkey, 0)
                    if v1 != v2:
                        differences.append(f"{key}.{subkey}: {v1} -> {v2} (Δ{v2 - v1:+d})")
            else:
                diff = val2 - val1 if isinstance(val1, (int, float)) else "N/A"
                if isinstance(diff, (int, float)):
                    differences.append(f"{key}: {val1} -> {val2} (Δ{diff:+d})")
                else:
                    differences.append(f"{key}: {val1} -> {val2}")

    if differences:
        print("\nDifferences found:")
        for diff in differences:
            print(f"  {diff}")
    else:
        print("\nNo differences found in metrics.")

    return len(differences) == 0


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(description="Analyze XRefer database structure or compare two databases.", formatter_class=argparse.RawTextHelpFormatter)  # Preserves formatting in help
    parser.add_argument("db1_path", metavar="<database1.gz>", type=str, help="Path to the first database file for analysis.")
    parser.add_argument("db2_path", metavar="<database2.gz>", type=str, nargs="?", default=None, help="Path to the second database file for comparison (optional).")  # Makes this argument optional
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.", default=False)

    args = parser.parse_args()

    try:
        if args.db2_path is None:
            analyzer = DBAnalyzer(args.db1_path, args.verbose)
            analyzer.summary()
            sys.exit(0)
        else:
            db1 = DBAnalyzer(args.db1_path)
            print(f"\nSummary for {Path(args.db1_path).name}")
            db1.summary()

            db2 = DBAnalyzer(args.db2_path)
            print(f"\nSummary for {Path(args.db2_path).name}")
            db2.summary()

            # Compare
            are_same = compare_databases(args.db1_path, args.db2_path)
            sys.exit(0 if are_same else 1)

    except FileNotFoundError as e:
        print(f"Error: Database file not found - {e.filename}")
        sys.exit(1)
    except ValueError as e:  # Catch specific error from _load_db
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
