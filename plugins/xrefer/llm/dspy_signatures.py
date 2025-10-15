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
DSPy Signatures with Pydantic integration.
"""

from typing import Any, Dict, List

import dspy
from xrefer.llm.schemas import ArtifactAnalysisResponse, CategorizationResponse, ClusterAnalysisResponse


class CategorizerSignature(dspy.Signature):
    """
    Categorize APIs and libraries into predefined categories based on their names.

    You will be given a list of API or library function names and a list of categories.
    Your task is to assign each item to the most appropriate category based solely on
    the function name, focusing on recognizable patterns, prefixes, and keywords.

    Base your decision on the name alone, without making assumptions about higher-level
    behaviors or implementations. If an item doesn't clearly fit into the main categories,
    assign it to the 'Others' category.
    """

    items: List[Dict[str, Any]] = dspy.InputField(description="List of items with index and name to categorize")
    categories: List[str] = dspy.InputField(description="Available category names")
    item_type: str = dspy.InputField(description="Type of items: 'api' or 'lib'")
    categorization: CategorizationResponse = dspy.OutputField(description="Category assignments mapping item indices to category indices")


class ArtifactAnalyzerSignature(dspy.Signature):
    """
    Identify interesting artifacts from a security analysis perspective.

    You will be given artifacts organized by type (Strings, APIs, CAPA capabilities, Libraries).
    Your task is to identify which artifacts are potentially interesting from a security,
    reverse engineering, or malware analysis perspective.

    Consider artifacts interesting if they:
    - Indicate suspicious or malicious behavior
    - Reveal implementation details useful for analysis
    - Show uncommon or security-relevant functionality
    - Provide insights into the binary's purpose
    """

    artifacts: Dict[str, Dict[int, str]] = dspy.InputField(description="Artifacts organized by type (Strings, APIs, CAPA, Libraries)")
    analysis: ArtifactAnalysisResponse = dspy.OutputField(description="List of indices for artifacts deemed interesting")


class ClusterAnalyzerSignature(dspy.Signature):
    """
    Analyze function clusters to understand binary functionality.

    You will be given a hierarchical structure of function clusters with their associated
    artifacts (API calls, strings, CAPA capabilities) and call flows.

    Your task is to:
    1. Provide a descriptive label for each cluster
    2. Explain what each cluster does based on its functions and artifacts
    3. Describe how clusters relate to each other
    4. Suggest a function naming prefix for renaming
    5. Identify if the cluster is likely library/runtime code
    6. Provide an overall binary description and category
    7. Generate a comprehensive analysis report

    Focus on understanding the binary's purpose, architecture, and notable behaviors.
    """

    template_prompt: str = dspy.InputField(description="Full template instructions combined with cluster data")
    cluster_data: str = dspy.InputField(description="Raw cluster hierarchy with functions and artifacts (for reference)")
    analysis: ClusterAnalysisResponse = dspy.OutputField(description="Complete cluster analysis with per-cluster metadata and binary-level insights")
