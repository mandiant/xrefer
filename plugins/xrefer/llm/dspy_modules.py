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

"""DSPy modules with structured inputs and Pydantic outputs."""

from typing import Any, Dict, List
import enum

import dspy
from pydantic import BaseModel, Field

from xrefer.llm.templates import CLUSTER_ANALYZER_PROMPT

class CategorizationResponse(BaseModel):
    """Response model for API/Library categorization."""

    category_assignments: Dict[str, int] = Field(..., description="Mapping of item index (as string) to category index (0-based)")

    class Config:
        json_schema_extra = {
            "example": {
                "category_assignments": {
                    "0": 0,
                    "1": 2,
                    "2": 5
                }
            }
        }

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

class CategorizerModule(dspy.Module):
    """DSPy module for API/library categorization with structured inputs."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.Predict(CategorizerSignature)

    def forward(self, items: List[str], categories: List[str], item_type: str = "api") -> CategorizationResponse:
        """
        Categorize items using DSPy with structured inputs.

        Args:
            items: List of API/library names to categorize
            categories: List of available category names
            item_type: Type of items ("api" or "lib")

        Returns:
            CategorizationResponse Pydantic model
        """
        items_dict = [{"index": i, "name": item} for i, item in enumerate(items)]

        result = self.predictor(
            items=items_dict,
            categories=categories,
            item_type=item_type
        )
        return result.categorization


class ArtifactAnalysisResponse(BaseModel):
    """Response model for artifact analysis."""

    interesting_indexes: List[int] = Field(..., description="List of artifact indices identified as interesting from a security perspective")

    class Config:
        json_schema_extra = {
            "example": {
                "interesting_indexes": [0, 3, 7, 12]
            }
        }


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

class ArtifactAnalyzerModule(dspy.Module):
    """DSPy module for artifact analysis with structured inputs."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.Predict(ArtifactAnalyzerSignature)

    def forward(self, artifacts: Dict[str, Dict[int, str]]) -> ArtifactAnalysisResponse:
        """
        Analyze artifacts using DSPy with structured inputs.

        Args:
            artifacts: Dict of artifacts organized by type (Strings, APIs, CAPA, Libraries)

        Returns:
            ArtifactAnalysisResponse Pydantic model
        """
        result = self.predictor(artifacts=artifacts)
        return result.analysis


class ClusterAnalysis(BaseModel):
    """Analysis for a single function cluster."""

    label: str = Field(..., description="Short, descriptive label for the cluster")
    description: str = Field(..., description="Detailed description of cluster functionality")
    relationships: str = Field(..., description="How this cluster relates to other clusters")
    function_prefix: str = Field(..., description="Suggested prefix for renaming functions in this cluster")
    library_or_runtime: int = Field(default=0, description="1 if cluster is likely library/runtime code, 0 if application code")

    class Config:
        json_schema_extra = {
            "example": {
                "label": "Network Communication",
                "description": "Handles HTTP requests and socket operations",
                "relationships": "Called by authentication cluster, uses crypto cluster",
                "function_prefix": "net_",
                "library_or_runtime": 0
            }
        }

class BinaryCategory(enum.Enum):
    DOWNLOADER = "Downloader"
    POINT_OF_SALE = "Point-of-Sale Malware"
    RANSOMWARE = "Ransomware"
    UPLOADER = "Uploader"
    REMOTE_CONTROL_AND_ADMINISTRATION_TOOL = "Remote Control and Administration Tool"
    BACKDOOR = "Backdoor"
    FILE_INFECTOR = "File Infector"
    DROPPER = "Dropper"
    INSTALLER = "Installer"
    LAUNCHER = "Launcher"
    CONTROLLER = "Controller"
    BUILDER = "Builder"
    DISRUPTION_TOOL = "Disruption Tool"
    CREDENTIAL_STEALER = "Credential Stealer"
    PRIVILEGE_ESCALATION_TOOL = "Privilege Escalation Tool"
    REMOTE_EXPLOITATION_TOOL = "Remote Exploitation Tool"
    EXPLOIT = "Exploit"
    TUNNELER = "Tunneler"
    LATERAL_MOVEMENT_TOOL = "Lateral Movement Tool"
    RECONNAISSANCE_TOOL = "Reconnaissance Tool"
    DATA_MINER = "Data Miner"
    KEYLOGGER = "Keylogger"
    SNIFFER = "Sniffer"
    ARCHIVER = "Archiver"
    SCREEN_CAPTURE_TOOL = "Screen Capture Tool"
    DECODER = "Decoder"
    DECRYPTER = "Decrypter"
    BOOTKIT = "Bootkit"
    FRAMEWORK = "Framework"
    ROOTKIT = "Rootkit"
    CRYPTOCURRENCY_MINER = "Cryptocurrency Miner"
    SPAMBOT = "Spambot"
    ATM_MALWARE = "ATM Malware"
    UTILITY = "Utility"
    UNDETERMINED = "Undetermined"


class ClusterAnalysisResponse(BaseModel):
    """Response model for cluster analysis."""

    clusters: Dict[str, ClusterAnalysis] = Field(..., description="Mapping of cluster_id to ClusterAnalysis")
    binary_description: str = Field(..., description="Overall description of the binary's functionality")
    binary_category: BinaryCategory = Field(..., description="Classification of the binary")
    binary_report: str = Field(default="", description="Detailed analysis report for the binary")

    class Config:
        json_schema_extra = {
            "example": {
                "clusters": {
                    "cluster_1": {
                        "label": "Initialization",
                        "description": "Sets up application state",
                        "relationships": "Called first, initializes all other clusters",
                        "function_prefix": "init_",
                        "library_or_runtime": 0
                    }
                },
                "binary_description": "Network monitoring tool with logging capabilities",
                "binary_category": "Utility",
                "binary_report": "Detailed analysis shows..."
            }
        }

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

class ClusterAnalyzerModule(dspy.Module):
    """DSPy module for cluster analysis with structured inputs."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.Predict(ClusterAnalyzerSignature)

    def forward(self, cluster_data: str) -> ClusterAnalysisResponse:
        """
        Analyze clusters using DSPy with structured inputs.

        Args:
            cluster_data: Formatted cluster hierarchy with functions and artifacts

        Returns:
            ClusterAnalysisResponse Pydantic model
        """
        template_prompt = CLUSTER_ANALYZER_PROMPT.replace("{cluster_data}", cluster_data)

        result = self.predictor(
            template_prompt=template_prompt,
            cluster_data=cluster_data,
        )
        return result.analysis
