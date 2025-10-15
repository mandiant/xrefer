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

from typing import Dict, List

import dspy

from xrefer.llm.dspy_signatures import ArtifactAnalyzerSignature, CategorizerSignature, ClusterAnalyzerSignature
from xrefer.llm.schemas import ArtifactAnalysisResponse, CategorizationResponse, ClusterAnalysisResponse
from xrefer.llm.templates import CLUSTER_ANALYZER_PROMPT


class CategorizerModule(dspy.Module):
    """DSPy module for API/library categorization with structured inputs."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.ChainOfThought(CategorizerSignature)

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

        # DSPy handles prompt formatting from structured inputs!
        result = self.predictor(
            items=items_dict,
            categories=categories,
            item_type=item_type
        )
        return result.categorization


class ArtifactAnalyzerModule(dspy.Module):
    """DSPy module for artifact analysis with structured inputs."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.ChainOfThought(ArtifactAnalyzerSignature)

    def forward(self, artifacts: Dict[str, Dict[int, str]]) -> ArtifactAnalysisResponse:
        """
        Analyze artifacts using DSPy with structured inputs.

        Args:
            artifacts: Dict of artifacts organized by type (Strings, APIs, CAPA, Libraries)

        Returns:
            ArtifactAnalysisResponse Pydantic model
        """
        # DSPy handles prompt formatting!
        result = self.predictor(artifacts=artifacts)
        return result.analysis


class ClusterAnalyzerModule(dspy.Module):
    """DSPy module for cluster analysis with structured inputs."""

    def __init__(self):
        super().__init__()
        self.predictor = dspy.ChainOfThought(ClusterAnalyzerSignature)

    def forward(self, cluster_data: str) -> ClusterAnalysisResponse:
        """
        Analyze clusters using DSPy with structured inputs.

        Args:
            cluster_data: Formatted cluster hierarchy with functions and artifacts

        Returns:
            ClusterAnalysisResponse Pydantic model
        """
        # Combine original template instructions with current cluster data without relying on str.format
        template_prompt = CLUSTER_ANALYZER_PROMPT.replace("{cluster_data}", cluster_data)

        # DSPy handles prompt formatting from structured inputs
        result = self.predictor(
            template_prompt=template_prompt,
            cluster_data=cluster_data,
        )
        return result.analysis
