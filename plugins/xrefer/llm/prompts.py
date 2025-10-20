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

import json
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Set

from xrefer.llm.templates import ARTIFACT_ANALYZER_PROMPT, CATEGORIZER_PROMPT, CLUSTER_ANALYZER_PROMPT

class PromptType(Enum):
    CATEGORIZER = "categorizer"
    ARTIFACT_ANALYZER = "artifact_analyzer"
    CLUSTER_ANALYZER = "cluster_analyzer"


class PromptTemplate(ABC):
    """
    Abstract base class for prompt templates.

    Provides interface for formatting prompts and parsing responses
    for different types of LLM interactions.
    """

    def __init__(self):
        self.template_text = self._load_template()

    def _load_template(self) -> str:
        """Return the prompt template text."""
        return self.template_text

    @abstractmethod
    def format(self, **kwargs) -> str:
        """
        Format the template with given parameters.
        """
        raise NotImplementedError

    def parse_response(self, response: str, **kwargs) -> Dict[str, Any] | Set[int]:
        """
        Parse the LLM response into structured data.

        Args:
            response: Raw response string from LLM

        Returns:
            Parsed data in structured format
        """
        assert response is not None, "No response to parse"
        v = self._parse_response_impl(response, **kwargs)
        # basemodel? -> model_dump()
        print(f"{v = }")
        if hasattr(v, "model_dump"):
            return v.model_dump()
        return v



    @abstractmethod
    def _parse_response_impl(self, response: str, **kwargs) -> Dict[str, Any] | Set[int]:
        """
        Parse LLM response into structured format.
        """
        raise NotImplementedError


class CategorizerPrompt(PromptTemplate):
    """
    Prompt template for API and library categorization.

    Handles prompts for categorizing APIs and libraries into predefined categories,
    using an index-based response format for efficiency.
    """

    def __init__(self):
        self.template_text = CATEGORIZER_PROMPT
        super().__init__()

    def format(self, items: List[str], categories: List[str], type: str = "api") -> str:
        """
        Format categorization prompt with items and categories.

        Args:
            items: List of APIs or libraries to categorize
            categories: List of available categories
            type: Type of items ("api" or "lib")

        Returns:
            str: Formatted prompt for LLM categorization
        """
        # Create indexed items list
        items_dict = [{"index": i, "name": item} for i, item in enumerate(items)]
        indexed_categories = [{"index": i, "name": category} for i, category in enumerate(categories)]

        formatted_prompt = self.template_text.replace("{{TYPE}}", type)
        formatted_prompt = formatted_prompt.replace("{{CATEGORIES}}", json.dumps(indexed_categories, indent=2))
        formatted_prompt = formatted_prompt.replace("{{ITEMS}}", json.dumps(items_dict, indent=2))
        return formatted_prompt

    def _parse_response_impl(self, response: str, categories: List[str]) -> Dict[str, int]:
        """
        Parse LLM categorization response into item-to-category mapping.

        Args:
            response: JSON response from LLM mapping indexes to category indexes
            categories: List of category names in correct order for index mapping

        Returns:
            Dict[str, int]: Mapping of items to their category indices

        Raises:
            ValueError: If response is not valid JSON
        """
        result = response
        category_assignments = result.category_assignments

        # Validate and normalize category assignments
        categorized_items = {}
        for item_idx_str, category_idx in category_assignments.items():
            # Ensure category index is valid
            if not (0 <= category_idx < len(categories)):
                category_idx = categories.index("Others")
            categorized_items[item_idx_str] = category_idx
        return categorized_items


class ArtifactAnalyzerPrompt(PromptTemplate):
    """
    Prompt template for analyzing potential malicious artifacts.
    """

    def __init__(self):
        self.template_text = ARTIFACT_ANALYZER_PROMPT
        super().__init__()

    def format(self, artifacts: Dict[str, Dict[int, str]]) -> str:
        """
        Format artifact analysis prompt.

        Args:
            artifacts: Dictionary of artifacts organized by type

        Returns:
            str: Formatted prompt for artifact analysis
        """
        return self.template_text + "\n" + json.dumps(artifacts, indent=2)

    def _parse_response_impl(self, response: str) -> Set[int]:
        """
        Parse LLM response into set of interesting artifact indices.

        Args:
            response: JSON response containing interesting_indexes

        Returns:
            Set[int]: Set of indices for artifacts identified as interesting

        Raises:
            ValueError: If response is not valid JSON or missing required key
        """
        # result = json.loads(response)
        result = response
        return set(result["interesting_indexes"])


class ClusterAnalyzerPrompt(PromptTemplate):
    """
    Prompt template for analyzing function clusters.
    """

    def __init__(self):
        self.template_text = CLUSTER_ANALYZER_PROMPT
        super().__init__()

    def format(self, cluster_data: str) -> str:
        """
        Format cluster analysis prompt.

        Args:
            cluster_data: Formatted string describing cluster hierarchy
        """
        return self.template_text.replace("{cluster_data}", cluster_data)

    def _parse_response_impl(self, response: str) -> Dict[str, Any]:
        """
        Parse LLM response into cluster analysis results.

        Expected format:
        {
            "clusters": {
                "cluster_12345": {
                    "label": str,
                    "description": str,
                    "relationships": str,
                    "function_prefix": str,
                    "library_or_runtime": int
                },
                ...
            },
            "binary_description": str,
            "binary_category": str,
            "binary_report": str
        }

        Args:
            response: JSON response containing cluster analysis

        Returns:
            Dict containing analysis results

        Raises:
            ValueError: If response is not valid JSON or missing required structure
        """
        result = response
        assert result is not None, "No response to parse"

        from pydantic import BaseModel
        if isinstance(result, BaseModel):
            result_dict = result.model_dump()
        else:
            result_dict = result

        # Ensure clusters are also converted to dicts
        if "clusters" in result_dict:
            clusters_dict = {}
            for cluster_id, cluster_data in result_dict["clusters"].items():
                if isinstance(cluster_data, BaseModel):
                    clusters_dict[cluster_id] = cluster_data.model_dump()
                else:
                    clusters_dict[cluster_id] = cluster_data
            result_dict["clusters"] = clusters_dict

        return result_dict
