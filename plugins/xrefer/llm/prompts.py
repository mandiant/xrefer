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

from xrefer.core.helpers import log
from xrefer.llm.templates import ARTIFACT_ANALYZER_PROMPT, CATEGORIZER_PROMPT, CLUSTER_ANALYZER_PROMPT


def _format_json_error(e: json.JSONDecodeError, response: str) -> str:
    """Format JSONDecodeError with context for better debugging."""
    lines = response.split("\n")
    error_line = e.lineno - 1
    error_col = e.colno - 1

    LINES_TO_SHOW = 5
    start_line = max(0, error_line - LINES_TO_SHOW)
    end_line = min(len(lines), error_line + LINES_TO_SHOW + 1)
    context_lines = []

    for i in range(start_line, end_line):
        prefix = ">>> " if i == error_line else "    "
        context_lines.append(f"{prefix}{i + 1:3d}: {lines[i]}")
    if error_line < len(lines):
        pointer = " " * (8 + error_col) + "^"
        context_lines.append(pointer)
    context = "\n".join(context_lines)
    return f"Invalid JSON response from model at line {e.lineno}, column {e.colno}: {e.msg}\n\nContext:\n{context}\n\nFull response length: {len(response)} chars"


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
        # NOTE: Just use json schema/pydantic and enforce structured output via code?
        if response.startswith("```json") and response.endswith("```"):
            response = response[len("```json") : -len("```")].strip()
        try:
            return self._parse_response_impl(response, **kwargs)
        except json.JSONDecodeError as e:
            raise ValueError(_format_json_error(e, response))

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

        # Parse the JSON response
        result = json.loads(response)
        category_assignments = result.get("category_assignments", {})

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
        result = json.loads(response)
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
        result = json.loads(response)
        # Validate required keys
        if not isinstance(result, dict):
            raise ValueError("Response must be a dictionary")

        required_keys = {"clusters", "binary_description", "binary_category"}
        if not all(key in result for key in required_keys):
            raise ValueError(f"Missing required keys. Found: {list(result.keys())}")

        # Validate clusters structure
        clusters = result["clusters"]
        if not isinstance(clusters, dict):
            raise ValueError("'clusters' must be a dictionary")

        for cluster_id, analysis in clusters.items():
            if not isinstance(analysis, dict):
                raise ValueError(f"Analysis for {cluster_id} must be a dictionary")

            required_analysis_keys = {"label", "description", "relationships", "function_prefix", "library_or_runtime"}  # if not all(key in analysis for key in required_analysis_keys):
            for key in required_analysis_keys:
                if key not in analysis:
                    log(f"Warning: Missing some analysis keys in {cluster_id}. Found: {list(analysis.keys())}")
        return result
