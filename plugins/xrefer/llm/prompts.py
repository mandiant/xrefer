# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
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
from enum import Enum
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Any

from xrefer.llm.templates.artifact_analyzer import ARTIFACT_ANALYZER_PROMPT 
from xrefer.llm.templates.categorizer import CATEGORIZER_PROMPT
from xrefer.llm.templates.cluster_analyzer import CLUSTER_ANALYZER_PROMPT
from xrefer.core.helpers import log


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
        
    @abstractmethod
    def parse_response(self, response: str) -> Dict:
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
        
    def parse_response(self, response: str, categories: List[str]) -> Dict[str, int]:
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
        try:
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
            
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON response from model")


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
        
    def parse_response(self, response: str) -> Set[int]:
        """
        Parse LLM response into set of interesting artifact indices.
        
        Args:
            response: JSON response containing interesting_indexes
            
        Returns:
            Set[int]: Set of indices for artifacts identified as interesting
            
        Raises:
            ValueError: If response is not valid JSON or missing required key
        """
        try:
            result = json.loads(response)
            return set(result["interesting_indexes"])
        except (json.JSONDecodeError, KeyError):
            raise ValueError("Invalid JSON response from model")
        

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
        
    def parse_response(self, response: str) -> Dict[str, Any]:
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
        try:
            result = json.loads(response)
            
            # Validate required keys
            if not isinstance(result, dict):
                raise ValueError("Response must be a dictionary")
                
            required_keys = {'clusters', 'binary_description', 'binary_category'}
            if not all(key in result for key in required_keys):
                raise ValueError(f"Missing required keys. Found: {list(result.keys())}")
                
            # Validate clusters structure
            clusters = result['clusters']
            if not isinstance(clusters, dict):
                raise ValueError("'clusters' must be a dictionary")
                
            for cluster_id, analysis in clusters.items():
                if not isinstance(analysis, dict):
                    raise ValueError(f"Analysis for {cluster_id} must be a dictionary")
                    
                required_analysis_keys = {'label', 'description', 'relationships', 'function_prefix', 'library_or_runtime'}
                if not all(key in analysis for key in required_analysis_keys):
                    log(f"Warning: Missing some analysis keys in {cluster_id}. Found: {list(analysis.keys())}")
            
            return result
            
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON response from model")
        except Exception as e:
            raise ValueError(f"Error parsing response: {str(e)}")
            