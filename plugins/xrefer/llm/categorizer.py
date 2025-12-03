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

from typing import Dict, List, Tuple

from xrefer.core.helpers import log
from xrefer.llm.base import ModelConfig, PromptType
from xrefer.llm.processor import LLMProcessor

CATEGORIES = [
    "File and Path I/O",
    "Network I/O",
    "Registry Operations",
    "Kernel-Mode and Driver I/O",
    "Process/Thread Operations",
    "System Information",
    "User Interface",
    "Cryptography",
    "Compression",
    "String Manipulation",
    "Time-related Operations",
    "Runtime Operations",
    "Memory Management",
    "Others",
]


class Categorizer:
    """Main interface for categorization functionality"""

    current_config: ModelConfig = None
    _processor: LLMProcessor = None

    @classmethod
    def _get_processor(cls) -> LLMProcessor:
        if not cls._processor:
            if not cls.current_config:
                raise ValueError("Model configuration not set. Use set_model_config() first.")
            cls._processor = LLMProcessor()
            cls._processor.set_model_config(cls.current_config)
        return cls._processor

    @classmethod
    def set_model_config(cls, config: ModelConfig):
        """Set the LLM configuration for categorization."""
        cls.current_config = config
        cls._processor = None  # Force new processor with new config

    @classmethod
    def categorize(cls, item_list: List[str], categorized_items: Dict[str, int], categories: List[str] = CATEGORIES, type: str = "api") -> Tuple[Dict[str, int], List[str]]:
        """
        Categorize items using LLM processing.

        Args:
            item_list: List of items to categorize
            categorized_items: Existing categorizations to preserve
            categories: List of possible categories
            type: Type of items being categorized ('api' or 'lib')

        Returns:
            Tuple containing:
            - Dictionary mapping items to category indices
            - List of category names
        """
        log(f"Categorizing items using LLM... (type: {type})")
        log("Categorization results are cached to disk. First time is the slowest and gets faster as cache builds up.")
        processor = cls._get_processor()

        if not processor.validate_api_key():
            return categorized_items, categories

        # Filter out already categorized items
        uncategorized = []
        for item in item_list:
            if item not in categorized_items:
                uncategorized.append(item)

        if not uncategorized:
            return categorized_items, categories

        # Process uncategorized items
        index_results = processor.process_items(items=uncategorized, prompt_type=PromptType.CATEGORIZER, categories=categories, type=type)
        index_results = index_results["category_assignments"]

        # Convert index-based results back to item mappings
        named_results = {}
        for i, item in enumerate(uncategorized):
            if str(i) in index_results:
                named_results[item] = index_results[str(i)]

        # Merge results with existing categorized items
        categorized_items.update(named_results)
        return categorized_items, categories
