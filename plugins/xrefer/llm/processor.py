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

from typing import Any, Dict, List

from xrefer.core.helpers import log
from xrefer.llm.base import ModelConfig, ModelType
from xrefer.llm.models import GoogleModel, OpenAIModel
from xrefer.llm.prompts import ArtifactAnalyzerPrompt, CategorizerPrompt, ClusterAnalyzerPrompt, PromptType


class LLMProcessor:
    """
    Core processor for handling Large Language Model operations.

    Manages interactions with different LLM providers (OpenAI, Google), handles
    token limits, batching, and response processing for various analysis tasks.

    Attributes:
        model: Instance of BaseModel implementing provider-specific interactions
        _prompts (Dict[PromptType, PromptTemplate]): Mapping of prompt types to templates
    """

    def __init__(self):
        self.model = None
        self._prompts = {PromptType.CATEGORIZER: CategorizerPrompt(), PromptType.ARTIFACT_ANALYZER: ArtifactAnalyzerPrompt(), PromptType.CLUSTER_ANALYZER: ClusterAnalyzerPrompt()}

    def set_model_config(self, config: ModelConfig) -> None:
        """
        Configure the LLM processor with specific model settings.

        Args:
            config (ModelConfig): Configuration containing provider, model name, and API key

        Raises:
            ValueError: If provider type is not supported
        """
        if config.provider == ModelType.GOOGLE:
            self.model = GoogleModel(config)
        elif config.provider == ModelType.OPENAI:
            self.model = OpenAIModel(config)
        else:
            raise ValueError(f"Unsupported model provider: {config.provider}")

    def validate_api_key(self) -> bool:
        if not self.model:
            raise ValueError("Model not configured")
        validation = self.model.validate_api_key()

        if not validation:
            log(f"{self.model.config.model_name} API key validation failed")

        return validation

    def estimate_tokens(self, text: str) -> int:
        """
        Estimate the number of tokens in a text using character-based heuristic.

        Uses a simple approximation of 4 characters per token. While not exact,
        this provides a conservative estimate for batching purposes.

        Args:
            text (str): Text to estimate tokens for

        Returns:
            int: Estimated number of tokens
        """
        """Estimate number of tokens in text using simple character-based heuristic"""
        return len(text) // 4  # Rough approximation - 4 chars per token

    def create_artifacts_dict(self, items: List[Dict[str, Any]]) -> Dict[str, Dict[int, str]]:
        """
        Convert list of artifacts into structured dictionary format for LLM processing.

        Organizes artifacts by type (Strings, APIs, CAPA, Libraries) for efficient processing.

        Args:
            items (List[Dict[str, Any]]): List of artifacts with 'type', 'index', and 'content' keys

        Returns:
            Dict[str, Dict[int, str]]: Nested dictionary organizing artifacts by type and index
        """
        artifacts_dict = {"Strings": {}, "APIs": {}, "CAPA": {}, "Libraries": {}}

        for item in items:
            if item["type"] == "string":
                artifacts_dict["Strings"][item["index"]] = item["content"]
            elif item["type"] == "api":
                artifacts_dict["APIs"][item["index"]] = item["content"]
            elif item["type"] == "capa":
                artifacts_dict["CAPA"][item["index"]] = item["content"]
            elif item["type"] == "lib":
                artifacts_dict["Libraries"][item["index"]] = item["content"]

        return artifacts_dict

    def calculate_optimal_batch_size(self, items: List[Any], prompt_type: PromptType, max_tokens: int, **kwargs) -> int:
        """Calculate optimal batch size based on token limits."""
        # Start with a small batch size
        test_size = min(10, len(items))

        while test_size > 0:
            # Create a test prompt with the current batch size
            test_items = items[:test_size]

            try:
                if prompt_type == PromptType.CATEGORIZER:
                    test_prompt = self._prompts[prompt_type].format(items=test_items, categories=kwargs.get("categories", []), type=kwargs.get("type", "api"))
                elif prompt_type == PromptType.ARTIFACT_ANALYZER:
                    test_artifacts = self.create_artifacts_dict(test_items)
                    test_prompt = self._prompts[prompt_type].format(artifacts=test_artifacts)
                # Handle types that must be processed as single batch
                elif prompt_type == PromptType.CLUSTER_ANALYZER:
                    return len(items)
                else:
                    raise ValueError(f"Unsupported prompt type: {prompt_type}")

                # Estimate tokens for the full prompt
                estimated_tokens = self.estimate_tokens(test_prompt)

                # Add safety margin (20%)
                estimated_tokens = int(estimated_tokens * 1.2)

                if estimated_tokens <= max_tokens:
                    if test_size == len(items):
                        return test_size

                    tokens_per_item = estimated_tokens / test_size
                    max_items = int((max_tokens * 0.9) / tokens_per_item)

                    return min(max_items, len(items))

                test_size = int(test_size * (max_tokens / estimated_tokens) * 0.9)

            except Exception as e:
                log(f"Error estimating tokens for batch size {test_size}: {e}")
                test_size = test_size // 2

        return 1

    def process_chunk(self, chunk: List[Any], prompt_type: PromptType, **kwargs) -> Any:
        """Process a single chunk of items through the LLM."""
        prompt_template = self._prompts[prompt_type]

        if prompt_type == PromptType.CATEGORIZER:
            prompt = prompt_template.format(items=chunk, categories=kwargs.get("categories", []), type=kwargs.get("type", "api"))
            response = self.model.query(prompt)
            return prompt_template.parse_response(response, categories=kwargs.get("categories", []))

        elif prompt_type == PromptType.ARTIFACT_ANALYZER:
            artifacts_dict = self.create_artifacts_dict(chunk)
            prompt = prompt_template.format(artifacts=artifacts_dict)
            response = self.model.query(prompt)
            return prompt_template.parse_response(response)

        elif prompt_type == PromptType.CLUSTER_ANALYZER:
            # For cluster analysis, chunk contains raw formatted cluster data
            prompt = prompt_template.format(cluster_data=chunk[0])  # Take first item since it's our formatted string
            response = self.model.query(prompt)
            return prompt_template.parse_response(response)

        else:
            raise ValueError(f"Unsupported prompt type: {prompt_type}")

    def check_for_missed_items(self, original_items: List[Any], results: Dict[str, Any], prompt_type: PromptType, **kwargs) -> Dict[str, Any]:
        """
        Check for and reprocess any items that were missed in initial processing.

        Args:
            original_items: Complete list of items that should have been processed
            results: Current results dictionary with index-based assignments
            prompt_type: Type of prompt used
            **kwargs: Additional prompt formatting arguments

        Returns:
            Dict[str, Any]: Updated results dictionary including retry attempts
        """
        if prompt_type == PromptType.CATEGORIZER:
            # For categorization, check if all indices have been assigned categories
            original_indices = set(str(i) for i in range(len(original_items)))
            processed_indices = set(results.keys())
            missed_indices = original_indices - processed_indices

            # Create list of missed items with their original indices
            missed_items = [{"index": int(idx), "name": original_items[int(idx)]} for idx in missed_indices]
        elif prompt_type == PromptType.ARTIFACT_ANALYZER:
            # For artifact filtering, check if all item indices are in results
            original_indices = {item["index"] for item in original_items}
            processed_indices = set(results.get("interesting_indexes", []))
            missed_items = [item for item in original_items if item["index"] in (original_indices - processed_indices)]

        # Skip check for cluster operations which must be complete
        elif prompt_type == PromptType.CLUSTER_ANALYZER:
            return results
        else:
            raise ValueError(f"Unsupported prompt type: {prompt_type}")

        if missed_items:
            log(f"Found {len(missed_items)} missed items. Processing them now.")
            try:
                # Process missed items with emphasis on completeness
                missed_results = self.process_chunk(missed_items, prompt_type, **kwargs)

                if prompt_type == PromptType.CATEGORIZER:
                    # Update category_assignments with missed results
                    if "category_assignments" not in results:
                        results["category_assignments"] = {}
                    results["category_assignments"].update(missed_results.get("category_assignments", {}))

                    # Double-check if any indices are still missing
                    final_missed_indices = set(str(i) for i in range(len(original_items))) - set(results["category_assignments"].keys())

                    if final_missed_indices:
                        # For categorization, assign missed items to "Others" category
                        categories = kwargs.get("categories", [])
                        others_index = categories.index("Others")
                        for idx in final_missed_indices:
                            results["category_assignments"][idx] = others_index
                            log(f"Assigning missed item index {idx} to Others category")
                else:
                    # For artifact filtering
                    if "interesting_indexes" in missed_results:
                        if "interesting_indexes" not in results:
                            results["interesting_indexes"] = []
                        results["interesting_indexes"].extend(missed_results["interesting_indexes"])

            except Exception as e:
                log(f"Error processing missed items: {str(e)}")
                if prompt_type == PromptType.CATEGORIZER:
                    # Assign any errored items to Others category
                    categories = kwargs.get("categories", [])
                    others_index = categories.index("Others")
                    for idx in missed_indices:
                        if idx not in results.get("category_assignments", {}):
                            if "category_assignments" not in results:
                                results["category_assignments"] = {}
                            results["category_assignments"][idx] = others_index
                            log(f"Assigning errored item index {idx} to Others category")

        return results

    def process_items(self, items: List[Any], prompt_type: PromptType, ignore_token_limit: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Process a list of items in parallel or sequential chunks based on the model type.

        This function is modified to handle indexing correctly for categorizer requests
        when items are processed in multiple chunks. Each chunk is zero-indexed by the LLM,
        so we must add the chunk's start index to these returned indexes before merging them
        into the final result.

        Args:
            items: List of items to process
            prompt_type: Type of prompt to use (CATEGORIZER, ARTIFACT_ANALYZER, etc.)
            ignore_token_limit: If True, processes all items in a single batch
            **kwargs: Additional prompt formatting arguments

        Returns:
            Dictionary containing processed results

        Raises:
            ValueError: If model not configured
        """
        if not self.model:
            raise ValueError("Model not configured")

        if not items:
            return {}

        # Check connectivity before processing
        if not self.model.check_connection():
            return {}

        # Special handling for cluster operations
        if prompt_type == PromptType.CLUSTER_ANALYZER:
            try:
                # Cluster analysis always processes all data at once
                return self.process_chunk([items], prompt_type, **kwargs)
            except Exception as e:
                log(f"Error in cluster {prompt_type.name.lower()}: {str(e)}")
                return {}

        if ignore_token_limit:
            log(f"Processing all {len(items)} items in single batch")
            try:
                result = self.process_chunk(items, prompt_type, **kwargs)
                return result
            except Exception as e:
                log(f"Error processing batch with token limit override: {e}")
                return {}

        max_tokens = self.model.get_max_input_tokens()
        batch_size = self.calculate_optimal_batch_size(items, prompt_type, max_tokens, **kwargs)

        log(f"Processing {len(items)} items in batches of {batch_size}")

        results = {}
        if isinstance(self.model, OpenAIModel):
            # Parallel processing for OpenAI
            from concurrent.futures import ThreadPoolExecutor, as_completed

            with ThreadPoolExecutor(max_workers=40) as executor:
                futures_map = {}
                # Submit chunks and store their start index
                for i in range(0, len(items), batch_size):
                    chunk = items[i : i + batch_size]
                    future = executor.submit(self.process_chunk, chunk, prompt_type, **kwargs)
                    futures_map[future] = i

                for future in as_completed(futures_map):
                    try:
                        chunk_result = future.result()
                        chunk_start = futures_map[future]

                        # If categorizer prompt, re-map the returned indices
                        if prompt_type == PromptType.CATEGORIZER:
                            adjusted_result = {}
                            for k, v in chunk_result.items():
                                original_idx = int(k) + chunk_start
                                adjusted_result[str(original_idx)] = v
                            results.update(adjusted_result)
                        else:
                            results.update(chunk_result)
                    except Exception as e:
                        log(f"Error processing chunk: {e}")

        else:
            # Google model - sequential processing
            total_chunks = (len(items) + batch_size - 1) // batch_size
            for i in range(0, len(items), batch_size):
                chunk = items[i : i + batch_size]
                chunk_num = i // batch_size + 1
                log(f"Processing chunk {chunk_num}/{total_chunks}")

                try:
                    chunk_result = self.process_chunk(chunk, prompt_type, **kwargs)
                    # If categorizer prompt, offset the indexes
                    if prompt_type == PromptType.CATEGORIZER:
                        adjusted_result = {}
                        for k, v in chunk_result.items():
                            original_idx = int(k) + i
                            adjusted_result[str(original_idx)] = v
                        results.update(adjusted_result)
                    else:
                        results.update(chunk_result)
                except Exception as e:
                    log(f"Error processing chunk {chunk_num}: {e}")

        # Check for missed items and re-process if needed
        results = self.check_for_missed_items(items, results, prompt_type, **kwargs)

        return results
