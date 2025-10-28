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
DSPy-native LLM processor with Pydantic validation.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import dspy

from xrefer.core.helpers import check_internet_connectivity, log
from xrefer.llm.base import ModelConfig, PromptType
from xrefer.llm.dspy_modules import ArtifactAnalysisResponse, ArtifactAnalyzerModule, CategorizationResponse, CategorizerModule, ClusterAnalysisResponse, ClusterAnalyzerModule


@dataclass
class ProcessConfig:
    """Type-safe configuration for processing."""
    categories: List[str] = field(default_factory=list)
    item_type: str = "api"


class LLMProcessor:
    """
    DSPy-native processor for LLM operations.
    """

    def __init__(self):
        self.lm: Optional[dspy.LM] = None
        self.config: Optional[ModelConfig] = None

    def set_model_config(self, config: ModelConfig) -> None:
        """
        Configure DSPy with the specified LLM.

        Args:
            config: Model configuration
        """
        self.config = config
        lm_kwargs = {
            "model": config.model_id,
            "api_key": config.api_key,
            "cache_seed": 0x72616e64306d,
        }
        # match <https://github.com/stanfordnlp/dspy/blob/1df5984007b7fd9bb56f3a8fba7a68b5517efb69/dspy/clients/lm.py#L92>'s logic
        if re.search(r'openai\/(?:o[1345]|gpt-5)(?:-(?:mini|nano|codex))?', config.model_id):
            lm_kwargs.update({"temperature": 1.0, "max_tokens": 16000})
        # For Gemini models, use full 65k output token capacity and force JSON mode
        # Gemini's structured output doesn't support dynamic object properties
        if 'gemini' in config.model_id.lower():
            lm_kwargs.update({"max_tokens": 65536})

        self.lm = dspy.LM(**lm_kwargs)
        dspy.settings.configure(lm=self.lm)
        try:
            assert False
            import mlflow
            mlflow.set_tracking_uri('http://127.0.0.1:5000')
            mlflow.set_experiment("XRefer")
            mlflow.dspy.autolog()
        except:
            pass

        # Initialize DSPy modules
        self._dspy_modules = {
            PromptType.CATEGORIZER: CategorizerModule(),
            PromptType.ARTIFACT_ANALYZER: ArtifactAnalyzerModule(),
            PromptType.CLUSTER_ANALYZER: ClusterAnalyzerModule()
        }

    def validate_api_key(self) -> bool:
        """Validate API key with a test call."""
        if not self.lm:
            raise ValueError("Model not configured")
        try:
            self.lm("Say 'valid'")
            return True
        except Exception as e:
            log(f"API validation failed: {e}")
            return False

    def _create_artifacts_dict(self, items: List[Dict[str, Any]]) -> Dict[str, Dict[int, str]]:
        """Convert artifacts list to structured dict."""
        artifacts = {"Strings": {}, "APIs": {}, "CAPA": {}, "Libraries": {}}
        type_map = {"string": "Strings", "api": "APIs", "capa": "CAPA", "lib": "Libraries"}

        for item in items:
            category = type_map.get(item["type"])
            if category:
                artifacts[category][item["index"]] = item["content"]

        return artifacts

    def _process_single(self, items: List[Any], prompt_type: PromptType, config: Optional[ProcessConfig]=None) -> Dict[str, Any]:
        """
        Process items using DSPy module.
        """
        if prompt_type == PromptType.CATEGORIZER:
            response: "CategorizationResponse" = CategorizerModule()(items=items, categories=config.categories, item_type=config.item_type)
            return response.model_dump()
        elif prompt_type == PromptType.ARTIFACT_ANALYZER:
            artifacts = self._create_artifacts_dict(items)
            response: "ArtifactAnalysisResponse" = ArtifactAnalyzerModule()(artifacts=artifacts)
            return set(response.interesting_indexes)
        elif prompt_type == PromptType.CLUSTER_ANALYZER:
            response: "ClusterAnalysisResponse" = ClusterAnalyzerModule()(cluster_data=items[0])
            return response.model_dump()
        else:
            raise ValueError(f"Unsupported prompt type: {prompt_type}")


    def _process_parallel(self, items: List[Any], prompt_type: PromptType, batch_size: int, config: Optional[ProcessConfig]=None) -> Dict[int, Any]:
        """Process items in parallel batches."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        import os
        max_workers = min(os.cpu_count() * 4, 20, len(items) // batch_size + 1)

        results = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}

            for i in range(0, len(items), batch_size):
                chunk = items[i:i + batch_size]
                future = executor.submit(self._process_single, chunk, prompt_type, config)
                futures[future] = i

            for future in as_completed(futures):
                chunk_result = future.result()
                chunk_start = futures[future]

                # Adjust indices for categorizer (use int consistently)
                if prompt_type == PromptType.CATEGORIZER:
                    for idx, cat_idx in chunk_result.items():
                        original_idx = int(idx) + chunk_start
                        results[original_idx] = cat_idx
                else:
                    results.update(chunk_result)

        return results

    def _process_sequential(self, items: List[Any], prompt_type: PromptType, batch_size: int, config: ProcessConfig) -> Dict[int, Any]:
        """Process items sequentially in batches."""
        results = {}
        total_chunks = (len(items) + batch_size - 1) // batch_size

        for i in range(0, len(items), batch_size):
            chunk = items[i:i + batch_size]
            chunk_num = i // batch_size + 1
            log(f"[+]Processing chunk {chunk_num}/{total_chunks}")

            chunk_result = self._process_single(chunk, prompt_type, config)

            # Adjust indices for categorizer
            if prompt_type == PromptType.CATEGORIZER:
                for idx, cat_idx in chunk_result.items():
                    original_idx = int(idx) + i
                    results[original_idx] = cat_idx
            else:
                results.update(chunk_result)

        return results

    def process_items(
        self,
        items: List[Any],
        prompt_type: PromptType,
        ignore_token_limit: bool = False,
        categories: Optional[List[str]] = None,
        type: str = "api"
    ) -> Dict[str, Any]:
        """
        Process items with automatic batching.

        DSPy/LiteLLM automatically handles:

        Args:
            items: Items to process
            prompt_type: Type of processing
            ignore_token_limit: If True, process all items at once
            categories: List of categories (for categorizer)
            type: Item type "api" or "lib" (for categorizer)

        Returns:
            Processed results
        """
        if not self.lm:
            raise ValueError("Model not configured")
        if not items:
            raise ValueError("No items to process")
        if not check_internet_connectivity():
            raise ConnectionError("No internet connectivity")

        if prompt_type == PromptType.CLUSTER_ANALYZER:
            return self._process_single([items], prompt_type)
        config = None
        if prompt_type == PromptType.CATEGORIZER:
            config = ProcessConfig(categories=categories or [], item_type=type)
            return self._process_single([items], prompt_type, config)

        if ignore_token_limit:
            log(f"[+] Processing all {len(items)} items in single batch")
            results = self._process_single(items, prompt_type, config)
            # Convert to str keys for backward compatibility
            if prompt_type == PromptType.CATEGORIZER:
                return {str(k): v for k, v in results.items()}
            return results

        # Batched processing
        # Simple heuristic: 50 items per batch (conservative, no token counting needed)
        batch_size = 50
        log(f"[+] Processing {len(items)} items in batches of {batch_size}")
        # NOTE: In a perfect world, dspy would support **native** batch processing (/v1/batches)
        # https://docs.litellm.ai/docs/batches
        # unfortunately, we live in a imperfect world...

        use_parallel = True

        if use_parallel:
            results = self._process_parallel(items, prompt_type, batch_size, config)
        else:
            results = self._process_sequential(items, prompt_type, batch_size, config)

        # Fill in missed items for categorizer
        if prompt_type == PromptType.CATEGORIZER:
            all_indices = set(range(len(items)))
            processed_indices = set(results.keys())
            missed_indices = all_indices - processed_indices

            if missed_indices:
                log(f"[*] Found {len(missed_indices)} missed items, assigning to Others")
                others_idx = config.categories.index("Others") if "Others" in config.categories else 0
                for idx in missed_indices:
                    results[idx] = others_idx

            # Convert to str keys for backward compatibility
            return {str(k): v for k, v in results.items()}

        return results
