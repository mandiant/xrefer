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

from typing import Dict, List, Set

from xrefer.llm.base import ModelConfig
from xrefer.llm.processor import LLMProcessor
from xrefer.llm.prompts import PromptType


class ArtifactAnalyzer:
    """Main interface for analyzing interesting artifacts"""

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
        cls.current_config = config
        cls._processor = None  # Force new processor with new config

    @classmethod
    def find_interesting_artifacts(cls, artifacts: List[Dict]) -> Set[int]:
        """
        Find potentially interesting artifacts from a security perspective.

        Args:
            artifacts: List of artifacts, each with 'type', 'index', and 'content' keys

        Returns:
            Set of indexes for interesting artifacts
        """
        processor = cls._get_processor()
        # Use token limit override for artifact analysis
        return processor.process_items(
            items=artifacts,
            prompt_type=PromptType.ARTIFACT_ANALYZER,
            ignore_token_limit=True,  # Process all artifacts in one batch
        )
