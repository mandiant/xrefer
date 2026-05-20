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

from contextlib import contextmanager
from typing import Dict, Iterator, List, Set

from xrefer.llm.base import ModelConfig, PromptType
from xrefer.llm.processor import LLMProcessor


@contextmanager
def _null_context() -> Iterator[None]:
    """No-op context manager so call-sites can write ``with cache_ctx:``
    unconditionally without branching on whether force-no-cache is on.
    """
    yield


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
    def find_interesting_artifacts(
        cls,
        artifacts: List[Dict],
        force_no_cache: bool = False,
    ) -> Set[int]:
        """
        Find potentially interesting artifacts from a security perspective.

        Args:
            artifacts: List of artifacts, each with 'type', 'index', and 'content' keys
            force_no_cache: when True, bypass DSPy/LiteLLM response cache
                for this call. The re-run handlers in the GUI always pass
                True because the point of re-running is to get a fresh
                LLM verdict, not replay a cached one.

        Returns:
            Set of indexes for interesting artifacts
        """
        processor = cls._get_processor()
        cache_ctx = processor.uncached_lm() if force_no_cache else _null_context()
        with cache_ctx:
            return processor.process_items(
                items=artifacts,
                prompt_type=PromptType.ARTIFACT_ANALYZER,
                ignore_token_limit=True,  # Process all artifacts in one batch
            )
