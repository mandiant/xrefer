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

from dataclasses import dataclass
from enum import Enum

class PromptType(Enum):
    CATEGORIZER = "categorizer"
    ARTIFACT_ANALYZER = "artifact_analyzer"
    CLUSTER_ANALYZER = "cluster_analyzer"

@dataclass
class ModelConfig:
    """
    Configuration for LLM model.

    Attributes:
        model_id (str): Fully qualified model identifier (e.g. "openai/gpt-4o-mini")
        api_key (str): API key for authentication
        ignore_token_limit (bool): Whether to ignore token limits
    """
    model_id: str
    api_key: str
    ignore_token_limit: bool = False
