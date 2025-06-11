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

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from xrefer.core.helpers import check_internet_connectivity
from xrefer.gui.helpers import log


class PromptType(Enum):
    """
    Enumeration of supported prompt types.

    Defines the different types of prompts that can be processed
    by the LLM system.
    """

    CATEGORIZATION = auto()
    ARTIFACT_FILTER = auto()
    CLUSTER_ANALYZER = auto()


class ModelType(Enum):
    """
    Enumeration of supported LLM providers.

    Defines the different LLM services that can be used
    for analysis.
    """

    OPENAI = "openai"
    GOOGLE = "google"


@dataclass
class ModelConfig:
    """
    Configuration for LLM model.

    Attributes:
        provider (ModelType): LLM provider to use
        model_name (str): Name of specific model to use
        api_key (str): API key for authentication
        organization (Optional[str]): Organization ID for OpenAI
        ignore_token_limit (bool): Whether to ignore token limits
    """

    provider: ModelType
    model_name: str
    api_key: str
    organization: Optional[str] = None
    ignore_token_limit: bool = False


class BaseModel(ABC):
    """
    Abstract base class for LLM model implementations.

    Defines interface that must be implemented by specific
    LLM provider implementations.

    Attributes:
        config (ModelConfig): Configuration for this model instance
    """

    def __init__(self, config: ModelConfig):
        self.config = config

    def check_connection(self) -> bool:
        """Check both internet connectivity and API access."""
        if not check_internet_connectivity():
            log("No internet connectivity detected")
            return False

        try:
            return self.validate_api_key()
        except Exception as e:
            log(f"API validation failed: {str(e)}")
            return False

    @abstractmethod
    def validate_api_key(self) -> bool:
        """
        Validate the API key works.

        Returns:
            bool: True if API key is valid and working
        """
        pass

    @abstractmethod
    def get_max_input_tokens(self, ignore_limit: bool = False) -> int:
        """
        Get maximum input tokens for this model.

        Args:
            ignore_limit: If True, returns a very large number instead of actual limit

        Returns:
            int: Maximum number of input tokens allowed
        """
        pass

    @abstractmethod
    def get_max_output_tokens(self) -> int:
        """
        Get maximum output tokens for this model.

        Returns:
            int: Maximum number of output tokens allowed
        """
        pass

    @abstractmethod
    def apply_rate_limit(self) -> None:
        """
        Apply any rate limiting needed for this model.

        Implementations should handle provider-specific rate limiting.
        """
        pass

    @abstractmethod
    def query(self, prompt: str) -> str:
        """
        Send query to model and get response.

        Args:
            prompt (str): Prompt to send to model

        Returns:
            str: Model's response text
        """
        pass
