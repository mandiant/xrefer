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

from time import sleep, time

import dspy

from xrefer.llm.base import BaseModel, ModelConfig

# TODO: Ugly
class GoogleModel(BaseModel):
    """
    Google's LLM (Gemini) implementation for XRefer using DSPy.

    Handles interactions with Google's LLM APIs including rate limiting,
    token management, and response processing.

    Attributes:
        last_request_time (float): Timestamp of last API request
        requests_this_minute (int): Counter for rate limiting
        lm (dspy.LM): DSPy language model instance
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.last_request_time = 0
        self.requests_this_minute = 0
        self.lm = None
        # HACK: We should be using appropriate API/configs for determining the correct token limits.
        # ref: https://ai.google.dev/gemini-api/docs/models#gemini-2.5-pro_1

    def get_max_input_tokens(self, ignore_limit: bool = False) -> int:
        """
        Get maximum allowed input tokens for Google's model.

        Args:
            ignore_limit (bool): If True, returns very large number instead of actual limit

        Returns:
            int: Maximum token limit (32768) or 1048576 if ignoring limits
        """
        if ignore_limit or self.config.ignore_token_limit:
            return 1_048_576  # gemini context windows are very large, however output tokens are very limited
        return 32768  # limiting input tokens to a small number to allow chunking, since large input sometimes means
        # large output requirements, unless the smaller limit is explicitly ignored

    def get_max_output_tokens(self) -> int:
        """
        Get maximum allowed output tokens for Google's model.

        Returns:
            int: Maximum output token limit (65536)
        """
        return 65_536

    def validate_api_key(self) -> bool:
        """
        Validate Google API key by making test request.

        Returns:
            bool: True if API key is valid, False otherwise
        """
        try:
            lm = self.get_client()
            response = lm("Say 'API key is valid'")
            return True
        except Exception:
            return False

    def apply_rate_limit(self) -> None:
        """
        Apply rate limiting for Google API requests.

        Ensures requests don't exceed 10 per minute by tracking
        request times and sleeping if necessary.
        """
        current_time = time()
        if current_time - self.last_request_time >= 60:
            self.requests_this_minute = 0
            self.last_request_time = current_time
        elif self.requests_this_minute >= 10:
            sleep_time = 60 - (current_time - self.last_request_time)
            sleep(sleep_time)
            self.requests_this_minute = 0
            self.last_request_time = time()
        self.requests_this_minute += 1

    def get_client(self) -> dspy.LM:
        """
        Get configured Google LLM client.

        Returns:
            dspy.LM: Configured DSPy language model ready for requests
        """
        if self.lm is None:
            # Use google/ prefix for Google models in DSPy
            model_name = self.config.model_name
            if not model_name.startswith("google/") and not model_name.startswith("gemini/"):
                model_name = f"gemini/{model_name}"

            self.lm = dspy.LM(
                model_name,
                api_key=self.config.api_key,
                max_tokens=self.get_max_output_tokens(),
            )
        return self.lm

    def query(self, prompt: str) -> str:
        """
        Send query to Google's LLM.

        Applies rate limiting and makes API request.

        Args:
            prompt (str): Prompt to send to model

        Returns:
            str: Model's response content
        """
        self.apply_rate_limit()
        lm = self.get_client()
        response = lm(prompt)
        # DSPy returns a list of responses, take the first one
        if isinstance(response, list):
            return response[0]
        return str(response)


class OpenAIModel(BaseModel):
    """
    OpenAI's GPT implementation for XRefer using DSPy.

    Handles interactions with OpenAI's API including token management
    and organization-aware configuration.

    Attributes:
        lm (dspy.LM): DSPy language model instance
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.lm = None

    def get_max_input_tokens(self, ignore_limit: bool = False) -> int:
        """
        Get maximum allowed input tokens for OpenAI model.

        Args:
            ignore_limit (bool): If True, returns very large number instead of actual limit

        Returns:
            int: Maximum token limit (8192) or 124000 if ignoring limits
        """
        if ignore_limit or self.config.ignore_token_limit:
            return 124000  # gpt seems to be less restrictive on parallel queries
        return 8192  # output tokens are limited again, same rationale as above for smaller limit
        # that + smaller limit equals parallel queries which equals quicker processing

    def get_max_output_tokens(self) -> int:
        """
        Get maximum allowed output tokens for OpenAI model.

        Returns:
            int: Maximum output token limit (16384)
        """
        return 16384

    def validate_api_key(self) -> bool:
        """
        Validate OpenAI API key by making test request.

        Returns:
            bool: True if API key is valid, False otherwise
        """
        try:
            lm = self.get_client()
            response = lm("Say 'API key is valid'")
            return True
        except Exception as err:
            return False

    def apply_rate_limit(self) -> None:
        """
        Apply rate limiting for OpenAI API requests.

        Currently a no-op as OpenAI handles rate limiting server-side.
        """
        pass

    def get_client(self) -> dspy.LM:
        """
        Get configured OpenAI client.

        Creates client with appropriate model, API key and organization settings.

        Returns:
            dspy.LM: Configured DSPy language model ready for requests
        """
        if self.lm is None:
            # Use openai/ prefix for OpenAI models in DSPy
            model_name = self.config.model_name
            if not model_name.startswith("openai/"):
                model_name = f"openai/{model_name}"

            kwargs = {
                "api_key": self.config.api_key,
                "max_tokens": self.get_max_output_tokens(),
            }

            # DSPy doesn't support organization parameter directly in LM constructor
            # It should be set via environment variable OPENAI_ORGANIZATION if needed
            if self.config.organization:
                import os
                os.environ["OPENAI_ORGANIZATION"] = self.config.organization

            self.lm = dspy.LM(model_name, **kwargs)
        return self.lm

    def query(self, prompt: str) -> str:
        """
        Send query to OpenAI's LLM.

        Makes API request and returns response content.

        Args:
            prompt (str): Prompt to send to model

        Returns:
            str: Model's response content
        """
        lm = self.get_client()
        response = lm(prompt)
        # DSPy returns a list of responses, take the first one
        if isinstance(response, list):
            return response[0]
        return str(response)
