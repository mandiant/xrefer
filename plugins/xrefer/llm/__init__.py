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

# NOTE: `processor` is deliberately NOT imported eagerly — its module pulls
# dspy/litellm, a measured ~4s import chain that would otherwise run at IDA
# plugin load (core/analyzer imports this package at plugin scan time). It
# loads on first LLM use via the lazy accessors in cluster_analyzer /
# categorizer; `import xrefer.llm.processor` still works directly.
from . import base
from .cluster_analyzer import ClusterAnalyzer
from .categorizer import Categorizer, CATEGORIES

__all__ = [
    "base",
    "ClusterAnalyzer",
    "Categorizer",
    "CATEGORIES",
]
