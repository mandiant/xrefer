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
Pydantic models for structured LLM outputs.

Defines type-safe schemas for categorization, artifact analysis,
and cluster analysis responses from the LLM.
"""

from typing import Dict, List
from pydantic import BaseModel, Field

class CategorizationResponse(BaseModel):
    """Response model for API/Library categorization."""

    category_assignments: Dict[str, int] = Field(
        ...,
        description="Mapping of item index (as string) to category index (0-based)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "category_assignments": {
                    "0": 0,
                    "1": 2,
                    "2": 5
                }
            }
        }


class ArtifactAnalysisResponse(BaseModel):
    """Response model for artifact analysis."""

    interesting_indexes: List[int] = Field(
        ...,
        description="List of artifact indices identified as interesting from a security perspective"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "interesting_indexes": [0, 3, 7, 12]
            }
        }


class ClusterAnalysis(BaseModel):
    """Analysis for a single function cluster."""

    label: str = Field(
        ...,
        description="Short, descriptive label for the cluster"
    )
    description: str = Field(
        ...,
        description="Detailed description of cluster functionality"
    )
    relationships: str = Field(
        ...,
        description="How this cluster relates to other clusters"
    )
    function_prefix: str = Field(
        ...,
        description="Suggested prefix for renaming functions in this cluster"
    )
    library_or_runtime: int = Field(
        default=0,
        description="1 if cluster is likely library/runtime code, 0 if application code"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "label": "Network Communication",
                "description": "Handles HTTP requests and socket operations",
                "relationships": "Called by authentication cluster, uses crypto cluster",
                "function_prefix": "net_",
                "library_or_runtime": 0
            }
        }


class ClusterAnalysisResponse(BaseModel):
    """Response model for cluster analysis."""

    clusters: Dict[str, ClusterAnalysis] = Field(
        ...,
        description="Mapping of cluster_id to ClusterAnalysis"
    )
    binary_description: str = Field(
        ...,
        description="Overall description of the binary's functionality"
    )
    binary_category: str = Field(
        ...,
        description="Classification of the binary (e.g., malware, utility, service)"
    )
    binary_report: str = Field(
        default="",
        description="Detailed analysis report for the binary"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "clusters": {
                    "cluster_1": {
                        "label": "Initialization",
                        "description": "Sets up application state",
                        "relationships": "Called first, initializes all other clusters",
                        "function_prefix": "init_",
                        "library_or_runtime": 0
                    }
                },
                "binary_description": "Network monitoring tool with logging capabilities",
                "binary_category": "Utility",
                "binary_report": "Detailed analysis shows..."
            }
        }
