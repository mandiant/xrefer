# Copyright 2026 Google LLC
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

"""Unit tests for Ghidra backend analyzer optimization configuration."""

from unittest.mock import MagicMock, patch
import sys


def test_configure_fast_analysis_options_and_sync():
    """Verifies configure_fast_analysis disables heavy analyzers and syncs options."""
    mock_options = MagicMock()
    mock_program = MagicMock()
    mock_program.getOptions.return_value = mock_options

    mock_mgr = MagicMock()

    mock_ghidra = MagicMock()
    mock_ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES = "Analysis Properties"
    mock_ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager.return_value = mock_mgr

    with patch.dict(sys.modules, {
        "ghidra": mock_ghidra,
        "ghidra.program.model.listing": mock_ghidra.program.model.listing,
        "ghidra.app.plugin.core.analysis": mock_ghidra.app.plugin.core.analysis,
    }):
        from xrefer.backend.ghidra.backend import configure_fast_analysis

        configure_fast_analysis(mock_program)

    mock_program.getOptions.assert_called_once_with("Analysis Properties")

    # Assert heavy/quadratic analyzers are disabled
    disabled_calls = [
        ("Decompiler Parameter ID", False),
        ("Decompiler Switch Analysis", False),
        ("Stack", False),
        ("Windows x86 PE RTTI Analyzer", False),
    ]
    for analyzer, enabled in disabled_calls:
        mock_options.setBoolean.assert_any_call(analyzer, enabled)

    # Assert essential reference analyzers remain enabled
    enabled_calls = [
        ("Subroutine References", True),
        ("ASCII Strings", True),
        ("Scalar Operand References", True),
    ]
    for analyzer, enabled in enabled_calls:
        mock_options.setBoolean.assert_any_call(analyzer, enabled)

    # Assert AutoAnalysisManager.initializeOptions() was called to sync headless options
    mock_mgr.initializeOptions.assert_called_once()
