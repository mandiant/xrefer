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

"""Regression tests for the light/full mode gating in run_secondary_analysis.

Light mode is the headless CLI default; its sole job is to produce the SAME
HTML/JSON report as full mode, only faster, by skipping work the report does
not depend on. These tests lock in the two load-bearing gating decisions that
make that true:

  * ``fix_thunk_xrefs`` MUST run in BOTH modes. It forwards a thunk's resolved
    import onto the *calling* function's DIRECT xrefs (and the entity's xref
    set), which both the cluster analysis and the generated report read
    directly. Gating it on full mode silently changed the report (the bug these
    tests guard against).
  * ``propagate_xref_nodes``, ``populate_xref_addrs`` and
    ``_populate_function_context_tables`` only build the INDIRECT/COMBINED xref
    sets and the per-function context-table cache, which feed the interactive
    views but are never read by the report or the clustering. They stay skipped
    in light mode for speed.

No IDA / LLM / disassembler: a stub XRefer (``object.__new__``) with recorder
methods drives ``run_secondary_analysis``'s control flow directly.
"""

from xrefer.core.analyzer import XRefer


def _make_recording_xrefer(mode):
    """A bare XRefer whose secondary-analysis sub-steps just record that they
    ran, so we can assert exactly which steps fire in each mode."""
    o = object.__new__(XRefer)
    o.mode = mode
    o.current_analysis_ep = 0x1000
    # One non-empty path so the ep_paths assertions in run_secondary_analysis
    # pass without a real disassembler.
    o.paths = {0x1000: {0x2000: [[0x1000, 0x2000]]}}

    calls = []

    def _propagate(iters):
        # while self.propagate_xref_nodes(iters): ... — return False so it is
        # evaluated exactly once and the loop body is skipped.
        calls.append("propagate_xref_nodes")
        return False

    o.generate_all_simple_call_paths_for_ep = lambda: calls.append("generate_paths")
    o.propagate_xref_nodes = _propagate
    o.fix_thunk_xrefs = lambda: calls.append("fix_thunk_xrefs")
    o.populate_xref_addrs = lambda: calls.append("populate_xref_addrs")
    o.cluster_all_non_excluded = lambda: calls.append("cluster_all_non_excluded")
    o._populate_function_context_tables = lambda: calls.append("context_tables")
    return o, calls


def test_light_mode_runs_report_relevant_steps():
    o, calls = _make_recording_xrefer("light")
    o.run_secondary_analysis()
    # Path generation, the thunk-import forwarding, and clustering all feed the
    # report, so they must run in light mode.
    assert "generate_paths" in calls
    assert "fix_thunk_xrefs" in calls
    assert "cluster_all_non_excluded" in calls


def test_light_mode_skips_interactive_only_steps():
    o, calls = _make_recording_xrefer("light")
    o.run_secondary_analysis()
    # Indirect-xref propagation, the indirect/combined address population, and
    # the context-table cache are interactive-only — skipped in light mode.
    assert "propagate_xref_nodes" not in calls
    assert "populate_xref_addrs" not in calls
    assert "context_tables" not in calls


def test_full_mode_runs_every_step():
    o, calls = _make_recording_xrefer("full")
    o.run_secondary_analysis()
    for step in (
        "generate_paths",
        "propagate_xref_nodes",
        "fix_thunk_xrefs",
        "populate_xref_addrs",
        "cluster_all_non_excluded",
        "context_tables",
    ):
        assert step in calls, f"full mode must run {step}"


def test_full_mode_preserves_step_order():
    o, calls = _make_recording_xrefer("full")
    o.run_secondary_analysis()
    # Propagation precedes the thunk fix, which precedes the indirect/combined
    # address population (the ordering the GUI's full path has always used).
    assert calls.index("propagate_xref_nodes") < calls.index("fix_thunk_xrefs")
    assert calls.index("fix_thunk_xrefs") < calls.index("populate_xref_addrs")
    assert calls.index("populate_xref_addrs") < calls.index("cluster_all_non_excluded")


def test_thunk_fix_fires_in_light_exactly_as_in_full():
    # The core losslessness guarantee, stated directly: fix_thunk_xrefs (which
    # writes DIRECT xrefs the report reads) fires in light just as in full.
    light_o, light_calls = _make_recording_xrefer("light")
    light_o.run_secondary_analysis()
    full_o, full_calls = _make_recording_xrefer("full")
    full_o.run_secondary_analysis()
    assert light_calls.count("fix_thunk_xrefs") == 1
    assert full_calls.count("fix_thunk_xrefs") == 1
