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

"""ESC navigation through the cluster table — the triage-loop history.

The core triage loop (table → click cluster → ESC → next cluster) used to
strand the analyst in the relationship overview: the table's history entry
is recorded with a toggle_ event, which go_back's filter skipped, so the
revert-to-clusters transitions existed but were unreachable. These tests
pin return_to_clusters_table's table-vs-overview discrimination, the
history truncation that keeps a further ESC walking toward base, and the
go_back filter exemption that lets K/N exits land back on the table.
"""

import importlib.util
import pathlib
import sys
import types

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_SM = _REPO / "plugins" / "xrefer" / "gui" / "state_machine.py"


def _load():
    for name in ("xrefer", "xrefer.gui"):
        if name not in sys.modules:
            pkg = types.ModuleType(name)
            pkg.__path__ = []
            sys.modules[name] = pkg
    spec = importlib.util.spec_from_file_location("xrefer.gui.state_machine", _SM)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["xrefer.gui.state_machine"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def sm():
    return _load().XReferStateMachine()


def _enter_graph_from_table(sm):
    sm.start_cluster_graphs()   # C from base -> cluster graphs
    sm.toggle_on_clusters()     # C again -> clusters TABLE
    sm.start_cluster_graphs()   # click a cluster chip -> its graph


def test_table_entered_graph_returns_to_table(sm):
    _enter_graph_from_table(sm)
    assert sm.current_state == sm.cluster_graphs
    assert sm.return_to_clusters_table() is True
    assert sm.current_state == sm.clusters


def test_subsequent_escs_walk_back_to_base(sm):
    _enter_graph_from_table(sm)
    assert sm.return_to_clusters_table() is True   # ESC #1: graph -> table
    success, _pos = sm.go_back()                   # ESC #2: table -> overview (how it was entered)
    assert success
    assert sm.current_state == sm.cluster_graphs
    success, _pos = sm.go_back()                   # ESC #3: overview -> base
    assert success
    assert sm.current_state == sm.base


def test_overview_entered_graph_keeps_overview_behavior(sm):
    sm.start_cluster_graphs()  # straight from base — no table visit
    assert sm.return_to_clusters_table() is False
    assert sm.current_state == sm.cluster_graphs  # untouched


def test_wrong_state_is_a_noop(sm):
    assert sm.return_to_clusters_table() is False
    assert sm.current_state == sm.base


def test_go_back_lands_on_table_after_matrix_exit(sm):
    # K from the clusters table: the table entry's toggle_ event must no
    # longer hide it from go_back (revert_attack_matrix_to_clusters exists).
    sm.start_cluster_graphs()
    sm.toggle_on_clusters()
    sm.start_attack_matrix()
    success, _pos = sm.go_back()
    assert success
    assert sm.current_state == sm.clusters


def test_go_back_still_skips_real_mode_flips(sm):
    # A state entered via a pin flip must remain invisible to go_back:
    # graph -> pinned (flip) -> help; ESC from help lands on graph, never
    # on the pinned intermediate.
    sm.start_graph()
    sm.toggle_on_pinned_graph()
    sm.start_help()
    success, _pos = sm.go_back()
    assert success
    assert sm.current_state == sm.graph
