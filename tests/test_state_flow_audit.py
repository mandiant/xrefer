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

"""Regression tests for the state/shortcut/revert flow audit (June 2026).

A multi-agent audit found that go_back's mode-flip skip stranded every
pinned/simplified state (round trips from help/neighborhood/matrix silently
dropped the pin and simplified modes; a shadowed toggle_on_graph arm caused
an ESC desync/dead-end), that the intermediate-paths (M) sub-view leaked its
bookkeeping across pivots and stack wipes, that cluster sync stranded True in
unpinned states, and that return_to_clusters_table only accepted the unpinned
graph. These tests drive the real XReferStateMachine headlessly to pin the
fixed flows. (View-layer pieces — P/B/peek gating, M handler routing — are
exercised in IDA; here we cover everything the state machine owns.)
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


@pytest.fixture()
def sm():
    return _load().XReferStateMachine()


def _id(state):
    return state.id


# --------------------------------------------------------------------------- #
# F-A: go_back must restore the exact pinned/simplified state on a round trip,
# and walk graph view-modes back one step at a time (no skip, no dead-end).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "open_steps, want",
    [
        (["start_graph", "toggle_simplified", "start_help"], "simplified_graph"),
        (["start_graph", "toggle_on_pinned_graph", "start_help"], "pinned_graph"),
        (["start_graph", "toggle_simplified", "toggle_on_pinned_graph", "start_help"], "pinned_simplified_graph"),
        (["start_neighborhood_graph", "toggle_pinned_neighborhood_graph", "start_help"], "pinned_neighborhood_graph"),
        (["start_cluster_graphs", "toggle_pinned_cluster_graph", "start_attack_matrix"], "pinned_cluster_graphs"),
    ],
)
def test_help_or_matrix_round_trip_restores_exact_mode(sm, open_steps, want):
    for s in open_steps:
        getattr(sm, s)()
    ok, _pos = sm.go_back()
    assert ok
    assert _id(sm.current_state) == want


def test_esc_walks_graph_modes_one_step_at_a_time(sm):
    sm.start_graph()
    sm.toggle_simplified()
    sm.toggle_on_pinned_graph()  # pinned_simplified_graph
    for want in ("simplified_graph", "graph", "base"):
        sm.go_back()
        assert _id(sm.current_state) == want


def test_search_entry_graph_esc_is_not_a_dead_end(sm):
    # search -> G(graph) -> S -> G(pin) -> ESC*3 must return to search,
    # not silently die (the shadowed toggle_on_graph arm used to strand it).
    sm.start_search()
    sm.start_graph()
    sm.toggle_simplified()
    sm.toggle_on_pinned_graph()
    for want in ("simplified_graph", "graph", "search"):
        ok, _pos = sm.go_back()
        assert ok
        assert _id(sm.current_state) == want


def test_toggle_on_graph_has_no_shadowed_arm(sm):
    # G-unpin from pinned_simplified keeps the simplified mode (first arm);
    # there must be no second pinned_simplified->graph arm to shadow it.
    sm.start_graph()
    sm.toggle_simplified()
    sm.toggle_on_pinned_graph()
    sm.toggle_on_graph()
    assert _id(sm.current_state) == "simplified_graph"


# --------------------------------------------------------------------------- #
# F-C: the pinned neighborhood graph is reachable (toggles wired) and the
# round trip restores it (covered above) — here just the toggle itself.
# --------------------------------------------------------------------------- #
def test_neighborhood_pin_toggles_round_trip(sm):
    sm.start_neighborhood_graph()
    assert sm.toggle_pinned_neighborhood_graph()
    assert _id(sm.current_state) == "pinned_neighborhood_graph"
    assert sm.toggle_unpinned_neighborhood_graph()
    assert _id(sm.current_state) == "neighborhood_graph"


# --------------------------------------------------------------------------- #
# F-D: cluster sync only ever stays True in pinned_cluster_graphs; any other
# landing clears it. return_to_clusters_table accepts both graph variants.
# --------------------------------------------------------------------------- #
def test_sync_clears_when_leaving_pinned_cluster_graphs(sm):
    sm.start_cluster_graphs()
    sm.toggle_cluster_sync()  # sync on, auto-pins
    assert sm.cluster_sync_enabled
    assert _id(sm.current_state) == "pinned_cluster_graphs"
    sm.toggle_unpinned_cluster_graph()  # an unpin via any path
    assert not sm.cluster_sync_enabled
    assert _id(sm.current_state) == "cluster_graphs"


def test_manual_pin_does_not_set_sync(sm):
    sm.start_cluster_graphs()
    sm.toggle_pinned_cluster_graph()
    assert not sm.cluster_sync_enabled


@pytest.mark.parametrize("pin", [False, True])
def test_return_to_clusters_table_from_either_variant(sm, pin):
    sm.start_cluster_graphs()
    sm.toggle_on_clusters()        # the clusters TABLE
    sm.toggle_on_cluster_graphs()  # click a cluster -> graph
    if pin:
        sm.toggle_pinned_cluster_graph()
        sm.toggle_unpinned_cluster_graph()  # a pin/unpin pair to skip
        sm.toggle_pinned_cluster_graph()    # land pinned
    assert sm.return_to_clusters_table()
    assert _id(sm.current_state) == "clusters"
    assert not sm.cluster_sync_enabled


def test_return_to_clusters_table_false_from_overview(sm):
    sm.start_cluster_graphs()  # base -> graph overview, never the table
    assert sm.return_to_clusters_table() is False


# --------------------------------------------------------------------------- #
# F-B: the intermediate sub-view bookkeeping is cleared at every leak point.
# --------------------------------------------------------------------------- #
def test_clear_cluster_history_discards_intermediate_view(sm):
    sm.start_cluster_graphs()
    sm.cluster_manager.push_cluster(5)
    sm._intermediate_view_func_ea = 0x1000
    sm._intermediate_view_pushed_cluster = True
    sm.clear_cluster_history()
    assert sm.intermediate_view_func_ea is None
    assert sm._intermediate_view_pushed_cluster is False
    assert sm.cluster_manager.get_current_cluster() is None


def test_reset_state_pops_stranded_intermediate_push(sm):
    sm.start_cluster_graphs()
    sm.cluster_manager.push_cluster(7)
    sm._intermediate_view_pushed_cluster = True
    sm._intermediate_view_func_ea = 0x2000
    sm.reset_state()
    assert sm.cluster_manager.get_current_cluster() is None
    assert sm._intermediate_view_pushed_cluster is False


def test_reset_state_leaves_a_genuine_push_intact(sm):
    sm.start_cluster_graphs()
    sm.cluster_manager.push_cluster(3)
    sm._intermediate_view_pushed_cluster = False  # no M push happened
    sm.reset_state()
    cur = sm.cluster_manager.get_current_cluster()
    assert cur is not None and cur.cluster_id == 3


def test_flip_intermediate_scope_refused_outside_cluster_graph_states(sm):
    sm.start_neighborhood_graph()
    sm._intermediate_view_func_ea = 0x3000
    before = sm._intermediate_view_show_all
    assert sm.flip_intermediate_scope() is False
    assert sm._intermediate_view_show_all == before


def test_flip_intermediate_scope_allowed_inside_cluster_graphs(sm):
    sm.start_cluster_graphs()
    sm._intermediate_view_func_ea = 0x3000
    assert sm.flip_intermediate_scope() is True


def test_discard_intermediate_view_clears_and_pops_unguarded(sm):
    sm.start_cluster_graphs()
    sm.cluster_manager.push_cluster(9)
    sm.start_neighborhood_graph()  # leave cluster-graph state, flag lingers
    sm._intermediate_view_func_ea = 0x4000
    sm._intermediate_view_pushed_cluster = True
    assert sm.discard_intermediate_view() is True
    assert sm.intermediate_view_func_ea is None
    assert sm.cluster_manager.get_current_cluster() is None
