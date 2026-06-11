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

"""Per-view row filter (S in the full-trace / orphans views).

The filter is a flag layered onto the current state — not the search
STATE, which is a base-view mode. Headless coverage: the state-machine
flag lifecycle (set/clear/reset) and the compact-hint advertisement for
exactly the two filterable views.
"""

import importlib.util
import pathlib
import sys
import types

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_GUI = _REPO / "plugins" / "xrefer" / "gui"


def _load_sm():
    for name in ("xrefer", "xrefer.gui"):
        if name not in sys.modules:
            pkg = types.ModuleType(name)
            pkg.__path__ = []
            sys.modules[name] = pkg
    spec = importlib.util.spec_from_file_location("xrefer.gui.state_machine", _GUI / "state_machine.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["xrefer.gui.state_machine"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_view_filter_flag_lifecycle():
    sm = _load_sm().XReferStateMachine()
    assert sm.view_filter_active is False
    sm.view_filter_active = True
    sm.search_filter = "crypt"
    assert sm.view_filter_active is True
    # reset_state (fired on every base entry) retires the filter wholesale.
    sm.reset_state()
    assert sm.view_filter_active is False
    assert sm.search_filter == ""


def test_clusters_filter_survives_graph_round_trip():
    """The triage loop: filter the table, click into a cluster graph,
    ESC back — the filter (and its text) must survive the round trip so
    the re-render matches the row stored at click time. Only entering
    base retires it."""
    sm = _load_sm().XReferStateMachine()
    sm.start_cluster_graphs()
    sm.toggle_on_clusters()  # the clusters TABLE
    sm.view_filter_active = True
    sm.search_filter = "net"
    sm.toggle_on_cluster_graphs()  # click-pivot into a cluster graph
    assert sm.view_filter_active and sm.search_filter == "net"
    assert sm.return_to_clusters_table()  # ESC return
    assert sm.current_state == sm.clusters
    assert sm.view_filter_active and sm.search_filter == "net"
    sm.to_base()
    assert sm.view_filter_active is False
    assert sm.search_filter == ""


def test_filter_hint_advertised_only_in_filterable_views():
    # Reuse the help-hints loader so the registry renders without IDA.
    sys.path.insert(0, str(_REPO / "tests"))
    try:
        from test_help_hints import _load_help_module
    finally:
        sys.path.pop(0)
    help_mod, _strip, _width = _load_help_module()
    ch = help_mod.ContextHelp()
    filter_states = {
        a_state
        for a in ch.actions
        if a.key == "S" and a.hint == "filter"
        for a_state in a.states
    }
    assert filter_states == {"full trace", "orphans", "clusters"}
