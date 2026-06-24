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

"""Sticky-state classification for the update() dispatch.

XReferView.update tears the panel down to base on every cross-function
cursor move unless the current state is sticky (a binary-wide reading view)
or a pinned graph. These tests pin the classification itself: which states
survive navigation, which pinned graphs persist, and that the two sets stay
disjoint. The real state machine is driven through its real transitions —
no IDA, Qt or network (gui/state_machine.py imports only python-statemachine
plus a lazily-imported logger).
"""

import importlib.util
import pathlib
import sys
import types

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_STATE_MACHINE_PY = _REPO / "plugins" / "xrefer" / "gui" / "state_machine.py"


def _load_state_machine_module():
    """Import gui/state_machine.py without running xrefer.gui's __init__."""
    for name in ("xrefer", "xrefer.gui"):
        if name not in sys.modules:
            pkg = types.ModuleType(name)
            pkg.__path__ = []
            sys.modules[name] = pkg
    spec = importlib.util.spec_from_file_location("xrefer.gui.state_machine", _STATE_MACHINE_PY)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["xrefer.gui.state_machine"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sm_module():
    return _load_state_machine_module()


@pytest.fixture
def sm(sm_module):
    return sm_module.XReferStateMachine()


def test_base_and_cursor_scoped_states_are_not_sticky(sm):
    assert not sm.is_sticky_state()  # base
    sm.start_graph()
    assert not sm.is_sticky_state()
    assert not sm.is_pinned_graph()


def test_reading_views_are_sticky(sm_module):
    routes = {
        "clusters": lambda m: (m.start_cluster_graphs(), m.toggle_on_clusters()),
        "orphans": lambda m: m.start_orphans(),
        "xref listing": lambda m: m.start_xref_listing(),
        "boundary results": lambda m: m.start_boundary_results(),
        "last boundary results": lambda m: m.start_last_boundary_results(),
        "attack matrix": lambda m: m.start_attack_matrix(),
        "help": lambda m: m.start_help(),
        "full trace": lambda m: (m.start_trace(), m.toggle_on_trace_scope_path(), m.toggle_on_trace_scope_full()),
    }
    for state_name, route in routes.items():
        m = sm_module.XReferStateMachine()
        route(m)
        assert m.current_state.name == state_name
        assert m.is_sticky_state(), f"{state_name} must be sticky"
        assert not m.is_pinned_graph(), f"{state_name} must not be a pinned graph"


def test_pinned_graphs_are_pinned_not_sticky(sm_module):
    routes = {
        "pinned graph": lambda m: (m.start_graph(), m.toggle_on_pinned_graph()),
        "pinned cluster graphs": lambda m: (m.start_cluster_graphs(), m.toggle_pinned_cluster_graph()),
        "pinned neighborhood graph": lambda m: (m.start_neighborhood_graph(), m.toggle_pinned_neighborhood_graph()),
    }
    for state_name, route in routes.items():
        m = sm_module.XReferStateMachine()
        try:
            route(m)
        except AttributeError as err:
            pytest.fail(f"transition helper missing for {state_name}: {err}")
        assert m.current_state.name == state_name
        assert m.is_pinned_graph(), f"{state_name} must report pinned"
        assert not m.is_sticky_state(), f"{state_name} must not be sticky"


def test_function_scoped_trace_states_are_not_sticky(sm_module):
    m = sm_module.XReferStateMachine()
    m.start_trace()
    assert m.current_state.name == "function trace"
    assert not m.is_sticky_state()
    m.toggle_on_trace_scope_path()
    assert m.current_state.name == "path trace"
    assert not m.is_sticky_state()
