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

"""Binary-wide artifact search state (Shift+S from home).

A real state like search — its own rendering, its own pivots — not a
per-view filter flag. Headless coverage locks the transition topology:
entry from base only, X/G pivots out, reverts back so ESC returns to
the result list, exits to base, sticky across cursor moves, and the
filter lifecycle through reset_state.
"""

import importlib.util
import pathlib
import sys
import types

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_SM = _REPO / "plugins" / "xrefer" / "gui" / "state_machine.py"


def _load_sm():
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
    return _load_sm().XReferStateMachine()


def test_entry_from_base_only(sm):
    assert sm.start_artifact_search()
    assert sm.current_state == sm.artifact_search
    # From any other state the transition is unavailable (safe_transition
    # returns False instead of raising) — e.g. from inside itself.
    assert not sm.start_artifact_search()


def test_pivot_to_xref_listing_and_back(sm):
    sm.start_artifact_search()
    sm.search_filter = "crypt"
    assert sm.start_xref_listing()
    assert sm.current_state == sm.xref_listing
    # ESC (go_back) must land back on the result list with the filter
    # text intact — the revert arm exists and nothing clears the filter.
    ok, _pos = sm.go_back()
    assert ok
    assert sm.current_state == sm.artifact_search
    assert sm.search_filter == "crypt"


def test_pivot_to_graph_and_back(sm):
    sm.start_artifact_search()
    assert sm.start_graph()
    assert sm.current_state == sm.graph
    ok, _pos = sm.go_back()
    assert ok
    assert sm.current_state == sm.artifact_search


def test_enter_returns_home_and_clears_filter(sm):
    sm.start_artifact_search()
    sm.search_filter = "beacon"
    assert sm.to_base()
    assert sm.current_state == sm.base
    # Entering base fires reset_state, which retires the filter text.
    assert sm.search_filter == ""


def test_artifact_search_is_sticky(sm):
    sm.start_artifact_search()
    assert sm.is_sticky_state()


def test_no_help_arm_keeps_h_typeable(sm):
    sm.start_artifact_search()
    assert not sm.start_help()
    assert sm.current_state == sm.artifact_search


def test_search_table_hint_registry_covers_artifact_search():
    sys.path.insert(0, str(_REPO / "tests"))
    try:
        from test_help_hints import _load_help_module
    finally:
        sys.path.pop(0)
    help_mod, _strip, _width = _load_help_module()
    ch = help_mod.ContextHelp()
    keys = ch.live_keys("artifact search")
    assert {"type", "X", "G", "ESC", "ENTER"} <= keys
    # H is excluded — the keystroke must stay typeable into the filter.
    assert "H" not in keys
