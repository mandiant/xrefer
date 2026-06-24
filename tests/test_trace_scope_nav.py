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

"""ESC stepping through the trace-scope cycle.

T cycles forward function -> path -> full -> function; ESC must step back
one scope at a time (full -> path -> function -> base). It used to skip
past path: go_back treated the trace toggle_ events as mode-flips and
there was no full -> path arm, so ESC from full jumped to function.
step_back_trace_scope() makes ESC a pure function of the current scope so
it never skips and never dead-ends on the cyclic history T builds; the
go_back exemption makes a state opened FROM a scope (help) return to that
exact scope.
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


def _cycle_to_full(sm):
    sm.start_trace()                      # T from base -> function
    sm.toggle_on_trace_scope_path()       # T -> path
    sm.toggle_on_trace_scope_full()       # T -> full
    assert sm.current_state == sm.trace_scope_full


def test_esc_steps_back_one_scope_at_a_time(sm):
    _cycle_to_full(sm)
    assert sm.step_back_trace_scope()
    assert sm.current_state == sm.trace_scope_path      # NOT function — no skip
    assert sm.step_back_trace_scope()
    assert sm.current_state == sm.trace_scope_function
    assert sm.step_back_trace_scope()
    assert sm.current_state == sm.base


def test_esc_from_wrapped_function_exits_to_base_not_deadend(sm):
    _cycle_to_full(sm)
    sm.toggle_on_trace_scope_function()   # 4th T wraps full -> function
    assert sm.current_state == sm.trace_scope_function
    # The cyclic history has function preceded by full with no function->full
    # arm; the deterministic step must still resolve (to base), never no-op.
    assert sm.step_back_trace_scope()
    assert sm.current_state == sm.base


def test_step_back_is_noop_outside_trace_scopes(sm):
    assert sm.current_state == sm.base
    assert sm.step_back_trace_scope() is False
    sm.start_orphans()
    assert sm.step_back_trace_scope() is False
    assert sm.current_state == sm.orphans


def test_help_opened_from_a_scope_returns_to_that_scope(sm):
    # help is reached via go_back (not the trace special-case), so the
    # go_back exemption must stop at the originating scope, not skip past it.
    _cycle_to_full(sm)
    sm.start_help()
    assert sm.current_state == sm.help
    ok, _pos = sm.go_back()
    assert ok
    assert sm.current_state == sm.trace_scope_full      # the scope H was opened from
