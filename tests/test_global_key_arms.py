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

"""Globally-advertised keys must have a transition arm in every state.

ENTER (to_base) and H (start_help) are presented as global, yet ENTER
silently no-oped in pinned graphs and the path/full trace scopes, and H
no-oped in the simplified graphs — the hint line advertised keys that did
nothing. This structural test walks every state and asserts the arm
exists (or the state is an explicit, documented exception), so a new view
can never reintroduce a silent dead key.
"""

import importlib.util
import pathlib
import sys
import types

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_SM = _REPO / "plugins" / "xrefer" / "gui" / "state_machine.py"

# States where the global key is legitimately dead, with the reason.
ENTER_EXCEPTIONS = {
    "base",  # already home — to_base from base is meaningless
    "search",  # ESC exits search; ENTER is part of the typing surface
}
HELP_EXCEPTIONS = {
    "help",  # H toggles back out via the revert arms, not start_help
    "search",  # 'h' must stay typeable into the filter
}


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


@pytest.fixture(scope="module")
def sm_cls():
    return _load().XReferStateMachine


def _sources(sm_cls, event_name):
    """States that own an arm for the given event."""
    return {
        t.source.id
        for state in sm_cls.states
        for t in state.transitions
        if event_name in {e.id if hasattr(e, "id") else str(e) for e in t.events}
    }


def test_enter_reaches_home_from_every_state(sm_cls):
    sources = _sources(sm_cls, "to_base")
    missing = [s.id for s in sm_cls.states if s.id not in sources and s.id not in ENTER_EXCEPTIONS]
    assert not missing, f"states where the global ENTER key silently no-ops: {missing}"


def test_help_opens_from_every_state(sm_cls):
    sources = _sources(sm_cls, "start_help")
    missing = [s.id for s in sm_cls.states if s.id not in sources and s.id not in HELP_EXCEPTIONS]
    assert not missing, f"states where the global H key silently no-ops: {missing}"


def test_help_can_return_to_every_state_it_opened_from(sm_cls):
    help_sources = _sources(sm_cls, "start_help")
    help_state = next(s for s in sm_cls.states if s.id == "help")
    revert_targets = {t.target.id for t in help_state.transitions}
    missing = sorted(help_sources - revert_targets)
    assert not missing, f"help can open from but never return to: {missing}"
