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

"""Guards the per-view compact help hint against drift.

``gui/help.py`` derives the one-line hint from a single registry
(``ContextHelp.actions``). These tests make that registry *self-policing*:
the real list of states and the real keyboard dispatcher are scraped straight
out of the source (gui/state_machine.py and gui/view.py), so adding a new
mode / view / state / key and forgetting to register a hint fails here without
anyone having to remember to re-audit. No IDA, Qt, or network — ``help.py`` is
loaded against tiny stubs for ``ida_lines`` and the two pure string helpers it
imports.
"""

import importlib.util
import pathlib
import re
import sys
import types

import pytest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_GUI = _REPO / "plugins" / "xrefer" / "gui"
_HELP_PY = _GUI / "help.py"
_STATE_MACHINE_PY = _GUI / "state_machine.py"
_VIEW_PY = _GUI / "view.py"
_HELPERS_PY = _GUI / "helpers.py"


def _load_help_module():
    """Import gui/help.py headlessly via stubbed dependencies."""

    class _IdaLinesStub:
        # Any SCOLOR_* lookup yields a single-byte colour code so the
        # \x01<code> / \x02<code> sequences strip to nothing for width math.
        def __getattr__(self, _name):
            return "\x10"

    sys.modules["ida_lines"] = _IdaLinesStub()

    # Bare package shells so `from xrefer.gui.helpers import ...` resolves
    # without running the real (IDA-heavy) package __init__ files.
    for name in ("xrefer", "xrefer.gui"):
        if name not in sys.modules:
            pkg = types.ModuleType(name)
            pkg.__path__ = []  # mark as a package
            sys.modules[name] = pkg

    helpers_stub = types.ModuleType("xrefer.gui.helpers")

    def strip_color_codes(text):
        return re.sub(r"\x01[\x00-\xff]|\x02[\x00-\xff]", "", text)

    def get_visible_width(text):
        return len(strip_color_codes(text))

    helpers_stub.strip_color_codes = strip_color_codes
    helpers_stub.get_visible_width = get_visible_width
    sys.modules["xrefer.gui.helpers"] = helpers_stub

    spec = importlib.util.spec_from_file_location("xrefer.gui.help", _HELP_PY)
    module = importlib.util.module_from_spec(spec)
    sys.modules["xrefer.gui.help"] = module
    spec.loader.exec_module(module)
    return module, strip_color_codes, get_visible_width


_HELP, _STRIP, _WIDTH = _load_help_module()
ContextHelp = _HELP.ContextHelp
_COMPACT_BUDGET = _HELP._COMPACT_BUDGET


# --------------------------------------------------------------------------- #
# Source-scraped ground truth (auto-updates as the plugin grows).
# --------------------------------------------------------------------------- #
def _all_state_names():
    """Every State("display name") declared in gui/state_machine.py."""
    text = _STATE_MACHINE_PY.read_text(encoding="utf-8")
    names = re.findall(r'State\(\s*"([^"]+)"', text)
    assert names, "no states scraped from state_machine.py — parser drifted?"
    return sorted(set(names))


def _dispatched_keys():
    """Keys wired into view.py's handle_key_specific_actions dispatcher."""
    text = _VIEW_PY.read_text(encoding="utf-8")
    block = text[text.index("def handle_key_specific_actions"):]
    # The dispatcher dict ends right before the `.get(vkey, self.handle_default)`
    # lookup; bound the scrape there so we only read the explicit mappings.
    block = block[: block.index("key_actions.get")]
    letters = set(re.findall(r'ord\("([A-Z])"\)\s*:\s*self\.handle_key_', block))
    specials = set()
    if re.search(r"\b13:\s*self\.handle_key_enter", block):
        specials.add("ENTER")
    if re.search(r"\b27:\s*self\.handle_key_escape", block):
        specials.add("ESC")
    assert letters, "no dispatched keys scraped from view.py — parser drifted?"
    return letters, specials


ALL_STATES = _all_state_names()
DISPATCH_LETTERS, DISPATCH_SPECIALS = _dispatched_keys()


def _tokens(hint_line):
    """Parse a rendered compact line into (key, desc) pairs, colours stripped."""
    plain = _STRIP(hint_line)
    out = []
    for chunk in plain.split(" · "):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, _, desc = chunk.partition(": ")
        out.append((key.strip(), desc.strip()))
    return out


@pytest.fixture(scope="module")
def ch():
    return ContextHelp()


# --------------------------------------------------------------------------- #
# Coverage: every real state and every dispatched key is accounted for.
# --------------------------------------------------------------------------- #
def test_every_state_has_a_hint(ch):
    """Each real state (except help) yields a non-empty, multi-token hint."""
    for state in ALL_STATES:
        line = ch.format_compact_hint(state)
        if state == "help":
            assert line == "", "help view must suppress its own hint line"
            continue
        keys = [k for k, _ in _tokens(line)]
        assert keys, f"state {state!r} produced an empty compact hint"
        non_help = [k for k in keys if k != "H"]
        assert non_help, f"state {state!r} hint only shows 'H' — needs real hints"
        assert keys[-1] == "H", f"state {state!r} hint must end with H: full help"


def test_unknown_state_degrades_to_help(ch):
    """A state nobody registered still renders something pointing at H."""
    assert _tokens(ch.format_compact_hint("does not exist")) == [("H", "full help")]


def test_every_dispatched_key_is_registered(ch):
    """Any key handled by view.py must exist in the help registry."""
    registered = {a.key for a in ch.actions}
    missing = (DISPATCH_LETTERS | DISPATCH_SPECIALS) - registered
    assert not missing, f"keys dispatched in view.py but absent from help registry: {sorted(missing)}"


def test_registry_states_are_real(ch):
    """No action references a state name that the state machine doesn't define."""
    valid = set(ALL_STATES)
    for action in ch.actions:
        bogus = action.states - valid
        assert not bogus, f"action {action.key!r} references unknown states {sorted(bogus)}"


# --------------------------------------------------------------------------- #
# Soundness: a hint never advertises something that isn't live there.
# --------------------------------------------------------------------------- #
def test_compact_keys_are_live_in_state(ch):
    for state in ALL_STATES:
        live = ch.live_keys(state)
        for key, _ in _tokens(ch.format_compact_hint(state)):
            assert key in live, f"hint for {state!r} shows {key!r} which is not live there"


def test_compact_line_within_budget(ch):
    for state in ALL_STATES:
        line = ch.format_compact_hint(state)
        assert _WIDTH(line) <= _COMPACT_BUDGET, (
            f"compact hint for {state!r} is {_WIDTH(line)} cols, over budget {_COMPACT_BUDGET}"
        )


# --------------------------------------------------------------------------- #
# Regression: the bug that started this — ATT&CK (K) is reachable from the home
# and cluster views, so its hint must appear there.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("state", ["base", "clusters", "cluster graphs", "pinned cluster graphs"])
def test_attack_matrix_hint_present_where_live(ch, state):
    keys = {k for k, _ in _tokens(ch.format_compact_hint(state))}
    assert "K" in keys, f"K: ATT&CK missing from {state!r} hint (it is live there)"


def test_attack_matrix_view_offers_heat_grid_and_exit(ch):
    keys = {k for k, _ in _tokens(ch.format_compact_hint("attack matrix"))}
    assert {"G", "L", "K"} <= keys, "attack matrix hint should expose G (heat-grid), L (library), K (exit)"


def test_expand_collapse_hint_in_both_table_views(ch):
    """E (expand/collapse) is the signature interaction of the xref + orphans
    tables — it must appear in BOTH compact lines, not just the sparse one."""
    for state in ("base", "orphans"):
        keys = {k for k, _ in _tokens(ch.format_compact_hint(state))}
        assert "E" in keys, f"E: expand all missing from {state!r} hint (it is live there)"


@pytest.mark.parametrize("state", ["graph", "pinned graph", "simplified graph", "pinned simplified graph"])
def test_node_detail_hint_present_in_graph_views(ch, state):
    """The D (node detail) toggle is live in every artifact-graph state, so its
    hint must show there alongside S (simplify) and G (pin)."""
    keys = {k for k, _ in _tokens(ch.format_compact_hint(state))}
    assert {"D", "S", "G"} <= keys, f"{state!r} hint should expose D (detail), S (simplify), G (pin)"


def test_search_and_trace_hints_are_specific(ch):
    search = {k for k, _ in _tokens(ch.format_compact_hint("search"))}
    assert "type" in search and "G" in search
    trace = dict(_tokens(ch.format_compact_hint("function trace")))
    assert trace.get("T") == "cycle scope"  # not the home-view "trace"
