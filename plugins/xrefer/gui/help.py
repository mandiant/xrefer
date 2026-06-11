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


from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional, Set

import ida_lines

from xrefer.gui.helpers import get_visible_width


class ActionCategory(Enum):
    KEYBOARD = auto()
    MOUSE = auto()


@dataclass
class Action:
    """One keyboard / mouse affordance plus the states where it is live.

    The list of these on :class:`ContextHelp` (``self.actions``) is the
    **single source of truth** for the per-view compact help hint rendered at
    the top of every XRefer view. There used to be two disconnected maps — this
    registry (which fed a now-removed bordered help box) and a separate
    hand-written ``if/elif`` inside ``format_compact_hint`` — and they drifted
    (e.g. the ATT&CK ``K`` mode was live in the home view but missing from its
    hint). Deriving the hint from this one registry makes that class of bug
    structurally impossible.

    Fields:
        key:        the label shown to the user (``"K"``, ``"click"``, ``"type"``).
        description: long-form text (kept for documentation / future full help).
        category:   keyboard vs mouse.
        states:     set of state *display names* (``State.name`` — e.g.
                    ``"cluster graphs"``, ``"attack matrix"``) where the action
                    is live. Empty set ⇒ global (live everywhere).
        hint:       terse label for the one-line compact hint. ``None`` ⇒ the
                    action is real but never teased on the compact line.
        weight:     when a state has more hinted actions than fit one line, the
                    highest-weight ones are kept. ``H`` is always kept and is
                    always rendered last.

    Keep ``states`` in sync with gui/view.py ``handle_key_*`` and the
    gui/state_machine.py transitions. tests/test_help_hints.py reads those two
    files directly and fails if a dispatched key or a real state has no entry
    here — so new modes/views are caught automatically, no manual re-audit.
    """

    key: str
    description: str
    category: ActionCategory
    states: Set[str] = None
    hint: Optional[str] = None
    weight: int = 0
    # States where a GLOBAL action is nonetheless dead — e.g. ``H`` inside
    # search, where the keystroke must stay typeable into the filter. The
    # hint must not advertise keys that won't fire.
    exclude_states: Set[str] = None

    def __post_init__(self):
        if self.states is None:
            self.states = set()
        if self.exclude_states is None:
            self.exclude_states = set()

    def live_in(self, state: str) -> bool:
        """True when this action is available in ``state`` (empty states ⇒ global)."""
        if state in self.exclude_states:
            return False
        return not self.states or state in self.states


# Visible width budget for the single compact hint line (excluding the 4-space
# indent the caller adds). Sized so the busiest views (home, cluster graphs)
# surface their primary modes — including ATT&CK — without wrapping a typical
# side panel. Over-budget views shed their lowest-weight hints to the full
# help screen (H). tests/test_help_hints.py enforces this bound per state.
_COMPACT_BUDGET = 92


class ContextHelp:
    """Builds the compact, state-aware help hint shown atop each XRefer view.

    The full keyboard/mouse reference lives in gui/helpers.py::help_text() (the
    ``H`` screen); this class only renders the terse one-liner. Both are kept
    honest against the registry below by tests/test_help_hints.py.
    """

    def __init__(self):
        KB = ActionCategory.KEYBOARD
        MS = ActionCategory.MOUSE

        # State groups (by State.name). Mirror gui/state_machine.py.
        GRAPH = {"graph", "pinned graph", "simplified graph", "pinned simplified graph"}
        CLUSTER_GRAPH = {"cluster graphs", "pinned cluster graphs"}
        TRACE = {"function trace", "path trace", "full trace"}
        NEIGHBORHOOD = {"neighborhood graph", "pinned neighborhood graph"}
        # "Simple" detail views: no special keys, just jump / hover / ESC.
        LISTS = {"boundary results", "last boundary results", "xref listing", "call focus"}

        self.actions: List[Action] = [
            # ----- Mouse gestures -------------------------------------------------
            # Modelled per state so the hint phrases the gesture by what it does
            # there (click "expand" a row vs "open cluster"; dbl-click "select"
            # an artifact vs "jump" to an address).
            Action("click", "expand / collapse the row", MS, {"base", "orphans"}, hint="expand", weight=85),
            Action("click", "open the cluster under the cursor", MS, {"clusters", *CLUSTER_GRAPH}, hint="open cluster", weight=85),
            Action("click", "open cluster / follow technique link", MS, {"attack matrix"}, hint="open cluster", weight=85),
            # In base, selection is double-click-only and gates B/D — non-obvious,
            # so keep it prominent (high weight). The *jump* variant is weighted
            # low: jump-on-double-click is a near-universal convention, so in the
            # crowded cluster-graph view it yields its slot to the non-obvious
            # toggles (R/J), while still surfacing in roomier graph/trace/list views.
            Action("dbl-click", "select / deselect the artifact", MS, {"base"}, hint="select", weight=82),
            Action("dbl-click", "jump to the address", MS, {*GRAPH, *CLUSTER_GRAPH, *NEIGHBORHOOD, *TRACE, *LISTS, "artifact search"}, hint="jump", weight=64),
            Action("hover", "show a details tooltip", MS, {"orphans", *NEIGHBORHOOD, *LISTS}, hint="details", weight=20),

            # ----- Global keyboard ------------------------------------------------
            Action("ESC", "go back / return to IDA", KB),
            Action("ENTER", "return to the home view", KB),
            # H is global EXCEPT in the typing surfaces (search, artifact
            # search), where the keystroke types into the filter (there is
            # deliberately no →help arm from either).
            Action("H", "show / hide the full help", KB, hint="full help", exclude_states={"search", "artifact search"}),
            Action("N", "rename the function / reference under the cursor", KB),
            # ESC teased only where the view is otherwise sparse.
            Action("ESC", "exit search", KB, {"search"}, hint="exit", weight=40),
            Action("ESC", "go back", KB, set(LISTS), hint="back", weight=40),

            # ----- Home (base) keyboard ------------------------------------------
            Action("S", "search / filter the view", KB, {"base"}, hint="search", weight=50),
            Action("Shift+S", "search artifacts across the whole binary", KB, {"base"}, hint="search all", weight=49),
            Action("S", "filter the rows (type to narrow, ESC clears)", KB, {"full trace", "orphans", "clusters"}, hint="filter", weight=60),
            Action("T", "trace API calls (cycle scopes)", KB, {"base"}, hint="trace", weight=64),
            Action("C", "cluster relationship graph", KB, {"base"}, hint="clusters", weight=80),
            Action("O", "orphan artifacts", KB, {"base"}, hint="orphans", weight=46),
            Action("X", "cross-references for the artifact", KB, {"base"}),
            Action("B", "boundary scan over selected artifacts", KB, {"base"}),
            Action("L", "last boundary scan results", KB, {"base"}),
            Action("P", "call focus (cursor on a 0x… call)", KB, {"base"}),
            Action("J", "jump to this function's cluster", KB, {"base"}),
            Action("D", "exclude selected artifacts", KB, {"base"}),

            # ----- Toggles spanning a few states ---------------------------------
            Action("U", "toggle exclusions on / off", KB, {"base", *TRACE}, hint="exclusions", weight=58),
            # Expand/collapse is the signature interaction of both the dense xref
            # tables (base) and the orphans table, so it earns a compact slot in
            # both — high enough to survive base's crowd of mode keys.
            Action("E", "expand / collapse all table sections", KB, {"base", "orphans"}, hint="expand all", weight=78),

            # ----- G: context-dependent ------------------------------------------
            Action("G", "artifact path graph", KB, {"base", "search", "artifact search"}, hint="paths", weight=76),
            Action("G", "pin / unpin the graph", KB, set(GRAPH), hint="pin", weight=76),
            Action("G", "pin / unpin the cluster graph", KB, set(CLUSTER_GRAPH), hint="pin", weight=76),
            Action("G", "open the ATT&CK heat-grid popup", KB, {"attack matrix"}, hint="heat-grid", weight=80),

            # ----- Inside artifact graphs ----------------------------------------
            Action("S", "toggle simplified / normal", KB, set(GRAPH), hint="simplify", weight=72),
            Action("D", "show / hide each node's artifacts", KB, set(GRAPH), hint="node detail", weight=70),

            # ----- V: neighborhood -----------------------------------------------
            Action("V", "neighborhood: clusters reachable from cursor", KB, {"base", "clusters", *CLUSTER_GRAPH, *GRAPH}, hint="neighborhood", weight=40),
            Action("V", "exit the neighborhood view", KB, set(NEIGHBORHOOD), hint="exit", weight=84),

            # ----- T: trace scope cycling ----------------------------------------
            Action("T", "cycle trace scope (function / path / full)", KB, set(TRACE), hint="cycle scope", weight=80),

            # ----- Cluster table / cluster graph ---------------------------------
            Action("C", "switch to the cluster graph", KB, {"clusters"}, hint="graph", weight=80),
            Action("C", "switch to the cluster table", KB, {"cluster graphs"}, hint="table", weight=60),
            Action("L", "show / hide library clusters", KB, {"clusters", *CLUSTER_GRAPH}, hint="hide library", weight=54),
            Action("R", "toggle description / report view", KB, {"clusters", *CLUSTER_GRAPH}, hint="report", weight=66),
            Action("J", "toggle cluster sync", KB, set(CLUSTER_GRAPH), hint="sync", weight=70),
            Action("M", "intermediate paths through cursor function", KB, {"base", "clusters", *CLUSTER_GRAPH}),
            Action("M", "intermediate paths through cursor function", KB, set(NEIGHBORHOOD), hint="paths", weight=70),
            Action("A", "intermediate scope: this cluster ↔ all", KB, set(CLUSTER_GRAPH)),

            # ----- ATT&CK matrix (K) ---------------------------------------------
            Action("K", "ATT&CK matrix (kill-chain)", KB, {"base", "clusters", *CLUSTER_GRAPH}, hint="ATT&CK", weight=90),
            Action("K", "exit the ATT&CK matrix", KB, {"attack matrix"}, hint="exit", weight=60),
            Action("L", "show / hide library clusters", KB, {"attack matrix"}, hint="hide library", weight=70),

            # ----- Search --------------------------------------------------------
            Action("type", "filter the current view", KB, {"search"}, hint="filter", weight=90),
            Action("X", "cross-references for the artifact", KB, {"search"}, hint="xrefs", weight=60),

            # ----- Artifact search (binary-wide, Shift+S) -------------------------
            Action("type", "filter artifacts binary-wide", KB, {"artifact search"}, hint="filter", weight=90),
            Action("X", "cross-references for the artifact", KB, {"artifact search"}, hint="xrefs", weight=60),
            Action("ESC", "exit to home", KB, {"artifact search"}, hint="exit", weight=40),

            # ----- Orphans -------------------------------------------------------
            Action("O", "exit the orphan artifacts view", KB, {"orphans"}, hint="exit", weight=60),
        ]

    # ------------------------------------------------------------------ queries
    def live_actions(self, state: str) -> List[Action]:
        """Every registered action available in ``state`` (in registry order)."""
        return [a for a in self.actions if a.live_in(state)]

    def live_keys(self, state: str) -> Set[str]:
        """Set of keys/gestures that have at least one live action in ``state``."""
        return {a.key for a in self.actions if a.live_in(state)}

    # --------------------------------------------------------------- rendering
    def _sep(self) -> str:
        return f"\x01{ida_lines.SCOLOR_SYMBOL} · \x02{ida_lines.SCOLOR_SYMBOL}"

    def _part(self, label: str, desc: str) -> str:
        return (
            f"\x01{ida_lines.SCOLOR_DNAME}{label}\x02{ida_lines.SCOLOR_DNAME}"
            f"\x01{ida_lines.SCOLOR_AUTOCMT}: {desc}\x02{ida_lines.SCOLOR_AUTOCMT}"
        )

    def _display_rank(self, action: Action) -> int:
        """Stable grouping for the rendered order of a compact line.

        Mouse gestures lead, then ``type`` (search), then the lettered keys,
        then navigation (``ESC`` / ``ENTER``); ``H`` is appended separately and
        always last.
        """
        if action.category == ActionCategory.MOUSE:
            return 0
        if action.key == "type":
            return 1
        if action.key in ("ESC", "ENTER"):
            return 3
        return 2

    def format_compact_hint(self, current_state: str) -> str:
        """Single dim, *state-aware* hint line for the top of each view.

        Derived entirely from ``self.actions``: it lists only gestures/keys
        actually live in ``current_state`` (so it never claims e.g. 'G: paths'
        in a graph where G pins, nor omits 'K: ATT&CK' in the home view), packs
        them to :data:`_COMPACT_BUDGET` keeping the highest-weight ones, always
        ends with 'H: full help', and returns '' for the help view itself.
        """
        if current_state == "help":
            return ""

        eligible = [a for i, a in enumerate(self.actions) if a.hint and a.live_in(current_state)]
        help_action = next((a for a in eligible if a.key == "H"), None)
        candidates = [a for a in eligible if a.key != "H"]

        # The final line is `sep.join(kept + [H])` → N parts have N-1 separators.
        # So reserve H's own width but NOT a separator for it; each token then
        # carries the single separator that precedes it. (Counting a separator
        # for H too would over-reserve by one and needlessly drop a token that
        # actually fits.)
        sep_w = get_visible_width(self._sep())
        used = 0
        if help_action is not None:
            used += get_visible_width(self._part(help_action.key, help_action.hint))

        index_of = {id(a): i for i, a in enumerate(self.actions)}
        kept: List[Action] = []
        # Highest weight first decides *what* survives the budget; ties break on
        # registry order for determinism.
        for action in sorted(candidates, key=lambda a: (-a.weight, index_of[id(a)])):
            width = get_visible_width(self._part(action.key, action.hint)) + sep_w
            if used + width <= _COMPACT_BUDGET:
                kept.append(action)
                used += width

        # Then re-order what survived for a readable line.
        kept.sort(key=lambda a: (self._display_rank(a), index_of[id(a)]))
        parts = [self._part(a.key, a.hint) for a in kept]
        if help_action is not None:
            parts.append(self._part(help_action.key, help_action.hint))
        return self._sep().join(parts)
