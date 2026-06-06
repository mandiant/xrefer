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
from typing import Dict, List, Set, Tuple

import ida_lines

from xrefer.gui.helpers import get_visible_width


class ActionCategory(Enum):
    KEYBOARD = auto()
    MOUSE = auto()


@dataclass
class Action:
    key: str
    description: str
    category: ActionCategory
    states: Set[str] = None

    def __post_init__(self):
        if self.states is None:
            self.states = set()

    def format(self) -> str:
        colored_key = f"\x01{ida_lines.SCOLOR_VOIDOP}{self.key}\x02{ida_lines.SCOLOR_VOIDOP}"
        colored_sep = f"\x01{ida_lines.SCOLOR_SYMBOL}:\x02{ida_lines.SCOLOR_SYMBOL}"
        colored_desc = f"\x01{ida_lines.SCOLOR_DATNAME}{self.description}\x02{ida_lines.SCOLOR_DATNAME}"
        return f"{colored_key}{colored_sep} {colored_desc}"


class ContextHelp:
    def __init__(self):
        self.box = {"tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│"}

        # Shortcut → state map. Audited against gui/view.py handle_key_*
        # handlers AND gui/state_machine.py transitions (a key is "live" in a
        # state only when its handler logic AND the transition it fires both
        # allow that state). A trailing state set scopes the action to those
        # states; no set ⇒ truly global. Keep in sync with
        # gui/helpers.py::help_text() and the audit in persistent memory
        # (project_shortcuts_help_audit.md).
        #
        # State display names:
        #   base, search, call focus, function trace, path trace, full trace,
        #   graph, pinned graph, simplified graph, pinned simplified graph,
        #   boundary results, last boundary results, orphans, clusters,
        #   cluster graphs, pinned cluster graphs, neighborhood graph,
        #   pinned neighborhood graph, xref listing, help

        GRAPH = {"graph", "pinned graph", "simplified graph", "pinned simplified graph"}
        CLUSTER_GRAPH = {"cluster graphs", "pinned cluster graphs"}
        TRACE = {"function trace", "path trace", "full trace"}
        NEIGHBORHOOD = {"neighborhood graph", "pinned neighborhood graph"}

        # Truly global — handlers have no state guard (ESC/ENTER/N) or work in
        # essentially every banner-bearing state (H).
        global_actions = [
            Action("ESC", "go back / return to IDA", ActionCategory.KEYBOARD),
            Action("ENTER", "return to home view", ActionCategory.KEYBOARD),
            Action("H", "show/hide help", ActionCategory.KEYBOARD),
            Action("N", "rename function/reference under cursor", ActionCategory.KEYBOARD),
            Action("click", "expand row / open cluster / show call details", ActionCategory.MOUSE),
            Action("dbl-click", "select artifact / jump to address", ActionCategory.MOUSE),
            Action("hover", "show tooltip", ActionCategory.MOUSE),
        ]

        # Home (base) — the per-function xref tables view.
        base_actions = [
            Action("S", "search / filter the view", ActionCategory.KEYBOARD, {"base"}),
            Action("T", "trace API calls (cycle scopes)", ActionCategory.KEYBOARD, {"base"}),
            Action("C", "cluster relationship graph", ActionCategory.KEYBOARD, {"base"}),
            Action("O", "orphan artifacts", ActionCategory.KEYBOARD, {"base"}),
            Action("X", "cross-references for artifact", ActionCategory.KEYBOARD, {"base"}),
            Action("B", "boundary scan over selected artifacts", ActionCategory.KEYBOARD, {"base"}),
            Action("L", "last boundary scan results", ActionCategory.KEYBOARD, {"base"}),
            Action("P", "call focus (cursor on a 0x… call)", ActionCategory.KEYBOARD, {"base"}),
            Action("J", "jump to this function's cluster", ActionCategory.KEYBOARD, {"base"}),
            Action("D", "exclude selected artifacts", ActionCategory.KEYBOARD, {"base"}),
        ]

        # U + E each span a couple of states (NOT global, as old code claimed).
        toggle_actions = [
            Action("U", "toggle exclusions on/off", ActionCategory.KEYBOARD, {"base", *TRACE}),
            Action("E", "expand/collapse table sections", ActionCategory.KEYBOARD, {"base", "orphans"}),
        ]

        # G has three context-dependent meanings.
        g_actions = [
            Action("G", "artifact path graph", ActionCategory.KEYBOARD, {"base", "search"}),
            Action("G", "pin/unpin graph", ActionCategory.KEYBOARD, set(GRAPH)),
            Action("G", "pin/unpin cluster graph", ActionCategory.KEYBOARD, set(CLUSTER_GRAPH)),
        ]

        # Inside artifact graphs: S simplifies, V opens neighborhood, G pins.
        graph_actions = [
            Action("S", "toggle simplified / normal", ActionCategory.KEYBOARD, set(GRAPH)),
        ]

        # V opens the neighborhood from many states; closes it from the two
        # neighborhood states.
        v_actions = [
            Action("V", "neighborhood: clusters reachable from cursor", ActionCategory.KEYBOARD, {"base", "clusters", *CLUSTER_GRAPH, *GRAPH}),
            Action("V", "exit neighborhood view", ActionCategory.KEYBOARD, set(NEIGHBORHOOD)),
        ]

        # T cycles scope once you are inside a trace view (T from base opens it).
        trace_actions = [
            Action("T", "cycle trace scope (function/path/full)", ActionCategory.KEYBOARD, set(TRACE)),
        ]

        # Cluster table / cluster graph keys.
        cluster_actions = [
            Action("C", "toggle cluster table / graph", ActionCategory.KEYBOARD, {"clusters", "cluster graphs"}),
            Action("L", "show/hide library clusters", ActionCategory.KEYBOARD, {"clusters", *CLUSTER_GRAPH}),
            Action("R", "toggle description / report view", ActionCategory.KEYBOARD, {"clusters", *CLUSTER_GRAPH}),
            Action("J", "toggle cluster sync", ActionCategory.KEYBOARD, set(CLUSTER_GRAPH)),
            Action("M", "intermediate paths through cursor function", ActionCategory.KEYBOARD, {"base", "clusters", *CLUSTER_GRAPH, *NEIGHBORHOOD}),
            Action("A", "intermediate scope: this cluster ↔ all", ActionCategory.KEYBOARD, set(CLUSTER_GRAPH)),
        ]

        # Search: only X and G transition out; any other key types into the
        # filter.
        search_actions = [
            Action("type", "filter the current view", ActionCategory.KEYBOARD, {"search"}),
            Action("X", "cross-references for artifact", ActionCategory.KEYBOARD, {"search"}),
        ]

        # Orphans view exit (E expand/collapse is covered by toggle_actions).
        orphan_actions = [
            Action("O", "exit orphan artifacts view", ActionCategory.KEYBOARD, {"orphans"}),
        ]

        # boundary results / last boundary results / call focus / xref listing /
        # help have no live keys beyond the globals.

        self.actions = (
            global_actions
            + base_actions
            + toggle_actions
            + g_actions
            + graph_actions
            + v_actions
            + trace_actions
            + cluster_actions
            + search_actions
            + orphan_actions
        )

        self._help_cache: Dict[Tuple[str, int], List[str]] = {}

    def _create_help_section(self, title: str, actions: List[Action], width: int) -> List[str]:
        box_color = f"\x01{ida_lines.SCOLOR_DATNAME}"
        box_end = f"\x02{ida_lines.SCOLOR_DATNAME}"
        lines = []

        title_colored = f"\x01{ida_lines.SCOLOR_PREFIX}{title}:\x02{ida_lines.SCOLOR_PREFIX}"
        base_padding = get_visible_width(f"{self.box['v']} {title}: ")

        current_line = []
        current_width = base_padding

        for action in actions:
            formatted_action = action.format()
            action_width = get_visible_width(formatted_action)
            if current_width + action_width + 3 > width - 5:
                line_content = " ".join(current_line)
                padding = width - get_visible_width(line_content) - 5
                full_line = f"{box_color}{self.box['v']}{box_end} {line_content}{' ' * (padding + 1)}{box_color}{self.box['v']}{box_end}"
                lines.append(full_line)
                current_line = [formatted_action]
                current_width = base_padding + action_width
            else:
                if current_line:
                    current_line.append(f"\x01{ida_lines.SCOLOR_SYMBOL}•\x02{ida_lines.SCOLOR_SYMBOL}")
                current_line.append(formatted_action)
                current_width += action_width + 3

        if current_line:
            line_content = " ".join(current_line)
            padding = width - get_visible_width(line_content) - 5
            full_line = f"{box_color}{self.box['v']}{box_end} {line_content}{' ' * (padding + 1)}{box_color}{self.box['v']}{box_end}"
            lines.append(full_line)

        return lines

    def _create_box_border(self, width: int, is_top: bool = True) -> str:
        box_color = f"\x01{ida_lines.SCOLOR_DATNAME}"
        box_end = f"\x02{ida_lines.SCOLOR_DATNAME}"

        adjusted_width = width - 1
        if is_top:
            return f"{box_color}{self.box['tl']}{self.box['h'] * (adjusted_width - 2)}{self.box['tr']}{box_end}"
        else:
            return f"{box_color}{self.box['bl']}{self.box['h'] * (adjusted_width - 2)}{self.box['br']}{box_end}"

    def format_help_text(self, current_state: str, width: int = 80) -> List[str]:
        if (current_state, width) in self._help_cache:
            return self._help_cache[(current_state, width)]

        lines = []
        lines.append(self._create_box_border(width, True))

        state_actions = self.get_state_actions(current_state)

        # Keyboard actions
        if state_actions[ActionCategory.KEYBOARD]:
            kb_lines = self._create_help_section("Keys", state_actions[ActionCategory.KEYBOARD], width)
            lines.extend(kb_lines)

        # Mouse actions
        if state_actions[ActionCategory.MOUSE]:
            mouse_lines = self._create_help_section("Mouse", state_actions[ActionCategory.MOUSE], width)
            lines.extend(mouse_lines)

        lines.append(self._create_box_border(width, False))

        self._help_cache[(current_state, width)] = lines
        return lines

    def get_state_actions(self, current_state: str) -> Dict[ActionCategory, List[Action]]:
        state_actions = {cat: [] for cat in ActionCategory}

        for action in self.actions:
            # If no states specified, global action. Otherwise, check membership
            if not action.states or current_state in action.states:
                state_actions[action.category].append(action)

        return state_actions

    def clear_cache(self) -> None:
        self._help_cache.clear()
