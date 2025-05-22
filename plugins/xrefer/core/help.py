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
from typing import Dict, List, Optional, Set, Tuple

import ida_lines
from xrefer.core.helpers import get_visible_width, strip_color_codes


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

        # States given:
        # 'base', 'search', 'call focus',
        # 'function trace', 'path trace', 'full trace',
        # 'graph', 'pinned graph', 'simplified graph', 'pinned simplified graph',
        # 'boundary results', 'last boundary results',
        # 'interesting artifacts', 'clusters', 'pinned cluster graphs', 'cluster graphs',
        # 'xref listing', 'help'

        # Global actions (no states specified = appear in all states)
        global_actions = [
            Action("ESC", "go back or return to IDA", ActionCategory.KEYBOARD),
            Action("ENTER", "return to home (base) state", ActionCategory.KEYBOARD),
            Action("H", "show/hide help", ActionCategory.KEYBOARD),
            Action("D", "add selected artifacts to exclusions", ActionCategory.KEYBOARD),
            Action("U", "toggle exclusions globally", ActionCategory.KEYBOARD),
            Action("E", "expand/collapse table sections", ActionCategory.KEYBOARD),
            Action("click", "expand items/access details", ActionCategory.MOUSE),
            Action("dbl-click", "select/deselect artifacts or jump", ActionCategory.MOUSE),
            Action("hover", "show tooltips/details", ActionCategory.MOUSE),
        ]

        # Actions for 'base' state
        base_actions = [
            Action("S", "enter search mode", ActionCategory.KEYBOARD, {"base"}),
            Action("T", "enter/cycle trace scopes", ActionCategory.KEYBOARD, {"base"}),
            Action("C", "enter clusters mode", ActionCategory.KEYBOARD, {"base"}),
            Action("I", "show interesting artifacts", ActionCategory.KEYBOARD, {"base"}),
            Action("X", "show cross-references for artifact", ActionCategory.KEYBOARD, {"base"}),
            Action("B", "run boundary scan (with selected artifacts)", ActionCategory.KEYBOARD, {"base"}),
            Action("L", "show last boundary scan results", ActionCategory.KEYBOARD, {"base"}),
            Action("G", "show artifact path graph (press again to pin/unpin)", ActionCategory.KEYBOARD, {"base"}),
            Action("P", "focus on a call instruction (call focus)", ActionCategory.KEYBOARD, {"base"}),
        ]

        # Search mode: no special actions besides global; user just types to filter
        # call focus: no additional actions except global

        # Trace modes:
        # After pressing T in base:
        # 'function trace', 'path trace', 'full trace' states:
        # No unique keys beyond globals.
        # If desired, we can specify that T is not visible here since it's only for base.
        # We'll leave them global or no states needed since no new keys for these states.

        # Clusters:
        # After pressing C in base: could be 'clusters' state or if you differentiate:
        # The user states "clusters" is a state. Possibly pressing C from base leads to 'clusters' first.
        # from 'clusters' pressing C might lead to 'cluster graphs' or pressing again might revert back.
        # Add keys relevant to clusters:
        # If you consider 'clusters' as initial cluster table view, 'cluster graphs' as a separate state:
        cluster_actions = [
            Action("C", "toggle cluster table/graph", ActionCategory.KEYBOARD, {"clusters", "cluster graphs"}),
            Action("J", "toggle cluster sync in graphs", ActionCategory.KEYBOARD, {"cluster graphs", "pinned cluster graphs"}),
        ]

        # Graph states:
        # 'graph', 'pinned graph', 'simplified graph', 'pinned simplified graph':
        # Let's assign:
        # G was only from base. In these states we might not show G again.
        # S is used to toggle simplified mode in artifact graphs. The user provided states like 'graph', 'pinned graph', etc.
        # Let's say we show 'S' in any graph-related states that support simplification:
        graph_states = ["graph", "pinned graph", "simplified graph", "pinned simplified graph"]
        graph_actions = [Action("S", "toggle simplified graph view", ActionCategory.KEYBOARD, set(graph_states))]

        search_actions = [
            Action("X", "show cross-references for artifact", ActionCategory.KEYBOARD, {"search"}),
            Action("G", "show artifact path graph (press again to pin/unpin)", ActionCategory.KEYBOARD, {"search"}),
        ]

        # Interesting artifacts ('interesting artifacts'):
        # No special keys besides global.

        # Xref listing ('xref listing'):
        # No special keys besides global.

        # Boundary results ('boundary results', 'last boundary results'):
        # If we want L to show in these states as well:
        # L is already shown in base, if we want it also in these states:
        boundary_actions = [Action("L", "show last boundary scan results", ActionCategory.KEYBOARD, {"boundary results", "last boundary results"})]

        # Since B triggers boundary scans, you might have 'boundary results' after pressing B or L from base.
        # Add these if needed.

        # Add all actions together
        self.actions = global_actions + base_actions + cluster_actions + graph_actions + search_actions + boundary_actions

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
