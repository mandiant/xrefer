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

from dataclasses import dataclass, field
from functools import wraps
from typing import Dict, List, Optional, Set, Tuple

from statemachine import State, StateMachine
from statemachine import exceptions as sm_exceptions
from xrefer.core.helpers import log


class XReferStateMachine(StateMachine):
    """
    State machine managing XRefer UI states and transitions.

    Handles all possible states and transitions of the XRefer interface,
    including search, graph view, trace analysis, and more.
    """

    # State definitions
    base = State("base", initial=True)
    search = State("search")
    call_focus = State("call focus")
    trace_scope_function = State("function trace")
    trace_scope_path = State("path trace")
    trace_scope_full = State("full trace")
    graph = State("graph")
    pinned_graph = State("pinned graph")
    simplified_graph = State("simplified graph")
    pinned_simplified_graph = State("pinned simplified graph")
    boundary_results = State("boundary results")
    last_boundary_results = State("last boundary results")
    interesting_artifacts = State("interesting artifacts")
    clusters = State("clusters")
    pinned_cluster_graphs = State("pinned cluster graphs")
    cluster_graphs = State("cluster graphs")
    xref_listing = State("xref listing")
    help = State("help")

    # primary transitions
    start_search = base.to(search)
    start_call_focus = base.to(call_focus)
    start_trace = base.to(trace_scope_function)
    start_graph = base.to(graph) | search.to(graph) | interesting_artifacts.to(graph)
    start_xref_listing = base.to(xref_listing) | search.to(xref_listing) | interesting_artifacts.to(xref_listing)
    start_boundary_results = base.to(boundary_results)
    start_last_boundary_results = base.to(last_boundary_results)
    start_interesting_artifacts = base.to(interesting_artifacts)
    start_cluster_graphs = base.to(cluster_graphs) | clusters.to(cluster_graphs)

    # help transition
    start_help = (
        base.to(help)
        | call_focus.to(help)
        | trace_scope_function.to(help)
        | graph.to(help)
        | pinned_graph.to(help)
        | boundary_results.to(help)
        | trace_scope_path.to(help)
        | last_boundary_results.to(help)
        | xref_listing.to(help)
        | trace_scope_full.to(help)
        | interesting_artifacts.to(help)
        | clusters.to(help)
        | cluster_graphs.to(help)
        | pinned_cluster_graphs.to(help)
    )

    # graph transitions
    toggle_on_pinned_graph = graph.to(pinned_graph) | simplified_graph.to(pinned_simplified_graph)
    toggle_on_graph = pinned_graph.to(graph) | pinned_simplified_graph.to(simplified_graph) | pinned_simplified_graph.to(graph)
    toggle_simplified = graph.to(simplified_graph) | pinned_graph.to(pinned_simplified_graph)
    toggle_normal = simplified_graph.to(graph) | pinned_simplified_graph.to(pinned_graph)
    toggle_pinned_cluster_graph = cluster_graphs.to(pinned_cluster_graphs)
    toggle_unpinned_cluster_graph = pinned_cluster_graphs.to(cluster_graphs)

    # interesting artifact transitions
    toggle_on_interesting_artifacts = clusters.to(interesting_artifacts)

    # cluster transitions
    toggle_on_cluster_graphs = clusters.to(cluster_graphs)
    toggle_on_clusters = cluster_graphs.to(clusters)

    # trace transitions
    toggle_on_trace_scope_path = trace_scope_function.to(trace_scope_path)
    toggle_on_trace_scope_full = trace_scope_path.to(trace_scope_full)
    toggle_on_trace_scope_function = trace_scope_full.to(trace_scope_function)

    # trace revert transition
    revert_trace_scope_path_to_trace_scope_fn = trace_scope_path.to(trace_scope_function)

    # help revert transitions
    revert_help_to_call_focus = help.to(call_focus)
    revert_help_to_trace_fn = help.to(trace_scope_function)
    revert_help_to_trace_p = help.to(trace_scope_path)
    revert_help_to_trace_f = help.to(trace_scope_full)
    revert_help_to_graph = help.to(graph)
    revert_help_to_pinned_graph = help.to(pinned_graph)
    revert_help_to_boundary_results = help.to(boundary_results)
    revert_help_to_last_boundary_results = help.to(last_boundary_results)
    revert_help_to_xref_listing = help.to(xref_listing)
    revert_help_to_interesting_artifacts = help.to(interesting_artifacts)
    revert_help_to_interesting_clusters = help.to(clusters)
    revert_help_to_interesting_cluster_graphs = help.to(cluster_graphs)
    revert_help_to_pinned_cluster_graphs = help.to(pinned_cluster_graphs)

    # search revert transitions
    revert_xref_listing_to_search = xref_listing.to(search)
    revert_graph_to_search = graph.to(search)

    # interesting artifacts revert transitions
    revert_graph_to_interesting_artifacts = graph.to(interesting_artifacts)
    revert_xref_listing_to_interesting_artifacts = xref_listing.to(interesting_artifacts)

    # base transition
    to_base = (
        search.to(base)
        | call_focus.to(base)
        | trace_scope_function.to(base)
        | graph.to(base)
        | simplified_graph.to(base)
        | boundary_results.to(base)
        | last_boundary_results.to(base)
        | xref_listing.to(base)
        | help.to(base)
        | interesting_artifacts.to(base)
        | clusters.to(base)
        | cluster_graphs.to(base)
        | pinned_cluster_graphs.to(base)
    )

    def __init__(self):
        self._search_filter = ""
        self._address_filter = ""
        self._cluster_sync_enabled: bool = False
        self._selected_index: Optional[int] = None
        self._boundary_methods: Optional[list] = None
        self._selected_refs = {}
        self._state_history: List[tuple] = []
        self._cursor_positions: Dict[State, Tuple[int, int, int]] = {}  # Maps states to (lineno, x, y)
        self.cluster_manager = ClusterStateManager()
        super().__init__()
        self._wrap_transitions()

    def on_enter_state(self, event_data) -> None:
        """Handle state entry events."""
        state_name = event_data.state.name if hasattr(event_data.state, "name") else str(event_data.state)
        event_name = event_data.event if isinstance(event_data.event, str) else getattr(event_data.event, "name", str(event_data.event))
        # log(f"Entering state: {state_name} (Event: {event_name})")

        if event_data.state == self.base:
            self.reset_state()

        if not self._state_history or self._state_history[-1][0] != self.current_state:
            self._state_history.append((self.current_state, event_data.event))

    def on_exit_state(self, event_data):
        """Only for debugging states."""
        state_name = event_data.state.name if hasattr(event_data.state, "name") else str(event_data.state)
        event_name = event_data.event if isinstance(event_data.event, str) else getattr(event_data.event, "name", str(event_data.event))
        # log(f"Exiting state: {state_name} (Event: {event_name})")

    def _wrap_transitions(self) -> bool:
        """
        Wrap all transition methods with safety checks.

        Ensures all state transitions are properly wrapped with error handling
        and logging.

        Returns:
            bool: True if wrapping was successful
        """
        for attr_name in dir(self):
            if attr_name.startswith(("start_", "end_", "to_", "toggle_", "revert_")):
                attr = getattr(self, attr_name)
                if callable(attr):
                    wrapped = safe_transition(attr)
                    setattr(self, attr_name, wrapped.__get__(self, self.__class__))

    def store_cursor_position(self, state: State, lineno: int, x: int = 0, y: int = 0) -> None:
        """Store cursor position for a given state."""
        self._cursor_positions[state] = (lineno, x, y)

    def get_cursor_position(self, state: State) -> Optional[Tuple[int, int, int]]:
        """Get stored cursor position for a state."""
        return self._cursor_positions.get(state)

    def go_back(self) -> Tuple[bool, Optional[Tuple[int, int, int]]]:
        """Navigate to previous valid state."""
        if len(self._state_history) <= 1:
            return False, None

        current_state = self.current_state

        # Iterate through history in reverse
        for i in range(len(self._state_history) - 2, -1, -1):
            prev_state, event = self._state_history[i]

            # Check if this state meets our criteria
            if prev_state != current_state and not event.startswith("toggle_"):
                # Find the transition
                for transition in current_state.transitions:
                    if transition.target == prev_state:
                        try:
                            # Get stored cursor position before updating history
                            cursor_pos = self.get_cursor_position(prev_state)
                            getattr(self, transition.event)()
                            # Remove states from history up to this point
                            self._state_history = self._state_history[: i + 1]
                            # log(f"Successfully transitioned to {self.current_state.name}")
                            return True, cursor_pos
                        except Exception as e:
                            # log(f"Error during transition: {str(e)}")
                            return False, None
                # log(f"No transition found from {current_state.name} to {prev_state.name}")
                return False, None

        # log("No suitable previous state found")
        return False, None

    def reset_state(self) -> None:
        """Reset state machine to initial conditions."""
        self._state_history.clear()
        self._cluster_sync_enabled = False
        self._search_filter = ""
        self._address_filter = ""
        self._selected_index = None

    def update_selected_refs(self, func_ea: int, e_index: int) -> None:
        """Update the set of selected references for a function."""
        if func_ea not in self._selected_refs:
            self._selected_refs[func_ea] = {e_index}
        elif e_index in self._selected_refs[func_ea]:
            self._selected_refs[func_ea].discard(e_index)
        else:
            self._selected_refs[func_ea].add(e_index)

    def get_selected_refs(self, func_ea: int) -> Set[int]:
        """Get set of selected references for a function."""
        return self._selected_refs.get(func_ea, set())

    def is_simplified_graph(self) -> bool:
        """Check if current state is a simplified graph view."""
        return self.current_state in (self.simplified_graph, self.pinned_simplified_graph)

    def is_pinned_graph(self) -> bool:
        """Check if current state is a pinned graph view."""
        return self.current_state in (self.pinned_graph, self.pinned_simplified_graph, self.pinned_cluster_graphs)

    def push_cluster_graph(self, cluster_id: int, parent_cluster_id: Optional[int] = None) -> None:
        """Delegate to cluster manager."""
        self.cluster_manager.push_cluster(cluster_id, parent_cluster_id)

    def get_current_cluster(self) -> Optional[Tuple[int, Optional[int]]]:
        """Convert ClusterViewState to original tuple format for compatibility."""
        if state := self.cluster_manager.get_current_cluster():
            return (state.cluster_id, state.parent_id)
        return None

    def get_previous_cluster(self) -> Optional[Tuple[int, Optional[int]]]:
        """Get previous cluster info maintaining original format."""
        # Temporarily pop current to get previous
        current = self.cluster_manager.pop_cluster()
        if not current:
            return None

        # Get previous (now current)
        previous = self.get_current_cluster()

        # Restore current
        self.cluster_manager.push_cluster(current)

        return previous

    def navigate_cluster_graph_back(self) -> bool:
        """Delegate navigation to cluster manager."""
        if self.current_state != self.cluster_graphs:
            return False

        return self.cluster_manager.pop_cluster() is not None

    def clear_cluster_history(self) -> None:
        """Delegate to cluster manager."""
        self.cluster_manager.clear()

    def store_cluster_position(self, cluster_id: int, lineno: int, x: int = 0, y: int = 0) -> None:
        """Delegate to cluster manager."""
        self.cluster_manager.store_cursor_pos(cluster_id, (lineno, x, y))

    def store_relationship_graph_position(self, lineno: int, x: int = 0, y: int = 0) -> None:
        """Delegate to cluster manager."""
        self.cluster_manager.store_relationship_pos((lineno, x, y))

    def get_cluster_position(self, cluster_id: int) -> Optional[Tuple[int, int, int]]:
        """Delegate to cluster manager."""
        return self.cluster_manager.get_cursor_pos(cluster_id)

    def get_relationship_graph_position(self) -> Optional[Tuple[int, int, int]]:
        """Delegate to cluster manager."""
        return self.cluster_manager.get_relationship_pos()

    def toggle_cluster_sync(self, event=None) -> bool:
        """
        Toggle cluster sync state and handle related state changes.

        Args:
            event: State machine event (optional)

        Returns:
            bool: True if state was changed
        """
        current_state = self.current_state

        # Only toggle if in appropriate states
        if current_state not in (self.cluster_graphs, self.pinned_cluster_graphs):
            return False

        self._cluster_sync_enabled = not self._cluster_sync_enabled

        # Handle pinned state based on sync
        if self._cluster_sync_enabled:
            if current_state == self.cluster_graphs:
                return self.toggle_pinned_cluster_graph()
        else:
            if current_state == self.pinned_cluster_graphs:
                return self.toggle_unpinned_cluster_graph()

        return True

    @property
    def search_filter(self) -> str:
        return self._search_filter

    @search_filter.setter
    def search_filter(self, value: str) -> None:
        self._search_filter = value

    @property
    def address_filter(self) -> str:
        return self._address_filter

    @address_filter.setter
    def address_filter(self, value: str) -> None:
        self._address_filter = value

    @property
    def boundary_methods(self) -> Optional[list]:
        return self._boundary_methods

    @boundary_methods.setter
    def boundary_methods(self, value: list) -> None:
        self._boundary_methods = value

    @property
    def selected_index(self) -> Optional[int]:
        return self._selected_index

    @selected_index.setter
    def selected_index(self, value: Optional[int]) -> None:
        self._selected_index = value

    @property
    def state_history(self) -> Optional[list]:
        """Get the state transition history."""
        return self._state_history

    @property
    def cluster_sync_enabled(self) -> bool:
        """Check if cluster sync is enabled."""
        return self._cluster_sync_enabled


@dataclass
class ClusterViewState:
    """
    Tracks view state for a single cluster.

    Attributes:
        cluster_id: ID of cluster
        simplified: Whether graph is in simplified mode
        cursor_pos: Saved cursor position (lineno, x, y)
        parent_id: ID of parent cluster if any
        dual_references: Set of addresses referencing this cluster directly
    """

    cluster_id: int
    simplified: bool = True
    cursor_pos: Optional[tuple[int, int, int]] = None
    parent_id: Optional[int] = None
    dual_references: Set[int] = field(default_factory=set)


class ClusterStateManager:
    """
    Manages view states for cluster graphs.

    Tracks current active cluster and view states for all clusters
    while staying coordinated with main state machine.
    """

    def __init__(self):
        self._cluster_states: Dict[int, ClusterViewState] = {}
        self._history: List[int] = []  # Stack of cluster IDs being viewed
        self._relationship_pos: Optional[tuple[int, int, int]] = None
        self._show_report: bool = False

    def push_cluster(self, cluster_id: int, parent_id: Optional[int] = None) -> None:
        """Add cluster to view history with dual-purpose awareness."""
        dual_refs = set()

        if cluster_id not in self._cluster_states:
            self._cluster_states[cluster_id] = ClusterViewState(cluster_id=cluster_id, parent_id=parent_id, dual_references=dual_refs)
        self._history.append(cluster_id)

    def pop_cluster(self) -> Optional[int]:
        """Remove and return top cluster from history."""
        if self._history:
            return self._history.pop()
        return None

    def get_current_cluster(self) -> Optional[ClusterViewState]:
        """Get state of currently viewed cluster."""
        if not self._history:
            return None
        return self._cluster_states[self._history[-1]]

    def toggle_view_mode(self) -> None:
        """Toggle between simplified/full view for current cluster."""
        if current := self.get_current_cluster():
            current.simplified = not current.simplified

    def toggle_report_view(self) -> None:
        """Toggle between showing description or full report."""
        self._show_report = not self._show_report

    def is_showing_report(self) -> bool:
        """Check if currently showing report view."""
        return self._show_report

    def store_cursor_pos(self, cluster_id: int, pos: tuple[int, int, int]) -> None:
        """Store cursor position for a cluster view."""
        if cluster_id in self._cluster_states:
            self._cluster_states[cluster_id].cursor_pos = pos

    def store_relationship_pos(self, pos: tuple[int, int, int]) -> None:
        """Store cursor position for relationship graph view."""
        self._relationship_pos = pos

    def get_cursor_pos(self, cluster_id: int) -> Optional[tuple[int, int, int]]:
        """Get stored cursor position for a cluster."""
        if state := self._cluster_states.get(cluster_id):
            return state.cursor_pos
        return None

    def get_relationship_pos(self) -> Optional[tuple[int, int, int]]:
        """Get stored cursor position for relationship graph."""
        return self._relationship_pos

    def clear(self) -> None:
        """Clear all stored states."""
        self._cluster_states.clear()
        self._history.clear()
        self._relationship_pos = None
        self._show_report = False


def safe_transition(func):
    """
    Decorator for safe state machine transitions.

    Wraps state transition functions with error handling and logging.
    Prevents crashes from invalid state transitions.

    Args:
        func: State transition function to wrap

    Returns:
        Wrapped function that handles transition errors gracefully
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
            return True
        except sm_exceptions.TransitionNotAllowed as e:
            self = args[0] if args else None
            current_state = self.current_state.name if self else "Unknown"
            # Use func.name if available, else func.__name__, else 'Unknown'
            attempted_transition = getattr(func, "name", getattr(func, "__name__", "Unknown"))
            # log(f"[XReferStateMachine] Transition not allowed: {attempted_transition} from {current_state}")
        except Exception as e:
            # log(f"[XReferStateMachine] Unexpected error during state transition: {str(e)}")
            pass

        return False

    return wrapper
