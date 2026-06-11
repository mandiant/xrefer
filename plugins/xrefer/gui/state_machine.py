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
    orphans = State("orphans")
    clusters = State("clusters")
    pinned_cluster_graphs = State("pinned cluster graphs")
    cluster_graphs = State("cluster graphs")
    neighborhood_graph = State("neighborhood graph")
    pinned_neighborhood_graph = State("pinned neighborhood graph")
    xref_listing = State("xref listing")
    help = State("help")
    attack_matrix = State("attack matrix")
    # Binary-wide artifact search (Shift+S from home): substring-filters
    # every entity — imports, libraries, strings, capa matches — as the
    # analyst types, with X / G / double-click pivots into the existing
    # views. A real state (like search), not a per-view filter flag: it
    # owns its own rendering rather than narrowing an underlying view.
    artifact_search = State("artifact search")

    # primary transitions
    start_search = base.to(search)
    start_artifact_search = base.to(artifact_search)
    start_call_focus = base.to(call_focus)
    start_trace = base.to(trace_scope_function)
    start_graph = base.to(graph) | search.to(graph) | artifact_search.to(graph)
    start_xref_listing = base.to(xref_listing) | search.to(xref_listing) | artifact_search.to(xref_listing)
    start_boundary_results = base.to(boundary_results)
    start_last_boundary_results = base.to(last_boundary_results)
    start_orphans = base.to(orphans)
    start_cluster_graphs = (
        base.to(cluster_graphs)
        | clusters.to(cluster_graphs)
        # M from the neighborhood view is allowed to land back inside
        # cluster_graphs (auto-activating the intermediate sub-view) so
        # the analyst can chain "show me my neighborhood" → "show me my
        # cluster's intermediate paths" without manually ESC-ing first.
        | neighborhood_graph.to(cluster_graphs)
        | pinned_neighborhood_graph.to(cluster_graphs)
        # Clicking a cluster chip inside the ATT&CK matrix jumps into that
        # cluster's graph.
        | attack_matrix.to(cluster_graphs)
    )
    # Neighborhood view is reachable from any banner-bearing state.
    # Centered on cursor, shows 1-hop callgraph adjacency to other
    # clusters; falls back to BFS-discovered nearest clusters when
    # the cursor has no direct neighbours.
    start_neighborhood_graph = (
        base.to(neighborhood_graph)
        | clusters.to(neighborhood_graph)
        | cluster_graphs.to(neighborhood_graph)
        | pinned_cluster_graphs.to(neighborhood_graph)
        | graph.to(neighborhood_graph)
        | pinned_graph.to(neighborhood_graph)
        | simplified_graph.to(neighborhood_graph)
        | pinned_simplified_graph.to(neighborhood_graph)
    )

    # ATT&CK matrix view — binary-wide (or cluster-scoped) kill-chain
    # coverage built from the per-cluster MITRE mappings. Reachable from the
    # home view and the cluster views; scoped to the active cluster when
    # entered from a cluster graph.
    start_attack_matrix = (
        base.to(attack_matrix)
        | clusters.to(attack_matrix)
        | cluster_graphs.to(attack_matrix)
        | pinned_cluster_graphs.to(attack_matrix)
    )

    # help transition
    start_help = (
        base.to(help)
        | call_focus.to(help)
        | trace_scope_function.to(help)
        | graph.to(help)
        | pinned_graph.to(help)
        | simplified_graph.to(help)
        | pinned_simplified_graph.to(help)
        | boundary_results.to(help)
        | trace_scope_path.to(help)
        | last_boundary_results.to(help)
        | xref_listing.to(help)
        | trace_scope_full.to(help)
        | orphans.to(help)
        | clusters.to(help)
        | cluster_graphs.to(help)
        | pinned_cluster_graphs.to(help)
        | neighborhood_graph.to(help)
        | pinned_neighborhood_graph.to(help)
        | attack_matrix.to(help)
    )

    # graph transitions
    toggle_on_pinned_graph = graph.to(pinned_graph) | simplified_graph.to(pinned_simplified_graph)
    toggle_on_graph = pinned_graph.to(graph) | pinned_simplified_graph.to(simplified_graph) | pinned_simplified_graph.to(graph)
    toggle_simplified = graph.to(simplified_graph) | pinned_graph.to(pinned_simplified_graph)
    toggle_normal = simplified_graph.to(graph) | pinned_simplified_graph.to(pinned_graph)
    toggle_pinned_cluster_graph = cluster_graphs.to(pinned_cluster_graphs)
    toggle_unpinned_cluster_graph = pinned_cluster_graphs.to(cluster_graphs)
    toggle_pinned_neighborhood_graph = neighborhood_graph.to(pinned_neighborhood_graph)
    toggle_unpinned_neighborhood_graph = pinned_neighborhood_graph.to(neighborhood_graph)

    # cluster transitions
    toggle_on_cluster_graphs = clusters.to(cluster_graphs)
    toggle_on_clusters = cluster_graphs.to(clusters)

    # trace transitions
    toggle_on_trace_scope_path = trace_scope_function.to(trace_scope_path)
    toggle_on_trace_scope_full = trace_scope_path.to(trace_scope_full)
    toggle_on_trace_scope_function = trace_scope_full.to(trace_scope_function)

    # trace revert transitions — ESC steps the scope cycle back one at a
    # time (full -> path -> function), the inverse of T's forward cycle.
    # The full -> path arm did not exist, so ESC from the full scope had
    # no single-step way back and skipped past path.
    revert_trace_scope_full_to_trace_scope_path = trace_scope_full.to(trace_scope_path)
    revert_trace_scope_path_to_trace_scope_fn = trace_scope_path.to(trace_scope_function)

    # help revert transitions
    revert_help_to_call_focus = help.to(call_focus)
    revert_help_to_trace_fn = help.to(trace_scope_function)
    revert_help_to_trace_p = help.to(trace_scope_path)
    revert_help_to_trace_f = help.to(trace_scope_full)
    revert_help_to_graph = help.to(graph)
    revert_help_to_pinned_graph = help.to(pinned_graph)
    revert_help_to_simplified_graph = help.to(simplified_graph)
    revert_help_to_pinned_simplified_graph = help.to(pinned_simplified_graph)
    revert_help_to_boundary_results = help.to(boundary_results)
    revert_help_to_last_boundary_results = help.to(last_boundary_results)
    revert_help_to_xref_listing = help.to(xref_listing)
    revert_help_to_orphans = help.to(orphans)
    revert_help_to_interesting_clusters = help.to(clusters)
    revert_help_to_interesting_cluster_graphs = help.to(cluster_graphs)
    revert_help_to_pinned_cluster_graphs = help.to(pinned_cluster_graphs)
    revert_help_to_neighborhood_graph = help.to(neighborhood_graph)
    revert_help_to_pinned_neighborhood_graph = help.to(pinned_neighborhood_graph)

    # Exit transitions for the neighborhood view — ``go_back`` walks the
    # state history looking for a transition from the *current* state to
    # the *previous* state. Without these, ESC from neighborhood would
    # always fall through to ``to_base`` (which reaches base only) and
    # the analyst would lose their cluster context. One reverse per
    # supported entry state (mirrors ``start_neighborhood_graph``).
    revert_neighborhood_graph_to_clusters = neighborhood_graph.to(clusters) | pinned_neighborhood_graph.to(clusters)
    revert_neighborhood_graph_to_cluster_graphs = neighborhood_graph.to(cluster_graphs) | pinned_neighborhood_graph.to(cluster_graphs)
    revert_neighborhood_graph_to_pinned_cluster_graphs = neighborhood_graph.to(pinned_cluster_graphs) | pinned_neighborhood_graph.to(pinned_cluster_graphs)
    revert_neighborhood_graph_to_graph = neighborhood_graph.to(graph) | pinned_neighborhood_graph.to(graph)
    revert_neighborhood_graph_to_simplified_graph = neighborhood_graph.to(simplified_graph) | pinned_neighborhood_graph.to(simplified_graph)
    revert_neighborhood_graph_to_pinned_graph = neighborhood_graph.to(pinned_graph) | pinned_neighborhood_graph.to(pinned_graph)
    revert_neighborhood_graph_to_pinned_simplified_graph = neighborhood_graph.to(pinned_simplified_graph) | pinned_neighborhood_graph.to(pinned_simplified_graph)

    # ATT&CK matrix exits — one reverse per entry state so go_back (ESC / K)
    # returns the analyst to wherever they opened it (base is covered by
    # to_base below).
    revert_attack_matrix_to_clusters = attack_matrix.to(clusters)
    revert_attack_matrix_to_cluster_graphs = attack_matrix.to(cluster_graphs)
    revert_attack_matrix_to_pinned_cluster_graphs = attack_matrix.to(pinned_cluster_graphs)
    revert_help_to_attack_matrix = help.to(attack_matrix)

    # search revert transitions
    revert_xref_listing_to_search = xref_listing.to(search)
    revert_graph_to_search = graph.to(search)
    # … and the same pair for artifact search, so ESC from a pivoted
    # xref listing / path graph returns to the result list (go_back
    # needs an explicit arm targeting the previous state).
    revert_xref_listing_to_artifact_search = xref_listing.to(artifact_search)
    revert_graph_to_artifact_search = graph.to(artifact_search)

    # base transition
    to_base = (
        search.to(base)
        | call_focus.to(base)
        | trace_scope_function.to(base)
        | trace_scope_path.to(base)
        | trace_scope_full.to(base)
        | graph.to(base)
        | simplified_graph.to(base)
        | pinned_graph.to(base)
        | pinned_simplified_graph.to(base)
        | boundary_results.to(base)
        | last_boundary_results.to(base)
        | xref_listing.to(base)
        | help.to(base)
        | orphans.to(base)
        | clusters.to(base)
        | cluster_graphs.to(base)
        | pinned_cluster_graphs.to(base)
        | neighborhood_graph.to(base)
        | pinned_neighborhood_graph.to(base)
        | attack_matrix.to(base)
        | artifact_search.to(base)
    )

    def __init__(self):
        self._search_filter = ""
        self._address_filter = ""
        self._cluster_sync_enabled: bool = False
        self._hide_library_clusters: bool = True
        # When non-None, the cluster-graph view renders the
        # "intermediate function paths" sub-view for this function
        # instead of the cluster's normal node graph. Set by the M key
        # from cluster_graphs and cleared by M or ESC. Kept on the
        # state machine (rather than on the view) so it survives
        # transitions and is cleared on reset_state alongside other
        # cluster UI flags.
        self._intermediate_view_func_ea: Optional[int] = None
        # When True, the intermediate view shows paths across every
        # cluster the function appears in. When False (default), it
        # scopes to the cluster the user came from — so the spider
        # graph stays small and contextual. Toggled with the A key
        # while in the intermediate view.
        self._intermediate_view_show_all: bool = False
        # Bookkeeping for the ESC / M-exit "full undo" path. When M
        # opens the intermediate view it may need to push a cluster
        # (overview state) and/or transition state (cross-view jump
        # from base / clusters / neighborhood). These flags let the
        # exit handler know what to roll back so M and ESC fully
        # mirror each other.
        self._intermediate_view_pushed_cluster: bool = False
        self._intermediate_view_transitioned_state: bool = False
        # Cluster the ATT&CK matrix is scoped to (None = binary-wide). Set
        # when K opens the matrix from a cluster graph; read by
        # draw_attack_matrix; cleared on reset_state.
        self._attack_matrix_scope_cluster_id: Optional[int] = None
        self._selected_index: Optional[int] = None
        # Per-view substring filter (S in the full-trace / orphans reading
        # views). Unlike the search STATE — a base-view mode with its own
        # transitions — this is a flag layered onto the current state: the
        # view keeps rendering, rows not matching search_filter are hidden,
        # and printable keys feed the filter while it is active. Cleared on
        # reset_state, on ESC, and whenever the state changes.
        self._view_filter_active: bool = False
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

            # toggle_ events are mode flips (pin, sync, library visibility)
            # whose states must not be revisited — EXCEPT the cluster
            # table <-> graph pair, a real view change that ESC / K / N
            # should walk back through (the revert_*_to_clusters
            # transitions exist but were never reachable past this filter,
            # stranding the triage loop in the overview).
            event_name = str(event)
            # toggle_ events are mode flips (pin, sync, library visibility)
            # whose states must not be revisited — EXCEPT real view changes
            # that ESC should walk back through one at a time: the cluster
            # table <-> graph pair, and the trace-scope cycle. Without the
            # trace exemptions, ESC returning from help (or any state opened
            # from a trace scope) would skip past the scope the user was in.
            is_mode_flip = event_name.startswith("toggle_") and event_name not in (
                "toggle_on_clusters",
                "toggle_on_cluster_graphs",
                "toggle_on_trace_scope_path",
                "toggle_on_trace_scope_full",
                "toggle_on_trace_scope_function",
            )

            # Check if this state meets our criteria
            if prev_state != current_state and not is_mode_flip:
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
                            # log(f"[-] Error during transition: {str(e)}")
                            return False, None
                # log(f"No transition found from {current_state.name} to {prev_state.name}")
                return False, None

        # log("No suitable previous state found")
        return False, None

    def return_to_clusters_table(self) -> bool:
        """ESC support for the table → cluster-graph → ESC triage loop.

        When the active cluster graph was entered FROM the clusters table,
        transition back to the table and truncate the history so a further
        ESC keeps walking toward base. The table's history entry is
        recorded with a toggle_ event, which ``go_back`` would need extra
        context to pick (the graph may legitimately sit between two table
        visits), so the raw history is scanned here: the nearest distinct
        prior state decides. Returns False when the graph was entered any
        other way (overview / base / chip click from elsewhere) — callers
        keep the existing overview behavior.
        """
        if self.current_state != self.cluster_graphs:
            return False
        for i in range(len(self._state_history) - 2, -1, -1):
            prev_state, _event = self._state_history[i]
            if prev_state == self.current_state:
                continue
            if prev_state != self.clusters:
                return False
            self._state_history = self._state_history[: i + 1]
            self.toggle_on_clusters()
            return True
        return False

    def step_back_trace_scope(self) -> bool:
        """ESC within the trace-scope cycle steps back exactly one scope
        (full -> path -> function) and then out to base.

        This is a pure function of the CURRENT scope, not of history, so
        it never skips a scope and never dead-ends on the cyclic history
        the T key builds (T wraps full -> function, which would otherwise
        leave ``go_back`` with no single-step arm to walk). Returns False
        when not in a trace scope, so the caller falls through to the
        normal ESC handling.
        """
        if self.current_state == self.trace_scope_full:
            return bool(self.revert_trace_scope_full_to_trace_scope_path())
        if self.current_state == self.trace_scope_path:
            return bool(self.revert_trace_scope_path_to_trace_scope_fn())
        if self.current_state == self.trace_scope_function:
            return bool(self.to_base())
        return False

    def reset_state(self) -> None:
        """Reset state machine to initial conditions."""
        self._state_history.clear()
        self._cluster_sync_enabled = False
        self._intermediate_view_func_ea = None
        self._intermediate_view_show_all = False
        self._intermediate_view_pushed_cluster = False
        self._intermediate_view_transitioned_state = False
        self._attack_matrix_scope_cluster_id = None
        self._search_filter = ""
        self._address_filter = ""
        self._view_filter_active = False
        self._selected_index = None

    def adopt_selected_refs(self, store: Dict[int, Set[int]]) -> None:
        """Use an externally-owned dict as the selection store.

        The view passes the core analyzer's persisted dict, so user
        selections survive IDA restarts: the state machine mutates the
        adopted dict in place and the analyzer pickles it with the DB —
        without the core layer ever importing gui state.
        """
        self._selected_refs = store

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
        return self.current_state in (self.pinned_graph, self.pinned_simplified_graph, self.pinned_cluster_graphs, self.pinned_neighborhood_graph)

    @property
    def view_filter_active(self) -> bool:
        """Whether the per-view row filter is live (see __init__ note)."""
        return self._view_filter_active

    @view_filter_active.setter
    def view_filter_active(self, value: bool) -> None:
        self._view_filter_active = bool(value)

    def is_sticky_state(self) -> bool:
        """Check if the current state is a binary-wide "reading" view.

        These views' content does not depend on the cursor function, so
        cross-function navigation in the disassembly must not tear them
        down — ESC / their toggle keys are the explicit exits. Boundary
        results are included because they render the selections of the
        function they were invoked from; the view keeps their func_ea
        frozen while sticky (see XReferView.update).
        """
        return self.current_state in (
            self.clusters,
            self.attack_matrix,
            self.orphans,
            self.xref_listing,
            self.boundary_results,
            self.last_boundary_results,
            self.trace_scope_full,
            self.help,
            self.artifact_search,
        )

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

    # NB: these helpers deliberately do *not* use the ``toggle_`` /
    # ``start_`` / ``revert_`` / ``to_`` / ``end_`` prefix — those
    # name patterns get auto-wrapped by ``_wrap_transitions`` for
    # state-transition error handling, and that wrapper double-binds
    # ``self`` (only safe for transitions taking ``event=None``).
    # These are plain data-flag flips so the prefix-free names keep
    # them out of the wrapper.

    def flip_intermediate_view(self, func_ea: Optional[int]) -> bool:
        """Toggle into / out of the intermediate-paths sub-view.

        The view is only meaningful when the user is currently in a
        cluster-graph state and the supplied ``func_ea`` is on a
        function that has at least one intermediate-path entry. The
        caller (key handler) is responsible for that precondition;
        this method just flips the flag.

        On exit, the M-undo bookkeeping flags
        (``_intermediate_view_pushed_cluster`` /
        ``_intermediate_view_transitioned_state``) are also cleared.
        Callers that need to inspect the *prior* values must read
        them before invoking the exit toggle.

        Returns True when the flag changed (caller should redraw).
        """
        if self.current_state not in (self.cluster_graphs, self.pinned_cluster_graphs):
            return False
        if self._intermediate_view_func_ea is not None:
            # Currently in intermediate view → exit.
            self._intermediate_view_func_ea = None
            self._intermediate_view_show_all = False
            self._intermediate_view_pushed_cluster = False
            self._intermediate_view_transitioned_state = False
            return True
        if func_ea is None:
            return False
        self._intermediate_view_func_ea = func_ea
        # Default scope is "current cluster only" (False); user can
        # widen it with A.
        self._intermediate_view_show_all = False
        return True

    def flip_intermediate_scope(self) -> bool:
        """Flip intermediate view between current-cluster and
        all-clusters scope. Only meaningful while the intermediate
        view is active.
        """
        if self._intermediate_view_func_ea is None:
            return False
        self._intermediate_view_show_all = not self._intermediate_view_show_all
        return True

    def toggle_hide_library_clusters(self, event=None) -> bool:
        """Flip the hide-library-clusters preference. Only meaningful from
        cluster table / cluster graph / pinned cluster graph states; returns
        False otherwise so the caller can fall back to other behavior.
        """
        if self.current_state not in (self.clusters, self.cluster_graphs, self.pinned_cluster_graphs, self.attack_matrix):
            return False
        self._hide_library_clusters = not self._hide_library_clusters
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

    @property
    def hide_library_clusters(self) -> bool:
        """Whether library clusters are filtered out of cluster views."""
        return self._hide_library_clusters

    @property
    def attack_matrix_scope_cluster_id(self) -> Optional[int]:
        """Cluster id the ATT&CK matrix is scoped to, or None for the
        binary-wide matrix."""
        return self._attack_matrix_scope_cluster_id

    @attack_matrix_scope_cluster_id.setter
    def attack_matrix_scope_cluster_id(self, value: Optional[int]) -> None:
        self._attack_matrix_scope_cluster_id = value

    @property
    def intermediate_view_func_ea(self) -> Optional[int]:
        """The function the intermediate-paths sub-view is rendering
        for, or ``None`` when the sub-view isn't active."""
        return self._intermediate_view_func_ea

    @property
    def intermediate_view_show_all(self) -> bool:
        """Whether the intermediate-paths sub-view is in 'all clusters'
        scope. False = current cluster only (default)."""
        return self._intermediate_view_show_all

    @property
    def intermediate_view_pushed_cluster(self) -> bool:
        """True when M pushed a cluster onto the cluster_manager
        stack when it opened the intermediate view. Used by the exit
        handler to know whether to pop on undo."""
        return self._intermediate_view_pushed_cluster

    @intermediate_view_pushed_cluster.setter
    def intermediate_view_pushed_cluster(self, value: bool) -> None:
        self._intermediate_view_pushed_cluster = bool(value)

    @property
    def intermediate_view_transitioned_state(self) -> bool:
        """True when M transitioned state to cluster_graphs (cross-
        view jump) when opening the intermediate view. Used by the
        exit handler to know whether to ``go_back`` on undo."""
        return self._intermediate_view_transitioned_state

    @intermediate_view_transitioned_state.setter
    def intermediate_view_transitioned_state(self, value: bool) -> None:
        self._intermediate_view_transitioned_state = bool(value)


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
            from xrefer.gui.helpers import log

            log(f"[XReferStateMachine] Unexpected error during state transition: {str(e)}")
            return False

        return False

    return wrapper
