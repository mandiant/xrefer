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


import enum
import re
import traceback
import weakref
from collections import OrderedDict, defaultdict
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple, Union

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_idaapi
import idaapi
import idautils
import idc
import networkx as nx
from qtpy import QtCore, QtGui, QtWidgets

from xrefer._vendor import ascii_graphs
from xrefer.core.analyzer import ApiCall, XRefer
from xrefer.core.helpers import (cap_artifact_entries, find_cluster_analysis, get_addr_from_text, longest_line_length, parse_cluster_id, remove_non_displayable,
                                 strip_color_codes, word_wrap_text, wrap_substring_with_string)
from xrefer.core.mitre import aggregate_mitre_matrix, mitre_attack_url
from xrefer.core.settings import XReferSettingsManager
from xrefer.gui.action_handlers import (ClusterEverythingHandler, EstimateClusterTokensHandler, CopyAllStringsHandler, CopyDirectIndirectStringsHandler, CopyDirectStringsHandler,
                                        CopyOrphanStringsHandler, CopyUncategorizedStringsHandler, PeekViewToggleHandler, ViewAttackMatrixHandler)
from xrefer.gui.help import ContextHelp
from xrefer.gui.helpers import (CollapseEventFilter, CollapseIndicator, FocusEventFilter, KeyEventFilter, colorize_api_call, create_cluster_relationship_graph,
                                create_colored_table_from_cols, create_xrefs_table_colored, draw_cluster_hierarchy, find_cluster_analysis,
                                format_api_call_for_ida, help_text, log, patch_asciinet, qt_object_alive, register_popup_action,
                                render_markdown_report_lines, set_focus_to_code, set_xref_coverage_color, twidget_to_qt)
from xrefer.gui.legacy.shim import format_ribbon
from xrefer.gui.state_machine import XReferStateMachine


class XReferView(idaapi.simplecustviewer_t):
    """
    Main view class for XRefer plugin.

    Provides the primary interface for displaying and interacting with
    cross-references, traces, graphs, and other analysis results.

    Attributes:
        original_ida_shortcuts (Dict): Stored IDA shortcuts for restoration
        xrefer_obj (XRefer): Core XRefer analysis object
        cell_regex (Pattern): Regex for parsing table cells
        address_regex (Pattern): Regex for finding addresses in text
        table_states (OrderedDict): Expansion state of tables
        subtable_states (Dict): Expansion state of subtables
        api_expansion_state (defaultdict): State of expanded API calls
        xref_coverage_dict (Dict): Cross-reference coverage tracking
        current_table (Optional[str]): Currently displayed table
        tooltip_cache (Dict): Cache of generated tooltips
        state_machine (XReferStateMachine): UI state management
        peek_flag (bool): Whether peek view is enabled
        last_boundary_scan_results (Optional[str]): Results from last boundary scan
    """

    class view_hooks(ida_kernwin.View_Hooks):
        def __init__(self):
            ida_kernwin.View_Hooks.__init__(self)

        @staticmethod
        def _dummy_cb(*args: Any) -> None:
            pass

        def _get_cb(self, view: Any, cb_name: str) -> Callable:
            cb: Callable = self._dummy_cb
            if view == self.GetWidget():
                cb = getattr(self, cb_name, cb)
            return cb

    def __init__(self, owner: Any, ep: Optional[int] = None):
        super(XReferView, self).__init__()
        self.original_ida_shortcuts = {}
        self.xrefer_obj: XRefer = self._xrefer(ep)
        self.context_help = ContextHelp()
        self.cell_regex: re.Pattern = re.compile(
            r"(?:^ {4,8}|[│┐└]\x02\x18\x20{3})"  # Match either standard indent or vertical line pattern
            r"(?:[☐☑]\x20)?"  # Optional selection checkbox (T2)
            r"(?:(?:imp|lib)\x20)?"  # Optional imp/lib type tag in the merged table (T2)
            r"\x01[^\x10]"  # Start of color code. Exclude CREFTAIL for address
            r"(?:\x20{0,4}(?:[→↓]\x20)?)?"  # Optional arrow with spaces
            r"(.+?)"  # The actual content (non-greedy)
            r"\x02."  # End of color code
            r"\x20*"  # Any number of trailing spaces
        )
        self.address_regex: re.Pattern = re.compile(r"0x[0-9a-fA-F]+")
        # Imports and libraries are both categorized into the same
        # Categorizer CATEGORIES, so two separate indirect tables would
        # repeat every category header. Present them as one merged table
        # (built by _merge_indirect_tables); import vs library stays
        # visually distinct via the existing row colors.
        self.merged_indirect_name: str = "INDIRECT IMPORT & LIBRARY XREFS"
        # Same redundancy in the orphans view: orphan imports and orphan
        # libraries both group by category, so merge them too.
        self.merged_orphan_name: str = "ORPHAN IMPORTS & LIBRARIES"
        self.table_states: OrderedDict[str, int] = OrderedDict(
            [
                (self.merged_indirect_name, 1),       # merged INDIRECT IMPORT + LIBRARY XREFS
                (self.xrefer_obj.table_names[3], 1),  # INDIRECT STRING XREFS
                (self.xrefer_obj.table_names[4], 1),  # INDIRECT CAPA XREFS
                ("DIRECT XREFS", 1),
                # Orphan-view tables. Same expand/collapse machinery
                # (handle_key_e, the [+]/[-] click handler, get_parent_table)
                # all key off membership in this dict, so registering them
                # here is enough — no separate state-tracking dicts needed.
                (self.merged_orphan_name, 1),
                ("ORPHAN STRINGS", 1),
                ("ORPHAN CAPA RULES", 1),
            ]
        )
        # HACK: Bring back color_tags just for IDA. We removed this from the core because we didn't want to keep IDA specific logic in core. However, to bring back the coloring in the IDA plugin, we directly
        self.xrefer_obj.color_tags = {
                self.xrefer_obj.table_names[1]: ida_lines.SCOLOR_DEMNAME, # "INDIRECT LIBRARY XREFS"
                self.xrefer_obj.table_names[2]: ida_lines.SCOLOR_IMPNAME, # "INDIRECT IMPORT XREFS"
                self.xrefer_obj.table_names[3]: ida_lines.SCOLOR_DSTR,    # "INDIRECT STRING XREFS"
                self.xrefer_obj.table_names[4]: ida_lines.SCOLOR_CODNAME, # "INDIRECT CAPA XREFS"
            }

        # Per-function tables that participate in the rotating
        # base-view loop. Orphan tables live in the same ``table_states``
        # dict (so the [+]/[-] click handler "just works") but are NOT
        # iterated as part of per-function rendering — that loop must
        # see only these per-function entries. The indirect import and
        # library tables are presented as one merged table.
        self.table_names: List[str] = [
            self.merged_indirect_name,
            self.xrefer_obj.table_names[3],
            self.xrefer_obj.table_names[4],
            "DIRECT XREFS",
        ]
        # Orphan-view tables in display order. Used by ``draw_orphans``
        # and by ``get_parent_table`` (which accepts either the per-
        # function names or these orphan names as parents of a "(+)" /
        # "(-)" sub-toggle line).
        self.orphan_table_names: List[str] = [
            self.merged_orphan_name,
            "ORPHAN STRINGS",
            "ORPHAN CAPA RULES",
        ]
        # Maps orphan table name -> EntityType id (1=lib, 2=import,
        # 3=string, 4=capa) so the renderer can pick the right color
        # tag and source list. The merged imports+libraries table is
        # handled separately (it spans two types), so it is not listed
        # here; ORPHAN IMPORTS / ORPHAN LIBRARIES remain as the source
        # types used when building the merged table.
        self._orphan_table_to_type: Dict[str, int] = {
            "ORPHAN IMPORTS": 2,
            "ORPHAN LIBRARIES": 1,
            "ORPHAN STRINGS": 3,
            "ORPHAN CAPA RULES": 4,
        }
        self.subtable_states: Dict[str, Dict[str, bool]] = {}
        self.api_expansion_state = defaultdict(lambda: defaultdict(lambda: {"direct": False, "indirect": False}))
        self.xref_coverage_dict: Dict[int, Dict[int, bool]] = {}
        self.current_table: Optional[str] = None
        self.tooltip_cache: Dict[int, Tuple[int, str]] = {}
        self.owner: Any = owner
        self.ui_hooks: Optional[Hooks] = None
        self.rebase_hook: Optional[RebaseHook] = None
        self.func_ea: Optional[int] = None
        self.state_machine: XReferStateMachine = XReferStateMachine()
        self.table_index_offset: int = len(self.table_names) - 1  # default starts from direct xrefs (last entry)
        self.table_count: int = len(self.table_names)
        # 8 spaces aligns expanded-table row content with the heading text that
        # follows the "----" continuation marker; see draw_function_context_table_heading.
        # Used to be OS-conditional (4 on macOS, 8 on Win/Linux) which produced
        # noticeably shallower indentation on Mac. Unified across platforms.
        self.indent: str = "        "
        self.INDENT: str = "    "  # Standard 4-space indentation
        self.peek_flag: bool = False
        self.last_boundary_scan_results: Optional[str] = None
        self.title: str = "XRefer - Navigator"
        self.focus_event_filter = None
        self.event_filter = None
        self.widget = None
        self.qt_widget = None
        self.dock_widget = None
        # Optional Qt children. Always present as attributes (set to None when
        # absent) so cleanup, deferred callbacks, and resize handlers can rely
        # on a uniform `is not None` / qt_object_alive check.
        self.collapse_indicator = None
        self.resize_filter = None
        self.close_handler = None
        self.last_non_graph_width = None
        self.in_graph_view = False
        self._is_collapsed = False
        self._from_double_click = False
        self._explicit_cluster_click = False
        # EXPERIMENT: "node detail" mode for the artifact-path graph. When on,
        # each function node also lists its direct artifacts (imports/strings/
        # capa/libs) inside the box — like the hover tooltip, but in-node. A
        # render flag (NOT a state) so it composes with the simplified/pinned
        # graph states instead of multiplying them; toggled by D in graph views
        # and folded into the graph cache key. Default off (it enlarges nodes).
        self.graph_node_artifacts = False
        # Per-artifact colour map for "node detail" mode, keyed by the same
        # graph cache_key: {displayed_artifact_text: SCOLOR}. Used to re-colour
        # each artifact by type AFTER the (colour-blind) ASCII layout. Kept
        # parallel to graph_cache (not inside it) because graph_cache is
        # serialized to the .xrefer DB and must keep its existing tuple shape.
        self._graph_artifact_colors: Dict[Any, Dict[str, int]] = {}
        # Cursor-independent ASCII layouts of the cluster graphs (see
        # _cluster_ascii_lines). View-local on purpose: unlike graph_cache it
        # is never serialized into the .xrefer DB, so a reload can't
        # resurrect layouts with stale function names.
        self._cluster_ascii_cache: Dict[Any, List[str]] = {}
        self._cluster_ascii_token: Any = None

        if self.xrefer_obj.lang:
            self.create()

    def __del__(self):
        """
        Clean up resources when the object is destroyed.
        """
        self.cleanup()

    def _connect_destroyed_handler(self, widget) -> None:
        """Connect a destroyed-signal slot bound to *this specific* widget.

        Why a closure: the destroyed signal fires asynchronously, after Qt
        processes ``deleteLater``. By that time, ``self.qt_widget`` may already
        have been reassigned to a *new* widget (recreate path). An unbound slot
        that does ``self.qt_widget = None`` would invalidate the new widget by
        mistake. Capturing ``widget`` in the closure means the slot only nils
        our reference when the destroyed widget IS still the one we hold.
        """
        def handler(*_args):
            if self.qt_widget is widget:
                self.qt_widget = None
                self.focus_event_filter = None
                self.event_filter = None
        widget.destroyed.connect(handler)

    def cleanup(self):
        """Clean up resources and event handlers, tolerant of partial teardown.

        IDA may have already destroyed the underlying widget by the time it
        invokes our cleanup, so each Qt access is guarded by a liveness check.
        Each block runs independently — a stale reference in one place doesn't
        prevent the rest of the cleanup from completing. Attributes are set to
        ``None`` rather than ``delattr``-ed so deferred callbacks see a stable
        attribute and bail out via ``qt_object_alive(self.X)``.
        """
        try:
            if qt_object_alive(self.qt_widget):
                if self.focus_event_filter is not None:
                    self.qt_widget.removeEventFilter(self.focus_event_filter)
                if self.event_filter is not None:
                    self.qt_widget.removeEventFilter(self.event_filter)

            self.focus_event_filter = None
            self.event_filter = None

            if qt_object_alive(self.collapse_indicator):
                self.collapse_indicator.hide()
                self.collapse_indicator.setParent(None)
                self.collapse_indicator.deleteLater()
            self.collapse_indicator = None

            self.resize_filter = None

            if qt_object_alive(self.dock_widget):
                self.dock_widget.setWidget(None)
                self.dock_widget.close()
                self.dock_widget.deleteLater()
            self.dock_widget = None

            if qt_object_alive(self.qt_widget):
                self.qt_widget.setParent(None)
                self.qt_widget.deleteLater()
            self.qt_widget = None

        except Exception as e:
            log(f"[-] Error during cleanup: {str(e)}")

    def s_view_activated(self) -> None:
        """
        Handle view activation.

        Updates cross-reference coverage dictionary and refreshes view
        when the XRefer window gains focus.
        """
        if self.func_ea is not None:
            self.xref_coverage_dict[self.func_ea] = self.generate_xref_coverage_dict(self.func_ea)
        self.update(True)

    def _xrefer(self, ep: Optional[int] = None) -> XRefer:
        xrefer_obj: XRefer = XRefer(ep)
        return xrefer_obj

    def create(self) -> None:
        """
        Initialize and create the XRefer view window.
        """
        try:
            # Clean up any existing resources first
            self.cleanup()
            patch_asciinet()

            if not idaapi.simplecustviewer_t.Create(self, self.title):
                log("widget creation failed")
                return

            # Get Qt widget for our viewer and set focus policy
            self.widget = self.GetWidget()
            if not self.widget:
                log("Failed to get widget")
                return

            self.qt_widget = twidget_to_qt(self.widget)
            if not self.qt_widget:
                log("Failed to get Qt widget")
                return

            # Clear our cached references when Qt destroys *this specific*
            # widget, so cleanup/show paths don't dereference stale wrappers.
            self._connect_destroyed_handler(self.qt_widget)

            self.qt_widget.setFocusPolicy(QtCore.Qt.StrongFocus)

            # Make the default widget invisible
            self.qt_widget.setVisible(False)

            # Create new event filters
            self.focus_event_filter = FocusEventFilter(self)
            self.event_filter = KeyEventFilter(self)

            # Install event filters
            self.qt_widget.installEventFilter(self.focus_event_filter)
            self.qt_widget.installEventFilter(self.event_filter)

            # Setup UI and rebase hooks
            self.setup_hooks()

            # Now create and show the dock widget
            self.show_custom_window()

            # Initial content population
            if not self.func_ea:
                idaapi.jumpto(int(self.xrefer_obj.current_analysis_ep))
                self.update(ea=int(self.xrefer_obj.current_analysis_ep))
            else:
                self.update(ea=self.func_ea)

        except Exception as e:
            log(f"[-] Error during create: {str(e)}")
            log(traceback.format_exc())
            self.cleanup()

        # Surface what happened to the just-run cluster analysis: a 'blocked'
        # budget dialog if it was skipped for window overflow, or a failure
        # dialog if it failed / completed partially — instead of letting the
        # initial-analysis flow swallow it. Outside the try/except above so a
        # dialog hiccup can't trigger view cleanup.
        try:
            from xrefer.gui.token_estimate import show_budget_block_if_pending, show_cluster_failure_if_pending
            show_budget_block_if_pending(getattr(self, "xrefer_obj", None))
            show_cluster_failure_if_pending(getattr(self, "xrefer_obj", None))
        except Exception:
            pass

    def show_custom_window(self) -> None:
        """
        Show custom docked window without using the default IDA tab view.
        """
        try:
            self.last_non_graph_width = None

            # Create dock window if needed
            self.position_window()

            if not self.dock_widget:
                log("Failed to create dock widget")
                return

            # Ensure event filters are properly installed
            if qt_object_alive(self.qt_widget):
                if not self.focus_event_filter:
                    self.focus_event_filter = FocusEventFilter(self)
                if not self.event_filter:
                    self.event_filter = KeyEventFilter(self)

                self.qt_widget.installEventFilter(self.focus_event_filter)
                self.qt_widget.installEventFilter(self.event_filter)

            # Force an initial refresh
            self.Refresh()

            # Get current function EA and update view
            current_ea = idc.get_screen_ea()
            func_ea = idc.get_name_ea_simple(idc.get_func_name(current_ea))
            if func_ea is not None:
                self.update(True)

            # Force a repaint
            if qt_object_alive(self.qt_widget):
                self.qt_widget.repaint()
        except Exception as e:
            log(f"[-] Error showing custom window: {str(e)}")
            self.cleanup()

    def Show(self, *args) -> None:
        """
        Override Show to use our custom window handling.

        If the underlying Qt widget was destroyed (e.g. user closed the dock),
        rebuild from scratch via ``create()``; otherwise just bring the existing
        window forward.
        """
        if not qt_object_alive(self.qt_widget):
            self.create()
        else:
            self.show_custom_window()

    def setup_hooks(self):
        """
        Setup UI and rebase hooks.
        """

        class Hooks(idaapi.UI_Hooks):
            def __init__(self, v: "XReferView"):
                ida_kernwin.UI_Hooks.__init__(self)
                self.hook()
                self.v: weakref.ReferenceType["XReferView"] = weakref.ref(v)

            def screen_ea_changed(self, ea: int, prev_ea: int) -> None:
                v: Optional["XReferView"] = self.v()
                if v is not None:
                    v.update(ea=ea)
                return super().screen_ea_changed(ea, prev_ea)

            def finish_populating_widget_popup(self, form: Any, popup: Any) -> None:
                menu_path: str = "XRefer/"
                menu_id = "XRefer:cluster_everything"
                tooltip = "Cluster all functions with non-excluded artifacts"
                label = "(Re-)run Cluster Analysis"
                register_popup_action(form, popup, menu_path, menu_id, label, ClusterEverythingHandler(), tooltip)
                menu_id = "XRefer:estimate_cluster_tokens"
                tooltip = "Estimate the cluster-analysis request + max response tokens against the model's context window"
                label = "Estimate Cluster Analysis Token Usage"
                register_popup_action(form, popup, menu_path, menu_id, label, EstimateClusterTokensHandler(), tooltip)
                menu_id = "XRefer:view_attack_matrix"
                tooltip = "Open the ATT&CK matrix heat-grid for the analyzed clusters' MITRE mappings"
                label = "View ATT&CK Matrix"
                register_popup_action(form, popup, menu_path, menu_id, label, ViewAttackMatrixHandler(), tooltip)
                menu_id = "XRefer:toggle_peek"
                tooltip = "Enable peeking of downstream cross-references of a clicked function in disassembly/pseudocode view"
                label = "Enable Peek View"
                register_popup_action(form, popup, menu_path, menu_id, label, PeekViewToggleHandler(), tooltip)
                copy_menu_path: str = "XRefer/Copy Strings/"
                register_popup_action(form, popup, copy_menu_path, "XRefer:copy_all_strings", "Copy all strings to clipboard", CopyAllStringsHandler(), "Copy every string discovered in the binary")
                register_popup_action(form, popup, copy_menu_path, "XRefer:copy_direct_strings", "Copy directly referenced strings to clipboard", CopyDirectStringsHandler(), "Copy strings reached through at least one direct cross-reference")
                register_popup_action(form, popup, copy_menu_path, "XRefer:copy_direct_indirect_strings", "Copy directly and indirectly referenced strings to clipboard", CopyDirectIndirectStringsHandler(), "Copy strings reached through direct or indirect cross-references")
                register_popup_action(form, popup, copy_menu_path, "XRefer:copy_orphan_strings", "Copy orphan strings to clipboard", CopyOrphanStringsHandler(), "Copy strings with no resolved use site reachable from an entry point")
                register_popup_action(form, popup, copy_menu_path, "XRefer:copy_uncategorized_strings", "Copy uncategorized strings to clipboard", CopyUncategorizedStringsHandler(), "Copy simple strings that carry no language-derived category")

        class RebaseHook(ida_idp.IDB_Hooks):
            def __init__(self, xrefer_view: "XReferView"):
                super().__init__()
                self.xrefer_view: "XReferView" = xrefer_view

            def allsegs_moved(self, info) -> int:
                self.xrefer_view.xrefer_obj.sync_image_base(False)
                # Cached cluster layouts and the func->cluster map embed
                # pre-rebase addresses.
                self.xrefer_view._invalidate_cluster_render_caches()
                self.xrefer_view.update(True)
                return 0

            def renamed(self, *args) -> int:
                # Cached cluster-graph layouts embed function names; drop
                # them when a cluster member is renamed so the next render
                # picks up the new name. Non-cluster renames are ignored
                # (they never appear in those layouts).
                try:
                    ea = int(args[0])
                except (IndexError, TypeError, ValueError):
                    return 0
                view = self.xrefer_view
                if view.xrefer_obj.clusters and ea in view._func_to_cluster_ids():
                    view._cluster_ascii_cache = {}
                    view._cluster_ascii_token = None
                return 0

        # Setup hooks if they don't exist
        if not self.ui_hooks:
            self.ui_hooks = Hooks(self)
            self.ui_hooks.hook()
        if not self.rebase_hook:
            self.rebase_hook = RebaseHook(self)
            self.rebase_hook.hook()

    def get_peek_state(self) -> bool:
        """Get current state of peek view."""
        return self.peek_flag

    def position_window(self) -> None:
        """Position and configure the window docking."""
        if not qt_object_alive(self.qt_widget):
            log("Qt widget not initialized")
            return

        # Find IDA's main window
        main_window = None
        for widget in QtWidgets.QApplication.topLevelWidgets():
            if widget.windowTitle().startswith("IDA - "):
                main_window = widget
                break

        if not main_window or not isinstance(main_window, QtWidgets.QMainWindow):
            log("Could not find IDA main window")
            return

        try:
            # Create new dock widget if it doesn't exist
            if not qt_object_alive(self.dock_widget):
                self.dock_widget = QtWidgets.QDockWidget(self.title, main_window)
                self.dock_widget.setObjectName("XReferDockWidget")

                # Store reference to XReferView in dock widget
                self.dock_widget.xrefer_view = self

                # Configure dock widget properties
                self.dock_widget.setFeatures(QtWidgets.QDockWidget.DockWidgetMovable | QtWidgets.QDockWidget.DockWidgetFloatable | QtWidgets.QDockWidget.DockWidgetClosable)

                # Set up the widget
                if self.qt_widget.parent():
                    self.qt_widget.setParent(None)
                self.dock_widget.setWidget(self.qt_widget)

                # Set size constraints
                default_witdh = self.xrefer_obj.settings["display_options"]["default_panel_width"]
                self.dock_widget.setMinimumWidth(default_witdh)
                self.dock_widget.setMinimumHeight(default_witdh)
                self.dock_widget.resize(default_witdh, self.dock_widget.height())
                self.dock_widget.updateGeometry()
                # Reset size constraints after a delay to allow resizing
                QtCore.QTimer.singleShot(100, self.reset_size_constraints)

                # Add dock widget to main window
                main_window.addDockWidget(QtCore.Qt.RightDockWidgetArea, self.dock_widget)

                # Create collapse indicator after dock widget setup
                self.collapse_indicator = CollapseIndicator(self.dock_widget, default_witdh)

                # Create and install event filter for dock widget
                self.resize_filter = CollapseEventFilter(self.collapse_indicator)
                self.dock_widget.installEventFilter(self.resize_filter)

                # Also monitor the main window for moves
                main_window.installEventFilter(self.resize_filter)

                # Handle close event
                def handle_close(event):
                    if qt_object_alive(self.collapse_indicator):
                        self.collapse_indicator.hide()
                    if qt_object_alive(self.dock_widget):
                        self.dock_widget.hide()
                    event.ignore()

                self.close_handler = handle_close
                self.dock_widget.closeEvent = self.close_handler

                # Connect visibility change handler
                self.dock_widget.visibilityChanged.connect(self.handle_visibility_changed)

                # Show dock widget and ensure indicator is visible
                self.dock_widget.show()

                # Schedule deferred repositioning. The lambdas may fire after
                # the dock has been closed/destroyed — guard each access via
                # the named helpers below.
                QtCore.QTimer.singleShot(50, self._show_and_reposition_indicator)
                QtCore.QTimer.singleShot(100, self._reposition_and_raise_indicator)
                QtCore.QTimer.singleShot(200, self._reposition_indicator)

            else:
                # If dock widget exists but is hidden, show it
                self.dock_widget.show()
                QtCore.QTimer.singleShot(50, self._show_and_reposition_indicator)
                QtCore.QTimer.singleShot(100, self._reposition_and_raise_indicator)

        except Exception as e:
            log(f"[-] Error creating dock widget: {str(e)}")
            self.cleanup()
            return

    # --- defensive helpers for deferred QTimer callbacks ---
    # Each runs after a delay; cleanup may have nilled the indicator in the
    # meantime. ``qt_object_alive`` returns False both for None and for a
    # wrapper whose C++ object has been deleted, so all three are safe no-ops
    # against a gone widget.

    def _show_and_reposition_indicator(self) -> None:
        if qt_object_alive(self.collapse_indicator):
            self.collapse_indicator.show()
            self.collapse_indicator.reposition()

    def _reposition_and_raise_indicator(self) -> None:
        if qt_object_alive(self.collapse_indicator):
            self.collapse_indicator.reposition()
            self.collapse_indicator.raise_()

    def _reposition_indicator(self) -> None:
        if qt_object_alive(self.collapse_indicator):
            self.collapse_indicator.reposition()

    def handle_visibility_changed(self, visible):
        """Handle dock widget visibility changes."""
        if visible and qt_object_alive(self.qt_widget):
            # Reinstall event filters if needed
            if not self.focus_event_filter:
                self.focus_event_filter = FocusEventFilter(self)
            if not self.event_filter:
                self.event_filter = KeyEventFilter(self)

            self.qt_widget.installEventFilter(self.focus_event_filter)
            self.qt_widget.installEventFilter(self.event_filter)

            # Show/reposition collapse indicator
            if qt_object_alive(self.collapse_indicator):
                self.collapse_indicator.show()
                self.collapse_indicator.reposition()

            self.update(True)
        elif not visible and qt_object_alive(self.collapse_indicator):
            self.collapse_indicator.hide()

    def reset_size_constraints(self):
        """Reset size constraints to allow user resizing.

        Scheduled via ``QTimer.singleShot`` after creating the dock; may fire
        after the dock has been closed. Skip silently if the dock is gone.
        """
        if not qt_object_alive(self.dock_widget):
            return
        self.dock_widget.setMinimumWidth(0)
        self.dock_widget.setMaximumWidth(16777215)  # Qt's QWIDGETSIZE_MAX
        self.dock_widget.updateGeometry()

    def override_ida_shortcuts(self) -> None:
        """
        Override global IDA shortcuts when view gains focus.

        Stores and disables global IDA shortcuts that might conflict with
        XRefer's keyboard handling.
        """
        app = QtWidgets.QApplication.instance()
        self.original_ida_shortcuts = {}
        for widget in app.allWidgets():
            for action in widget.actions():
                shortcut = action.shortcut()
                if shortcut == QtGui.QKeySequence(QtCore.Qt.Key_Space):
                    # Store the original shortcut to restore later
                    self.original_ida_shortcuts[action] = shortcut
                    # Clear the shortcut
                    action.setShortcut(QtGui.QKeySequence())

    def restore_ida_shortcuts(self) -> None:
        """
        Restore previously stored IDA shortcuts.

        Restores global IDA shortcuts when view loses focus.
        """
        """Restore global space shortcuts when viewer loses focus."""
        for action, shortcut in self.original_ida_shortcuts.items():
            action.setShortcut(shortcut)
        self.original_ida_shortcuts.clear()

    def toggle_collapsed_state(self, collapsed: bool) -> None:
        """Track widget collapsed state."""
        self._is_collapsed = collapsed

    def is_collapsed(self) -> bool:
        """Check if widget is currently collapsed."""
        return self._is_collapsed

    def OnClick(self, shift: bool) -> bool:
        """
        Handle mouse click events in the view.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if handled
        """
        try:
            word: str = self.get_current_word()
        except Exception as err:
            return False

        # ATT&CK matrix: clicking a technique id opens its MITRE page.
        if self.state_machine.current_state == self.state_machine.attack_matrix:
            url = mitre_attack_url(word)
            if url:
                try:
                    QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))
                except Exception:
                    pass
                return True

        # Handle cluster navigation
        if self.state_machine.current_state in (self.state_machine.cluster_graphs, self.state_machine.pinned_cluster_graphs, self.state_machine.clusters, self.state_machine.base, self.state_machine.attack_matrix):
            cluster_manager = self.state_machine.cluster_manager

            # If in cluster graph states, store current position before switching
            if self.state_machine.current_state not in (self.state_machine.base, self.state_machine.clusters, self.state_machine.attack_matrix):
                lineno, x, y = self.GetPos()
                if current := cluster_manager.get_current_cluster():
                    # Save cursor for the old cluster
                    cluster_id = parse_cluster_id(word)
                    if cluster_id is not None and cluster_id == current.cluster_id:
                        # Clicking on the same cluster ID
                        return True
                    cluster_manager.store_cursor_pos(current.cluster_id, (lineno, x, y))
                else:
                    cluster_manager.store_relationship_pos((lineno, x, y))

            # Check if user clicked on a cluster ID
            cluster_id = parse_cluster_id(word)
            if cluster_id is not None:
                # Mark that the user explicitly clicked a cluster ID
                self._explicit_cluster_click = True

                cluster = self.xrefer_obj.find_cluster_by_id(cluster_id)
                if cluster:
                    # Prepare to navigate to that cluster
                    if current := cluster_manager.get_current_cluster():
                        parent_id = current.cluster_id
                    else:
                        parent_id = None
                    cluster_manager.push_cluster(cluster_id, parent_id)

                    # Switch state to cluster graphs if needed
                    self.state_machine.start_cluster_graphs()
                    self.update(True)  # Force refresh
                    self.Jump(0, 0)
                    return True

        # Handle API expansion
        if word in ("→", "↓"):
            parent_table = self.get_parent_table()
            is_direct = parent_table.startswith("D")
            if is_direct or parent_table[9] == "I":
                line: str = self.GetCurrentLine()
                _, api_name = self.extract_cell_item(line)
                if api_name:
                    self.toggle_api_expansion(api_name, is_direct)
                    self.update(True)
                    return True

        # Expand / collapse: click anywhere on a heading or category row (each
        # starts with a ▸/▾ chevron) to toggle it. The label is parsed by
        # stripping color codes + chevron + the trailing "(N)" count, so it
        # works wherever on the row the click landed.
        try:
            clean = strip_color_codes(self.GetCurrentLine()).strip()
            if clean[:1] in ("▸", "▾"):
                label = self._strip_count_suffix(clean[1:].strip())
                if label in self.table_states:
                    self.table_states[label] = not self.table_states[label]
                    self.update(True)
                    return True
                table_name: Optional[str] = self.get_parent_table()
                if table_name and label in self.subtable_states.get(table_name, {}):
                    self.subtable_states[table_name][label] = not self.subtable_states[table_name][label]
                    self.update(True)
                    return True
        except Exception:
            pass

        return True

    def OnDblClick(self, shift: bool) -> bool:
        """
        Handle mouse double-click events in the view.
        """
        word: str = self.get_current_word()

        try:
            addr: int = get_addr_from_text(word)
            # Set a flag to indicate double-click navigation
            self._from_double_click = True
            idaapi.jumpto(int(addr))
            self.update(True, ea=addr)
            # Reset the flag after update
            self._from_double_click = False

        except Exception as err:
            line: str = self.GetCurrentLine()
            xref_cell, xref_item = self.extract_cell_item(line)

            if xref_item:
                try:
                    e_index: int = self.xrefer_obj.reverse_entity_lookup_index[xref_item]
                    self.state_machine.update_selected_refs(self.func_ea, e_index)

                    if e_index in self.state_machine.get_selected_refs(self.func_ea):
                        self.select_cell(xref_cell)
                    else:
                        self.deselect_cell(xref_cell)

                    self.update(True)
                except Exception as err:
                    pass
        return True

    def OnKeydown(self, vkey: int, shift: bool) -> bool:
        """
        Handle keyboard events in the view.

        Processes all keyboard shortcuts and commands based on current state.

        Args:
            vkey (int): Virtual key code of pressed key
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True to indicate event was handled
        """
        # While a modal dialog is open (e.g. the token-estimate box with its
        # model-search completer), the xrefer view must not process keys. IDA
        # can still route OnKeydown here even with the dialog up, which would
        # scroll the view behind it and steal arrow keys from the completer.
        # Report them as handled so nothing moves underneath the dialog.
        try:
            if QtWidgets.QApplication.activeModalWidget() is not None:
                return True
        except Exception:
            pass

        # Store current position before state change
        lineno, x, y = self.GetPos()
        self.state_machine.store_cursor_position(self.state_machine.current_state, lineno, x, y)

        state_before_handling_key = self.state_machine.current_state
        should_update = self.handle_key_specific_actions(vkey, shift)
        state_after_handling_key = self.state_machine.current_state

        # Check if we're entering or exiting graph view
        is_graph_before = state_before_handling_key in (
            self.state_machine.graph,
            self.state_machine.pinned_graph,
            self.state_machine.simplified_graph,
            self.state_machine.pinned_simplified_graph,
            self.state_machine.clusters,
            self.state_machine.cluster_graphs,
            self.state_machine.pinned_cluster_graphs,
        )

        is_graph_after = state_after_handling_key in (
            self.state_machine.graph,
            self.state_machine.pinned_graph,
            self.state_machine.simplified_graph,
            self.state_machine.pinned_simplified_graph,
            self.state_machine.clusters,
            self.state_machine.cluster_graphs,
            self.state_machine.pinned_cluster_graphs,
        )

        # Update graph state tracking
        if not is_graph_before and is_graph_after:
            self.in_graph_view = True
        elif is_graph_before and not is_graph_after:
            self.in_graph_view = False

        if state_after_handling_key == self.state_machine.search:
            if state_before_handling_key == self.state_machine.search:
                self.handle_search_input(vkey, shift)
                should_update = True

        if should_update:
            self.update(True)

        return True

    def OnHint(self, lineno: int) -> Optional[str]:
        """
        Generate tooltip text for the current line.

        Creates context-sensitive tooltips showing details about functions,
        cross-references, strings, or clusters depending on cursor position.

        Args:
            lineno (int): Line number where tooltip is requested

        Returns:
            Optional[str]: Tooltip text with color codes, or None if no tooltip
        """
        tooltip = None

        try:
            word: str = self.get_current_word()

            # Check for cluster ID first
            cluster_id = parse_cluster_id(word)
            if cluster_id is not None:
                cluster = self.xrefer_obj.find_cluster_by_id(cluster_id)
                if cluster:
                    # Look up analysis data using helper function
                    analysis_data = find_cluster_analysis(self.xrefer_obj.cluster_analysis, cluster_id)

                    if analysis_data and all(key in analysis_data for key in ["label", "description", "relationships"]):
                        tooltip = self.generate_cluster_tooltip(cluster, analysis_data)
                        return tooltip

            # Try to parse as address if not a cluster ID
            try:
                addr: int = get_addr_from_text(word)
                tooltip = self.generate_addr_tooltip(addr)
            except Exception:
                # Try string tooltip
                line: str = self.GetCurrentLine(True)
                _, xref_item = self.extract_cell_item(line)

                if xref_item:
                    try:
                        e_index: int = self.xrefer_obj.reverse_entity_lookup_index[xref_item]
                        # Indirect rows: list the callee functions this artifact
                        # is reached through (the indirection's "through what").
                        via_tip = self._indirect_via_tooltip(e_index)
                        str_tip = None
                        try:
                            matched_lines = self.xrefer_obj.entities[e_index][4]
                            all_repos = self.xrefer_obj.entities[e_index][5]
                            str_tip = self.generate_str_tooltip(matched_lines, all_repos)
                        except Exception:
                            str_tip = None
                        # OnHint must return an IDA hint tuple (num_lines, text)
                        # to display; merge the two (each already that shape).
                        tooltip = self._combine_tooltips(via_tip, str_tip)
                    except Exception as err:
                        tooltip = None

        except Exception as err:
            pass

        return tooltip

    def handle_search_input(self, vkey: int, shift: bool) -> None:
        """
        Handle keyboard input during search mode.

        Updates search filter based on keyboard input, handling special keys
        and printable characters appropriately.

        Args:
            vkey (int): Virtual key code of pressed key
            shift (bool): Whether shift key is pressed
        """
        special_key_codes = {161, 162, 163, 164, 165, 16, 17, 18, 9, 13, 27, 32, 33, 34, 35, 36, 37, 38, 39, 40, 45, 46, 91, 92, 93, *range(112, 124), 144, 145, 20, 8}

        if vkey == 8:  # backspace
            self.state_machine.search_filter = self.state_machine.search_filter[:-1]
        elif isinstance(vkey, str) and vkey.isprintable():
            self.state_machine.search_filter += vkey.lower()
        elif vkey not in special_key_codes:
            self.state_machine.search_filter += chr(vkey).lower()

    def handle_key_specific_actions(self, vkey: int, shift: bool) -> bool:
        key_actions: Dict[int, Callable[[bool], bool]] = {
            ord("A"): self.handle_key_a,
            ord("B"): self.handle_key_b,
            ord("C"): self.handle_key_c,
            ord("D"): self.handle_key_d,
            ord("E"): self.handle_key_e,
            ord("G"): self.handle_key_g,
            ord("H"): self.handle_key_h,
            ord("J"): self.handle_key_j,
            ord("K"): self.handle_key_k,
            ord("L"): self.handle_key_l,
            ord("M"): self.handle_key_m,
            ord("N"): self.handle_key_n,
            ord("O"): self.handle_key_o,
            ord("P"): self.handle_key_p,
            ord("R"): self.handle_key_r,
            ord("S"): self.handle_key_s,
            ord("T"): self.handle_key_t,
            ord("U"): self.handle_key_u,
            ord("V"): self.handle_key_v,
            ord("X"): self.handle_key_x,
            13: self.handle_key_enter,
            27: self.handle_key_escape,
        }

        key_handler: Callable[[bool], bool] = key_actions.get(vkey, self.handle_default)
        should_update = False

        try:
            should_update = key_handler(shift)
        except Exception as err:
            log(str(err))
            self.state_machine.to_base()  # Revert to base state on error

        return should_update

    def handle_key_b(self, shift: bool) -> bool:
        """
        Handle 'b' key press for boundary analysis.

        Initiates boundary method scan for currently selected artifacts,
        finding functions that contain all selected items.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if boundary scan was initiated, False otherwise
        """
        if self.state_machine.start_boundary_results():
            scan_entities = self.state_machine.get_selected_refs(self.func_ea)
            boundary_methods: List[int] = self.xrefer_obj.run_boundary_scan(scan_entities)
            self.state_machine.boundary_methods = boundary_methods
            return True
        return False

    def handle_key_c(self, shift: bool) -> bool:
        """
        Handle 'c' key press for cluster views.
        Toggles between cluster table and graph views.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if cluster view state was changed
        """
        if self.state_machine.current_state == self.state_machine.base:
            # Gate BEFORE the state transition: entering a cluster view with
            # no cluster data would re-render (and previously re-crash) on
            # every cross-function cursor move via screen_ea_changed.
            if not self.xrefer_obj.clusters:
                log("No cluster data — run Edit > XRefer > Run Analysis > (Re-)run Cluster Analysis first (requires an LLM configured under Edit > XRefer > Configure)")
                return False
            # Enter cluster table view
            return self.state_machine.start_cluster_graphs()
        elif self.state_machine.current_state == self.state_machine.cluster_graphs:
            # Switch to graph view
            return self.state_machine.toggle_on_clusters()
        elif self.state_machine.current_state == self.state_machine.clusters:
            # Switch back to table view
            return self.state_machine.toggle_on_cluster_graphs()
        return False

    def handle_key_p(self, shift: bool) -> bool:
        """
        Handle 'p' key press for call focus.

        Switches view to call focus mode when cursor is on a call instruction,
        showing context specific to that call.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if focus mode was entered, False otherwise
        """
        if self.state_machine.current_state != self.state_machine.call_focus:
            word: str = self.GetCurrentWord()
            if word.startswith("0x"):
                try:
                    addr: int = int(word, base=16)
                    if addr:
                        self.state_machine.address_filter = word
                        self.Jump(0, 0)
                        return self.state_machine.start_call_focus()
                except Exception:
                    pass
        return False

    def handle_key_d(self, shift: bool) -> bool:
        """
        Handle 'd' key press.

        Context-sensitive:
            * In the artifact-path graph states (graph / pinned / simplified /
              pinned-simplified), toggles "node detail" — whether each function
              node lists its direct artifacts inside the box.
            * In ``base``, adds the currently selected items to exclusions.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if handled, False if not in an appropriate state
        """
        sm = self.state_machine
        if sm.current_state in (sm.graph, sm.pinned_graph, sm.simplified_graph, sm.pinned_simplified_graph):
            # EXPERIMENT: flip in-node artifact rendering for the paths graph.
            self.graph_node_artifacts = not self.graph_node_artifacts
            return True

        if sm.current_state != sm.base:
            return False

        self.handle_exclusions()
        return True

    def handle_key_e(self, shift: bool) -> bool:
        """
        Handle 'e' key press for expand/collapse.

        Toggles expansion state of current table section. Active in the
        ``base`` xrefs view and in the ``orphans`` view, since both use
        the same ``table_states`` / ``subtable_states`` machinery.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if expansion state was toggled, False otherwise
        """
        if self.state_machine.current_state in (self.state_machine.base, self.state_machine.orphans):
            table_name: Optional[str] = self.get_parent_table()
            try:
                val: bool = not list(self.subtable_states[table_name].values())[0]
                for key in self.subtable_states[table_name]:
                    self.subtable_states[table_name][key] = val
            except Exception:
                pass
            return True
        return False

    def handle_key_g(self, shift: bool) -> bool:
        """
        Handle 'g' key press for graph view.

        Toggles between different graph states (normal, pinned, simplified)
        or initiates graph view for selected item.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if graph state was changed, False otherwise
        """
        current_state = self.state_machine.current_state

        if current_state == self.state_machine.attack_matrix:
            # G opens the Navigator-style heat-grid popup for the matrix.
            self.open_attack_matrix_popup()
            return True

        if current_state == self.state_machine.cluster_graphs:
            # Pin cluster graph
            return self.state_machine.toggle_pinned_cluster_graph()
        elif current_state == self.state_machine.pinned_cluster_graphs:
            # Unpin cluster graph
            return self.state_machine.toggle_unpinned_cluster_graph()

        # Handle regular graph pinning (existing logic)
        if current_state in (self.state_machine.graph, self.state_machine.pinned_graph, self.state_machine.simplified_graph, self.state_machine.pinned_simplified_graph):
            if current_state in (self.state_machine.graph, self.state_machine.simplified_graph):
                return self.state_machine.toggle_on_pinned_graph()
            else:
                return self.state_machine.toggle_on_graph()
        else:
            line: str = self.GetCurrentLine()
            _, xref_item = self.extract_cell_item(line)
            if xref_item:
                e_index: int = self.xrefer_obj.reverse_entity_lookup_index[xref_item]
                self.state_machine.selected_index = e_index

                return self.state_machine.start_graph()

        return False

    def handle_key_h(self, shift: bool) -> bool:
        """
        Handle 'h' key press for help display.

        Shows help text explaining available commands and features.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if help was displayed
        """
        return self.state_machine.start_help()

    def handle_key_k(self, shift: bool) -> bool:
        """Handle 'k' key — toggle the ATT&CK matrix view.

        Opens a kill-chain matrix built from the per-cluster MITRE ATT&CK
        mappings: a coverage strip plus tactic-grouped techniques, each
        linking back to the cluster(s) that ground it. Binary-wide from the
        home / cluster-table views; scoped to the active cluster when opened
        from a cluster graph. Pressing K again (or ESC) returns to the prior
        view. No-op until cluster analysis exists.
        """
        sm = self.state_machine
        current = sm.current_state

        if current == sm.attack_matrix:
            success, cursor_pos = sm.go_back()
            if cursor_pos:
                self.Jump(*cursor_pos)
            return True

        if current not in (sm.base, sm.clusters, sm.cluster_graphs, sm.pinned_cluster_graphs):
            return False
        if not self.xrefer_obj.clusters or not self.xrefer_obj.cluster_analysis:
            # Say why instead of silently swallowing the keypress.
            log("ATT&CK matrix needs cluster analysis — run Edit > XRefer > Run Analysis > (Re-)run Cluster Analysis first")
            return False

        # Scope to the active cluster when opened from a cluster graph;
        # otherwise present the whole binary.
        scope_id = None
        if current in (sm.cluster_graphs, sm.pinned_cluster_graphs):
            if cur := sm.cluster_manager.get_current_cluster():
                scope_id = cur.cluster_id
        sm.attack_matrix_scope_cluster_id = scope_id
        return sm.start_attack_matrix()

    def handle_key_j(self, shift: bool) -> bool:
        """
        Handle 'j' key press for cluster sync and navigation.

        Toggles sync mode in cluster views and handles function-to-cluster navigation.
        Prioritizes finding functions in current cluster before searching others,
        and normal nodes before intermediate nodes.

        Args:
            shift: Whether shift key is pressed

        Returns:
            bool: True if state was changed
        """
        current_state = self.state_machine.current_state

        # If in cluster view, toggle sync
        if current_state in (self.state_machine.cluster_graphs, self.state_machine.pinned_cluster_graphs):
            if not self.state_machine.cluster_sync_enabled:
                result = self.find_function_in_clusters(self.func_ea)

                if result:
                    cluster_id, is_intermediate = result
                    if not is_intermediate:
                        self.state_machine.cluster_manager.push_cluster(cluster_id)
                    # if current := self.state_machine.cluster_manager.get_current_cluster():
                    #     current.simplified = not is_intermediate

            self.state_machine.toggle_cluster_sync()
            return True

        # If in base state, try to find and display cluster
        elif current_state == self.state_machine.base:
            if not self.xrefer_obj.clusters:
                return False

            # Get current cluster ID if we're displaying one
            current_cluster_id = None
            if current := self.state_machine.cluster_manager.get_current_cluster():
                current_cluster_id = current.cluster_id

            result = self.find_function_in_clusters(self.func_ea, current_cluster_id)
            if result:
                cluster_id, is_intermediate = result

                if not is_intermediate:
                    # Switch to cluster graph view
                    if self.state_machine.start_cluster_graphs():
                        # Push cluster and configure view
                        self.state_machine.cluster_manager.push_cluster(cluster_id)
                        # if current := self.state_machine.cluster_manager.get_current_cluster():
                        #     current.simplified = not is_intermediate

                        # Enable sync and pin graph
                        self.state_machine.toggle_cluster_sync()
                        return True
            else:
                log(f"Function 0x{self.func_ea:x} not found in any clusters")

        return False

    def handle_key_l(self, shift: bool) -> bool:
        """
        Handle 'l' key press.

        Context-sensitive:
            * In ``clusters`` / ``cluster graphs`` / ``pinned cluster graphs``
              states, toggles whether library clusters are hidden in the
              cluster table and relationship graph.
            * Elsewhere, falls through to the original behavior of showing
              the most recent boundary scan results.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if the view should be redrawn
        """
        if self.state_machine.toggle_hide_library_clusters():
            return True
        return self.state_machine.start_last_boundary_results()

    def handle_key_o(self, shift: bool) -> bool:
        """Handle 'o' key press for the orphan-artifacts view.

        ``O`` is a toggle but is intentionally only wired up in two states:

        * From ``base`` it transitions into ``orphans`` (and the dispatcher
          calls :meth:`draw_orphans`).
        * From ``orphans`` it transitions back to ``base``.

        From any other state ``O`` is a no-op so the user doesn't end up
        opening the orphans table from inside a graph / cluster / search
        flow they're in the middle of.

        ESC continues to work as a generic "go back" via the state
        history, so the user has two ways to exit the table.
        """
        if self.state_machine.current_state == self.state_machine.base:
            return self.state_machine.start_orphans()
        if self.state_machine.current_state == self.state_machine.orphans:
            return self.state_machine.to_base()
        return False

    def _exit_intermediate_view_with_undo(self) -> bool:
        """Close the intermediate sub-view and roll back everything M
        did to open it.

        M may have (a) just flipped the flag in place, (b) pushed a
        cluster onto the cluster_manager stack (when opened from the
        cluster_graphs overview), and/or (c) transitioned state from
        base / clusters / neighborhood into cluster_graphs (cross-
        view jump). The bookkeeping flags
        ``intermediate_view_pushed_cluster`` /
        ``intermediate_view_transitioned_state`` recorded which of
        those happened. Reading them before the flip is important —
        the flip clears them.

        Used by both M (exit toggle) and ESC so the two exit paths
        are symmetric.
        """
        sm = self.state_machine
        if sm.intermediate_view_func_ea is None:
            return False
        if sm.current_state not in (sm.cluster_graphs, sm.pinned_cluster_graphs):
            return False

        pushed = sm.intermediate_view_pushed_cluster
        transitioned = sm.intermediate_view_transitioned_state

        if not sm.flip_intermediate_view(None):
            return False

        if pushed:
            sm.cluster_manager.pop_cluster()

        cursor_pos: Optional[Tuple[int, int, int]] = None
        if transitioned:
            success, cursor_pos = sm.go_back()
            # go_back failure isn't fatal — caller still gets a redraw
            # of whatever state we ended up in.

        self._explicit_cluster_click = True
        if cursor_pos:
            self.Jump(*cursor_pos)
        return True

    def handle_key_m(self, shift: bool) -> bool:
        """Handle 'm' key — open / close the intermediate-paths view.

        Behaviour:

        * **Already inside the intermediate sub-view** (any cluster-
          graph state) → M closes the sub-view and rolls back every
          side-effect M had when opening it (cluster push and state
          transition, when applicable). Mirrors ESC.
        * **Otherwise**, when the cursor is on a function that is
          intermediate of at least one cluster, M opens the sub-view.
          The handler will (a) push that cluster onto the cluster
          stack if no cluster is currently in view (covers the
          cluster_graphs *overview* state too — without this push,
          ``draw_cluster_graph`` falls through to the overview header
          and the intermediate flag is invisible), and (b) transition
          state to ``cluster_graphs`` from base / clusters /
          neighborhood / pinned_neighborhood.
        * **Anywhere else** M is a no-op so it doesn't collide with
          disasm / search / orphan flows.
        """
        sm = self.state_machine
        current = sm.current_state

        if sm.intermediate_view_func_ea is not None:
            return self._exit_intermediate_view_with_undo()

        # Open path. Eligible source states are those where the banner
        # hint advertises M.
        eligible = (
            sm.cluster_graphs,
            sm.pinned_cluster_graphs,
            sm.base,
            sm.clusters,
            sm.neighborhood_graph,
            sm.pinned_neighborhood_graph,
        )
        if current not in eligible:
            return False
        if not self.func_ea:
            return False

        # Cursor must be intermediate of something — reuse the same
        # classifier the Status row uses so the target cluster matches
        # what the analyst sees in the banner.
        status_kind, owner_ids = self._classify_cursor_relative_to_clusters(None)
        if status_kind != "intermediate" or not owner_ids:
            return False
        target_cluster_id = owner_ids[0]

        # Ensure a cluster is pushed so draw_individual_cluster_graph
        # is the dispatch target — without a pushed cluster,
        # draw_cluster_graph renders the overview header and never
        # checks the intermediate flag. Reuse an existing push if it
        # matches the target so we don't double-stack.
        pushed_now = False
        current_pushed = sm.cluster_manager.get_current_cluster()
        if current_pushed is None or current_pushed.cluster_id != target_cluster_id:
            sm.cluster_manager.push_cluster(target_cluster_id)
            pushed_now = True

        # Transition to cluster_graphs if we came from elsewhere.
        transitioned = current not in (sm.cluster_graphs, sm.pinned_cluster_graphs)
        if transitioned:
            if not sm.start_cluster_graphs():
                if pushed_now:
                    sm.cluster_manager.pop_cluster()
                return False

        if not sm.flip_intermediate_view(self.func_ea):
            if pushed_now:
                sm.cluster_manager.pop_cluster()
            return False

        # Record bookkeeping AFTER the flip — flip_intermediate_view
        # clears these on exit, so setting them post-entry guarantees
        # the next exit reads accurate values.
        sm.intermediate_view_pushed_cluster = pushed_now
        sm.intermediate_view_transitioned_state = transitioned

        self._explicit_cluster_click = True
        return True

    def handle_key_a(self, shift: bool) -> bool:
        """Handle 'a' key press — toggle scope of the intermediate view.

        Only meaningful while the intermediate sub-view is active.
        Flips between "current cluster only" (default — keeps the
        spider graph small and contextual) and "all clusters" (the
        previous global behaviour).
        """
        if self.state_machine.intermediate_view_func_ea is None:
            return False
        return self.state_machine.flip_intermediate_scope()

    def handle_key_v(self, shift: bool) -> bool:
        """Handle 'v' key — toggle the cursor neighborhood graph view.

        Available wherever the cluster context banner appears (base,
        clusters, cluster_graphs, paths_graph). Renders a focused
        asciinet graph with the cursor function in the centre and
        every adjacent cluster's gateway function around it; ESC
        returns to the previous view.

        Pressing V while already in the neighborhood view exits back
        the same way ESC would, so the same key both opens and
        closes the view.
        """
        sm = self.state_machine
        current = sm.current_state

        if current in (sm.neighborhood_graph, sm.pinned_neighborhood_graph):
            sm.go_back()
            return True

        eligible = (
            sm.base,
            sm.clusters,
            sm.cluster_graphs,
            sm.pinned_cluster_graphs,
            sm.graph,
            sm.simplified_graph,
            sm.pinned_graph,
            sm.pinned_simplified_graph,
        )
        if current not in eligible:
            return False
        if not self.func_ea:
            return False
        return sm.start_neighborhood_graph()

    def handle_key_n(self, shift: bool) -> bool:
        """
        Handle 'n' key press for function renaming.

        If the current word under the cursor corresponds directly to the start of a function,
        prompt the user to rename that function. If not, fallback to the logic of finding
        a function via its cross-references and renaming it.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if function was renamed, False if not on valid reference
        """
        word: str = self.get_current_word()
        addr: Optional[int] = None

        try:
            addr: int = get_addr_from_text(word)

            # Check if addr is itself a function start
            func_name_at_addr = idc.get_func_name(addr)

            if func_name_at_addr:
                new_name: str = idaapi.ask_str(func_name_at_addr, 0, "Enter new function name:")
                if new_name:
                    if idaapi.set_name(addr, new_name):
                        idaapi.refresh_idaview_anyway()
                        return True

            xrefs: List[idaapi.xref_t] = list(idautils.XrefsFrom(addr))
            xref_to_func_ea: int = 0
            old_name: str = ""
            for xref in xrefs:
                try:
                    if not idc.func_contains(addr, xref.to):
                        old_name = idc.get_func_name(xref.to)
                        xref_to_func_ea = xref.to
                        break
                except:
                    pass

            if old_name:
                idaapi.jumpto(int(addr))
                new_name: str = idaapi.ask_str(old_name, 0, "Enter new function name:")
                if new_name:
                    if idaapi.set_name(xref_to_func_ea, new_name):
                        idaapi.refresh_idaview_anyway()
                        func_ea: int = idc.get_name_ea_simple(idc.get_func_name(ida_idaapi.ea_t(addr)))
                        self.xref_coverage_dict[func_ea] = self.generate_xref_coverage_dict(func_ea)
                        return True
        except:
            pass

        return False

    def handle_key_r(self, shift: bool) -> bool:
        """
        Handle 'r' key press for resetting cluster graph history.

        When in cluster graph view, resets navigation history and returns
        to relationship graph view.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if handled, False otherwise
        """
        # Only handle in cluster graph modes
        if self.state_machine.current_state not in (self.state_machine.cluster_graphs, self.state_machine.pinned_cluster_graphs, self.state_machine.clusters):
            return False

        if self.state_machine.current_state != self.state_machine.clusters:
            if not self.state_machine.cluster_manager.get_current_cluster():
                # Toggle between description and report view
                self.state_machine.cluster_manager.toggle_report_view()
                return True
        else:
            self.state_machine.cluster_manager.toggle_report_view()
            return True

        # Clear cluster history
        self.state_machine.clear_cluster_history()

        # Return to base cluster state
        if self.state_machine.current_state == self.state_machine.pinned_cluster_graphs:
            self.state_machine.toggle_unpinned_cluster_graph()

        return True

    def handle_key_s(self, shift: bool) -> bool:
        """
        Handle 's' key press for search and graph simplification.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if handled, False if not
        """
        if self.state_machine.start_search():
            self.Jump(0, 0)
            return True

        # Finally handle other graph modes
        current_state = self.state_machine.current_state
        if current_state in (self.state_machine.graph, self.state_machine.pinned_graph):
            return self.state_machine.toggle_simplified()
        elif current_state in (self.state_machine.simplified_graph, self.state_machine.pinned_simplified_graph):
            return self.state_machine.toggle_normal()

        return False

    def handle_key_t(self, shift: bool) -> bool:
        """
        Handle 't' key press for trace view cycling.

        Cycles through different trace view scopes (function, path, full)
        or enters trace view mode.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if trace view state was changed
        """
        current_state = self.state_machine.current_state
        if current_state not in (self.state_machine.trace_scope_function, self.state_machine.trace_scope_path, self.state_machine.trace_scope_full):
            return self.state_machine.start_trace()
        elif current_state == self.state_machine.trace_scope_function:
            return self.state_machine.toggle_on_trace_scope_path()
        elif current_state == self.state_machine.trace_scope_path:
            return self.state_machine.toggle_on_trace_scope_full()
        else:
            return self.state_machine.toggle_on_trace_scope_function()

    def handle_key_u(self, shift: bool) -> bool:
        """
        Handle 'u' key press for toggling exclusions.

        Toggles global exclusions functionality on/off.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if exclusions was toggled, False if not in appropriate state
        """
        if self.state_machine.current_state not in (
            self.state_machine.base,
            self.state_machine.trace_scope_function,
            self.state_machine.trace_scope_path,
            self.state_machine.trace_scope_full,
        ):
            return False

        # Toggle the exclusions setting
        current_setting = self.xrefer_obj.settings["enable_exclusions"]
        self.xrefer_obj.settings["enable_exclusions"] = not current_setting

        # Save the updated setting
        self.xrefer_obj.settings_manager.save_settings(self.xrefer_obj.settings)
        self.xrefer_obj.process_exclusions()

        # Process exclusions and re-populate tables
        self.xrefer_obj.clear_affected_function_tables()

        return True

    def handle_key_x(self, shift: bool) -> bool:
        """
        Handle 'x' key press for cross-reference listing.

        Shows detailed cross-reference listing for selected item.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if xref listing was shown, False if no item selected
        """
        line: str = self.GetCurrentLine()
        _, xref_item = self.extract_cell_item(line)

        if xref_item:
            try:
                e_index: int = self.xrefer_obj.reverse_entity_lookup_index[xref_item]
                self.state_machine.selected_index = e_index
                return self.state_machine.start_xref_listing()
            except KeyError:
                return False

        return False

    def handle_key_enter(self, shift: bool) -> bool:
        """
        Handle Enter key press for navigation.

        Reset the view and go back to home page (function context tables view)

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if navigation occurred
        """
        self.state_machine.to_base()
        return True

    def handle_key_escape(self, shift: bool) -> bool:
        """
        Handle escape key for navigation.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: True if handled, False if not
        """
        if self.state_machine.current_state in (self.state_machine.cluster_graphs, self.state_machine.pinned_cluster_graphs):
            # If the intermediate sub-view is active, ESC first closes
            # *that* and rolls back every side-effect M had when
            # opening it (cluster push, state transition). M and ESC
            # are symmetric exits — pressing ESC inside the sub-view
            # takes the analyst back to where M was pressed in one
            # keystroke. Subsequent ESC presses then continue the
            # normal cluster-pop unwinding.
            if self._exit_intermediate_view_with_undo():
                self.update(True)
                return True

            cluster_manager = self.state_machine.cluster_manager

            # Store current position before navigation
            if current := cluster_manager.get_current_cluster():
                lineno, x, y = self.GetPos()
                cluster_manager.store_cursor_pos(current.cluster_id, (lineno, x, y))

                # Pop current cluster
                cluster_manager.pop_cluster()

                # Check if we should try to go back to relationship graph
                if not cluster_manager.get_current_cluster():  # History is empty
                    top_clusters = self.xrefer_obj.clusters or []
                    if len(top_clusters) == 1 and not top_clusters[0].subclusters:
                        # Single cluster with no subclusters - go back in state machine
                        success, cursor_pos = self.state_machine.go_back()
                        if cursor_pos:
                            self.Jump(*cursor_pos)
                        return success
                    else:
                        # Multiple clusters - restore relationship graph position
                        if pos := cluster_manager.get_relationship_pos():
                            self.Jump(*pos)
                else:
                    # Restore previous cluster's position
                    if prev := cluster_manager.get_current_cluster():
                        if pos := cluster_manager.get_cursor_pos(prev.cluster_id):
                            self.Jump(*pos)

                self.update(True)
                return True

        # Otherwise try default escape handling
        if len(self.state_machine.state_history) <= 1:
            set_focus_to_code()
            return False
        else:
            success, cursor_pos = self.state_machine.go_back()

            if cursor_pos:
                lineno, x, y = cursor_pos
                self.Jump(lineno, x, y)  # Restore cursor position
            if success:
                return True
            return False

    def handle_default(self, shift: bool) -> bool:
        """
        Handle unrecognized key press.

        Default handler for keys without specific handlers.

        Args:
            shift (bool): Whether shift key is pressed

        Returns:
            bool: False to indicate no action taken
        """
        return False

    def handle_exclusions(self) -> None:
        """
        Process exclusions of selected entities.

        Adds selected items to appropriate exclusions, updates settings,
        and refreshes view to reflect changes. Handles different entity
        types (APIs, libraries, strings, CAPA matches) appropriately.
        """
        # Get selected entities
        selected_entities = self.state_machine.get_selected_refs(self.func_ea)
        if not selected_entities:
            log("No artifacts selected for exclusions")
            return

        # Load current exclusions
        settings_manager = XReferSettingsManager()
        exclusions = settings_manager.load_exclusions()

        # Process each selected entity
        for entity_index in selected_entities:
            entity = self.xrefer_obj.entities[entity_index]
            category_name = entity[0]  # First item is the category
            name = entity[1]  # Second item is the full name
            entity_type = entity[2]  # Third item is the type (1=lib, 2=api, 3=string, 4=capa)

            # Extract the name part after the last dot
            if entity_type == 2:  # 2=api
                name = name.split(".")[-1] if "." in name else name

            # Map entity type to exclusions category
            type_to_category = {1: "libs", 2: "apis", 3: "strings", 4: "capa"}

            exclusion_category = type_to_category.get(entity_type)
            if exclusion_category:
                # Add to appropriate exclusions if not already present
                if name not in exclusions[exclusion_category]:
                    exclusions[exclusion_category].append(name)
                    log(f"Added '{name}' to {exclusion_category} exclusions")

        # Save updated exclusions
        self.xrefer_obj.settings["enable_exclusions"] = True
        settings_manager.save_exclusions(exclusions)
        settings_manager.save_settings(self.xrefer_obj.settings)
        self.xrefer_obj.process_exclusions()
        log("Exclusions updated successfully")

        # Re-populate context tables to reflect the excluded items
        self.xrefer_obj.clear_affected_function_tables()

    def toggle_api_expansion(self, api_name: str, is_direct: bool) -> None:
        """
        Toggle expansion state of API call details.

        Controls whether detailed call information (arguments, return values)
        is shown for a specific API.

        Args:
            api_name (str): Name of API to toggle expansion for
            is_direct (bool): Whether this is a direct or indirect call
        """
        expansion_type = "direct" if is_direct else "indirect"
        current_state = self.api_expansion_state[self.func_ea][api_name][expansion_type]
        self.api_expansion_state[self.func_ea][api_name][expansion_type] = not current_state

    def extract_cell_item(self, line: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract item content from a table cell with debug output.
        """
        if line:
            cell_match: Optional[re.Match] = self.cell_regex.search(line)

            if cell_match:
                xref_cell: str = cell_match.group(1)
                xref_item: str = xref_cell.replace("\x04", "").strip()
                return xref_cell, xref_item

        return None, None

    def _add_expanded_calls(self, api_name: str, is_direct: bool) -> None:
        indent = "      " if is_direct else f"{self.indent}  "
        if is_direct:
            calls = self.xrefer_obj.get_direct_calls(api_name, self.func_ea)
        else:
            calls = self.xrefer_obj.get_indirect_calls(api_name, self.func_ea)

        for call, count in calls:
            self.AddLine(f"{indent}{colorize_api_call(call)} x {count}")

    def add_expanded_calls(self, line: str) -> bool:
        """
        Add expanded API call information to view.

        When an API call is expanded, adds detailed call information including
        arguments and return values below the main entry.

        Args:
            line (str): Line containing API call to expand

        Returns:
            bool: True if expansion was added, False otherwise
        """
        is_direct = self.current_table.startswith("D")
        _, xref_item = self.extract_cell_item(line)
        if xref_item:
            expansion_type = "direct" if is_direct else "indirect"
            if self.api_expansion_state[self.func_ea][xref_item][expansion_type]:
                line = line.replace("→", "↓", 1)
                self.AddLine(line)
                self._add_expanded_calls(xref_item, is_direct)
                return True

        return False

    def print_xref_item(self, line: str, filter: str) -> None:
        """
        Print a cross-reference item with appropriate filtering and formatting.

        Handles filtering based on search state and adds appropriate coloring
        and expansion state to the item.

        Args:
            line (str): Line to print
            filter (str): Current filter string to apply
        """
        newline: str = None
        printed = False

        if filter:
            if filter in line:
                newline = self.prepare_xref_colors(line, self.xref_coverage_dict[self.func_ea])

        elif self.state_machine.current_state in (self.state_machine.search, self.state_machine.call_focus, self.state_machine.graph):
            if self.state_machine.search_filter in line.lower():
                newline = wrap_substring_with_string(line, self.state_machine.search_filter, "\x04")

        else:
            newline = self.prepare_xref_colors(line, self.xref_coverage_dict[self.func_ea])

        if newline:
            if "→" in newline:
                printed = self.add_expanded_calls(newline)

            if not printed:
                self.AddLine(newline)

    def draw_boundary_scan_results(self) -> None:
        """
        Draw results of boundary method scan.

        Displays formatted table of boundary methods found containing
        all selected artifacts, including function addresses and names.
        """
        boundary_methods = self.state_machine.boundary_methods
        entity_list = self.state_machine.get_selected_refs(self.func_ea)

        if not len(boundary_methods):
            self.ClearLines()
            self.last_boundary_scan_results = ["NO BOUNDARY METHODS FOUND"]
            self.AddLine("")
            self.AddLine("    %s" % self.last_boundary_scan_results[0])
            self.Refresh()
            return

        self.ClearLines()
        self.print_ribbon()

        boundary_methods_names: List[str] = [idc.get_func_name(func_ea) for func_ea in boundary_methods]
        cols: List[List[Union[int, str]]] = [boundary_methods, boundary_methods_names]
        results_table: List[str] = create_colored_table_from_cols(["BOUNDARY METHOD ADDRESS", "BOUNDARY METHOD NAME"], cols, ida_lines.SCOLOR_DEMNAME)

        sorted_entity_list: List[int] = sorted(entity_list, key=lambda x: self.xrefer_obj.entities[x][2])
        key_values: List[int] = [self.xrefer_obj.entities[x][2] for x in sorted_entity_list]
        key_counts: OrderedDict[int, int] = OrderedDict()

        for key in key_values:
            if key not in key_counts:
                key_counts[key] = 0
            key_counts[key] += 1

        type_list: List[int] = list(key_counts.keys())
        type_count: List[int] = list(key_counts.values())
        tag_index: Dict[int, List[int]] = {}
        start: int = 2

        for index, entity_type in enumerate(type_list):
            tag_index[self.xrefer_obj.color_tags[self.xrefer_obj.table_names[entity_type]]] = [start, start + type_count[index]]
            start += type_count[index]

        rows: List[List[str]] = [[self.xrefer_obj.entities[x][1]] for x in sorted_entity_list]
        params_table: List[str] = create_xrefs_table_colored("BOUNDARY SCAN PARAMETERS", rows, tag_index)
        params_table[0] = "\x01" + ida_lines.SCOLOR_DEMNAME + params_table[0] + "\x02" + ida_lines.SCOLOR_DEMNAME
        params_table[1] = "\x01" + ida_lines.SCOLOR_DEMNAME + params_table[1] + "\x02" + ida_lines.SCOLOR_DEMNAME
        results_table += ["", "", ""] + params_table

        for line in results_table:
            self.AddLine("    %s" % line)

        self.last_boundary_scan_results = results_table

    def draw_last_boundary_scan_results(self) -> None:
        """
        Draw results from last boundary method scan.

        Displays cached results from previous boundary scan or exits
        if no previous results exist.
        """
        if not self.last_boundary_scan_results:
            self.state_machine.end_last_boundary_results()
        else:
            self.ClearLines()
            for line in self.last_boundary_scan_results:
                self.AddLine("    %s" % line)

    def draw_orphans(self) -> None:
        """Draw the orphan-artifacts view.

        One table per entity type (imports, libraries, strings, capa
        rules), each rendered with the same colored heading + ``▾`` / ``▸``
        chevron disclosure and per-group sub-toggle used by the per-function
        xref tables, so the layout is visually identical to the rest of
        xrefer. Every row carries the artifact name in the first column
        followed by every address that references it
        (``self.entity_xrefs[idx]``), matching the address-after-name layout
        of the regular xrefs tables.

        Expand/collapse re-uses ``self.table_states`` and
        ``self.subtable_states``, so clicking a ▾/▸ header row and the ``E``
        shortcut all work without any bespoke wiring.
        """
        self.ClearLines()
        self.print_ribbon()

        INDENT = "    "
        orphan_groups = self.xrefer_obj.collect_orphan_entities()
        type_label = {
            1: "LIBRARIES",
            2: "IMPORTS",
            3: "STRINGS",
            4: "CAPA RULES",
        }
        total = sum(len(orphan_groups.get(t, [])) for t in (1, 2, 3, 4))

        header = f"ORPHAN ARTIFACTS DISCOVERED → {ida_lines.COLSTR(str(total), ida_lines.SCOLOR_VOIDOP)}"
        self.AddLine(f"{INDENT}{ida_lines.COLSTR(header, ida_lines.SCOLOR_DATNAME)}")
        self.AddLine("")

        breakdown_parts: List[str] = []
        for type_id in (2, 1, 3, 4):  # match orphan_table_names display order
            count = len(orphan_groups.get(type_id, []))
            count_str = ida_lines.COLSTR(str(count), ida_lines.SCOLOR_VOIDOP)
            breakdown_parts.append(f"{type_label[type_id]}: {count_str}")
        self.AddLine(f"{INDENT}{ida_lines.COLSTR(' • '.join(breakdown_parts), ida_lines.SCOLOR_VOIDOP)}")
        self.AddLine("")

        if total == 0:
            self.AddLine(f"{INDENT}NO ORPHAN ARTIFACTS FOUND")
            return

        # Build and render the orphan tables. The merged imports+libraries
        # table spans two entity types, so it is built specially; the rest
        # map 1:1 to a single type.
        for table_name in self.orphan_table_names:
            if table_name == self.merged_orphan_name:
                built = self._build_merged_orphan_table(orphan_groups)
            else:
                type_id = self._orphan_table_to_type[table_name]
                indices = orphan_groups.get(type_id, [])
                if not indices:
                    continue
                built = self._build_orphan_table(table_name, type_id, indices)
            if built is None:
                continue
            self._draw_orphan_table(table_name, built)

    def _build_orphan_table(self, table_name: str, type_id: int, entity_indices: List[int]) -> Optional[Dict[str, Any]]:
        """Group entities by ``entity[0]`` (namespace / category) and
        produce a colored table ready to render.

        Returns ``{"heading": [head_line, sep_line], "rows": OrderedDict[group: List[str]]}``
        in the same shape as ``self.xrefer_obj.table_data[func_ea][...]``,
        so the renderer can share logic with the per-function tables.
        """
        # Group by namespace/category (entity[0]). Stable insertion order.
        string_storage = getattr(self.xrefer_obj, "string_storage_addrs", {}) or {}
        groups: "OrderedDict[str, List[List[Any]]]" = OrderedDict()
        for idx in entity_indices:
            entity = self.xrefer_obj.entities[idx]
            category = entity[0] or "uncategorized"
            row: List[Any] = [entity[1]]
            # Append every address this entity is referenced from. Sorted
            # so the table is deterministic across runs.
            addrs = sorted(self.xrefer_obj.entity_xrefs.get(idx, set()))
            # String fallback: if no code use site was statically
            # resolvable (very common for Rust strings referenced via
            # const slice structs), surface the data-section storage
            # address so the row isn't blank and the user can still
            # navigate to where the string lives.
            if not addrs and type_id == 3:
                addrs = sorted(string_storage.get(idx, set()))
            row.extend(addrs)
            groups.setdefault(category, []).append(row)

        if not groups:
            return None

        # Sort groups alphabetically and rows within each group by name
        # for predictable navigation.
        sorted_groups: "OrderedDict[str, List[List[Any]]]" = OrderedDict()
        for category in sorted(groups.keys(), key=lambda s: s.lower()):
            rows = sorted(groups[category], key=lambda r: (r[0] or "").lower())
            sorted_groups[category] = rows

        flat_rows: List[List[Any]] = []
        for rows in sorted_groups.values():
            flat_rows.extend(rows)

        color_tag = self.xrefer_obj.color_tags[self.xrefer_obj.table_names[type_id]]
        colored_table = create_xrefs_table_colored(table_name, flat_rows, color_tag)
        # Layout mirrors finalize_table in analyzer.py: index 1 = heading
        # text, index 2 = separator dashes, index 3+ = row data.
        heading = colored_table[1:3] if len(colored_table) >= 3 else []

        per_group_rows: "OrderedDict[str, List[str]]" = OrderedDict()
        offset = 3
        for category, rows in sorted_groups.items():
            n = len(rows)
            per_group_rows[category] = colored_table[offset : offset + n]
            offset += n

        return {"heading": heading, "rows": per_group_rows}

    def _build_merged_orphan_table(self, orphan_groups: Dict[int, List[int]]) -> Optional[Dict[str, Any]]:
        """Build one orphan table combining orphan imports (type 2) and
        orphan libraries (type 1), grouped by their shared category — the
        same redundancy fix applied to the per-function indirect tables.

        Each source type is built via :meth:`_build_orphan_table` so it
        keeps its own row color (imports vs libraries); the per-category
        rows are then concatenated (imports first). Returns None when
        there are no orphan imports or libraries.
        """
        import_indices = orphan_groups.get(2, [])  # EntityType.IMPORT
        lib_indices = orphan_groups.get(1, [])      # EntityType.LIBRARY
        imp_built = self._build_orphan_table(self.merged_orphan_name, 2, import_indices) if import_indices else None
        lib_built = self._build_orphan_table(self.merged_orphan_name, 1, lib_indices) if lib_indices else None
        if imp_built is None and lib_built is None:
            return None

        merged_rows: "OrderedDict[str, List[str]]" = OrderedDict()
        for built in (imp_built, lib_built):
            if not built:
                continue
            for category, rows in built["rows"].items():
                merged_rows.setdefault(category, []).extend(rows)

        # Re-sort categories alphabetically: each source table sorted its
        # own categories, but their union needs one consistent ordering.
        sorted_rows: "OrderedDict[str, List[str]]" = OrderedDict()
        for category in sorted(merged_rows.keys(), key=lambda s: s.lower()):
            sorted_rows[category] = merged_rows[category]

        self._align_merged_name_columns(sorted_rows)
        heading = (imp_built or lib_built)["heading"]
        return {"heading": heading, "rows": sorted_rows}

    def _draw_orphan_table(self, table_name: str, built: Dict[str, Any]) -> None:
        """Render a single orphan table honouring the top-level expand
        state in ``self.table_states[table_name]`` and the per-group
        state in ``self.subtable_states[table_name]``."""
        self.current_table = table_name
        is_expanded = bool(self.table_states.get(table_name, 1))
        # Top-level heading: ▾/▸ chevron + artifact count — same idiom as the
        # function context tables (T1/T2). Markers/labels are parsed back via
        # strip_color_codes + chevron, so click-toggle and E work here too.
        total = sum(len(r) for r in built.get("rows", {}).values() if r)
        fmt = "▾ %s" if is_expanded else "▸ %s"
        head_text = built["heading"][0] if built["heading"] else table_name
        hline = ida_lines.COLSTR(fmt % head_text, ida_lines.SCOLOR_DATNAME)
        if total:
            hline += "  " + ida_lines.COLSTR(f"({total})", ida_lines.SCOLOR_VOIDOP)
        self.AddLine(hline)

        if not is_expanded:
            self.AddLine("")
            return

        # Separator line with the "----" continuation under the heading.
        if len(built["heading"]) > 1:
            sep = built["heading"][1]
            self.AddLine(ida_lines.COLSTR(f"    ----{sep}", ida_lines.SCOLOR_DATNAME))

        subtable_states: Dict[str, bool] = self.subtable_states.setdefault(table_name, {})
        for group_key, group_rows in built["rows"].items():
            sub_expanded = subtable_states.setdefault(group_key, False)
            if sub_expanded:
                self.AddLine(self._category_line("▾", group_key, len(group_rows)))
                # Rows are already colored via create_xrefs_table_colored;
                # AddLine directly so we don't drag in print_xref_item's
                # per-function coverage-coloring path (it dereferences
                # ``xref_coverage_dict[self.func_ea]`` which isn't populated
                # for the orphans view).
                for line in group_rows:
                    self.AddLine(f"{self.indent}{line}")
            else:
                self.AddLine(self._category_line("▸", group_key, len(group_rows)))

        self.AddLine("")

    def _emit_no_cluster_data_state(self, indent: str) -> None:
        """Explain why there is no cluster data and what to do about it.

        Replaces the bare "NO CLUSTER ANALYSIS AVAILABLE" dead end. The
        diagnosis is derived from state already on hand, in order of
        specificity: a budget-blocked run, an unconfigured/disabled LLM,
        or an analysis that simply has not been run yet. Menu paths name
        the real registered actions.
        """

        def line(text: str, tag: int = ida_lines.SCOLOR_DSTR) -> None:
            self.AddLine(f"{indent}\x01{tag}{text}\x02{tag}")

        line("No cluster analysis available.", ida_lines.SCOLOR_DATNAME)
        self.AddLine("")
        if getattr(self.xrefer_obj, "cluster_token_budget_exceeded", None):
            line("The last run was blocked: the estimated request exceeds the model's context window.")
            line("Pick a larger-context model in Edit > XRefer > Configure, or check sizing via")
            line("Edit > XRefer > Run Analysis > Estimate Cluster Analysis Token Usage.")
        elif not getattr(self.xrefer_obj, "llm_lookups", False):
            line("LLM lookups are disabled or not configured.")
            line("Set a model and API key in Edit > XRefer > Configure, then run")
            line("Edit > XRefer > Run Analysis > (Re-)run Cluster Analysis.")
        else:
            line("Cluster analysis has not produced data yet.")
            line("Run Edit > XRefer > Run Analysis > (Re-)run Cluster Analysis,")
            line("or check the Output window for errors from the last run.")

    def draw_clusters(self) -> None:
        """Draw clusters view with comprehensive headers."""
        self.ClearLines()
        self.print_ribbon()

        LINE_WIDTH = 85  # Consistent width for all text blocks
        INDENT = "    "  # Standard 4-space indent

        # This view is reachable without cluster data (first run with no
        # LLM configured, chip clicks, pinned variants) — never crash on
        # clusters=None, diagnose instead.
        if not self.xrefer_obj.clusters:
            self._emit_no_cluster_data_state(INDENT)
            self.Jump(0, 0)
            self.Refresh()
            return

        # Count total clusters and functions, respecting the
        # hide-library toggle so the header reflects what is shown.
        total_functions = set()
        total_clusters = 0
        hide_library = self.state_machine.hide_library_clusters

        def count_cluster_stats(cluster):
            nonlocal total_clusters, total_functions
            if hide_library and getattr(cluster, "is_library", False):
                return
            total_clusters += 1
            total_functions.update(cluster.nodes)
            for subcluster in cluster.subclusters:
                count_cluster_stats(subcluster)

        for cluster in self.xrefer_obj.clusters:
            count_cluster_stats(cluster)

        # Quiet stat header — the ribbon already names this view, so no
        # ALL-CAPS title / arrows / full-width rule.
        header = (
            ida_lines.COLSTR(str(total_clusters), ida_lines.SCOLOR_VOIDOP)
            + ida_lines.COLSTR(" clusters · ", ida_lines.SCOLOR_DSTR)
            + ida_lines.COLSTR(str(len(total_functions)), ida_lines.SCOLOR_VOIDOP)
            + ida_lines.COLSTR(" functions", ida_lines.SCOLOR_DSTR)
        )
        self.AddLine(f"{INDENT}{header}")
        self.AddLine("")

        self.print_llm_disclaimer()

        # Get cluster analysis data
        cluster_analysis = self.xrefer_obj.cluster_analysis
        if not cluster_analysis:
            self._emit_no_cluster_data_state(INDENT)
            self.Jump(0, 0)
            self.Refresh()
            return

        # Add binary information with proper alignment
        binary_cat = cluster_analysis.get("binary_category", "Unknown")
        if isinstance(binary_cat, enum.Enum):
            binary_cat = binary_cat.name

        # Print category on one line
        self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_DNAME}Binary Category: \x02{ida_lines.SCOLOR_DNAME}\x01{ida_lines.SCOLOR_VOIDOP}{binary_cat}\x02{ida_lines.SCOLOR_VOIDOP}")

        # Report (markdown) or plain description, per the R toggle
        showing_report = self.state_machine.cluster_manager.is_showing_report()
        binary_desc = cluster_analysis.get(
            "binary_report" if showing_report else "binary_description", "Not available"
        )
        self._emit_binary_summary_body(binary_desc, showing_report, INDENT, LINE_WIDTH)
        self.AddLine("")

        # Get formatted lines from helper
        lines = draw_cluster_hierarchy(
            self.xrefer_obj.clusters,
            cluster_analysis,
            self.xrefer_obj.paths,
            hide_library=self.state_machine.hide_library_clusters,
        )

        # Add lines to view
        for line in lines:
            self.AddLine(line)

        self.Jump(0, 0)
        self.Refresh()

    def draw_attack_matrix(self) -> None:
        """Draw the ATT&CK matrix view.

        Aggregates the per-cluster MITRE ATT&CK mappings into a binary-wide
        (or cluster-scoped) kill-chain matrix: a coverage strip listing every
        tactic with a bar scaled to its technique count, then the techniques
        grouped by tactic in kill-chain order. Each technique shows a single
        representative rationale and the cluster(s) that ground it as
        clickable ``cluster.id.NNNN`` tokens; the technique id is clickable
        too (opens its attack.mitre.org page).
        """
        self.ClearLines()
        self.print_ribbon()

        LINE_WIDTH = 85
        INDENT = "    "
        BAR_CELLS = 10

        def col(text: str, tag: int) -> str:
            return ida_lines.COLSTR(text, tag)

        sm = self.state_machine
        scope_id = sm.attack_matrix_scope_cluster_id

        cluster_analysis = self.xrefer_obj.cluster_analysis
        if not cluster_analysis:
            self._emit_no_cluster_data_state(INDENT)
            self.Jump(0, 0)
            self.Refresh()
            return

        hide_library = sm.hide_library_clusters
        matrix = aggregate_mitre_matrix(
            self.xrefer_obj.clusters,
            cluster_analysis,
            scope_cluster_id=scope_id,
            hide_library=hide_library if scope_id is None else False,
        )

        # ---- Header ----------------------------------------------------
        if scope_id is not None:
            header = (
                f"ATT&CK MATRIX → cluster.id.{scope_id:04d}  "
                f"{col(str(matrix.technique_count), ida_lines.SCOLOR_VOIDOP)} TECHNIQUE(S) / "
                f"{col(str(matrix.tactic_count), ida_lines.SCOLOR_VOIDOP)} TACTIC(S)"
            )
        else:
            header = (
                f"ATT&CK MATRIX → "
                f"{col(str(matrix.technique_count), ida_lines.SCOLOR_VOIDOP)} TECHNIQUES ACROSS "
                f"{col(str(matrix.tactic_count), ida_lines.SCOLOR_VOIDOP)} TACTICS"
            )
        self.AddLine(f"{INDENT}{col(header, ida_lines.SCOLOR_DATNAME)}")
        self.AddLine(f"{INDENT}{col('=' * LINE_WIDTH, ida_lines.SCOLOR_DATNAME)}")
        self.AddLine("")

        self.print_llm_disclaimer()

        # Summary subline + interaction hint.
        if scope_id is not None:
            sub = f"Scope: cluster.id.{scope_id:04d} — press K or ESC to return to all clusters"
        else:
            uncovered = len(matrix.uncovered_tactics)
            sub = (
                f"Grounded in {matrix.clusters_with_techniques} of {matrix.total_clusters} "
                f"clusters · {uncovered} tactic(s) not observed · Enterprise matrix"
            )
            if hide_library:
                sub += " · library clusters hidden (L)"
        self.AddLine(f"{INDENT}{col(sub, ida_lines.SCOLOR_DSTR)}")
        if scope_id is None:
            hint = "(K/ESC exit · G grid · L hide library · click cluster.id.xxxx · T#### → MITRE)"
        else:
            hint = "(K/ESC exit · G grid · click cluster.id.xxxx · T#### → MITRE)"
        self.AddLine(f"{INDENT}{col(hint, ida_lines.SCOLOR_AUTOCMT)}")
        self.AddLine("")

        if matrix.is_empty:
            self.AddLine(f"{INDENT}{col('No MITRE ATT&CK techniques were mapped for these clusters.', ida_lines.SCOLOR_DSTR)}")
            self.AddLine(f"{INDENT}{col('(Techniques are produced during cluster analysis when artifacts support them.)', ida_lines.SCOLOR_AUTOCMT)}")
            self.Jump(0, 0)
            self.Refresh()
            return

        # ---- Kill-chain coverage strip ---------------------------------
        self.AddLine(f"{INDENT}{col('KILL-CHAIN COVERAGE', ida_lines.SCOLOR_DATNAME)}")
        self.AddLine(f"{INDENT}{col('-' * LINE_WIDTH, ida_lines.SCOLOR_AUTOCMT)}")
        max_n = matrix.max_tactic_count or 1
        label_w = max((len(t) for t, _ in matrix.coverage), default=10)
        for tactic, count in matrix.coverage:
            filled = int(round(count / max_n * BAR_CELLS)) if max_n else 0
            if count > 0 and filled == 0:
                filled = 1
            filled = min(filled, BAR_CELLS)
            label = tactic.ljust(label_w)
            count_str = str(count) if count else "·"
            if count > 0:
                self.AddLine(
                    f"{INDENT}  {col(label, ida_lines.SCOLOR_DNAME)}  "
                    f"{col('█' * filled, ida_lines.SCOLOR_VOIDOP)}"
                    f"{col('░' * (BAR_CELLS - filled), ida_lines.SCOLOR_AUTOCMT)}  "
                    f"{col(count_str, ida_lines.SCOLOR_VOIDOP)}"
                )
            else:
                self.AddLine(
                    f"{INDENT}  {col(label, ida_lines.SCOLOR_AUTOCMT)}  "
                    f"{col('░' * BAR_CELLS, ida_lines.SCOLOR_AUTOCMT)}  "
                    f"{col(count_str, ida_lines.SCOLOR_AUTOCMT)}"
                )
        self.AddLine("")

        # ---- Techniques by tactic --------------------------------------
        self.AddLine(f"{INDENT}{col('TECHNIQUES BY TACTIC', ida_lines.SCOLOR_DATNAME)}")
        self.AddLine(f"{INDENT}{col('-' * LINE_WIDTH, ida_lines.SCOLOR_AUTOCMT)}")

        id_w = 11
        body_indent = INDENT + "  " + " " * id_w  # aligns under the technique name
        rat_width = max(20, LINE_WIDTH - len(body_indent))
        name_avail = LINE_WIDTH - len(INDENT) - 2 - id_w
        for group in matrix.tactics:
            self.AddLine("")
            self.AddLine(f"{INDENT}{col(group.tactic, ida_lines.SCOLOR_DNAME)}")
            for t in group.techniques:
                name = t.name or ""
                if len(name) > name_avail:
                    name = name[: name_avail - 2] + ".."
                id_col = t.id.ljust(id_w)
                self.AddLine(
                    f"{INDENT}  {col(id_col, ida_lines.SCOLOR_VOIDOP)}{col(name, ida_lines.SCOLOR_DSTR)}"
                )
                rat = t.representative_rationale
                if rat:
                    for wrapped in word_wrap_text(rat, rat_width):
                        self.AddLine(f"{body_indent}{col(wrapped, ida_lines.SCOLOR_AUTOCMT)}")
                # Cluster chips — binary-wide only (the scoped view already
                # names its cluster in the header).
                if scope_id is None and t.cluster_ids:
                    chip_lines = self._pack_cluster_chips(t.cluster_ids, rat_width - 2)
                    for i, chip_line in enumerate(chip_lines):
                        prefix = col("↳ ", ida_lines.SCOLOR_SYMBOL) if i == 0 else "  "
                        self.AddLine(f"{body_indent}{prefix}{col(chip_line, ida_lines.SCOLOR_DEMNAME)}")

        self.Jump(0, 0)
        self.Refresh()

    def _pack_cluster_chips(self, cluster_ids: List[int], width: int) -> List[str]:
        """Pack ``cluster.id.NNNN`` tokens into lines no wider than ``width``,
        keeping each token whole so it stays clickable."""
        tokens = [f"cluster.id.{cid:04d}" for cid in cluster_ids]
        lines: List[str] = []
        cur = ""
        for tok in tokens:
            cand = tok if not cur else f"{cur}   {tok}"
            if len(cand) > width and cur:
                lines.append(cur)
                cur = tok
            else:
                cur = cand
        if cur:
            lines.append(cur)
        return lines

    def open_attack_matrix_popup(self) -> None:
        """Open the Qt heat-grid popup for the current ATT&CK matrix.

        Aggregates the same matrix the TUI view shows (honoring the current
        cluster scope and the hide-library toggle) and hands it to the
        modal popup. Defensive — a popup failure must never crash the view.
        """
        try:
            cluster_analysis = self.xrefer_obj.cluster_analysis
            if not cluster_analysis:
                return
            sm = self.state_machine
            scope_id = sm.attack_matrix_scope_cluster_id
            matrix = aggregate_mitre_matrix(
                self.xrefer_obj.clusters,
                cluster_analysis,
                scope_cluster_id=scope_id,
                hide_library=sm.hide_library_clusters if scope_id is None else False,
            )
            from xrefer.gui.attack_matrix_popup import show_attack_matrix_popup

            suffix = f"cluster.id.{scope_id:04d}" if scope_id is not None else None
            try:
                base_name = idaapi.get_root_filename() or None
            except Exception:
                base_name = None
            show_attack_matrix_popup(matrix, title_suffix=suffix, base_name=base_name)
        except Exception as e:
            log(f"[-] Error opening ATT&CK matrix popup: {str(e)}")

    def _emit_binary_summary_body(self, binary_desc: str, showing_report: bool, indent: str, line_width: int) -> None:
        """Emit the binary report (markdown) or plain description.

        When the R-toggle is on the report view, ``binary_desc`` is the
        LLM's markdown ``binary_report``; it is rendered through the
        bare-bones markdown renderer (headings, bullets, bold/code) so
        it reads as structured text instead of an unbroken blob. If
        rendering raises for any reason, fall back to plain word-wrap so
        the view never breaks. The plain ``binary_description`` keeps the
        established label-inline style.
        """
        if showing_report:
            self.AddLine(f"{indent}\x01{ida_lines.SCOLOR_DNAME}Binary Report:\x02{ida_lines.SCOLOR_DNAME}")
            self.AddLine("")
            try:
                for line in render_markdown_report_lines(binary_desc, line_width, indent):
                    self.AddLine(line)
                return
            except Exception as e:
                log(f"[-] Report markdown render failed; showing plain text: {str(e)}")
                for wrapped in word_wrap_text(binary_desc, line_width):
                    self.AddLine(f"{indent}\x01{ida_lines.SCOLOR_DSTR}{wrapped}\x02{ida_lines.SCOLOR_DSTR}")
                return

        desc_label = "Binary Description: "
        first_line_width = line_width - len(desc_label)
        self.AddLine(f"{indent}\x01{ida_lines.SCOLOR_DNAME}{desc_label}\x02{ida_lines.SCOLOR_DNAME}\x01{ida_lines.SCOLOR_DSTR}{binary_desc[:first_line_width]}\x02{ida_lines.SCOLOR_DSTR}")
        remaining = binary_desc[first_line_width:]
        while remaining:
            chunk = remaining[:line_width]
            remaining = remaining[line_width:]
            self.AddLine(f"{indent}\x01{ida_lines.SCOLOR_DSTR}{chunk}\x02{ida_lines.SCOLOR_DSTR}")

    def _get_intermediate_paths_containing_function(self, func_ea: int, scope_cluster_id: Optional[int] = None) -> List[Tuple[int, List[int], int]]:
        """
        Find intermediate paths containing a specific function.

        Args:
            func_ea: Address of function to find in intermediate paths.
            scope_cluster_id: When provided, restrict the search to the
                given cluster and its subclusters, ignoring paths from
                unrelated clusters. ``None`` means "search every
                cluster" (the prior global behaviour).

        Returns:
            List of tuples (source_node, path, target_node) where:
            - source_node: Address of source cluster node/interesting function
            - path: Complete path including intermediates
            - target_node: Address of target cluster node/interesting function
        """
        paths_with_func: List[Tuple[int, List[int], int]] = []
        seen: Set[Tuple[int, Tuple[int, ...], int]] = set()

        # Search all clusters for relevant intermediate paths
        def search_cluster(cluster):
            for (source, target), paths in cluster.intermediate_paths.items():
                for path in paths:
                    # Check if function is in this path (but not as source/target)
                    if func_ea in path and func_ea != path[0] and func_ea != path[-1]:
                        key = (source, tuple(path), target)
                        if key in seen:
                            continue
                        seen.add(key)
                        paths_with_func.append((source, list(path), target))

            # Search subclusters recursively
            for subcluster in cluster.subclusters:
                search_cluster(subcluster)

        if scope_cluster_id is not None:
            scope_root = self.xrefer_obj.find_cluster_by_id(scope_cluster_id)
            if scope_root is not None:
                search_cluster(scope_root)
        else:
            for cluster in self.xrefer_obj.clusters:
                search_cluster(cluster)

        return paths_with_func

    def draw_intermediate_function_graph(self, func_ea: int) -> None:
        """
        Draw specialized graph view for intermediate function navigation.
        Focuses on the selected intermediate node and only displays the subgraph
        connecting it to interesting nodes in both directions, with special handling
        for multi-cluster (shared) functions.

        Scope follows ``state_machine.intermediate_view_show_all``: when
        False (default), only paths within the cluster the user came
        from are rendered, keeping the spider graph tight and
        contextual. When True, every cluster's intermediate paths are
        merged (the previous global behaviour). The A key flips this
        toggle while the view is active.
        """
        # Establish scope. Default = current cluster only.
        current_cluster = self.state_machine.cluster_manager.get_current_cluster()
        current_id = current_cluster.cluster_id if current_cluster else None
        show_all = self.state_machine.intermediate_view_show_all
        scope_for_query = None if show_all else current_id

        containing_paths = self._get_intermediate_paths_containing_function(func_ea, scope_cluster_id=scope_for_query)
        # If a scoped query produced nothing but a global one would,
        # fall back to global so the user never sees an empty view —
        # but flag the scope mismatch in the banner so they know.
        scoped_was_empty = (not containing_paths) and (scope_for_query is not None)
        if scoped_was_empty:
            containing_paths = self._get_intermediate_paths_containing_function(func_ea, scope_cluster_id=None)
        if not containing_paths:
            self.ClearLines()
            self.print_ribbon()
            self.AddLine("    No intermediate paths found containing this function")
            return

        # Setup view with consistent styling
        self.ClearLines()
        self.print_ribbon()

        # Header — describe what the view actually shows in plain
        # terms (the chains where this function sits between two
        # cluster members) instead of relying on insider vocabulary
        # like "intermediate" or zoom metaphors. Scope marker covers
        # single cluster, all clusters, and the empty-scope fallback.
        if show_all:
            scope_marker = "across all clusters"
        elif current_id is not None and not scoped_was_empty:
            scope_marker = f"in cluster.id.{current_id:04d}"
        elif scoped_was_empty:
            scope_marker = f"in cluster.id.{current_id:04d} (no matches → showing all clusters)"
        else:
            scope_marker = "across all clusters"
        header = f"PATHS BETWEEN CLUSTER MEMBERS THAT GO THROUGH THIS FUNCTION ({scope_marker})"
        self.AddLine(f"    \x01{ida_lines.SCOLOR_DATNAME}{header}\x02{ida_lines.SCOLOR_DATNAME}")
        self.AddLine(f"    {'-' * len(header)}")
        # Sub-heading: explain the role + how to zoom back out. Avoid
        # the "zoomed-in chain" framing — describe the role plainly so
        # the analyst doesn't need to translate.
        zoom_hint = ida_lines.COLSTR(
            "(this function acts as a bridge linking two cluster members on each chain — press V to zoom out to the cluster overview, ESC to leave)",
            ida_lines.SCOLOR_DSTR,
        )
        self.AddLine(f"    {zoom_hint}")
        # Sticky context banner — show the cluster the user came from
        # (if any) so they know this view didn't replace their cluster
        # context, just augmented it.
        for line in self._build_cluster_context_banner(current_id):
            self.AddLine(line)

        # Scope status — explicit so the analyst always knows whether
        # the spider is scoped to the cluster they came from or merged
        # across every cluster.
        if show_all:
            scope_text = f"Scope: ALL CLUSTERS — press A to scope to current cluster, M to exit"
        elif current_id is not None and not scoped_was_empty:
            scope_text = f"Scope: cluster.id.{current_id:04d} only — press A to expand to all clusters, M to exit"
        elif scoped_was_empty:
            scope_text = (
                f"Scope: cluster.id.{current_id:04d} had no matching paths — falling back to ALL CLUSTERS. "
                f"Press A or M to dismiss."
            )
        else:
            scope_text = "Scope: ALL CLUSTERS (no current cluster context) — press M to exit"
        self.AddLine(f"    \x01{ida_lines.SCOLOR_DNAME}{scope_text}\x02{ida_lines.SCOLOR_DNAME}")
        self.AddLine("")

        # Recursively gather all nodes from clusters and subclusters
        def gather_interesting_nodes(c, nodes_set):
            nodes_set.update(c.nodes)
            nodes_set.add(c.root_node)
            nodes_set.update(c.cluster_refs.keys())
            for sc in c.subclusters:
                gather_interesting_nodes(sc, nodes_set)

        # Prepare sets for interesting nodes
        interesting_nodes = set(self.xrefer_obj.artifact_functions)  # nodes with artifacts
        for cluster in self.xrefer_obj.clusters:
            gather_interesting_nodes(cluster, interesting_nodes)

        def is_interesting_node(addr: int) -> bool:
            return addr in interesting_nodes

        # Build a mapping of func_ea -> set of cluster_ids for cluster membership
        from collections import defaultdict

        func_clusters = defaultdict(set)

        def map_cluster_functions(c):
            func_clusters[c.root_node].add(c.id)
            for n in c.nodes:
                func_clusters[n].add(c.id)
            for sc in c.subclusters:
                map_cluster_functions(sc)

        for c in self.xrefer_obj.clusters:
            map_cluster_functions(c)

        def get_cluster_count(addr: int) -> int:
            return len(func_clusters[addr])

        def is_final_cluster_node(addr: int) -> bool:
            # A final cluster node is one that belongs to exactly one cluster
            return get_cluster_count(addr) == 1

        # Create networkx graph
        graph = nx.DiGraph()
        node_classifications = {}  # addr -> {'type': str, 'cluster': Optional[int]}

        def format_node_label(addr: int) -> str:
            """Format node label with cluster information if available."""
            # IDA 9.x SWIG bindings reject non-strict ea_t — wrap.
            name = idc.get_func_name(ida_idaapi.ea_t(int(addr)))
            if len(name) > 25:
                name = name[:22] + "..."

            cluster_id = None
            cluster_label = ""

            # Recursive check for cluster membership
            def recurse_find_cluster_id(c):
                if addr in c.nodes or addr == c.root_node:
                    return c.id, c
                for sc in c.subclusters:
                    result = recurse_find_cluster_id(sc)
                    if result is not None:
                        return result
                return None

            found_cluster = None
            for cluster in self.xrefer_obj.clusters:
                result = recurse_find_cluster_id(cluster)
                if result is not None:
                    cluster_id, found_cluster = result
                    break

            if cluster_id is not None and found_cluster:
                cluster_data = find_cluster_analysis(self.xrefer_obj.cluster_analysis, cluster_id)
                if cluster_data and cluster_data.get("label"):
                    cluster_label = f" - {cluster_data['label']}"
                    if len(cluster_label) > 30:
                        cluster_label = cluster_label[:27] + "..."

            # Determine if intermediate
            is_intermediate = not is_interesting_node(addr)

            node_classifications[addr] = {"type": "intermediate" if is_intermediate else "normal", "cluster": cluster_id}

            if cluster_id is not None:
                return f"0x{addr:x} - {name}\ncluster.id.{cluster_id:04d}{cluster_label}"
            elif is_intermediate:
                return f"0x{addr:x} - {name} (i)"
            else:
                return f"0x{addr:x} - {name}"

        included_edges = set()
        included_nodes = set()

        def add_path_segment(path_segment: List[int]) -> None:
            # Add all nodes in this segment and connect them with edges
            for i, node in enumerate(path_segment):
                label = format_node_label(node)
                graph.add_node(label)
                if i > 0:
                    prev_label = format_node_label(path_segment[i - 1])
                    edge = (prev_label, label)
                    if edge not in included_edges:
                        graph.add_edge(prev_label, label)
                        included_edges.add(edge)
                included_nodes.add(node)

        def find_final_path_segment(path: List[int], start_index: int, direction: int) -> List[int]:
            """
            direction: -1 for backward, +1 for forward
            Start from func_ea at start_index, move in direction until we find a final cluster node.

            Rules:
            - We can pass through intermediate and non-final interesting nodes.
            - If we reach a final cluster node, stop and include the path up to that node.
            - If we reach the end without a final cluster node, return just [func_ea].
            """
            segment = [path[start_index]]
            i = start_index + direction
            while 0 <= i < len(path):
                node = path[i]
                segment.append(node)
                if is_interesting_node(node):
                    if is_final_cluster_node(node):
                        # Found a final cluster node, stop and keep entire segment
                        break
                    else:
                        # Non-final interesting node, continue searching
                        i += direction
                        continue
                # Not interesting, just move on
                i += direction
            else:
                # Reached end without final cluster node
                # Check if the last node is final cluster node:
                if len(segment) > 1 and is_interesting_node(segment[-1]) and is_final_cluster_node(segment[-1]):
                    # The last node is a final cluster node, this is acceptable
                    pass
                else:
                    # No final cluster node found
                    return [path[start_index]]

            return (
                segment
                if len(segment) > 1 or (is_interesting_node(segment[-1]) and is_final_cluster_node(segment[-1])) or (segment[-1] == path[start_index] and is_final_cluster_node(segment[-1]))
                else [path[start_index]]
            )

        for source, path, target in containing_paths:
            if func_ea not in path:
                continue
            idx = path.index(func_ea)

            # Backward segment
            backward_segment = find_final_path_segment(path, idx, direction=-1)
            backward_segment.reverse()
            add_path_segment(backward_segment)

            # Forward segment
            forward_segment = find_final_path_segment(path, idx, direction=+1)
            add_path_segment(forward_segment)

        try:
            # Generate ASCII graph
            if len(graph.nodes()) == 1:
                graph_lines = ["", "", *ascii_graphs.graph_to_ascii(graph).splitlines(), "", ""]
            else:
                graph_lines = ascii_graphs.graph_to_ascii(graph).splitlines()

            normal_count = sum(1 for info in node_classifications.values() if info["type"] == "normal")
            intermediate_count = sum(1 for info in node_classifications.values() if info["type"] == "intermediate")
            cluster_count = sum(1 for info in node_classifications.values() if info["cluster"] is not None)

            stats = f"Graph contains {normal_count} direct nodes ({cluster_count} in clusters) and {intermediate_count} intermediate nodes"
            self.AddLine(f"    \x01{ida_lines.SCOLOR_NUMBER}{stats}\x02{ida_lines.SCOLOR_NUMBER}")
            self.AddLine("")

            # Add graph section
            self.AddLine(f"    \x01{ida_lines.SCOLOR_DNAME}Intermediate Path Graph:\x02{ida_lines.SCOLOR_DNAME}")
            self.AddLine("")

            # Print graph with proper coloring
            for line in graph_lines:
                colored_line = self._format_cluster_graph_line(line, highlight_addr=func_ea)
                self.AddLine(f"        {colored_line}")

            # Add navigation help
            self.AddLine("")
            self.AddLine(f"    \x01{ida_lines.SCOLOR_DNAME}Navigation:\x02{ida_lines.SCOLOR_DNAME}")
            self.AddLine(f"    \x01{ida_lines.SCOLOR_SEGNAME}- Double-click addresses to navigate\x02{ida_lines.SCOLOR_SEGNAME}")
            self.AddLine(f"    \x01{ida_lines.SCOLOR_SEGNAME}- ESC to navigate back\x02{ida_lines.SCOLOR_SEGNAME}")

            # Add legend
            self.AddLine("")
            self.AddLine(f"    \x01{ida_lines.SCOLOR_DNAME}Legend:\x02{ida_lines.SCOLOR_DNAME}")
            self.AddLine("    \x01\x12■\x02\x12 Current Function")
            self.AddLine(f"    \x01{ida_lines.SCOLOR_DNAME}■\x02{ida_lines.SCOLOR_DNAME} Cluster Node")
            self.AddLine(f"    \x01{ida_lines.SCOLOR_VOIDOP}■\x02{ida_lines.SCOLOR_VOIDOP} Intermediate Node (i)")

        except Exception as e:
            log(f"[-] Error creating intermediate path graph: {str(e)}")
            self.AddLine(f"    Error: {str(e)}")

    def _classify_node_roles(self, func_ea: int) -> Dict[int, Dict[str, Union[str, Optional[int]]]]:
        """
        Classify all nodes by their roles in relation to clusters and the target function.

        Args:
            func_ea: Function address being analyzed

        Returns:
            Dict mapping node addresses to their classifications:
                - type: "current" | "endpoint" | "intermediate"
                - cluster: cluster_id or None
        """
        node_classifications = {}

        # Recursive function to find a node's cluster ID
        def recurse_check_cluster(node: int, c) -> Optional[int]:
            if node in c.nodes or node == c.root_node:
                return c.id
            for sc in c.subclusters:
                cid = recurse_check_cluster(node, sc)
                if cid is not None:
                    return cid
            return None

        def get_cluster_id(node: int) -> Optional[int]:
            for cluster in self.xrefer_obj.clusters:
                cid = recurse_check_cluster(node, cluster)
                if cid is not None:
                    return cid
            return None

        paths = self._get_intermediate_paths_containing_function(func_ea)
        for source, path, target in paths:
            for idx, node in enumerate(path):
                if node in node_classifications:
                    continue

                # Determine node type
                is_endpoint = idx == 0 or idx == len(path) - 1
                is_target = node == func_ea
                if is_target:
                    node_type = "current"
                elif is_endpoint:
                    node_type = "endpoint"
                else:
                    node_type = "intermediate"

                # Get cluster membership
                cluster_id = get_cluster_id(node)

                node_classifications[node] = {"type": node_type, "cluster": cluster_id}

        return node_classifications

    def _classify_node_roles(self, func_ea: int) -> Dict[int, Dict[str, Union[str, Optional[int]]]]:
        """
        Classify all nodes by their roles in relation to clusters and the target function.

        Args:
            func_ea: Function address being analyzed

        Returns:
            Dict mapping node addresses to their classifications:
                - type: "current" | "endpoint" | "intermediate"
                - cluster: cluster_id or None
        """
        node_classifications = {}

        # Helper to check cluster membership
        def get_cluster_id(node: int) -> Optional[int]:
            for cluster in self.xrefer_obj.clusters:
                if node in cluster.nodes or node == cluster.root_node:
                    return cluster.id
                for subcluster in cluster.subclusters:
                    if node in subcluster.nodes or node == subcluster.root_node:
                        return subcluster.id
            return None

        # Process each node from paths
        paths = self._get_intermediate_paths_containing_function(func_ea)
        for source, path, target in paths:
            for idx, node in enumerate(path):
                if node in node_classifications:
                    continue

                # Determine node type
                is_endpoint = idx == 0 or idx == len(path) - 1
                is_target = node == func_ea

                if is_target:
                    node_type = "current"
                elif is_endpoint:
                    node_type = "endpoint"
                else:
                    node_type = "intermediate"

                # Get cluster membership
                cluster_id = get_cluster_id(node)

                node_classifications[node] = {"type": node_type, "cluster": cluster_id}

        return node_classifications

    def draw_cluster_graph(self) -> None:
        """Draw cluster graph."""
        self.ClearLines()
        self.print_ribbon()

        LINE_WIDTH = 85
        INDENT = "    "

        # Reachable without cluster data (first run with no LLM configured,
        # pinned variants, sync redraws) — diagnose instead of crashing on
        # clusters=None below.
        if not self.xrefer_obj.clusters:
            self._emit_no_cluster_data_state(INDENT)
            return

        # Count total clusters and subclusters
        total_clusters = 0
        unique_functions = set()

        # If there's only one cluster with no subclusters, go directly to its individual view
        if len(self.xrefer_obj.clusters) == 1 and not self.xrefer_obj.clusters[0].subclusters:
            cluster = self.xrefer_obj.clusters[0]
            if not self.state_machine.cluster_manager.get_current_cluster():
                self.state_machine.cluster_manager.push_cluster(cluster.id)
            self.draw_individual_cluster_graph(cluster.id)
            return

        def count_cluster_stats(cluster):
            nonlocal total_clusters
            total_clusters += 1
            unique_functions.update(cluster.nodes)
            for subcluster in cluster.subclusters:
                count_cluster_stats(subcluster)

        for cluster in self.xrefer_obj.clusters:
            count_cluster_stats(cluster)

        # If a specific cluster is selected, hand off before printing
        # the overview header / banner so the individual-cluster view
        # owns the banner alone (avoids stacking two banners).
        cluster_manager = self.state_machine.cluster_manager
        current_view = cluster_manager.get_current_cluster()
        if current_view:
            self.draw_individual_cluster_graph(current_view.cluster_id)
            return

        # Quiet stat header (ribbon names the view) + compact cursor context
        # instead of the full View/Function/Status/Adjacent banner.
        header = (
            ida_lines.COLSTR(str(total_clusters), ida_lines.SCOLOR_VOIDOP)
            + ida_lines.COLSTR(" clusters · ", ida_lines.SCOLOR_DSTR)
            + ida_lines.COLSTR(str(len(unique_functions)), ida_lines.SCOLOR_VOIDOP)
            + ida_lines.COLSTR(" functions", ida_lines.SCOLOR_DSTR)
        )
        self.AddLine(f"{INDENT}{header}")
        self.AddLine("")
        self._emit_compact_cluster_context(self.func_ea)

        self.print_llm_disclaimer()

        # Get cluster analysis data
        cluster_analysis = self.xrefer_obj.cluster_analysis
        if not cluster_analysis:
            self._emit_no_cluster_data_state(INDENT)
            return

        # Print binary analysis with enhanced formatting
        binary_cat = cluster_analysis.get("binary_category", "Unknown")
        # if it's enum
        if isinstance(binary_cat, enum.Enum):
            binary_cat = str(binary_cat.name)

        # Print category with special highlighting for important classifications
        cat_color = ida_lines.SCOLOR_VOIDOP
        self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_DNAME}Binary Category: \x02{ida_lines.SCOLOR_DNAME}\x01{cat_color}{binary_cat}\x02{cat_color}")

        # Report (markdown) or plain description, per the R toggle
        showing_report = self.state_machine.cluster_manager.is_showing_report()
        binary_desc = cluster_analysis.get(
            "binary_report" if showing_report else "binary_description", "Not available"
        )
        self._emit_binary_summary_body(binary_desc, showing_report, INDENT, LINE_WIDTH)
        self.AddLine("")

        def build_layout() -> Optional[List[str]]:
            graph = create_cluster_relationship_graph(
                self.xrefer_obj.clusters,
                self.xrefer_obj.cluster_analysis,
                paths=self.xrefer_obj.paths,
                hide_library=self.state_machine.hide_library_clusters,
            )
            if not graph:
                return None
            # For single node case, add some padding to make it visible
            if len(graph.nodes()) == 1:
                return ["", "", *ascii_graphs.graph_to_ascii(graph).splitlines(), "", ""]
            return ascii_graphs.graph_to_ascii(graph).splitlines()

        try:
            # Layout is cursor-independent and cached per library-visibility
            # toggle; only the colorization below runs per redraw.
            graph_lines = self._cluster_ascii_lines(("overview", self.state_machine.hide_library_clusters), build_layout)

            if graph_lines is None:
                self.AddLine(f"{INDENT}FAILED TO CREATE CLUSTER GRAPH")
                return

            # Add enhanced legend
            self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_DNAME}Cluster Relationship Graph:\x02{ida_lines.SCOLOR_DNAME}")
            self.AddLine("")

            try:
                for line in graph_lines:
                    colored_line = self._format_cluster_graph_line(line)
                    self.AddLine(f"{INDENT}    {colored_line}")

                # Add navigation and interaction hints
                self.AddLine("")
                self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_DNAME}Navigation:\x02{ida_lines.SCOLOR_DNAME}")
                self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Click cluster IDs to explore details\x02{ida_lines.SCOLOR_SEGNAME}")
                self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Hover over cluster IDs to view cluster information\x02{ida_lines.SCOLOR_SEGNAME}")
                self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press C to toggle between cluster table and cluster graph view\x02{ida_lines.SCOLOR_SEGNAME}")
                if self.state_machine.cluster_sync_enabled:
                    self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press J to disable cluster sync (currently ON - following function navigation)\x02{ida_lines.SCOLOR_SEGNAME}")
                else:
                    self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press J to enable cluster sync (currently OFF)\x02{ida_lines.SCOLOR_SEGNAME}")
                if self.state_machine.hide_library_clusters:
                    self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press L to show library clusters (currently hidden)\x02{ida_lines.SCOLOR_SEGNAME}")
                else:
                    self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press L to hide library clusters (currently shown)\x02{ida_lines.SCOLOR_SEGNAME}")
                self.AddLine(f"    \x01{ida_lines.SCOLOR_SEGNAME}- Press ESC to return to previous view\x02{ida_lines.SCOLOR_SEGNAME}")

            except Exception as e:
                log(f"[-] Error converting graph to ASCII: {str(e)}")
                self.AddLine(f"{INDENT}Error visualizing graph: {str(e)}")

        except nx.NetworkXError as e:
            log(f"NetworkX error: {str(e)}")
            self.AddLine(f"{INDENT}Error creating graph: {str(e)}")
        except Exception as e:
            log(f"[-] Error in cluster graph generation: {str(e)}")
            self.AddLine(f"{INDENT}Unexpected error: {str(e)}")

    def _format_cluster_graph_line(self, line: str, highlight_addr: Optional[int] = None, format_type: str = "default") -> str:
        """
        Format graph line with proper coloring for all graph visualization types.

        Args:
            line: Graph line to format
            highlight_addr: Optional address to highlight as current function
            format_type: Type of formatting to apply:
                - 'default': Standard cluster/path graph formatting
                - 'intermediate': Special formatting for intermediate function graphs

        Returns:
            str: Formatted line with color codes
        """
        # Color entire line as base graph color first
        colored_line = f"\x01{ida_lines.SCOLOR_LIBNAME}{line}\x02{ida_lines.SCOLOR_LIBNAME}"

        # Color cluster IDs and their labels
        colored_line = re.sub(
            r"(cluster\.id\.\d{4}(?:\s*-\s*[^\n│─└┌┐]*)?)",  # Match ID and optional label
            lambda m: f"\x01{ida_lines.SCOLOR_DEMNAME}{m.group(1)}\x02{ida_lines.SCOLOR_DEMNAME}",
            colored_line,
        )

        # Handle function addresses and names with proper coloring
        def format_function_text(match):
            addr_str = match.group(1)
            remainder = match.group(2) or ""  # Get any remaining text (function name, etc)

            # If this is a known hex address, try to highlight it
            if addr_str.startswith("0x"):
                try:
                    addr = int(addr_str, 16)
                    # Check if this is the highlighted address
                    if highlight_addr is not None and addr == highlight_addr:
                        # TODO: Is this a bug? Why are we using `COLOR_ERROR`. COLOR_ADDR feels more appropriate skip for now.
                        return f"\x01\x12{addr_str}{remainder}\x02\x12"

                    # Only apply intermediate node coloring in intermediate graph mode
                    if format_type == "intermediate" and "(i)" in remainder:
                        return f"\x01{ida_lines.SCOLOR_VOIDOP}{addr_str}{remainder}\x02{ida_lines.SCOLOR_VOIDOP}"

                except ValueError:
                    pass

            # Regular function coloring
            return f"\x01{ida_lines.SCOLOR_DNAME}{addr_str}{remainder}\x02{ida_lines.SCOLOR_DNAME}"

        # Color addresses and function names
        colored_line = re.sub(
            r"(0x[0-9a-fA-F]+)((?:\s*-\s*[^\n│─└┌┐]*)?)",  # Match addr and optional name/desc
            format_function_text,
            colored_line,
        )

        return colored_line

    def _cluster_short_label(self, cluster_id: int) -> str:
        """Return a short LLM-supplied label for a cluster, or an empty
        string if no analysis exists. Used to keep banner lines compact."""
        analysis = self.xrefer_obj.cluster_analysis or {}
        data = find_cluster_analysis(analysis, cluster_id) or {}
        return (data.get("label") or "").strip()

    def _invalidate_cluster_render_caches(self) -> None:
        """Drop every view-side cache derived from cluster data: the ASCII
        layouts of the cluster graphs and the func→cluster-ids map. Called
        when cluster data or the addresses/names baked into it change
        (cluster re-analysis, image rebase, cluster-function rename)."""
        self._cluster_ascii_cache = {}
        self._cluster_ascii_token = None
        self._func_to_cluster_ids_cache = None

    def _cluster_ascii_lines(self, key: Any, build: Callable[[], Optional[List[str]]]) -> Optional[List[str]]:
        """Return the (cached) cursor-independent ASCII layout for a cluster
        graph view.

        The Sugiyama layout is the expensive part of cluster-graph rendering
        — hundreds of milliseconds and superlinear in node count — and it
        does not depend on the cursor: the per-cursor highlight is applied
        line by line afterwards. Caching the raw ASCII lines per view key
        means cluster sync pays only the colorization pass on each cursor
        landing instead of a full relayout.

        Cache entries are additionally guarded by the identity of the
        clusters / cluster_analysis objects: any re-analysis or DB reload
        reassigns those, which flushes the cache even if an explicit
        invalidation site is ever missed. The wait box is shown only while
        actually building (cache misses); hits render instantly.

        ``build`` returns the layout lines, or None on failure — failures
        are reported by the caller and never cached.
        """
        token = (
            id(self.xrefer_obj.clusters),
            len(self.xrefer_obj.clusters or []),
            id(self.xrefer_obj.cluster_analysis),
            # paths is mutated in place by secondary-EP analysis and feeds
            # the overview graph; the EP set tracks that mutation.
            tuple(sorted(self.xrefer_obj.paths or {})),
        )
        if token != self._cluster_ascii_token:
            self._cluster_ascii_cache = {}
            self._cluster_ascii_token = token
        lines = self._cluster_ascii_cache.get(key)
        if lines is None:
            # Synchronous main-thread work; IDA nests show/hide pairs.
            idaapi.show_wait_box("HIDECANCEL\nGenerating graph...")
            try:
                lines = build()
            finally:
                idaapi.hide_wait_box()
            if lines is None:
                return None
            self._cluster_ascii_cache[key] = lines
        return lines

    def _func_to_cluster_ids(self) -> Dict[int, Set[int]]:
        """Build (lazily) a mapping ``func_ea → {cluster_ids}`` covering
        every function that is a member (``nodes`` or ``root_node``) of
        any cluster or subcluster. Cached on the view because clusters
        do not change for the life of an analysis session.

        Used by the cursor classifier to find clusters that don't
        formally contain the cursor function but DO contain a direct
        caller / callee — i.e. clusters the function is callgraph-
        adjacent to. Without this, a util function only ever shows up
        under the one cluster the analyzer happens to have decomposed
        it into, even when xrefs make it obvious that other clusters
        also depend on it.
        """
        cache = getattr(self, "_func_to_cluster_ids_cache", None)
        if cache is not None:
            return cache
        cache = defaultdict(set)

        def walk(c: "FunctionalCluster") -> None:
            cache[c.root_node].add(c.id)
            for n in c.nodes:
                cache[n].add(c.id)
            for sc in c.subclusters:
                walk(sc)

        for top in self.xrefer_obj.clusters or []:
            walk(top)
        self._func_to_cluster_ids_cache = cache
        return cache

    def _ensure_callgraph_indices(self) -> None:
        """Lazily build forward / reverse function-call indices off
        ``xrefer_obj.caller_xrefs_cache``.

        Why not query IDA on every cursor move:

        * The analyzer's ``create_xref_mapping`` (in ``core/analyzer``)
          already walks every instruction in every basic block via the
          backend abstraction and populates ``caller_xrefs_cache`` with
          every cross-function reference, jumps included. Re-running
          equivalent logic from view code per cursor move duplicates
          work the analyzer already did.
        * Reading the same source guarantees the banner's adjacency /
          nearest-cluster picture matches what cluster decomposition,
          path walks and orphan classification all see. No drift.
        * Eliminates per-cursor SWIG roundtrips into IDA — these are
          plain dict lookups after the first build.
        * Sidesteps the "``XrefsFrom(func_start)`` only sees the
          prologue" foot-gun the previous version stepped on with
          thunks.

        We still touch IDA once per (parent, child) entry at build
        time to drop targets that aren't function starts (the cache
        contains every outgoing reference, including data refs to
        ``.rdata`` etc.). That's a one-shot O(refs) pass on first
        access, then everything below is pure-Python.

        IDA-API usage is intentionally confined to ``view.py`` (the
        IDA-side GUI code). The analyzer stays on the backend
        abstraction.
        """
        if getattr(self, "_callgraph_callees_cache", None) is not None:
            return
        callees: Dict[int, List[Tuple[int, int]]] = {}
        callers: Dict[int, List[Tuple[int, int]]] = {}
        raw_cache = getattr(self.xrefer_obj, "caller_xrefs_cache", {}) or {}
        for parent_ea, child_map in raw_cache.items():
            try:
                parent_int = int(parent_ea)
            except Exception:
                continue
            for child_ea, source_addrs in child_map.items():
                try:
                    child_int = int(child_ea)
                except Exception:
                    continue
                if child_int == parent_int:
                    continue  # self-recursion isn't useful for callgraph hops
                try:
                    tgt_func = ida_funcs.get_func(ida_idaapi.ea_t(child_int))
                except Exception:
                    tgt_func = None
                if tgt_func is None or tgt_func.start_ea != child_int:
                    continue  # not a function start — skip data refs, jump-table entries, etc.
                for addr in source_addrs:
                    try:
                        addr_int = int(addr)
                    except Exception:
                        continue
                    callees.setdefault(parent_int, []).append((child_int, addr_int))
                    callers.setdefault(child_int, []).append((parent_int, addr_int))
        self._callgraph_callees_cache = callees
        self._callgraph_callers_cache = callers

    def _iter_callees(self, func_ea: int) -> Iterator[Tuple[int, int]]:
        """Yield ``(callee_func_start, call_site_addr)`` for every
        unique function called or jumped to from anywhere inside
        ``func_ea`` — sourced from the analyzer's pre-built call
        graph (``caller_xrefs_cache``), not a fresh IDA query.

        See :meth:`_ensure_callgraph_indices` for why we read from the
        cache rather than asking IDA per cursor move.
        """
        self._ensure_callgraph_indices()
        seen: Set[int] = set()
        for callee_ea, addr in self._callgraph_callees_cache.get(int(func_ea), ()):
            if callee_ea in seen:
                continue
            seen.add(callee_ea)
            yield (callee_ea, addr)

    def _iter_callers(self, func_ea: int) -> Iterator[Tuple[int, int]]:
        """Yield ``(caller_func_start, call_site_addr)`` for every
        unique function that calls or jumps to ``func_ea`` — sourced
        from the lazily-built reverse index off
        ``caller_xrefs_cache``.

        See :meth:`_ensure_callgraph_indices` for the rationale.
        """
        self._ensure_callgraph_indices()
        seen: Set[int] = set()
        for caller_ea, addr in self._callgraph_callers_cache.get(int(func_ea), ()):
            if caller_ea in seen:
                continue
            seen.add(caller_ea)
            yield (caller_ea, addr)

    def _nearest_clusters_via_callgraph(self, max_depth: int = 3, max_results: int = 3) -> List[Tuple[int, int, int, str]]:
        """BFS the call graph (callers first, then callees) outward
        from the cursor function until cluster members are found.

        Used by the banner when the cursor is on an unclassified
        function so the analyst gets an actionable "nearest cluster"
        hint instead of the dead-end ``not in any cluster`` message.
        Direct (1-hop) neighbours are already surfaced by
        ``_adjacent_clusters_for_cursor`` — this method extends the
        reach a couple more hops so functions that are deep in
        glue / boilerplate code still resolve to a useful navigation
        anchor.

        Caller direction is searched first (an analyst landing on a
        function usually wants to know "who called me into this
        thicket"). Callee direction is searched second as a fallback.

        Returns up to ``max_results`` entries
        ``(cluster_id, hop_count, gateway_func_ea, direction)``
        where ``direction`` is either ``"caller"`` or ``"callee"`` and
        ``gateway_func_ea`` is the cluster-member function that was
        hit.
        """
        if not self.func_ea or max_depth < 1:
            return []
        func_to_clusters = self._func_to_cluster_ids()
        found: Dict[int, Tuple[int, int, str]] = {}

        def walk(direction: str) -> None:
            if len(found) >= max_results:
                return
            seen: Set[int] = {self.func_ea}
            frontier: List[Tuple[int, int]] = [(self.func_ea, 0)]
            while frontier and len(found) < max_results:
                ea, depth = frontier.pop(0)
                if depth >= max_depth:
                    continue
                neighbours = self._iter_callers(ea) if direction == "caller" else self._iter_callees(ea)
                for neighbor_ea, edge_addr in neighbours:
                    if neighbor_ea in seen:
                        continue
                    seen.add(neighbor_ea)
                    clusters_here = func_to_clusters.get(neighbor_ea, ())
                    landed = False
                    for cid in clusters_here:
                        if cid not in found:
                            found[cid] = (depth + 1, neighbor_ea, direction)
                            landed = True
                    if not landed:
                        frontier.append((neighbor_ea, depth + 1))

        walk("caller")
        walk("callee")
        return sorted(
            ((cid, depth, gateway_ea, direction) for cid, (depth, gateway_ea, direction) in found.items()),
            key=lambda t: (t[1], t[0]),  # nearest first, then deterministic by cluster id
        )

    def _adjacent_clusters_for_cursor(self, exclude_ids: Set[int]) -> List[Tuple[int, int, int, str]]:
        """Find clusters that contain a direct caller or callee of the
        function under the cursor — a 1-hop callgraph neighbor that
        belongs to a cluster not already accounted for by the
        member / intermediate tiers.

        Returns ``[(cluster_id, neighbor_func_ea, edge_addr, direction), …]``
        where ``direction`` is ``"caller"`` (a function in that cluster
        calls cursor) or ``"callee"`` (cursor calls a function in that
        cluster). At most one entry per cluster — the first
        relationship discovered, preferring callers (callers are the
        more useful direction for navigation).
        """
        if not self.func_ea:
            return []

        func_to_clusters = self._func_to_cluster_ids()
        seen: Dict[int, Tuple[int, int, str]] = {}

        # Callers first: callers naturally reference the function's
        # entry point, so a single XrefsTo on the start address (via
        # _iter_callers) finds them all.
        for caller_ea, edge_addr in self._iter_callers(self.func_ea):
            for cid in func_to_clusters.get(caller_ea, ()):
                if cid in exclude_ids or cid in seen:
                    continue
                seen[cid] = (caller_ea, edge_addr, "caller")

        # Callees second: must walk every instruction inside the
        # function (via _iter_callees) — the JMP/CALL we're after sits
        # on a non-prologue instruction and is invisible to a single
        # XrefsFrom(start). Without this, thunks like
        # ``push/mov/pop/jmp clustered_func`` show up as having no
        # callee adjacency at all.
        for callee_ea, edge_addr in self._iter_callees(self.func_ea):
            for cid in func_to_clusters.get(callee_ea, ()):
                if cid in exclude_ids or cid in seen:
                    continue
                seen[cid] = (callee_ea, edge_addr, "callee")

        return [(cid, neighbor, addr, direction) for cid, (neighbor, addr, direction) in seen.items()]

    def _intermediate_gateways_for_cursor(self) -> List[Tuple[int, int, int, str]]:
        """For each cluster the cursor is an *intermediate of*, find
        the closest path endpoint (a member of that cluster) and
        return it as a gateway.

        The 1-hop ``_adjacent_clusters_for_cursor`` query misses
        intermediate-of relationships because the path from cursor to
        a cluster member typically routes through other intermediate
        functions (``member → intermediate_A → cursor → intermediate_B
        → member``), so cursor's direct neighbors aren't members.
        This method walks ``cluster.intermediate_paths`` (path tuples
        include endpoints — see
        ``ClusterManager.simplify_path_with_intermediates``) and picks
        the closer of the two endpoints per cluster.

        Returns ``[(cluster_id, gateway_func_ea, hops, direction), …]``
        where ``hops`` is the number of edges between cursor and the
        gateway, and ``direction`` is ``"caller"`` if the gateway is
        upstream from cursor (path source) or ``"callee"`` if
        downstream (path target).
        """
        if not self.func_ea:
            return []

        # cluster_id → (gateway_ea, hops, direction) — keep the closest
        # endpoint when the same cursor appears in multiple paths under
        # the same cluster.
        best: Dict[int, Tuple[int, int, str]] = {}

        def consider(cluster_id: int, gateway_ea: int, hops: int, direction: str) -> None:
            existing = best.get(cluster_id)
            if existing is None or hops < existing[1]:
                best[cluster_id] = (gateway_ea, hops, direction)

        def walk(cluster: "FunctionalCluster") -> None:
            for (_src, _tgt), paths in (cluster.intermediate_paths or {}).items():
                for path in paths:
                    try:
                        idx = path.index(self.func_ea)
                    except ValueError:
                        continue
                    if idx <= 0 or idx >= len(path) - 1:
                        # Endpoint, not intermediate — skip.
                        continue
                    src_hops = idx                  # cursor → … → path[0]
                    tgt_hops = len(path) - 1 - idx  # cursor → … → path[-1]
                    if src_hops <= tgt_hops:
                        consider(cluster.id, path[0], src_hops, "caller")
                    else:
                        consider(cluster.id, path[-1], tgt_hops, "callee")
            for sub in cluster.subclusters or []:
                walk(sub)

        for top in self.xrefer_obj.clusters or []:
            walk(top)

        return [(cid, gw, hops, direction) for cid, (gw, hops, direction) in best.items()]

    def _classify_cursor_relative_to_clusters(self, current_cluster_id: Optional[int]) -> Tuple[str, List[int]]:
        """Decide what status to show for ``self.func_ea`` relative to the
        cluster the user is currently viewing.

        Returns ``(status_kind, cluster_ids)``:

        * ``"in_current"``: the cursor is in ``current_cluster_id``.
          ``cluster_ids`` is ``[current_cluster_id]``.
        * ``"in_other"``: the cursor is in some other cluster(s).
          ``cluster_ids`` lists every cluster (sorted) that contains the
          function — useful for surfacing multi-cluster ``xutil_``
          membership in step D.
        * ``"intermediate"``: the cursor isn't in any cluster's nodes
          but appears in one or more cluster intermediate paths.
          ``cluster_ids`` lists those cluster ids.
        * ``"unclassified"``: the cursor isn't in any cluster or
          intermediate path. ``cluster_ids`` is empty.
        * ``"no_function"``: the cursor isn't on a recognised function
          at all (or func_ea is unset).
        """
        if not self.func_ea:
            return ("no_function", [])
        func = ida_funcs.get_func(ida_idaapi.ea_t(int(self.func_ea)))
        if func is None:
            return ("no_function", [])

        containing: List[int] = []

        def walk(c: "FunctionalCluster") -> None:
            if self.func_ea in c.nodes or self.func_ea == c.root_node:
                containing.append(c.id)
            for sc in c.subclusters:
                walk(sc)

        for top in self.xrefer_obj.clusters or []:
            walk(top)

        if containing:
            unique_ids = sorted(set(containing))
            if current_cluster_id is not None and current_cluster_id in unique_ids:
                return ("in_current", unique_ids)
            return ("in_other", unique_ids)

        # Not in any cluster's nodes — check intermediate paths.
        intermediate_owners: List[int] = []

        def walk_intermediate(c: "FunctionalCluster") -> None:
            for (_src, _tgt), paths in c.intermediate_paths.items():
                for path in paths:
                    if self.func_ea in path:
                        intermediate_owners.append(c.id)
                        return
            for sc in c.subclusters:
                walk_intermediate(sc)

        for top in self.xrefer_obj.clusters or []:
            walk_intermediate(top)

        if intermediate_owners:
            return ("intermediate", sorted(set(intermediate_owners)))
        return ("unclassified", [])

    def _format_cluster_chip(self, cluster_id: int, is_current: bool = False) -> str:
        """Format a single cluster as a compact, *pre-coloured* chip
        suitable for inline use in the banner.

        Output: ``★ cluster.id.NNNN - Label`` in ``SCOLOR_DEMNAME``
        (the same color used for cluster IDs in ``print_cluster_xrefs``
        and ``print_cluster_membership``), with an optional dimmed
        ``(this view)`` suffix in ``SCOLOR_VOIDOP`` when the chip
        refers to the cluster currently being rendered.

        ``cluster.id.NNNN`` is intentionally written in the same shape
        used by the other views so the existing ``parse_cluster_id``
        click handler navigates from these chips for free.
        """
        label = self._cluster_short_label(cluster_id)
        body = f"★ cluster.id.{cluster_id:04d}"
        if label:
            body += f" - {label}"
        out = ida_lines.COLSTR(body, ida_lines.SCOLOR_DEMNAME)
        if is_current:
            out += " " + ida_lines.COLSTR("(this view)", ida_lines.SCOLOR_VOIDOP)
        return out

    # Banner indentation + label-column width chosen so that values
    # line up vertically across rows and match the four-space indent
    # used by every other section in the cluster view (see
    # _print_cluster_header / print_cluster_xrefs).
    _BANNER_INDENT = "    "
    _BANNER_LABEL_WIDTH = 11  # max label "Adjacent: " padded to 11 chars

    def _banner_field(self, label: str, value: str, continuation: Optional[List[str]] = None) -> List[str]:
        """Render a banner row as ``Label:    value`` plus any
        continuation lines indented to the value column.

        Labels are coloured ``SCOLOR_DNAME`` (matching the
        ``Description:`` / ``Binary Category:`` style used by the
        cluster header section). Values are passed through verbatim so
        the caller controls cluster-chip / address / count colouring.
        """
        padded = label.ljust(self._BANNER_LABEL_WIDTH)
        label_str = ida_lines.COLSTR(padded, ida_lines.SCOLOR_DNAME)
        out: List[str] = [f"{self._BANNER_INDENT}{label_str}{value}"]
        if continuation:
            cont_indent = " " * self._BANNER_LABEL_WIDTH
            for cont in continuation:
                out.append(f"{self._BANNER_INDENT}{cont_indent}{cont}")
        return out

    def _format_status_value(self, status_kind: str, cluster_ids: List[int], current_cluster_id: Optional[int]) -> Tuple[str, Optional[List[str]]]:
        """Return ``(value, continuation_lines_or_None)`` for the
        Status banner row, given the cursor's classification.

        Continuation lines are dimmed hint text or actionable
        prompts (e.g. ``press M to view paths``); the primary value
        carries the high-signal info.
        """
        # Centralised colour helpers — keeps row-by-row code compact.
        def count_chip(text: str) -> str:
            return ida_lines.COLSTR(text, ida_lines.SCOLOR_VOIDOP)

        def hint(text: str) -> str:
            return ida_lines.COLSTR(text, ida_lines.SCOLOR_DSTR)

        def action(text: str) -> str:
            return ida_lines.COLSTR(text, ida_lines.SCOLOR_SEGNAME)

        if status_kind == "in_current":
            if len(cluster_ids) == 1:
                return ida_lines.COLSTR("in this cluster", ida_lines.SCOLOR_DEMNAME), None
            others = len(cluster_ids) - 1
            value = (
                ida_lines.COLSTR("xutil", ida_lines.SCOLOR_DATNAME)
                + " — in this cluster + "
                + count_chip(f"{others} other(s)")
            )
            return value, [hint("see Roles section below for full list")]

        if status_kind == "in_other":
            if len(cluster_ids) == 1:
                chip = self._format_cluster_chip(cluster_ids[0])
                return f"in {chip}", None
            value = (
                ida_lines.COLSTR("xutil", ida_lines.SCOLOR_DATNAME)
                + " — in "
                + count_chip(f"{len(cluster_ids)} clusters")
            )
            return value, [hint("see Roles section below for full list")]

        if status_kind == "intermediate":
            # Only advertise M when the current state actually wires
            # the key — otherwise the hint is misleading (the analyst
            # presses M and nothing happens). M is bound from
            # cluster_graphs / pinned_cluster_graphs (in-place toggle)
            # and from base / clusters / neighborhood states (cross-
            # view jump that lands inside cluster_graphs with the
            # intermediate sub-view auto-activated).
            sm = self.state_machine
            m_states = (
                sm.cluster_graphs,
                sm.pinned_cluster_graphs,
                sm.base,
                sm.clusters,
                sm.neighborhood_graph,
                sm.pinned_neighborhood_graph,
            )
            m_active = sm.current_state in m_states
            m_hint = action("press M to see which cluster members this function bridges") if m_active else None
            if len(cluster_ids) == 1:
                chip = self._format_cluster_chip(cluster_ids[0], is_current=(cluster_ids[0] == current_cluster_id))
                cont = [m_hint] if m_hint else None
                return f"intermediate of {chip}", cont
            value = "intermediate of " + count_chip(f"{len(cluster_ids)} clusters")
            cont = [hint("see Roles section below for full list")]
            if m_hint:
                cont.append(m_hint)
            return value, cont

        # unclassified
        nearest = self._nearest_clusters_via_callgraph(max_depth=3, max_results=1)
        if nearest:
            cid, hops, gateway_ea, direction = nearest[0]
            chip = self._format_cluster_chip(cid, is_current=(cid == current_cluster_id))
            arrow = ida_lines.COLSTR("←" if direction == "caller" else "→", ida_lines.SCOLOR_VOIDOP)
            try:
                gateway_name = idc.get_func_name(ida_idaapi.ea_t(int(gateway_ea))) or ""
            except Exception:
                gateway_name = ""
            via = ida_lines.COLSTR(f"0x{gateway_ea:x}", ida_lines.SCOLOR_DEMNAME)
            if gateway_name:
                via += f" ({gateway_name})"
            hop_text = count_chip(f"{hops} hop{'s' if hops != 1 else ''}")
            value = ida_lines.COLSTR("not in any cluster", ida_lines.SCOLOR_DSTR)
            cont = [f"↳ nearest: {chip} {arrow} {via}  ({hop_text})"]
            return value, cont
        return (
            ida_lines.COLSTR("not in any cluster", ida_lines.SCOLOR_DSTR),
            [hint("(no nearby cluster within 3 hops)")],
        )

    def _emit_compact_cluster_context(self, func_ea: int) -> None:
        """Emit a compact 2-line cluster-context strip (membership + adjacency)
        for the xref and cluster-graph-overview views.

        Replaces the full multi-row banner (View/Function/Status/Adjacent) plus
        the verbose ``print_cluster_membership`` roles block: the current
        function's address/name already live in the ribbon, and the full role
        breakdown lives in the cluster views. Reuses the banner's classification
        and adjacency helpers, so the membership chip + labels are identical —
        just without the repetition. No-op when the cursor isn't on a function.
        """
        try:
            on_func = bool(self.func_ea) and ida_funcs.get_func(ida_idaapi.ea_t(int(self.func_ea))) is not None
        except Exception:
            on_func = False
        if not on_func:
            return

        status_kind, cluster_ids = self._classify_cursor_relative_to_clusters(None)
        if status_kind == "no_function":
            return
        value, _cont = self._format_status_value(status_kind, cluster_ids, None)
        for line in self._banner_field("Clusters:", value):
            self.AddLine(line)

        adj = self._adjacent_clusters_for_cursor(exclude_ids=set(cluster_ids))
        if adj:
            adj.sort(key=lambda t: t[0])
            shown = adj[:4]
            cont: List[str] = []
            for cid, _neighbor_ea, edge_addr, direction in shown:
                chip = self._format_cluster_chip(cid)
                arrow = ida_lines.COLSTR("←" if direction == "caller" else "→", ida_lines.SCOLOR_VOIDOP)
                edge = ida_lines.COLSTR(f"0x{edge_addr:x}", ida_lines.SCOLOR_DEMNAME)
                cont.append(f"↳ {chip} {arrow} {edge}")
            if len(adj) > len(shown):
                cont.append(ida_lines.COLSTR(f"↳ …and {len(adj) - len(shown)} more", ida_lines.SCOLOR_DSTR))
            for line in self._banner_field("Adjacent:", "", cont):
                self.AddLine(line)
        self.AddLine("")

    def _build_cluster_context_banner(
        self,
        current_cluster_id: Optional[int],
        view_label: Optional[str] = None,
        show_sync: bool = True,
    ) -> List[str]:
        """Build the colored banner shown at the top of various views.

        Layout — one field per line, label-aligned, coloured to match
        the rest of the cluster UI:

        ::

            View:       ★ cluster.id.NNNN - Label   sync: ON
            Cursor:     0x...  func_name
            Status:     <classification>
                        ↳ contextual hint
            Adjacent:
                        ↳ ★ cluster.id.AAAA - … ← 0x...
                        ↳ ★ cluster.id.BBBB - … → 0x...

        Field labels use ``SCOLOR_DNAME`` (matching ``Description:`` /
        ``Binary Category:`` in the cluster header), cluster chips use
        ``SCOLOR_DEMNAME`` (matching ``print_cluster_xrefs`` and the
        Roles section), counts use ``SCOLOR_VOIDOP`` (matching the
        cluster-graph and orphan-table headers), hints are dimmed in
        ``SCOLOR_DSTR``, and actionable prompts (``press M …``) use
        ``SCOLOR_SEGNAME``.

        Args:
            current_cluster_id: When set and ``view_label`` is None,
                the View row renders the cluster chip for that id.
                Also threaded into the cursor-classification logic so
                ``(this view)`` annotations resolve correctly.
            view_label: Optional plain text to use as the View row
                value, overriding the auto-generated cluster chip.
                Used by non-cluster views (base xrefs, paths graph,
                etc.) where the View row should describe what the
                analyst is actually looking at, not "cluster
                relationship overview" by default.
            show_sync: When False, the View row omits the
                ``sync: ON/OFF`` chip entirely. Sync state is only
                meaningful inside cluster-graph states; non-cluster
                callers should pass False to avoid misleading the
                analyst about behavior that doesn't apply.
        """
        out: List[str] = []

        # ── View row ────────────────────────────────────────────────
        sync_chip = ""
        if show_sync:
            sync_on = self.state_machine.cluster_sync_enabled
            sync_color = ida_lines.SCOLOR_VOIDOP if sync_on else ida_lines.SCOLOR_DSTR
            sync_chip = "   " + ida_lines.COLSTR(f"sync: {'ON' if sync_on else 'OFF'}", sync_color)
        if view_label is not None:
            view_value = ida_lines.COLSTR(view_label, ida_lines.SCOLOR_DSTR) + sync_chip
        elif current_cluster_id is not None:
            view_value = self._format_cluster_chip(current_cluster_id) + sync_chip
        else:
            view_value = (
                ida_lines.COLSTR("cluster relationship overview", ida_lines.SCOLOR_DSTR)
                + sync_chip
            )
        out.extend(self._banner_field("View:", view_value))

        # ── Function gate ──────────────────────────────────────────
        # The current function (addr + name) already lives in the ribbon, so
        # the banner no longer repeats it as a "Function:" row; it only needs
        # to know whether the cursor is on a function to decide whether the
        # Status / Adjacent rows below apply.
        try:
            on_func = ida_funcs.get_func(ida_idaapi.ea_t(int(self.func_ea))) is not None if self.func_ea else False
        except Exception:
            on_func = False
        if not self.func_ea or not on_func:
            return out

        # ── Status row ─────────────────────────────────────────────
        # Both the M and V discoverability hints live as continuation
        # lines of the Status row so they share a single indentation
        # column — no separate "Hint:" label that would make the two
        # cross-promotion hints look asymmetric.
        status_kind, cluster_ids = self._classify_cursor_relative_to_clusters(current_cluster_id)
        if status_kind == "no_function":
            return out  # already short-circuited above; defensive

        # Compute the 1-hop adjacency once — it feeds both the
        # Adjacent row below and the V-hint applicability check.
        adj = self._adjacent_clusters_for_cursor(exclude_ids=set(cluster_ids))

        # V hint applies whenever the neighborhood view would actually
        # have something to draw (1-hop adjacency, intermediate-of, or
        # a BFS hit). Suppressed inside the neighborhood view itself.
        sm = self.state_machine
        v_hint: Optional[str] = None
        if sm.current_state not in (sm.neighborhood_graph, sm.pinned_neighborhood_graph):
            v_has_content = (
                bool(adj)
                or bool(self._intermediate_gateways_for_cursor())
                or bool(self._nearest_clusters_via_callgraph(max_depth=3, max_results=1))
            )
            if v_has_content:
                v_hint = ida_lines.COLSTR(
                    "press V to see which clusters this function can reach",
                    ida_lines.SCOLOR_SEGNAME,
                )

        status_value, status_cont = self._format_status_value(status_kind, cluster_ids, current_cluster_id)
        all_cont: List[str] = list(status_cont) if status_cont else []
        if v_hint:
            all_cont.append(v_hint)
        out.extend(self._banner_field("Status:", status_value, all_cont if all_cont else None))

        # ── Adjacent row (call-graph 1-hop, only when non-empty) ───
        if adj:
            adj.sort(key=lambda t: t[0])
            shown = adj[:5]
            cont: List[str] = []
            for cid, _neighbor_ea, edge_addr, direction in shown:
                chip = self._format_cluster_chip(cid)
                arrow = ida_lines.COLSTR("←" if direction == "caller" else "→", ida_lines.SCOLOR_VOIDOP)
                edge = ida_lines.COLSTR(f"0x{edge_addr:x}", ida_lines.SCOLOR_DEMNAME)
                cont.append(f"↳ {chip} {arrow} {edge}")
            if len(adj) > len(shown):
                cont.append(ida_lines.COLSTR(f"↳ …and {len(adj) - len(shown)} more", ida_lines.SCOLOR_DSTR))
            # Empty primary value — the meaningful content is in the
            # continuation chips, presented as a clean nested list.
            out.extend(self._banner_field("Adjacent:", "", cont))

        return out

    def find_function_in_clusters(self, func_ea: int, current_cluster_id: Optional[int] = None) -> Optional[Tuple[int, bool]]:
        """
        Search for the given function in all clusters and their nested subclusters, with priority given
        to the currently displayed cluster if provided.

        1. If current_cluster_id is provided and found, check that cluster first (root, nodes).
        If found, return immediately.
        2. If not found in the current cluster (or no current_cluster_id provided),
        recursively gather every cluster and subcluster and check all for normal nodes.
        3. Unlike previous versions, we no longer check intermediate nodes.

        Args:
            func_ea: Address of the function to find.
            current_cluster_id: Optional ID of the currently displayed cluster/subcluster.

        Returns:
            (cluster_id, False) if found as a root or normal node, otherwise None.
        """

        if not self.xrefer_obj or not self.xrefer_obj.clusters:
            return None

        log(f"\nSearching for function 0x{func_ea:x}")

        def check_root_node(cluster) -> Optional[Tuple[int, bool]]:
            if func_ea == cluster.root_node:
                return (cluster.id, False)
            return None

        def check_normal_nodes(cluster) -> Optional[Tuple[int, bool]]:
            if func_ea in cluster.nodes:
                return (cluster.id, False)
            return None

        # If current_cluster_id is provided, check that cluster first
        if current_cluster_id is not None:
            current_view = self.xrefer_obj.find_cluster_by_id(current_cluster_id)
            if current_view:
                # Check current cluster first (root and nodes)
                if result := check_root_node(current_view):
                    return result
                if result := check_normal_nodes(current_view):
                    return result

        # Recursively gather all clusters and subclusters
        def gather_all_clusters(clusters):
            result = []

            def recurse(c):
                result.append(c)
                for sc in c.subclusters:
                    recurse(sc)

            for top_cluster in clusters:
                recurse(top_cluster)
            return result

        all_clusters = gather_all_clusters(self.xrefer_obj.clusters)

        # Check normal nodes (root and nodes) in all clusters
        for cluster in all_clusters:
            if result := check_root_node(cluster):
                return result
            if result := check_normal_nodes(cluster):
                return result

        # Not found
        return None

    def format_graph_line(self, line: str) -> str:
        """Format a graph line with proper coloring including dual-purpose indicators."""
        # Color entire line as base graph color first
        colored_line = f"\x01{ida_lines.SCOLOR_LIBNAME}{line}\x02{ida_lines.SCOLOR_LIBNAME}"

        # Color cluster IDs and add dual-purpose indicators
        colored_line = re.sub(r"(cluster\.id\.\d+)", lambda m: self._format_cluster_id(m.group(1)), colored_line)

        # Color labels differently
        colored_line = re.sub(
            r"([^\n│─└┌┐]+)$",  # Match text at end of line that isn't a graph character
            lambda m: f"\x01{ida_lines.SCOLOR_DSTR}{m.group(1)}\x02{ida_lines.SCOLOR_DSTR}",
            colored_line,
        )

        # Color addresses and indicate intermediates
        colored_line = re.sub(
            r"(0x[0-9a-fA-F]+)(\s*\(i\))?",
            lambda m: (
                f"\x01{ida_lines.SCOLOR_VOIDOP}{m.group(1)}{m.group(2) or ''}\x02{ida_lines.SCOLOR_VOIDOP}"
                if m.group(2)
                # If has (i) suffix, use VOIDOP color
                else f"\x01{ida_lines.SCOLOR_CREFTAIL}{m.group(1)}\x02{ida_lines.SCOLOR_CREFTAIL}"
            ),
            colored_line,
        )

        return colored_line

    def _format_cluster_id(self, cluster_id_str: str) -> str:
        """Format cluster ID"""
        return f"\x01{ida_lines.SCOLOR_DEMNAME}{cluster_id_str}\x02{ida_lines.SCOLOR_DEMNAME}"

    def print_cluster_membership(self, func_ea: int) -> None:
        """
        Display cluster membership information for a function.
        Shows all roles the function plays across different clusters and subclusters,
        including cases where it may be both a regular node and intermediate node.

        Args:
            func_ea: Function address to show cluster info for
        """
        if not self.xrefer_obj.clusters:
            return

        # Track memberships and roles
        direct_memberships = []  # Regular node membership
        intermediate_memberships = []  # Intermediate node membership
        root_memberships = []  # Root node membership

        # Helper to format cluster info consistently
        def format_cluster_info(cluster_id: int) -> str:
            """Format cluster ID and label with consistent styling."""
            cluster_str = f"cluster.id.{cluster_id:04d}"

            # Get cluster data
            cluster_data = find_cluster_analysis(self.xrefer_obj.cluster_analysis, cluster_id)

            if cluster_data and cluster_data.get("label"):
                cluster_str += f" - {cluster_data['label']}"

            return cluster_str

        # Check all clusters and subclusters
        def check_cluster(cluster, parent_id=None):
            cluster_info = format_cluster_info(cluster.id)

            # First check if function is root node
            is_member_here = False
            if func_ea == cluster.root_node:
                root_memberships.append((cluster_info, parent_id))
                is_member_here = True
            # Check if function is regular node (but not root node)
            elif func_ea in cluster.nodes:  # Only add as regular node if not root
                direct_memberships.append((cluster_info, parent_id))
                is_member_here = True

            # Only classify as "intermediary in this cluster" when the
            # function is *not* already a member of this cluster, AND
            # the path's endpoints are themselves direct members of
            # this cluster.
            #
            # The endpoint-membership check filters out paths that
            # were copied up from subclusters by ``extract_cluster``
            # (clusters.py:585-586 / :592-593). Those paths' endpoints
            # are subcluster members, not parent members, so calling
            # the cursor function "intermediary in the parent" would
            # be misleading — the path doesn't actually connect any
            # of the parent's own member functions.
            if not is_member_here:
                found_intermediate = False
                for (src, tgt), paths in cluster.intermediate_paths.items():
                    if found_intermediate:
                        break
                    src_is_member = (src == cluster.root_node) or (src in cluster.nodes)
                    tgt_is_member = (tgt == cluster.root_node) or (tgt in cluster.nodes)
                    if not (src_is_member and tgt_is_member):
                        continue
                    for path in paths:
                        if func_ea in path and func_ea != path[0] and func_ea != path[-1]:
                            intermediate_memberships.append((cluster_info, parent_id))
                            found_intermediate = True
                            break

            # Recursively check subclusters
            for subcluster in cluster.subclusters:
                check_cluster(subcluster, cluster.id)

        # Process all clusters
        for cluster in self.xrefer_obj.clusters:
            check_cluster(cluster)

        if not (direct_memberships or intermediate_memberships or root_memberships):
            return

        # Print membership information with proper formatting
        self.AddLine("")  # Add spacing

        # Composite header indicating all roles
        roles = []
        if root_memberships:
            roles.append("root node")
        if direct_memberships:
            roles.append("node")
        if intermediate_memberships:
            roles.append("intermediary node")

        header = "This function serves following roles in clusters:"
        self.AddLine(f"    \x01{ida_lines.SCOLOR_DATNAME}{header}\x02{ida_lines.SCOLOR_DATNAME}")
        self.AddLine(f"    {'-' * len(header)}")

        # Print root memberships first if any
        if root_memberships:
            self.AddLine(f"    \x01{ida_lines.SCOLOR_DEMNAME}As root node in:\x02{ida_lines.SCOLOR_DEMNAME}")
            for info, parent_id in root_memberships:
                prefix = "└──" if parent_id else "●"
                cluster_text = f"    {prefix} \x01{ida_lines.SCOLOR_DEMNAME}{info}\x02{ida_lines.SCOLOR_DEMNAME}"
                if parent_id:
                    cluster_text += f" \x01{ida_lines.SCOLOR_DSTR}(subcluster)\x02{ida_lines.SCOLOR_DSTR}"
                self.AddLine(cluster_text)
            self.AddLine("")

        # Print direct memberships if any
        if direct_memberships:
            self.AddLine(f"    \x01{ida_lines.SCOLOR_DEMNAME}As regular node in:\x02{ida_lines.SCOLOR_DEMNAME}")
            for info, parent_id in direct_memberships:
                prefix = "└──" if parent_id else "●"
                cluster_text = f"    {prefix} \x01{ida_lines.SCOLOR_DEMNAME}{info}\x02{ida_lines.SCOLOR_DEMNAME}"
                if parent_id:
                    cluster_text += f" \x01{ida_lines.SCOLOR_DSTR}(subcluster)\x02{ida_lines.SCOLOR_DSTR}"
                self.AddLine(cluster_text)
            self.AddLine("")

        # Intermediate memberships are demoted to a one-line summary.
        # The intermediary role is structurally weaker than membership
        # (the function is just on a call path between two cluster
        # members, not itself an "interesting" member) and listing
        # every intermediary cluster usually adds noise without
        # changing what the analyst does next. The count + first label
        # gives enough signal that this function is connective tissue
        # in N clusters; the cluster relationship graph and the
        # intermediate-paths drill-down view (M key) are where you'd
        # go for detail.
        if intermediate_memberships:
            count = len(intermediate_memberships)
            sample_info = intermediate_memberships[0][0]
            if count == 1:
                summary = f"Also intermediary in {sample_info}"
            else:
                summary = f"Also intermediary in {count} cluster(s) — including {sample_info}"
            self.AddLine(f"    \x01{ida_lines.SCOLOR_ALTOP}{summary}\x02{ida_lines.SCOLOR_ALTOP}")

        # Add final spacing
        self.AddLine("")

    def draw_individual_cluster_graph(self, cluster_id: int) -> None:
        """
        Render and display the internal graph for a given cluster, including its subclusters and node connections.

        This method:
        • Locates and validates the specified cluster by its unique ID.
        • Recursively gathers all nodes belonging to the cluster (including subclusters and cluster references).
        • If cluster sync is enabled, it checks whether the currently active function in disassembly/pseudocode
            view belongs to this cluster—or if it qualifies as an 'intermediate' node. If neither condition is met,
            and the user did not explicitly select this cluster, a "FUNCTION NOT FOUND" message is shown.
        • Otherwise, it proceeds to:
            - Print cluster headers/metadata (e.g., labels and descriptions).
            - Print cross-reference information related to the cluster's root node.
            - Generate and display an ASCII-graph (or other textual representation) of the cluster's
                nodes, edges, and subclusters, optionally highlighting the active function if applicable.
        • Handles additional logic to gracefully skip the "not found" message when the user explicitly navigates
            to this cluster (e.g., by clicking a cluster ID in the cluster graph interface).

        Args:
            cluster_id (int): The unique integer identifier of the cluster to be displayed.

        Returns:
            None. The cluster information is rendered and printed directly into the plugin's custom viewer.
        """
        try:
            cluster = self.xrefer_obj.find_cluster_by_id(cluster_id)
            if not cluster:
                self.AddLine(f"{self.INDENT}ERROR: Could not find cluster {cluster_id}")
                return

            current = self.state_machine.cluster_manager.get_current_cluster()
            if not current:
                return

            cluster_data = find_cluster_analysis(self.xrefer_obj.cluster_analysis, cluster_id)

            # If the user has explicitly entered the intermediate-paths
            # sub-view (M key), render that instead of the cluster's
            # node graph. Replaces the previous auto-trigger that fired
            # whenever cursor sync landed on a function outside any
            # cluster — that auto-trigger was disorienting because the
            # view morphed silently. Now it only fires on deliberate
            # opt-in.
            if self.state_machine.intermediate_view_func_ea is not None:
                self.draw_intermediate_function_graph(self.state_machine.intermediate_view_func_ea)
                return

            # We used to dead-end here with "FUNCTION NOT FOUND IN ANY
            # DISCOVERED CLUSTERS OR INTERMEDIATE NODES" whenever
            # cluster sync's cursor moved to a function not in this
            # cluster's nodes. That message paired with the old
            # auto-trigger of the intermediate view: if the function
            # was intermediate, the auto-trigger fired BEFORE this
            # check; if it wasn't, the dead-end was the result.
            #
            # Now that the intermediate view is opt-in via M (Step G),
            # falling through to "FUNCTION NOT FOUND" leaves the
            # analyst with a useless dead-end on every xint_ cursor
            # landing. Instead, just render the current cluster and
            # let the banner above explain where the cursor actually
            # lives ("intermediate of cluster X — press M to view
            # paths", "in cluster Y", "not in any cluster", etc.).
            #
            # The ``_explicit_cluster_click`` reset below is preserved
            # because some callers expect the flag to be cleared after
            # a draw, even though we no longer branch on it.
            if self._explicit_cluster_click:
                self._explicit_cluster_click = False

            # If we get here, either the function is recognized or user explicitly clicked.
            # Proceed to show the cluster as normal.

            # Cursor-related information up top, then cluster-level
            # information, then the graph itself. This keeps the
            # analyst's eye flowing from "where am I?" → "what is
            # this cluster?" → "how is it shaped?" without splitting
            # cursor info across two separated sections.

            # 1) Banner — compact cursor summary + view context.
            for line in self._build_cluster_context_banner(cluster_id):
                self.AddLine(line)
            self.AddLine("")

            # 2) Detailed cursor role breakdown (root / regular /
            #    intermediary) across every cluster + subcluster, so
            #    the analyst doesn't have to ESC back to the base
            #    xrefs view to see it. Empty when the cursor isn't on
            #    a function with any cluster ties.
            if self.func_ea:
                self.print_cluster_membership(self.func_ea)

            # 3) Cluster-level header — description, label, LLM
            #    relationships. Stable per cluster, doesn't change as
            #    the cursor moves.
            self._print_cluster_header(cluster, cluster_data)

            # 4) Cluster connectivity — which other clusters call into
            #    this cluster's root. Also cluster-level, not cursor-
            #    related.
            self.print_cluster_xrefs(cluster, self.INDENT)

            # 5) The graph itself.
            self._draw_cluster_nodes(cluster, self.func_ea)

        except Exception as e:
            log(f"[-] Error drawing cluster graph: {str(e)}")
            self.AddLine(f"{self.INDENT}Error: {str(e)}")
            raise e

    def _print_cluster_header(self, cluster: "FunctionalCluster", cluster_data: Dict) -> None:
        """Print cluster header with wrapped text."""
        header = f"Cluster {cluster.id_str}"
        if cluster_data and cluster_data.get("label"):
            header += f" - {cluster_data['label']}"
        self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_DEMNAME}{header}\x02{ida_lines.SCOLOR_DEMNAME}")

        # Add separator
        self.AddLine(f"{self.INDENT}{'=' * len(header)}")
        self.AddLine("")

        # Show cluster metadata with text wrapping
        if cluster_data:
            if desc := cluster_data.get("description"):
                self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_DATNAME}Description:\x02{ida_lines.SCOLOR_DATNAME}")
                # Word wrap the description
                words = desc.split()
                line = []
                line_length = 0
                max_length = 80

                for word in words:
                    if line_length + len(word) + (1 if line else 0) <= max_length:
                        line.append(word)
                        line_length += len(word) + (1 if line else 0)
                    else:
                        self.AddLine(f"{self.INDENT}  \x01{ida_lines.SCOLOR_DSTR}{' '.join(line)}\x02{ida_lines.SCOLOR_DSTR}")
                        line = [word]
                        line_length = len(word)
                if line:
                    self.AddLine(f"{self.INDENT}  \x01{ida_lines.SCOLOR_DSTR}{' '.join(line)}\x02{ida_lines.SCOLOR_DSTR}")

            if rels := cluster_data.get("relationships"):
                self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_DATNAME}Relationships:\x02{ida_lines.SCOLOR_DATNAME}")

                # First, color all cluster IDs in the entire text
                processed_rels = re.sub(r"(cluster\.id\.\d{4})", lambda m: f"\x01{ida_lines.SCOLOR_DATNAME}{m.group(1)}\x02{ida_lines.SCOLOR_DATNAME}", rels)

                # Then do word wrapping while preserving color codes
                words = processed_rels.split()
                line = []
                line_length = 0
                max_length = 80

                for word in words:
                    # Calculate visible length (excluding color codes)
                    word_length = len(strip_color_codes(word))

                    if line_length + word_length + (1 if line else 0) <= max_length:
                        line.append(word)
                        line_length += word_length + (1 if line else 0)
                    else:
                        # Wrap entire line in DSTR color
                        wrapped_line = " ".join(line)
                        self.AddLine(f"{self.INDENT}  \x01{ida_lines.SCOLOR_DSTR}{wrapped_line}\x02{ida_lines.SCOLOR_DSTR}")
                        line = [word]
                        line_length = word_length

                if line:
                    wrapped_line = " ".join(line)
                    self.AddLine(f"{self.INDENT}  \x01{ida_lines.SCOLOR_DSTR}{wrapped_line}\x02{ida_lines.SCOLOR_DSTR}")

            self.AddLine("")

    def print_cluster_xrefs(self, cluster: "FunctionalCluster", indent: str = "    ") -> None:
        """Print xrefs to cluster root node with comprehensive membership information."""
        # Group xrefs by function
        func_xrefs = defaultdict(list)
        for xref in idautils.XrefsTo(ida_idaapi.ea_t(cluster.root_node)):
            if ida_bytes.is_code(ida_bytes.get_full_flags(xref.frm)):
                func = ida_funcs.get_func(xref.frm)
                if func:
                    func_xrefs[func.start_ea].append(xref.frm)

        if not func_xrefs:
            return

        self.AddLine(f"{indent}\x01{ida_lines.SCOLOR_DEMNAME}Cross-references to cluster root:\x02{ida_lines.SCOLOR_DEMNAME}")

        # Get current cluster ID to avoid redundant display
        current_cluster_id = None
        if current := self.state_machine.cluster_manager.get_current_cluster():
            current_cluster_id = current.cluster_id

        def find_function_memberships(func_ea: int, in_cluster: "FunctionalCluster") -> List[Tuple[int, str, str]]:
            """Find all cluster memberships for a function with role information."""
            memberships = []

            def check_cluster(cluster, parent_id=None):
                # Skip current cluster
                if cluster.id == current_cluster_id:
                    return

                # Get cluster info
                data = find_cluster_analysis(self.xrefer_obj.cluster_analysis, cluster.id)
                if not data:
                    return

                membership_found = False

                # Check root node role
                if func_ea == cluster.root_node:
                    memberships.append((cluster.id, data.get("label", ""), "root"))
                    membership_found = True
                # Check direct membership
                elif func_ea in cluster.nodes:
                    memberships.append((cluster.id, data.get("label", ""), "member"))
                    membership_found = True
                # Check intermediate paths
                else:
                    for _, paths in cluster.intermediate_paths.items():
                        for path in paths:
                            if func_ea in path and func_ea != path[0] and func_ea != path[-1]:
                                memberships.append((cluster.id, data.get("label", ""), "intermediate"))
                                membership_found = True
                                break
                        if membership_found:
                            break

                # Check subclusters recursively
                for subcluster in cluster.subclusters:
                    check_cluster(subcluster, cluster.id)

            # Check all clusters (except the one we're displaying)
            for cluster in self.xrefer_obj.clusters:
                if cluster is not in_cluster:  # Avoid checking the cluster we're displaying xrefs for
                    check_cluster(cluster)

            return memberships

        # Process each function's xrefs
        for func_ea, xrefs in sorted(func_xrefs.items()):
            # Get all cluster memberships for this function
            memberships = find_function_memberships(func_ea, cluster)

            # Format function name
            func_name = idc.get_func_name(func_ea)
            if len(func_name) > 30:
                func_name = f"{func_name[:27]}..."

            # Format cluster membership info
            cluster_info = []
            if memberships:
                for cluster_id, label, role in memberships:
                    # Add role indicator
                    role_indicator = {
                        "root": "★",  # Star for root nodes
                        "member": "●",  # Filled circle for direct members
                        "intermediate": "○",  # Empty circle for intermediate nodes
                    }[role]

                    # Format cluster reference
                    if label:
                        cluster_info.append(f"{role_indicator} cluster.id.{cluster_id:04d} - {label}")
                    else:
                        cluster_info.append(f"{role_indicator} cluster.id.{cluster_id:04d}")

            # Print function with membership info
            self.AddLine(f"{indent}  \x01{ida_lines.SCOLOR_DEMNAME}{func_name}\x02{ida_lines.SCOLOR_DEMNAME}")

            if cluster_info:
                # Print cluster memberships with proper color
                for info in cluster_info:
                    self.AddLine(f"{indent}    \x01{ida_lines.SCOLOR_ALTOP}{info}\x02{ida_lines.SCOLOR_ALTOP}")

            # Print xref addresses
            last_idx = len(xrefs) - 1
            for idx, xref in enumerate(sorted(xrefs)):
                prefix = "└──" if idx == last_idx else "├──"
                self.AddLine(f"{indent}      \x01{ida_lines.SCOLOR_CREFTAIL}{prefix} 0x{xref:x}\x02{ida_lines.SCOLOR_CREFTAIL}")

        self.AddLine("")

    def _draw_cluster_nodes(self, cluster: "FunctionalCluster", func_ea: int) -> None:
        """
        Draw cluster showing its constituent nodes and relationships.
        Auto-scrolls to highlighted function when cluster sync is enabled.

        Args:
            cluster: FunctionalCluster object to visualize
            func_ea: Optional function EA to highlight in the graph
        """

        simplified = True

        # Show node counts
        interesting_count = len(cluster.nodes)
        if simplified:
            self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_NUMBER}Simplified graph showing {interesting_count} nodes\x02{ida_lines.SCOLOR_NUMBER}")
        self.AddLine("")

        def build_layout() -> List[str]:
            graph = cluster.to_graph(cluster_analysis=self.xrefer_obj.cluster_analysis, include_intermediate=not simplified)
            return ascii_graphs.graph_to_ascii(graph).splitlines()

        try:
            # Layout is cursor-independent and cached; only the per-line
            # highlight colorization below runs on every cursor landing.
            graph_lines = self._cluster_ascii_lines(("cluster", cluster.id), build_layout)
            highlighted_position = None

            for line in graph_lines:
                # Format line with proper coloring
                colored_line = self._format_cluster_graph_line(line, highlight_addr=func_ea)

                # Capture the highlight's display position as the line is
                # added — self.Count() is the index this AddLine lands on,
                # exact by construction. (The previous header-line ESTIMATE
                # ignored word-wrap and whole sections and drifted tens of
                # lines, leaving the synced node off-screen.)
                if func_ea is not None:
                    func_addr = f"0x{func_ea:x}"
                    if func_addr in line and "\x01\x12" in colored_line:
                        # Find exact column position of the address
                        clean_line = strip_color_codes(line)
                        addr_column = clean_line.find(func_addr)
                        highlighted_position = (self.Count(), addr_column)

                self.AddLine(f"{self.INDENT}    {colored_line}")

            # Auto-scroll to highlighted line and ensure address is visible
            if highlighted_position is not None and self.state_machine.cluster_sync_enabled and not self._from_double_click:  # Do not adjust view if we are coming from a double click navigation
                line_num, column = highlighted_position
                self.Jump(line_num, column + 100)

        except Exception as e:
            log(f"[-] Error drawing cluster nodes: {str(e)}")

            self.AddLine(f"{self.INDENT}Error visualizing nodes: {str(e)}")

        # Add navigation hints
        self.AddLine("")
        self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_DNAME}Navigation:\x02{ida_lines.SCOLOR_DNAME}")

        # Interactive elements
        if cluster.subclusters:
            self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Click cluster IDs to explore subclusters\x02{ida_lines.SCOLOR_SEGNAME}")
        self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Hover over cluster IDs to view cluster information\x02{ida_lines.SCOLOR_SEGNAME}")
        self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Hover over addresses to view function details\x02{ida_lines.SCOLOR_SEGNAME}")
        self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Double-click addresses to navigate to their location\x02{ida_lines.SCOLOR_SEGNAME}")

        # View controls
        # self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press S to toggle between simplified/full views\x02{ida_lines.SCOLOR_SEGNAME}')
        if self.state_machine.current_state == self.state_machine.pinned_cluster_graphs:
            self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press G to unpin graph (graph view will disappear when navigating to a new function)\x02{ida_lines.SCOLOR_SEGNAME}")
        else:
            self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press G to pin graph (graph view will not disappear when navigating to a new function)\x02{ida_lines.SCOLOR_SEGNAME}")

        # Updated sync status message
        if self.state_machine.cluster_sync_enabled:
            self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press J to disable cluster sync (currently ON - following function navigation)\x02{ida_lines.SCOLOR_SEGNAME}")
        else:
            self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press J to enable cluster sync (currently OFF)\x02{ida_lines.SCOLOR_SEGNAME}")

        self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press C to toggle between cluster table and cluster graph view\x02{ida_lines.SCOLOR_SEGNAME}")
        if self.state_machine.hide_library_clusters:
            self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press L to show library clusters (currently hidden)\x02{ida_lines.SCOLOR_SEGNAME}")
        else:
            self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press L to hide library clusters (currently shown)\x02{ida_lines.SCOLOR_SEGNAME}")
        self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press R to go back to cluster relationship graph\x02{ida_lines.SCOLOR_SEGNAME}")
        self.AddLine(f"{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- ESC to navigate back\x02{ida_lines.SCOLOR_SEGNAME}")

    def draw_entity_xrefs(self) -> None:
        e_index = self.state_machine.selected_index
        entity: Tuple[str, str, int] = self.xrefer_obj.entities[e_index]
        table_name: str = self.xrefer_obj.table_names[entity[2]]
        entity_content: str = entity[1]
        entity_color_tag: int = self.xrefer_obj.color_tags[table_name]
        xref_items: List[List[Union[int, str]]] = self.xrefer_obj.generate_entity_xrefs_listing(e_index)
        results_table: List[str] = create_colored_table_from_cols(["XREF METHOD ADDRESS", "ORPHAN", "XREF METHOD NAME"], xref_items, ida_lines.SCOLOR_DEMNAME)
        self.ClearLines()
        self.print_ribbon()
        heading: str = f"    \x01{ida_lines.SCOLOR_DEMNAME}XREFS (\x01{entity_color_tag}{entity_content}\x02{entity_color_tag})\x02{ida_lines.SCOLOR_DEMNAME}"
        self.AddLine(heading)
        self.AddLine("")

        for line in results_table:
            self.AddLine("    %s" % line)

    def draw_help(self) -> None:
        self.ClearLines()
        self.print_ribbon()
        s_help: List[str] = help_text()

        for line in s_help:
            line = ida_lines.COLSTR(line, ida_lines.SCOLOR_DEMNAME)
            self.AddLine(line)

        self.Refresh()

    def update(self, force: bool = False, ea: Optional[int] = None) -> None:
        if self._is_collapsed:
            return

        if not ea and not self.func_ea:
            return

        if ea:
            func_ea: int = idc.get_name_ea_simple(idc.get_func_name(ea))
            current_func = ida_funcs.get_func(ea)

            if self.func_ea:
                prev_func = ida_funcs.get_func(self.func_ea)
                if current_func is not None and prev_func is not None and current_func == prev_func:
                    if not self.peek_flag:
                        return

            # Handle cluster sync if enabled
            if self.state_machine.cluster_sync_enabled and self.state_machine.current_state in (self.state_machine.cluster_graphs, self.state_machine.pinned_cluster_graphs):
                current_cluster = self.state_machine.cluster_manager.get_current_cluster()
                current_cluster_id = current_cluster.cluster_id if current_cluster else None

                result = self.find_function_in_clusters(func_ea, current_cluster_id)

                if result:
                    cluster_id, is_intermediate = result
                    current = self.state_machine.cluster_manager.get_current_cluster()

                    # Store current position before navigation
                    if current:
                        lineno, x, y = self.GetPos()
                        self.state_machine.cluster_manager.store_cursor_pos(current.cluster_id, (lineno, x, y))

                        # Only switch clusters if different from current
                        if cluster_id != current.cluster_id:
                            self.state_machine.cluster_manager.push_cluster(cluster_id)
                            new_current = self.state_machine.cluster_manager.get_current_cluster()
                            if new_current:
                                new_current.simplified = True
                        else:
                            # Update view mode for current cluster
                            current.simplified = True
                    else:
                        # No current cluster, push new one
                        self.state_machine.cluster_manager.push_cluster(cluster_id)
                        new_current = self.state_machine.cluster_manager.get_current_cluster()
                        if new_current:
                            new_current.simplified = True

                    force = True
                    self.func_ea = func_ea
                else:
                    force = True
                    self.func_ea = func_ea
                    log(f"Function 0x{self.func_ea:x} not found in any clusters")

            elif self.peek_flag and not self.state_machine.is_sticky_state() and not self.state_machine.is_pinned_graph():
                # Peek hijacks the panel with a call-focus preview; while a
                # reading view or pinned graph is up, it must not.
                # Get all operands of the current instruction
                has_func_operand = False
                # Check up to 6 operands (typical maximum in IDA)
                for i in range(6):
                    op_type = idc.get_operand_type(ea, i)
                    if op_type == idc.o_void:  # No more operands
                        break

                    # Get the operand value if it's an address
                    if op_type in [idc.o_near, idc.o_far, idc.o_mem, idc.o_imm]:
                        op_addr = idc.get_operand_value(ea, i)
                        target_func = ida_funcs.get_func(op_addr)

                        # Check if operand points to start of a different function
                        if target_func and op_addr == target_func.start_ea and (not current_func or target_func.start_ea != current_func.start_ea):
                            has_func_operand = True
                            break

                if has_func_operand:
                    self.state_machine.start_call_focus()
                    self.state_machine.address_filter = f"0x{ea:x}"
                    force = True

                else:
                    self.state_machine.to_base()
                    self.state_machine.address_filter = ""
                    force = True

                self.func_ea = func_ea

        else:
            func_ea = self.func_ea

        if ea and func_ea != self.func_ea or force:
            if not force and self.state_machine.current_state:
                sm = self.state_machine
                if sm.is_sticky_state():
                    # Binary-wide reading views (cluster table, ATT&CK
                    # matrix, orphans, xref listing, boundary results,
                    # full trace, help) survive disassembly navigation —
                    # including double-clicking address links INSIDE them.
                    # No re-render either: several end with Jump(0,0), so a
                    # redraw per cursor move would swap state-loss for
                    # scroll-loss. Track the cursor function for when the
                    # user leaves, except for boundary results, which
                    # render the selections of the function they were
                    # invoked from.
                    if sm.current_state not in (sm.boundary_results, sm.last_boundary_results):
                        self.func_ea = func_ea
                    return
                # Pinned graphs persist across navigation and re-render
                # below (highlight / recenter follows the cursor). This
                # covers all four pinned states — previously only
                # pinned_cluster_graphs was exempted and a pinned
                # neighborhood graph was torn down.
                if not sm.is_pinned_graph():
                    sm.to_base()
                self.func_ea = func_ea

            if func_ea not in self.xref_coverage_dict:
                self.xref_coverage_dict[func_ea] = self.generate_xref_coverage_dict(func_ea)

            self.load_function_context()

    def print_context_help(self) -> None:
        """Print a single compact context hint.

        Replaces the old multi-line bordered help box (which ate ~6-8 lines of
        a usually-short panel and whose width was only an estimate). The hint
        teaches the non-obvious gestures and points to H for the full per-state
        shortcut screen. Still gated by the ``show_help_banner`` setting.
        """
        if not self.xrefer_obj.settings["display_options"]["show_help_banner"]:
            return

        current_state = self.state_machine.current_state.name
        hint = self.context_help.format_compact_hint(current_state)
        if not hint:  # e.g. the help view itself — no self-referential hint line
            return
        self.AddLine(f"    {hint}")
        self.AddLine("")

    def print_ribbon(self) -> None:
        """Print status ribbon and aligned context help."""
        ribbon = self.generate_ribbon_text()
        ribbon = f"{ribbon.ljust(500, ' ')}"
        formatted_ribbon, bg_color = format_ribbon(ribbon)
        self.AddLine(formatted_ribbon, bgcolor=bg_color)
        self.AddLine("")
        self.print_context_help()

    def generate_ribbon_text(self) -> str:
        """
        Generate text content for status ribbon.

        Creates appropriate ribbon content based on current state and settings.

        Returns:
            str: Formatted ribbon text with state-specific information
        """
        base_text: str = "[ XRefer ]"
        esc_str: str = "[ ESC to go back ]"
        # Compact H affordance kept in the ribbon so help stays discoverable
        # even when the compact help line is turned off (show_help_banner) or
        # suppressed (the help view). Minor overlap with the help line's
        # 'H: full help' when both are shown is accepted.
        h_str: str = "[ H help ]"
        exclusions_str: str = f"[ exclusions: {'on' if self.xrefer_obj.settings['enable_exclusions'] else 'off'} ]"
        content: str = ""

        current_state = self.state_machine.current_state
        func_name = idc.get_func_name(self.func_ea)
        if not func_name:
            func_name = "<none>"

        # Handle each state with a suitable content line
        if current_state == self.state_machine.help:
            content = f"[ help ]{esc_str}"
        elif current_state == self.state_machine.boundary_results:
            content = f"[ boundary scan results ]{esc_str}{h_str}"
        elif current_state == self.state_machine.last_boundary_results:
            # Added handling for last_boundary_results
            content = f"[ last boundary scan results ]{esc_str}{h_str}"
        elif current_state == self.state_machine.xref_listing:
            content = f"[ xrefs listing ]{esc_str}{h_str}"
        elif current_state in (self.state_machine.trace_scope_function, self.state_machine.trace_scope_path, self.state_machine.trace_scope_full):
            # Trace scopes show trace info, exclusions, and back/help
            content = f"{self.get_trace_ribbon_content()}{exclusions_str}{esc_str}{h_str}"
        elif current_state in (
            self.state_machine.graph,
            self.state_machine.pinned_graph,
            self.state_machine.simplified_graph,
            self.state_machine.pinned_simplified_graph,
            self.state_machine.cluster_graphs,
            self.state_machine.pinned_cluster_graphs,
        ):
            # Graph-related states show graph info plus ESC/Help
            content = f"{self.get_graph_ribbon_content()}{esc_str}{h_str}"
        elif current_state == self.state_machine.call_focus:
            # Call focus shows func info, exclusions, back/help
            content = f"[ func_ea: 0x{self.func_ea:x} ][ call focus ][ func_name: {func_name} ]{exclusions_str}{esc_str}{h_str}"
        elif current_state == self.state_machine.search:
            # Search shows current filter text
            content = f"[ search ]: {self.state_machine.search_filter}"
        elif current_state == self.state_machine.clusters:
            # Added handling for clusters state (cluster table view)
            content = f"[ clusters ]{esc_str}{h_str}"
        else:
            # Default (base): show func info, exclusions, selection count, help.
            selected_n = len(self.state_machine.get_selected_refs(self.func_ea))
            sel_str = f"[ selected: {selected_n} ]" if selected_n else ""
            content = f"[ func_ea: 0x{self.func_ea:x} ][ func_name: {func_name} ]{exclusions_str}{sel_str}{h_str}"

        return f"{base_text}{content}"

    def get_trace_ribbon_content(self) -> str:
        current_state = self.state_machine.current_state
        trace_info: str = f"[ func_ea: 0x{self.func_ea:x} ][ trace "
        if current_state == self.state_machine.trace_scope_function:
            trace_info = f"{trace_info}scope=function ]"
        elif current_state == self.state_machine.trace_scope_path:
            trace_info = f"{trace_info}scope=path ]"
        elif current_state == self.state_machine.trace_scope_full:
            trace_info = f"{trace_info}scope=full ]"
        return trace_info

    def get_graph_ribbon_content(self) -> str:
        graph_type = []

        if self.state_machine.is_simplified_graph():
            graph_type.append("simplified")
        if self.state_machine.is_pinned_graph():
            graph_type.append("pinned")

        if self.state_machine.current_state in (self.state_machine.cluster_graphs, self.state_machine.pinned_cluster_graphs):
            graph_type.append("cluster graph")
        else:
            graph_type.append("path graph")
        graph_type_str = " ".join(graph_type)

        return f"[ func_ea: 0x{self.func_ea:x} ][ {graph_type_str} ][ func_name: {idc.get_func_name(self.func_ea)} ]"

    def auto_resize_for_graph_content(self) -> None:
        """
        Auto-resize widget based on content width for graph views.
        Only resizes in graph modes and cluster graph mode while maintaining flexible sizing.
        """
        if not self.xrefer_obj.settings["display_options"]["auto_size_graphs"]:
            return

        # Safety check for dock widget
        if not qt_object_alive(self.dock_widget):
            return

        # Only resize for specific states
        is_graph_view = self.state_machine.current_state in (
            self.state_machine.graph,
            self.state_machine.pinned_graph,
            self.state_machine.simplified_graph,
            self.state_machine.pinned_simplified_graph,
            self.state_machine.clusters,
            self.state_machine.cluster_graphs,
            self.state_machine.pinned_cluster_graphs,
        )

        if not is_graph_view:
            if not self.in_graph_view:
                # Exiting graph view - restore previous width if it was different
                default_width = self.xrefer_obj.settings["display_options"]["default_panel_width"]
                if self.last_non_graph_width and self.last_non_graph_width != default_width:
                    width_to_set = self.last_non_graph_width
                else:
                    width_to_set = default_width

                self.dock_widget.setMinimumWidth(width_to_set)
                self.dock_widget.setMaximumWidth(width_to_set)
                self.dock_widget.updateGeometry()
                QtCore.QTimer.singleShot(100, self.reset_size_constraints)
            self.in_graph_view = False
            return

        if not qt_object_alive(self.qt_widget) or not qt_object_alive(self.dock_widget):
            return

        # Store current width before entering graph view if not already in it
        if not self.in_graph_view:
            self.last_non_graph_width = self.dock_widget.width()
            self.in_graph_view = True

        # Find IDA's main window
        main_window = None
        for widget in QtWidgets.QApplication.topLevelWidgets():
            if widget.windowTitle().startswith("IDA - "):
                main_window = widget
                break

        if not main_window:
            return

        # Get main window width and calculate maximum allowed width for dock
        # Leave some space for other widgets (e.g. 20% of main window width)
        main_width = main_window.width()
        max_allowed_width = int(main_width * 0.8)  # Use 80% of main window width as maximum
        line_count = self.Count()

        # Calculate maximum line width
        max_width = self.xrefer_obj.settings["display_options"]["default_panel_width"]  # Use default as minimum
        line_count = self.Count()

        if line_count < 7:
            return

        # Skip first 6 lines
        for i in range(6, line_count):
            line, _, _ = self.GetLine(i)
            # Remove color codes for accurate width calculation
            clean_line = strip_color_codes(line)
            # Add padding for margins and scrollbar
            line_width = len(clean_line) * 8  # Approximate pixel width based on character count
            max_width = max(max_width, line_width)

        # Cap width to maximum allowed
        max_width = min(max_width, max_allowed_width)

        self.dock_widget.setMinimumWidth(max_width)
        self.dock_widget.setMaximumWidth(max_width)
        self.dock_widget.updateGeometry()
        QtCore.QTimer.singleShot(100, self.reset_size_constraints)

    def print_llm_disclaimer(self, disclaimer_index: int = 0) -> bool:
        """Print LLM disclaimer if not hidden in settings."""
        if self.xrefer_obj.settings["display_options"]["hide_llm_disclaimer"]:
            return False

        disclaimer_lines = [
            ("LLM-assisted analysis — low confidence; verify findings manually. Right-click to re-run.",),
            ("LLM-bubbled artifacts — may be inconsistent or miss indicators; a triage starting point.",),
        ]
        INDENT = "    "  # Standard 4-space indent
        for line in disclaimer_lines[disclaimer_index]:
            self.AddLine(f"{INDENT}\x01{ida_lines.SCOLOR_VOIDOP}{line}\x02{ida_lines.SCOLOR_VOIDOP}")
        self.AddLine("")
        return True

    def load_function_context(self) -> None:
        """
        Load and configure function context data for display.

        Handles different view states and content types, including but not limited to:
        - Graph views (normal and simplified)
        - Boundary scan results
        - Trace displays (function, path, and full scope)
        - Cross-reference listings
        - Clusters
        - Help display

        Side Effects:
            - Updates display based on current state
            - May trigger graph generation
            - May load cached results
            - Updates view contents
            - Auto-resizes widget based on content width
        """
        self.ClearLines()

        # Map states to their handler functions
        state_actions = {
            self.state_machine.graph: self.draw_paths_graph,
            self.state_machine.simplified_graph: self.draw_paths_graph,
            self.state_machine.pinned_graph: self.draw_paths_graph,
            self.state_machine.pinned_simplified_graph: self.draw_paths_graph,
            self.state_machine.boundary_results: self.draw_boundary_scan_results,
            self.state_machine.last_boundary_results: self.draw_last_boundary_scan_results,
            self.state_machine.orphans: self.draw_orphans,
            self.state_machine.clusters: self.draw_clusters,
            self.state_machine.cluster_graphs: self.draw_cluster_graph,
            self.state_machine.pinned_cluster_graphs: self.draw_cluster_graph,
            self.state_machine.neighborhood_graph: self.draw_neighborhood_graph,
            self.state_machine.pinned_neighborhood_graph: self.draw_neighborhood_graph,
            self.state_machine.trace_scope_function: self.handle_trace_scope_function,
            self.state_machine.trace_scope_path: self.handle_trace_scope_path,
            self.state_machine.trace_scope_full: self.handle_trace_scope_full,
            self.state_machine.xref_listing: self.draw_entity_xrefs,
            self.state_machine.attack_matrix: self.draw_attack_matrix,
            self.state_machine.help: self.draw_help,
        }

        # Get appropriate handler or use default table context
        state_handler = state_actions.get(self.state_machine.current_state, self.handle_table_context)

        # Graph rendering (artifact path graphs via G, neighborhood graphs)
        # can be slow for large/complex graphs — the ASCII layout
        # especially. Put up IDA's wait box so the user gets "Generating
        # graph..." feedback instead of a seemingly frozen UI. Simple
        # graphs render instantly and the box just flashes. This is all
        # synchronous on the main thread, so the show/hide pair is safe
        # (unlike background-thread wait-box use). Cluster graph states are
        # absent on purpose: their layouts are cached (_cluster_ascii_lines)
        # and the box is shown there only on an actual rebuild, so cluster
        # sync doesn't flash a wait box on every cursor landing.
        graph_states = {
            self.state_machine.graph,
            self.state_machine.simplified_graph,
            self.state_machine.pinned_graph,
            self.state_machine.pinned_simplified_graph,
            self.state_machine.neighborhood_graph,
            self.state_machine.pinned_neighborhood_graph,
        }
        if self.state_machine.current_state in graph_states:
            idaapi.show_wait_box("HIDECANCEL\nGenerating graph...")
            try:
                state_handler()
            finally:
                idaapi.hide_wait_box()
        else:
            state_handler()

        # Auto-resize if in appropriate state
        self.auto_resize_for_graph_content()
        self.Refresh()

    def is_api_excluded(self, api_name: str) -> bool:
        """
        Check if an API is excluded.

        Args:
            api_name (str): Full API name (e.g., 'kernel32.CreateFileW')

        Returns:
            bool: True if the API is excluded, False otherwise
        """
        # If exclusions is disabled, nothing is excluded
        if not self.xrefer_obj.settings["enable_exclusions"]:
            return False

        # Extract API name without module prefix
        api_suffix = api_name.split(".")[-1].lower()

        # Check against exclusions
        exclusions = self.xrefer_obj.settings_manager.load_exclusions()
        return api_suffix in (name.lower() for name in exclusions["apis"])

    def filter_api_calls(self, calls: List[ApiCall]) -> List[ApiCall]:
        """Drop API call records whose api_name is on the exclusions list."""
        if not self.xrefer_obj.settings["enable_exclusions"]:
            return calls
        return [c for c in calls if not self.is_api_excluded(c.api_name)]

    def _render_trace(self, calls: List[ApiCall], empty_msg: str) -> None:
        """Shared rendering for the three trace scopes."""
        self.ClearLines()
        self.print_ribbon()

        if not calls:
            self.AddLine(empty_msg)
            return

        filtered_calls = self.filter_api_calls(calls)
        if not filtered_calls:
            self.AddLine("    ALL API CALLS ARE EXCLUDED")
            return

        for rec in filtered_calls:
            self.AddLine(format_api_call_for_ida(rec))

    def handle_trace_scope_function(self) -> None:
        """Function-scope trace: API calls made directly from the current function."""
        self._render_trace(
            self.xrefer_obj.gather_sorted_function_api_calls(self.func_ea),
            "    NO API CALLS FOUND FOR CURRENT FUNCTION",
        )

    def handle_trace_scope_path(self) -> None:
        """Path-scope trace: direct + indirect API calls reachable from the current function."""
        self._render_trace(
            self.xrefer_obj.gather_sorted_path_api_calls(self.func_ea),
            "    NO API CALLS FOUND FOR CURRENT PATH",
        )

    def handle_trace_scope_full(self) -> None:
        """Full-scope trace: every API call in the trace database."""
        self._render_trace(
            self.xrefer_obj.gather_sorted_full_api_calls(),
            "    NO API CALLS FOUND IN DATABASE",
        )

    def handle_no_context_available(self) -> None:
        """
        Handle case when no function context is available.

        Displays message indicating no context is available for
        current function address.
        """
        self.AddLine(f" [0x{self.func_ea:x}] NO FUNCTION CONTEXT AVAILABLE")

    def handle_table_context(self) -> None:
        """
        Handle display of function context tables.

        Displays appropriate tables showing cross-references, imports, strings,
        and other relevant information for current function.
        """
        self.ClearLines()
        self.print_ribbon()

        if ida_funcs.get_func(self.func_ea):
            if self.func_ea in self.xrefer_obj.global_xrefs:
                # Compact 2-line cluster context (membership + 1-hop adjacency).
                # Replaces the full banner + the verbose roles block: the
                # function addr/name live in the ribbon and the full role
                # breakdown lives in the cluster views.
                self._emit_compact_cluster_context(self.func_ea)
                self.draw_function_context_tables(self.func_ea)
            else:
                self.handle_no_context_available()

    def _align_merged_name_columns(self, rows_by_category: "OrderedDict[str, List[str]]") -> None:
        """Normalise the name-column width across a merged xref table so
        import and library addresses line up.

        Imports and libraries are tabulated as separate tables, each
        sizing its first (name) column to its own longest entry, so when
        their rows share a category the address columns start at
        different offsets. Each colored row has the shape
        ``\\x01<tag><name+padding>\\x02<tag><addresses>``; this re-pads
        the narrower rows' name column in place to the widest one across
        the whole merged table, so the addresses align. (Sub-columns of
        multi-address rows keep whatever spacing their source table gave
        them.)
        """
        def name_col_width(row: str) -> int:
            if len(row) < 3 or row[0] != "\x01":
                return -1
            end = row.find("\x02", 2)
            return end - 2 if end >= 0 else -1

        widths = [w for rows in rows_by_category.values() for w in map(name_col_width, rows) if w >= 0]
        if not widths:
            return
        target = max(widths)
        for rows in rows_by_category.values():
            for i, row in enumerate(rows):
                w = name_col_width(row)
                if 0 <= w < target:
                    end = row.find("\x02", 2)
                    rows[i] = row[:end] + (" " * (target - w)) + row[end:]

    def _merge_indirect_tables(self, func_ea: int) -> None:
        """Collapse the separate INDIRECT IMPORT XREFS and INDIRECT
        LIBRARY XREFS tables into one merged table.

        Both are grouped by the same Categorizer categories, so showing
        them separately repeats every category header. This concatenates
        each category's rows (imports first, then libraries) and
        relabels the heading, leaving ``core``/``table_data`` generation
        untouched. Imports vs libraries stay distinguishable by their
        existing row colors. Idempotent — safe to call repeatedly.
        """
        td = self.xrefer_obj.table_data.get(func_ea)
        if td is None or self.merged_indirect_name in td:
            return

        import_name = self.xrefer_obj.table_names[2]
        lib_name = self.xrefer_obj.table_names[1]
        imp_tbl = td.pop(import_name, None)
        lib_tbl = td.pop(lib_name, None)

        merged_rows: "OrderedDict[str, List[str]]" = OrderedDict()
        for tbl in (imp_tbl, lib_tbl):
            if not tbl:
                continue
            for category, rows in tbl.get("rows", {}).items():
                if rows:
                    merged_rows.setdefault(category, []).extend(rows)

        # Reuse a source heading's exact formatting, relabeled to the
        # merged name (prefer imports' heading; fall back to libraries').
        heading: List[str] = []
        for tbl, src_name in ((imp_tbl, import_name), (lib_tbl, lib_name)):
            if tbl and tbl.get("heading"):
                heading = [line.replace(src_name, self.merged_indirect_name) for line in tbl["heading"]]
                break

        self._align_merged_name_columns(merged_rows)
        td[self.merged_indirect_name] = {"heading": heading, "rows": merged_rows}

    def _emit_reaches_summary(self, func_ea: int) -> None:
        """Emit a one-line 'at a glance' summary of what this function reaches.

        Counts are taken from the same ``table_data`` the tables below render
        (post-merge, post-exclusion), so the summary's numbers always match the
        per-table counts. No-op when the function reaches nothing.
        """
        td = self.xrefer_obj.table_data.get(func_ea, {})

        def tcount(name: str) -> int:
            tbl = td.get(name)
            if not tbl:
                return 0
            return sum(len(v) for v in tbl.get("rows", {}).values() if v)

        direct = tcount("DIRECT XREFS")
        imps_libs = tcount(self.merged_indirect_name)
        strings = tcount(self.xrefer_obj.table_names[3])
        capa = tcount(self.xrefer_obj.table_names[4])
        total = direct + imps_libs + strings + capa
        if not total:
            return

        def num(n: int) -> str:
            return ida_lines.COLSTR(str(n), ida_lines.SCOLOR_VOIDOP)

        def dim(s: str) -> str:
            return ida_lines.COLSTR(s, ida_lines.SCOLOR_DSTR)

        line = (
            f"    {dim('Reaches ')}{num(total)}{dim(' artifacts')}"
            f"{dim(' · direct ')}{num(direct)}"
            f"{dim(' · indirect: ')}{num(imps_libs)}{dim(' imports & libs, ')}"
            f"{num(strings)}{dim(' strings, ')}{num(capa)}{dim(' capa')}"
        )
        self.AddLine(line)
        self.AddLine("")

    def draw_function_context_tables(self, func_ea: int) -> bool:
        """
        Draw all relevant tables for a function.

        Displays all applicable cross-reference tables based on current state
        and table expansion settings.

        Args:
            func_ea (int): Address of function to display tables for
        """
        printed = False
        if func_ea not in self.xref_coverage_dict:
            self.xref_coverage_dict[func_ea] = self.generate_xref_coverage_dict(func_ea)

        # Ensure the per-function tables exist, then collapse the indirect
        # import/library pair into one merged table before rendering.
        if func_ea not in self.xrefer_obj.table_data:
            self.xrefer_obj.table_data[func_ea] = self.xrefer_obj.create_sorted_table(func_ea)
        self._merge_indirect_tables(func_ea)
        self._emit_reaches_summary(func_ea)

        for table_index in range(self.table_count):
            table_start_index: int = (table_index + self.table_index_offset) % self.table_count
            table_name: str = self.table_names[table_start_index]
            try:
                table_data = self.xrefer_obj.table_data[func_ea][table_name]
            except KeyError:
                self.xrefer_obj.table_data[func_ea] = self.xrefer_obj.create_sorted_table(func_ea)
                self._merge_indirect_tables(func_ea)
                table_data = self.xrefer_obj.table_data[func_ea][table_name]

            if table_data:
                printed = True
                if self.table_states[table_name] or self.state_machine.current_state in (self.state_machine.call_focus, self.state_machine.search):
                    self.draw_function_context_table(func_ea, table_name)
                else:
                    self.draw_function_context_table_heading(func_ea, table_name, "▸ %s")
                    self.AddLine("")

        return printed

    def draw_function_context_table(self, func_ea: int, table_name: str) -> None:
        """
        Draw a specific table type for a function.

        Handles display of a single table type including headers and
        content based on expansion state.

        Args:
            func_ea (int): Address of function table belongs to
            table_name (str): Name/type of table to draw
        """
        self.current_table = table_name
        self.draw_function_context_table_heading(func_ea, table_name)

        subtable_states: Dict[str, bool] = self.subtable_states.setdefault(table_name, {})

        for inner_table_key, inner_table in self.xrefer_obj.table_data[func_ea][table_name]["rows"].items():
            is_expanded: bool = subtable_states.setdefault(inner_table_key, False)

            if is_expanded or table_name.startswith("D") or self.state_machine.current_state in (self.state_machine.call_focus, self.state_machine.search):
                self.display_function_context_table_contents(table_name, inner_table_key, inner_table)
            else:
                # Collapsed category — chevron + artifact count, gaugeable without expanding.
                self.AddLine(self._category_line("▸", inner_table_key, len(inner_table)))

        if self.xrefer_obj.table_data[func_ea][table_name]["rows"]:
            self.AddLine("")

    def display_function_context_table_contents(self, table_name: str, inner_table_key: str, inner_table: List[str]) -> None:
        """
        Display contents of a specific table section.

        Handles the actual rendering of table rows with appropriate indentation
        and formatting based on table type.

        Args:
            table_name (str): Name of containing table
            inner_table_key (str): Key for this section of table
            inner_table (List[str]): Content rows to display
        """
        if not table_name.startswith("D") and not self.state_machine.current_state == self.state_machine.call_focus:
            self.AddLine(self._category_line("▾", inner_table_key, len(inner_table)))

        line_prefix: str = "    " if table_name.startswith("D") else self.indent
        is_merged = table_name == self.merged_indirect_name

        for line in inner_table:
            # T2: a selection checkbox (☑ when the row carries a \x04 select
            # mark) and, in the merged table, an imp/lib type tag inferred from
            # the row's leading color byte. Both are uncolored and accounted for
            # in cell_regex, so double-click still resolves the artifact name.
            box = "☑ " if "\x04" in line else "☐ "
            tag = ""
            if is_merged and len(line) > 1 and line[0] == "\x01":
                cbyte = ord(line[1])
                if cbyte == ida_lines.SCOLOR_IMPNAME:
                    tag = "imp "
                elif cbyte == ida_lines.SCOLOR_DEMNAME:
                    tag = "lib "
            self.print_xref_item(f"{line_prefix}{box}{tag}{line}", self.state_machine.address_filter)

    def _category_line(self, marker: str, key: str, count: int) -> str:
        """Build a category header line: '<chevron> <category>  (N)'.

        Starts with a color code (not raw spaces) so ``cell_regex`` never
        mistakes it for a selectable row."""
        return (
            ida_lines.COLSTR(f"    {marker} ", ida_lines.SCOLOR_DATNAME)
            + ida_lines.COLSTR(key, ida_lines.SCOLOR_DNAME)
            + "  " + ida_lines.COLSTR(f"({count})", ida_lines.SCOLOR_VOIDOP)
        )

    def _indirect_via_funcs(self, e_index: int) -> List[int]:
        """The current function's callees through which an *indirect* artifact
        is reached — i.e. which of ``self.func_ea``'s direct callees begin a
        call path that references entity ``e_index``. Empty for direct refs or
        when unknown. Sorted for stable display.

        Note: for INDIRECT xrefs the ``*_ea`` buckets map entity_index -> set
        of callee function EAs (unlike DIRECT, where they map to call-site
        addresses); ``process_rows_for_indirect_xrefs`` relies on the same
        shape.
        """
        try:
            entity = self.xrefer_obj.entities[e_index]
            base = {1: "libs", 2: "imports", 3: "strings", 4: "capa", 5: "api_trace"}.get(entity[2])
            if not base:
                return []
            bucket = self.xrefer_obj.entity_suffix_map.get(base, f"{base}_ea")
            gx = self.xrefer_obj.global_xrefs.get(self.func_ea)
            if not gx:
                return []
            indirect = gx.get(self.xrefer_obj.INDIRECT_XREFS, {})
            return sorted(indirect.get(bucket, {}).get(e_index, ()))
        except Exception:
            return []

    def _combine_tooltips(self, *tips) -> Optional[Tuple[int, str]]:
        """Merge IDA hint tuples ``(num_important_lines, text)`` into one,
        skipping ``None``/empty. ``OnHint`` must return this tuple shape for the
        hint to DISPLAY (a bare string is accepted but silently not shown)."""
        valid: List[Tuple[int, str]] = []
        for t in tips:
            if not t:
                continue
            if isinstance(t, tuple) and len(t) == 2:
                n, text = t
            else:  # defensive: coerce a bare string
                text = str(t)
                n = text.count("\n") + 1
            if text:
                valid.append((int(n), text))
        if not valid:
            return None
        total = sum(n for n, _ in valid) + (len(valid) - 1)  # +blank separators
        return total, "\n\n".join(text for _, text in valid)

    def _indirect_via_tooltip(self, e_index: int) -> Optional[Tuple[int, str]]:
        """Hover body for an indirect artifact: the callee functions it is
        reached through (the indirection's 'through what').

        Returns an IDA hint tuple ``(num_important_lines, text)`` — the shape
        ``OnHint`` must return for the tip to actually DISPLAY — or ``None``
        when the artifact isn't reached indirectly from the current function.

        Deliberately does NOT gate on ``get_parent_table()`` — that reads the
        mouse line (``GetLineNo(mouse=1)``), which returns -1 inside the OnHint
        callback. ``_indirect_via_funcs`` is itself indirect-only (empty for a
        purely direct ref), so it's a sufficient gate on its own.

        The body is colorized to match the function-address tooltips: a keyword
        header with an emphasized count, a dashed rule, then each callee in the
        function-name colour (``SCOLOR_DEMNAME``) and a dimmed overflow line."""
        callees = self._indirect_via_funcs(e_index)
        if not callees:
            return None
        # SWIG's get_func_name wants a real ea_t; the callee values come from the
        # backend and aren't always plain ints, so wrap as ida_idaapi.ea_t(int(…)).
        func_trunc_length: int = 60
        names: List[str] = []
        for c in callees:
            name = idc.get_func_name(ida_idaapi.ea_t(int(c))) or f"0x{int(c):x}"
            if len(name) > func_trunc_length:
                name = f"{name[:func_trunc_length]}..."
            names.append(name)
        shown = names[:12]
        overflow = len(names) - len(shown)

        kw: int = ida_lines.SCOLOR_KEYWORD   # header label
        num: int = ida_lines.SCOLOR_VOIDOP   # the count
        fn: int = ida_lines.SCOLOR_DEMNAME   # callee names (matches addr tooltips)
        dim: int = ida_lines.SCOLOR_AUTOCMT  # "+N more"

        # Size the rule to the widest *visible* line (color codes excluded).
        plain = [f"Reached through {len(names)} function(s):"] + [f"  {n}" for n in shown]
        if overflow > 0:
            plain.append(f"  … (+{overflow} more)")
        sep_len = max(len(p) for p in plain)

        header = (
            f"\x01{kw}Reached through \x02{kw}"
            f"\x01{num}{len(names)}\x02{num}"
            f"\x01{kw} function(s):\x02{kw}"
        )
        lines = [header, f"\x01{fn}{'-' * sep_len}\x02{fn}"]
        lines += [f"  \x01{fn}{n}\x02{fn}" for n in shown]
        if overflow > 0:
            lines.append(f"  \x01{dim}… (+{overflow} more)\x02{dim}")
        return len(lines), "\n".join(lines)

    def draw_function_context_table_heading(self, func_ea: int, table_name: str, fmt: str = "▾ %s") -> None:
        """
        Print formatted table heading.

        Displays table header with appropriate formatting and expansion indicators.

        Args:
            func_ea (int): Function address table belongs to
            table_name (str): Name of table to create heading for
            fmt (str): Format string for heading (default: '[-] %s')
        """
        try:
            if not self.xrefer_obj.table_data[func_ea][table_name]["heading"]:
                return
        except KeyError:
            return

        heading_line: str = self.xrefer_obj.table_data[func_ea][table_name]["heading"][0]
        hline: str = ida_lines.COLSTR(fmt % heading_line, ida_lines.SCOLOR_DATNAME)
        # Append the artifact count so the magnitude of each table is legible
        # at a glance — including when the table is collapsed.
        total = sum(len(v) for v in self.xrefer_obj.table_data[func_ea][table_name].get("rows", {}).values() if v)
        if total:
            hline += "  " + ida_lines.COLSTR(f"({total})", ida_lines.SCOLOR_VOIDOP)
        self.AddLine(hline)
        heading_line = self.xrefer_obj.table_data[func_ea][table_name]["heading"][1]
        # Non-direct tables get a "----" continuation marker that visually
        # extends the dashed line from the "(-)" expansion indicator. Direct
        # tables stand on their own and don't need it. Used to be OS-gated
        # (only Win/Linux got the marker); unified across platforms.
        if not table_name.startswith("D"):
            hline = ida_lines.COLSTR(f"    ----{heading_line}", ida_lines.SCOLOR_DATNAME)
        else:
            hline = ida_lines.COLSTR(f"    {heading_line}", ida_lines.SCOLOR_DATNAME)
        self.AddLine(hline)

    def generate_xref_coverage_dict(self, func_ea: int) -> Dict[int, bool]:
        """
        Generate dictionary tracking cross-reference coverage.

        Creates mapping of cross-reference addresses to their coverage status
        based on function names and references.

        Args:
            func_ea (int): Function address to analyze coverage for

        Returns:
            Dict[int, bool]: Dictionary mapping xref addresses to coverage status
        """
        if func_ea not in self.xrefer_obj.caller_xrefs_cache:
            return {}

        xref_coverage_dict: Dict[int, bool] = {}
        flag: Optional[bool] = None

        for xref_to in self.xrefer_obj.caller_xrefs_cache[func_ea].keys():
            if idc.func_contains(ida_idaapi.ea_t(xref_to), ida_idaapi.ea_t(xref_to)):
                if idc.get_func_name(ida_idaapi.ea_t(xref_to)).startswith("sub_"):
                    flag = False
                else:
                    flag = True

                for xref_frm in self.xrefer_obj.caller_xrefs_cache[func_ea][xref_to]:
                    if xref_frm not in xref_coverage_dict:
                        xref_coverage_dict[xref_frm] = flag

        return xref_coverage_dict

    def prepare_xref_colors(self, line: str, xref_coverage_dict: Dict[int, bool]) -> str:
        """
        Apply appropriate colors to cross-references based on coverage.

        Colors cross-references differently based on whether they are covered
        by analysis or not.

        Args:
            line (str): Line containing cross-references
            xref_coverage_dict (Dict[int, bool]): Coverage status dictionary

        Returns:
            str: Line with color codes applied based on coverage
        """
        for xref_frm in xref_coverage_dict.keys():
            line = set_xref_coverage_color(line, "0x%x" % xref_frm, xref_coverage_dict[xref_frm])

        return line

    def select_cell(self, cell: str) -> None:
        """
        Mark a table cell as selected.

        Updates internal state and visual representation to show cell as selected.

        Args:
            cell (str): Cell content to mark as selected
        """
        if self.state_machine.current_state == self.state_machine.search:
            cell = cell.replace("\x04", "")

        for table_name in self.xrefer_obj.table_data[self.func_ea]:
            for inner_table_key, inner_table in self.xrefer_obj.table_data[self.func_ea][table_name]["rows"].items():
                for i in range(0, len(inner_table)):
                    row: str = inner_table[i]
                    orig_row_length: int = len(row)
                    replaced: str = wrap_substring_with_string(row, cell, "\x04", case=True)
                    if len(replaced) == orig_row_length:
                        continue

                    self.xrefer_obj.table_data[self.func_ea][table_name]["rows"][inner_table_key][i] = replaced

    def deselect_cell(self, cell: str) -> None:
        """
        Remove selection from a table cell.

        Updates internal state and visual representation to remove selection.

        Args:
            cell (str): Cell content to deselect
        """
        if self.state_machine.current_state == self.state_machine.search:
            parts: List[str] = cell.split("\x04")
            if len(parts) > 3:
                cell = "\x04".join([parts[0], "".join(parts[1:-1]), parts[-1]])

        for table_name in self.xrefer_obj.table_data[self.func_ea]:
            for inner_table_key, inner_table in self.xrefer_obj.table_data[self.func_ea][table_name]["rows"].items():
                for i in range(0, len(inner_table)):
                    row: str = inner_table[i]
                    if cell in row:
                        self.xrefer_obj.table_data[self.func_ea][table_name]["rows"][inner_table_key][i] = row.replace("\x04", "")

    def generate_addr_tooltip(self, func_ea: int) -> Optional[Tuple[int, str]]:
        """
        Generate tooltip for address/function.

        Creates detailed tooltip showing function information including direct
        cross-references and relevant metadata.

        Args:
            func_ea (int): Function address to generate tooltip for

        Returns:
            Optional[Tuple[int, str]]: Tuple of (line count, tooltip text) if generated,
                                     None if no tooltip available
        """
        line_count: int = 0
        tooltip: str = ""
        func_trunc_length: int = 60
        func_name: str = idc.get_func_name(func_ea)
        if len(func_name) > func_trunc_length:
            func_name = f"{func_name[:func_trunc_length]}..."
        func_name = f"\x01{ida_lines.SCOLOR_DEMNAME}{func_name}\x02{ida_lines.SCOLOR_DEMNAME}\n"

        if func_ea in self.tooltip_cache:
            _line_count, _tooltip = self.tooltip_cache[func_ea]
            if func_ea != _tooltip[0]:
                _tooltip = _tooltip.splitlines()
                _tooltip[0] = func_name[:-1]
                _tooltip = "\n".join(_tooltip)
                self.tooltip_cache[func_ea] = _line_count, _tooltip
            return self.tooltip_cache[func_ea]

        try:
            direct_xref_entities: Dict[str, Set[int]] = self.xrefer_obj.global_xrefs[func_ea][0]
        except:
            return None

        func_name_len: int = len(func_name)

        for _type in "libs", "imports", "strings", "capa":
            for e_index in direct_xref_entities[_type]:
                entity: Tuple[str, str, int] = self.xrefer_obj.entities[e_index]
                table_name: str = self.xrefer_obj.table_names[entity[2]]
                entity_content: str = entity[1]
                entity_color_tag: int = self.xrefer_obj.color_tags[table_name]
                if _type == "imports":
                    api_calls = self.xrefer_obj.get_direct_calls(entity_content, func_ea)
                    total_calls = sum(count for _, count in api_calls)
                    total_lines = len(api_calls)
                    displayed_calls = api_calls[:3]  # Limit to 3 calls

                    # Add "(x more)" if there are more than 3 calls
                    if total_lines > 3:
                        sum_of_first_three_calls = sum(count for _, count in api_calls[:3])
                        entity_content += f"\x02  ({total_calls - sum_of_first_three_calls} more)"

                    tooltip += f"\x01{entity_color_tag}{entity_content}\x02{entity_color_tag}\n"
                    line_count += 1

                    if displayed_calls:
                        for call, _ in displayed_calls:
                            # Limit the length of the call string and add "..." if truncated
                            if len(call) > 150:
                                call = call[:150] + "..."
                            tooltip += f"  {colorize_api_call(call)}\n"
                            line_count += 1
                else:
                    tooltip += f"\x01{entity_color_tag}{entity_content}\x02{entity_color_tag}\n"
                    line_count += 1

        sep_len: int = longest_line_length(tooltip)
        sep_len = sep_len - 4 if sep_len >= func_name_len else func_name_len - 4
        sep: str = "-" * sep_len
        func_name += f"\x01{ida_lines.SCOLOR_DEMNAME}{sep}\x02{ida_lines.SCOLOR_DEMNAME}\n"
        tooltip = func_name + tooltip
        line_count += 2

        if line_count > 2:
            self.tooltip_cache[func_ea] = line_count, tooltip
        else:
            s_no_xrefs: str = ida_lines.COLSTR("No Direct XRefs", ida_lines.SCOLOR_DEMNAME)
            tooltip += f"{s_no_xrefs}\n"
            self.tooltip_cache[func_ea] = 3, tooltip

        return self.tooltip_cache[func_ea]

    def generate_str_tooltip(self, line_dict: Dict[str, str], repo_names: List[str]) -> Tuple[int, str]:
        """
        Generate tooltip for string references.

        Creates tooltip showing string context from source repositories.

        Args:
            line_dict (Dict[str, str]): Dictionary mapping line numbers to code lines
            repo_names (List[str]): List of repository names where string was found

        Returns:
            Tuple[int, str]: Tuple of (number of lines, formatted tooltip text)
        """
        line_count = 0
        tooltip = ""

        # Iterate over line_dict items sorted by line number
        for line_number, line_text in sorted(line_dict.items(), key=lambda x: int(x[0])):
            # Colorize the line number
            line_num_str = f"\x01{ida_lines.SCOLOR_KEYWORD}{line_number}\x02{ida_lines.SCOLOR_KEYWORD}"
            # Colorize the line text
            line_text_str = f"\x01{ida_lines.SCOLOR_DEMNAME}{line_text}\x02{ida_lines.SCOLOR_DEMNAME}"
            # Combine them into a single line
            tooltip_line = f"{line_num_str}: {line_text_str}\n"
            tooltip += tooltip_line
            line_count += 1

        # If repo_names is not empty, add separator and additional repository hits
        if repo_names:
            # Add separator
            sep = "-" * 20
            tooltip += f"{sep}\n"
            line_count += 1

            # Add "Additional repository hits:" header
            header_str = f"\x01{ida_lines.SCOLOR_KEYWORD}Matched Repos:\x02{ida_lines.SCOLOR_KEYWORD}\n"
            tooltip += header_str
            line_count += 1

            # List each repository name with its index
            for idx, repo_name in enumerate(repo_names, start=1):
                # Colorize the repository name
                repo_name_str = f"\x01{ida_lines.SCOLOR_IMPNAME}{repo_name}\x02{ida_lines.SCOLOR_IMPNAME}"
                repo_line = f"{idx}- {repo_name_str}\n"
                tooltip += repo_line
                line_count += 1

        return line_count, tooltip

    def generate_cluster_tooltip(self, cluster: "FunctionalCluster", analysis_data: Dict) -> str:
        """
        Generate comprehensive tooltip for cluster with all available data.

        Args:
            cluster: Cluster to generate tooltip for
            analysis_data: Dictionary containing cluster analysis data

        Returns:
            str: Formatted tooltip text with color codes
        """
        tooltip = []

        # Cluster header with ID
        header = f"Cluster {cluster.id_str}"
        if cluster.parent_cluster_id:
            header += f" (Subcluster of {cluster.parent_cluster_id})"
        tooltip.append(f"\x01{ida_lines.SCOLOR_DEMNAME}{header}\x02{ida_lines.SCOLOR_DEMNAME}")

        # Add separator
        separator = "=" * len(header)
        tooltip.append(f"\x01{ida_lines.SCOLOR_DEMNAME}{separator}\x02{ida_lines.SCOLOR_DEMNAME}")

        # Add basic cluster info
        if analysis_data:
            # Label (if available)
            if label := analysis_data.get("label"):
                tooltip.append(f"\x01{ida_lines.SCOLOR_DEMNAME}Label:\x02{ida_lines.SCOLOR_DEMNAME} \x01{ida_lines.SCOLOR_IMPNAME}{label}\x02{ida_lines.SCOLOR_IMPNAME}")

            # Description (if available)
            if desc := analysis_data.get("description"):
                tooltip.append(f"\x01{ida_lines.SCOLOR_DEMNAME}Description:\x02{ida_lines.SCOLOR_DEMNAME}")
                # Word wrap description
                words = desc.split()
                line = []
                line_length = 0
                max_length = 80

                for word in words:
                    if line_length + len(word) + 1 <= max_length:
                        line.append(word)
                        line_length += len(word) + 1
                    else:
                        tooltip.append(f"\x01{ida_lines.SCOLOR_DSTR}  {' '.join(line)}\x02{ida_lines.SCOLOR_DSTR}")
                        line = [word]
                        line_length = len(word)
                if line:
                    tooltip.append(f"\x01{ida_lines.SCOLOR_DSTR}  {' '.join(line)}\x02{ida_lines.SCOLOR_DSTR}")

            # Relationships (if available)
            if rels := analysis_data.get("relationships"):
                tooltip.append(f"\x01{ida_lines.SCOLOR_DEMNAME}Relationships:\x02{ida_lines.SCOLOR_DEMNAME}")
                # Word wrap relationships
                words = rels.split()
                line = []
                line_length = 0
                max_length = 80

                for word in words:
                    if line_length + len(word) + 1 <= max_length:
                        line.append(word)
                        line_length += len(word) + 1
                    else:
                        tooltip.append(f"\x01{ida_lines.SCOLOR_DSTR}  {' '.join(line)}\x02{ida_lines.SCOLOR_DSTR}")
                        line = [word]
                        line_length = len(word)
                if line:
                    tooltip.append(f"\x01{ida_lines.SCOLOR_DSTR}  {' '.join(line)}\x02{ida_lines.SCOLOR_DSTR}")

        # Add function count and artifacts
        tooltip.append("")  # Add spacing
        tooltip.append(f"\x01{ida_lines.SCOLOR_DEMNAME}Functions: \x02{ida_lines.SCOLOR_DEMNAME}\x01{ida_lines.SCOLOR_NUMBER}{len(cluster.nodes)}\x02{ida_lines.SCOLOR_NUMBER}")

        line_count = len(tooltip)
        return line_count, "\n".join(tooltip)

    # Per-artifact width clamp for "node detail" mode (keeps boxes from going
    # absurdly wide on a single long string). No *line-count* cap — the
    # experiment shows every direct artifact; tall nodes are expected.
    _NODE_ARTIFACT_TRUNC = 26

    def _graph_artifact_cap(self) -> Optional[int]:
        """Effective per-type artifact cap for graph node-detail mode, or
        ``None`` when capping is disabled (show all — the default).

        Driven by the ``display_options`` settings ``cap_graph_node_artifacts``
        (bool) and ``graph_node_artifact_cap`` (int). A non-positive / malformed
        value reads as "no cap" so a bad setting never hides everything."""
        opts = self.xrefer_obj.settings.get("display_options", {})
        if not opts.get("cap_graph_node_artifacts", False):
            return None
        try:
            n = int(opts.get("graph_node_artifact_cap", 6))
        except (TypeError, ValueError):
            return None
        return n if n > 0 else None

    def _node_artifact_entries(self, ea: int) -> List[Tuple[str, int]]:
        """``(display_text, SCOLOR)`` for each of a function's *direct* xrefs —
        the data the hover tooltip shows, but for in-node rendering. One entry
        per artifact (imports → strings → capa → libs), truncated to
        ``_NODE_ARTIFACT_TRUNC``; the colour is the entity's per-type tag
        (``color_tags`` — IMPORT→IMPNAME, STRING→DSTR, CAPA→CODNAME,
        LIBRARY→DEMNAME), so the node matches the tooltip's palette. No type
        tag: colour carries the type. Returns ``[]`` for functions with no
        direct artifacts (node stays as small as today).

        When the ``cap_graph_node_artifacts`` setting is on, each type is capped
        to ``_graph_artifact_cap()`` entries with a dim ``(+N more)`` overflow
        line per truncated type (the cap is folded into ``draw_paths_graph``'s
        cache key so a changed cap re-renders rather than returning a stale box).

        The text is laid out plain (the ASCII layout is colour-blind and sizes
        boxes by raw width); the colour is applied post-layout by
        ``draw_paths_graph`` via the per-key ``_graph_artifact_colors`` map."""
        try:
            direct = self.xrefer_obj.global_xrefs[ea][self.xrefer_obj.DIRECT_XREFS]
        except Exception:
            return []

        per_type: List[Tuple[str, List[Tuple[str, int]]]] = []
        for key in ("imports", "strings", "capa", "libs"):
            items: List[Tuple[str, int]] = []
            for e_index in sorted(direct.get(key, ())):
                try:
                    entity = self.xrefer_obj.entities[e_index]
                    name = entity[1]
                    color = self.xrefer_obj.color_tags[self.xrefer_obj.table_names[entity[2]]]
                except Exception:
                    continue
                # Strip IDA colour-control bytes too: an artifact carrying a
                # stray \x01/\x02 would desync the post-layout colour scan.
                name = name.replace("\x01", "").replace("\x02", "")
                name = name.replace("\n", " ").replace("\r", " ").strip()
                if not name:
                    continue
                if len(name) > self._NODE_ARTIFACT_TRUNC:
                    name = name[: self._NODE_ARTIFACT_TRUNC - 2] + ".."
                items.append((name, color))
            per_type.append((key, items))

        return cap_artifact_entries(per_type, self._graph_artifact_cap(), ida_lines.SCOLOR_AUTOCMT)

    def _colorize_node_artifacts(self, line: str, artifact_items: List[Tuple[str, int]]) -> str:
        """Colour EVERY occurrence of each node artifact in a rendered graph line.

        The ASCII layout packs nodes side-by-side, so the same artifact name
        recurs across boxes on a single output line. ``wrap_substring_with_string``
        only wraps the *first* occurrence, which left every box but the leftmost
        uncoloured (and, with vertical box offsets, coloured some artifacts in a
        node and not others). This does a single left-to-right scan instead:

        * existing IDA colour-code pairs (``\\x01X`` / ``\\x02X``) are copied
          verbatim as opaque 2-char skips, so the blanket DEMNAME wrap and the
          func_ea / entity highlights already applied survive untouched;
        * at each plain position the LONGEST artifact starting there wins, so a
          prefix artifact never bleeds into a longer one (CreateFile vs
          CreateFileW);
        * a match is emitted wrapped and the cursor advances past it, so an
          already-coloured span is never re-entered.

        Case-sensitive (matches the rest of the graph colouring). ``artifact_items``
        must be pre-sorted longest-first; empty keys are skipped (an empty match
        would loop / emit unbalanced codes)."""
        out: List[str] = []
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if ch in ("\x01", "\x02") and i + 1 < n:
                out.append(line[i:i + 2])
                i += 2
                continue
            match = None
            for text, color in artifact_items:
                if text and line.startswith(text, i):
                    match = (text, color)
                    break
            if match is not None:
                text, color = match
                out.append(f"\x01{color}{text}\x02{color}")
                i += len(text)
            else:
                out.append(ch)
                i += 1
        return "".join(out)

    def draw_paths_graph(self) -> None:
        """
        Draw ASCII graph of paths to selected cross-reference.

        Generates and displays ASCII art representation of paths from entry points
        to selected reference, with appropriate coloring and caching.
        Handles both normal and simplified graph views.
        """
        e_index = self.state_machine.selected_index
        entity: Tuple[str, str, int] = self.xrefer_obj.entities[e_index]
        table_name: str = self.xrefer_obj.table_names[entity[2]]
        entity_content: str = entity[1]
        entity_color_tag: int = self.xrefer_obj.color_tags[table_name]
        xrefs: Set[int] = self.xrefer_obj.entity_xrefs[e_index]
        entity_wrap_start: str = f"\x01{entity_color_tag}"
        entity_wrap_end: str = f"\x02{entity_color_tag}"
        colored_entity: str = f"{entity_wrap_start}{entity_content}{entity_wrap_end}"

        # Update heading based on graph type
        is_simplified = self.state_machine.is_simplified_graph()
        is_pinned = self.state_machine.is_pinned_graph()
        graph_type = "SIMPLIFIED " if is_simplified else ""
        heading: str = f"    \x01{ida_lines.SCOLOR_DEMNAME}{graph_type}PATHS (entry_point(s) -> {colored_entity})\x02{ida_lines.SCOLOR_DEMNAME}"

        heading_len: int = len(heading) - 12
        heading_underline: str = f"    \x01{ida_lines.SCOLOR_DEMNAME}{'-' * heading_len}\x02{ida_lines.SCOLOR_DEMNAME}"
        g_paths: List[List[int]] = []
        _graph: Optional[List[bytes]] = None

        # Use different cache keys for normal and simplified graphs
        # Cache key carries every dimension that changes the rendered ASCII:
        # the simplified axis and the node-detail (artifacts) axis.
        _ck_parts = []
        if is_simplified:
            _ck_parts.append("simplified")
        if self.graph_node_artifacts:
            _ck_parts.append("artifacts")
            # Fold the per-type cap into the key so toggling the cap (or changing
            # its value) renders fresh instead of returning a stale cached box.
            _cap = self._graph_artifact_cap()
            if _cap is not None:
                _ck_parts.append(f"cap{_cap}")
        cache_key = "_".join([*_ck_parts, str(e_index)]) if _ck_parts else e_index

        # display_text -> SCOLOR for post-layout per-type artifact colouring.
        node_artifact_colors: Dict[str, int] = {}

        # graph_cache is serialized into the .xrefer DB, but the parallel
        # per-key colour map (_graph_artifact_colors) is view-local and is NOT
        # persisted. After a DB reload a node-detail key can therefore be present
        # in graph_cache with no colour map — which would render every artifact
        # in the fallback colour. Treat that as a miss so the node re-renders
        # (rebuilding both the box and its colour map). Membership (not truthiness)
        # is the test: a graph legitimately free of artifacts has the key present
        # with an empty map and still counts as a valid hit.
        _have_colors = (not self.graph_node_artifacts) or (cache_key in self._graph_artifact_colors)
        if cache_key in self.xrefer_obj.graph_cache and _have_colors:
            _graph, num_original_nodes, num_simplified_nodes = self.xrefer_obj.graph_cache[cache_key]
            node_artifact_colors = self._graph_artifact_colors.get(cache_key, {})
        else:
            # Collect paths and track unique nodes
            original_nodes = set()
            simplified_nodes = set()

            for xref in xrefs:
                # ``xref`` is sourced from ``entity_xrefs`` which holds
                # ``xrefer.backend.base.Address`` instances — an int
                # subclass introduced by the gsoc_2025 backend
                # abstraction. IDA 9.3's SWIG bindings strict-typecheck
                # ``ea_t`` and reject int subclasses, so we explicitly
                # cast to a plain int (then wrap via ``ida_idaapi.ea_t``
                # to match the pattern used at every other ea-crossing
                # site in this file).
                xref_func: ida_funcs.func_t = ida_funcs.get_func(ida_idaapi.ea_t(int(xref)))
                if not xref_func:
                    continue

                xref_func_ea: int = xref_func.start_ea

                for ep in self.xrefer_obj.paths:
                    try:
                        paths_from_ep: List[List[int]] = self.xrefer_obj.paths[ep][xref_func_ea]
                        for path in paths_from_ep:
                            original_nodes.update(path)
                            if is_simplified:
                                simplified_path = self.xrefer_obj.simplify_path(path)
                                simplified_nodes.update(simplified_path)
                                g_paths.append(simplified_path)
                            else:
                                g_paths.append(path)
                                simplified_nodes = original_nodes.copy()
                    except KeyError:
                        pass

            # Get the counts before graph creation
            num_original_nodes = len(original_nodes)
            num_simplified_nodes = len(simplified_nodes)

            try:
                # Create graph with the paths
                graph = nx.DiGraph()
                for path in g_paths:
                    for i in range(len(path) - 1):
                        if i == 0:
                            graph.add_edge(f"ENTRYPOINT\n0x{path[i]:x}", f"0x{path[i + 1]:x}")
                        else:
                            graph.add_edge(f"0x{path[i]:x}", f"0x{path[i + 1]:x}")
                    graph.add_edge(f"0x{path[-1]:x}", entity_content)

                def is_entrypoint_node(node: str) -> bool:
                    return node.startswith("ENTRYPOINT\n0x")

                def is_function_node(node: str) -> bool:
                    if is_entrypoint_node(node):
                        return True
                    if node.startswith("0x"):
                        try:
                            int(node[2:], 16)
                            return True
                        except:
                            return False
                    return False

                def get_function_ea(node: str) -> int:
                    if is_entrypoint_node(node):
                        # node like "ENTRYPOINT\n0x401000"
                        lines = node.split("\n")
                        ea_str = lines[1]
                    else:
                        # node like "0x401000"
                        ea_str = node
                    return int(ea_str[2:], 16)

                # We'll relabel function nodes with centered, truncated text
                func_nodes = []

                for node in graph.nodes():
                    if is_function_node(node):
                        ea = get_function_ea(node)
                        func_name = idc.get_func_name(ea)
                        if not func_name:
                            func_name = "<no_name>"
                        # The node title shouldn't be the most-truncated line.
                        if self.graph_node_artifacts:
                            # Node-detail: give the name the same budget as the
                            # artifacts (same cap → box no wider than they make it).
                            if len(func_name) > self._NODE_ARTIFACT_TRUNC:
                                func_name = func_name[: self._NODE_ARTIFACT_TRUNC - 2] + ".."
                        else:
                            # Normal mode: keep names tight so plain graphs stay narrow.
                            if len(func_name) > 12:
                                func_name = func_name[:12] + ".."

                        addr_str = f"0x{ea:x}"

                        if is_entrypoint_node(node):
                            # Three lines: ENTRYPOINT, addr, func_name
                            lines = ["ENTRYPOINT", addr_str, func_name]
                        else:
                            # Two lines: addr, func_name
                            lines = [addr_str, func_name]

                        # "Node detail" mode: append the function's direct
                        # artifacts under the header (plain text; per-type
                        # colour recorded for the post-layout pass below).
                        header_count = len(lines)
                        if self.graph_node_artifacts:
                            for art_text, art_color in self._node_artifact_entries(ea):
                                lines.append(art_text)
                                node_artifact_colors[art_text] = art_color

                        # Determine this node's max line length
                        node_max_len = max(len(line) for line in lines)

                        # Header lines (addr / name) are centred; the artifact
                        # list reads better left-aligned within the box.
                        rendered_lines = [
                            f"{line:^{node_max_len}}" if i < header_count else f"{line:<{node_max_len}}"
                            for i, line in enumerate(lines)
                        ]
                        new_label = "\n".join(rendered_lines)

                        func_nodes.append((node, new_label))

                if func_nodes:
                    mapping = {node: new_label for node, new_label in func_nodes}
                    graph = nx.relabel_nodes(graph, mapping, copy=True)

                _graph = ascii_graphs.graph_to_ascii(graph).splitlines()
                self.xrefer_obj.graph_cache[cache_key] = (_graph, num_original_nodes, num_simplified_nodes)
                self._graph_artifact_colors[cache_key] = node_artifact_colors
            except:
                self.state_machine.go_back()
                self.update(True)
                log("Graph too large to draw")
                return

        self.ClearLines()
        self.print_ribbon()
        self.AddLine(heading)
        self.AddLine(heading_underline)

        # Sticky context banner — same shape as the cluster graph view
        # so the analyst keeps a consistent "where am I" anchor while
        # following an artifact path. View label describes this view
        # explicitly (paths-to-artifact, possibly simplified / pinned)
        # rather than a cluster context. Sync hidden because cluster
        # sync only governs cluster-graph behavior.
        paths_view_label = "artifact path graph"
        if is_simplified:
            paths_view_label = "simplified " + paths_view_label
        if self.graph_node_artifacts:
            paths_view_label += " (detailed nodes)"
        if is_pinned:
            paths_view_label += " (pinned)"
        for line in self._build_cluster_context_banner(
            current_cluster_id=None,
            view_label=paths_view_label,
            show_sync=False,
        ):
            self.AddLine(line)
        self.AddLine("")

        # Node-detail status (mirrors the simplified reduction note below) so
        # the mode + its toggle key stay discoverable while it's on.
        if self.graph_node_artifacts:
            detail_str = f"    \x01{ida_lines.SCOLOR_AUTOCMT}Nodes show their direct artifacts — D to toggle\x02{ida_lines.SCOLOR_AUTOCMT}"
            self.AddLine(detail_str)

        # Add node reduction info if in simplified mode
        if is_simplified and num_original_nodes > num_simplified_nodes:
            reduction = (num_original_nodes - num_simplified_nodes) / num_original_nodes * 100
            reduction_str = f"    \x01{ida_lines.SCOLOR_NUMBER}Graph reduced from {num_original_nodes} to {num_simplified_nodes} nodes ({reduction:.1f}% reduction)\x02{ida_lines.SCOLOR_NUMBER}"
            self.AddLine(reduction_str)

        self.AddLine("")
        func_ea: str = f"0x{self.func_ea:x}"

        # Pre-sort artifacts longest-first so the per-position greedy match
        # prefers the longer of two that share a prefix (CreateFileW over
        # CreateFile). Built once; the per-line colourer reuses it.
        artifact_items = sorted(node_artifact_colors.items(), key=lambda kv: len(kv[0]), reverse=True)

        for line in _graph:
            line: str = line
            line = ida_lines.COLSTR(line, ida_lines.SCOLOR_DEMNAME)
            line = wrap_substring_with_string(line, func_ea, "\x01\x12", "\x02\x12", case=True)
            line = wrap_substring_with_string(line, entity_content, entity_wrap_start, entity_wrap_end, True)
            # "Node detail": recolour EVERY occurrence of each artifact by its
            # type (post-layout, since the ASCII layout is colour-blind). Must
            # colour all occurrences, not just the first — the layout packs
            # nodes side-by-side, so the same artifact name recurs across boxes
            # on one rendered line.
            if artifact_items:
                line = self._colorize_node_artifacts(line, artifact_items)
            self.AddLine(f"        {line}")

        self.Refresh()

    # ── Neighborhood graph ─────────────────────────────────────────
    # Cursor-centric mini-graph that visualises 1-hop call-graph
    # adjacency to other clusters (and falls back to the BFS-discovered
    # nearest clusters when the cursor has no direct neighbours). It's
    # the visual companion to the ``Adjacent:`` row in the context
    # banner — instead of reading a list of "you can reach cluster X
    # via Y", the analyst sees the wiring all at once with cursor in
    # the middle.

    _NEIGHBORHOOD_NAME_TRUNC = 16  # max func-name chars in a node label

    def _format_neighborhood_func_name(self, ea: int) -> str:
        """Return a fixed-width-friendly function name for a node label."""
        try:
            fname = idc.get_func_name(ida_idaapi.ea_t(int(ea))) or ""
        except Exception:
            fname = ""
        if not fname:
            fname = f"sub_{ea:x}"
        if len(fname) > self._NEIGHBORHOOD_NAME_TRUNC:
            fname = fname[: self._NEIGHBORHOOD_NAME_TRUNC - 2] + ".."
        return fname

    def _make_neighborhood_node_label(self, header: str, ea: int) -> str:
        """Build a 3-line centred asciinet node label.

        ``header`` is the top line (``[CURSOR]`` for the centre,
        ``cluster.id.NNNN`` or ``cluster.id.NNNN (3h)`` for gateways);
        the address and function name follow. All three lines are
        centre-padded to the longest line's width so asciinet draws a
        proportionate box.
        """
        lines = [header, f"0x{ea:x}", self._format_neighborhood_func_name(ea)]
        width = max(len(l) for l in lines)
        return "\n".join(f"{l:^{width}}" for l in lines)

    def _build_neighborhood_graph_data(self) -> Optional[Dict[str, Any]]:
        """Collect everything needed to render the cursor neighborhood.

        Returns a dict with::

            cursor_ea: int
            cursor_clusters: List[int]   # cursor's own cluster memberships
            adjacent: List[(cid, neighbor_ea, edge_addr, direction)]
            nearest:  List[(cid, hops, gateway_ea, direction)]
                       # populated only when adjacent is empty, so the
                       # graph still has something to show

        Returns ``None`` when the cursor isn't on a function — the
        caller renders an explanatory message instead.
        """
        if not self.func_ea:
            return None
        try:
            on_func = ida_funcs.get_func(ida_idaapi.ea_t(int(self.func_ea))) is not None
        except Exception:
            on_func = False
        if not on_func:
            return None

        func_to_clusters = self._func_to_cluster_ids()
        cursor_clusters = sorted(func_to_clusters.get(self.func_ea, ()))

        adjacent = self._adjacent_clusters_for_cursor(exclude_ids=set(cursor_clusters))
        adjacent.sort(key=lambda t: t[0])

        # Intermediate-of relationships are multi-hop and invisible to
        # the strict 1-hop adjacency query above. Surfacing them here
        # is what closes the "Status says intermediate of cluster X but
        # X isn't in the graph" gap. Skip clusters already covered by
        # the 1-hop tier so we never render the same cluster twice.
        adj_cids = {t[0] for t in adjacent}
        intermediate = [
            t for t in self._intermediate_gateways_for_cursor() if t[0] not in adj_cids
        ]
        intermediate.sort(key=lambda t: (t[2], t[0]))  # nearest first, then deterministic

        nearest: List[Tuple[int, int, int, str]] = []
        if not adjacent and not intermediate:
            # Fall back to the 3-hop BFS so the view still has content
            # — same data the Status row's "nearest cluster" hint uses.
            nearest = self._nearest_clusters_via_callgraph(max_depth=3, max_results=5)

        return {
            "cursor_ea": self.func_ea,
            "cursor_clusters": cursor_clusters,
            "adjacent": adjacent,
            "intermediate": intermediate,
            "nearest": nearest,
        }

    def draw_neighborhood_graph(self) -> None:
        """Render the cursor-centric neighborhood graph view.

        Layout: heading → context banner → ascii graph (cursor in the
        middle, gateway nodes for each adjacent / nearest cluster
        around it).
        """
        self.ClearLines()
        self.print_ribbon()

        is_pinned = self.state_machine.current_state == self.state_machine.pinned_neighborhood_graph
        title = "CLUSTERS THIS FUNCTION CAN REACH"
        heading = f"    \x01{ida_lines.SCOLOR_DEMNAME}{title}\x02{ida_lines.SCOLOR_DEMNAME}"
        underline = f"    \x01{ida_lines.SCOLOR_DEMNAME}{'-' * len(title)}\x02{ida_lines.SCOLOR_DEMNAME}"
        self.AddLine(heading)
        self.AddLine(underline)
        # Sub-heading: explain the view's role plainly and tell the
        # analyst how to drill into any one cluster's actual chains.
        zoom_hint = ida_lines.COLSTR(
            "(each surrounding box is a cluster the current function calls into, is called from, or bridges as an intermediate — press M to see the full chains for any (intermediate) cluster, ESC to leave)",
            ida_lines.SCOLOR_DSTR,
        )
        self.AddLine(f"    {zoom_hint}")

        view_label = "clusters this function reaches" + (" (pinned)" if is_pinned else "")
        for line in self._build_cluster_context_banner(
            current_cluster_id=None,
            view_label=view_label,
            show_sync=False,
        ):
            self.AddLine(line)
        self.AddLine("")

        data = self._build_neighborhood_graph_data()
        if data is None:
            self.AddLine(f"    \x01{ida_lines.SCOLOR_DSTR}Not inside a recognised function.\x02{ida_lines.SCOLOR_DSTR}")
            self.Refresh()
            return
        if not data["adjacent"] and not data["intermediate"] and not data["nearest"]:
            self.AddLine(
                f"    \x01{ida_lines.SCOLOR_DSTR}No adjacent or nearby clusters within 3 hops.\x02{ida_lines.SCOLOR_DSTR}"
            )
            self.Refresh()
            return

        # Build the asciinet graph: cursor centre + one gateway per
        # neighbouring cluster, edge direction encodes caller/callee.
        cursor_label = self._make_neighborhood_node_label("[CURRENT FN]", data["cursor_ea"])
        graph = nx.DiGraph()
        graph.add_node(cursor_label)

        seen_labels: Set[str] = {cursor_label}

        def add_gateway(cid: int, ea: int, header: str, direction: str) -> None:
            label = self._make_neighborhood_node_label(header, ea)
            # Disambiguate node-label collisions (different clusters
            # sharing the exact same gateway display string) by
            # appending invisible marker — asciinet treats labels as
            # node identity, so true duplicates would silently merge.
            tag = 1
            unique = label
            while unique in seen_labels:
                tag += 1
                unique = f"{label}\n#{tag}"
            seen_labels.add(unique)
            if direction == "caller":
                graph.add_edge(unique, cursor_label)
            else:
                graph.add_edge(cursor_label, unique)

        for cid, neighbor_ea, _edge_addr, direction in data["adjacent"]:
            header = f"cluster.id.{cid:04d}"
            add_gateway(cid, neighbor_ea, header, direction)

        # Intermediate-of clusters: closest path endpoint, hop count
        # annotates how many edges the analyst would walk to land on a
        # member. Always rendered when present — they're the multi-hop
        # relationship the 1-hop tier structurally cannot see.
        for cid, gateway_ea, hops, direction in data["intermediate"]:
            hop_text = "hop" if hops == 1 else "hops"
            header = f"cluster.id.{cid:04d} (intermediate, {hops} {hop_text})"
            add_gateway(cid, gateway_ea, header, direction)

        # Hop-annotated BFS gateways only when both adjacent and
        # intermediate are empty (handled by the data builder).
        for cid, hops, gateway_ea, direction in data["nearest"]:
            hop_text = "hop" if hops == 1 else "hops"
            header = f"cluster.id.{cid:04d} ({hops} {hop_text} away)"
            add_gateway(cid, gateway_ea, header, direction)

        try:
            graph_lines = ascii_graphs.graph_to_ascii(graph).splitlines()
        except Exception as e:
            log(f"[-] Error rendering neighborhood graph: {e}")
            self.AddLine(
                f"    \x01{ida_lines.SCOLOR_DSTR}Graph too large to draw.\x02{ida_lines.SCOLOR_DSTR}"
            )
            self.Refresh()
            return

        cursor_addr = f"0x{data['cursor_ea']:x}"
        for line in graph_lines:
            colored = self.format_graph_line(line)
            # Highlight cursor address in the rendered graph so the
            # centre node stands out from the gateways.
            colored = wrap_substring_with_string(colored, cursor_addr, "\x01\x12", "\x02\x12", case=True)
            self.AddLine(f"    {colored}")

        self.Refresh()

    def get_current_word(self) -> Optional[str]:
        """
        Get word under cursor in view.

        Extracts the complete word at current cursor position, handling
        special cases for addresses and color codes.

        Returns:
            Optional[str]: Word under cursor, or None if no valid word found
        """
        _, xpos, _ = self.GetPos(True)
        line = self.GetCurrentLine(True)

        if not line:
            return None

        # Handle SCOLOR_IMPNAME case
        line = line.replace("\x01\x22", "").replace("\x02\x22", "")

        # Remove non-displayable characters
        line = remove_non_displayable(line)

        # Adjust xpos if characters before it were removed
        xpos = min(xpos, len(line) - 1)

        # Fast path: check if cursor is directly on '0x'
        if line.startswith("0x", xpos) or (xpos > 0 and line.startswith("0x", xpos - 1)):
            start = xpos if line.startswith("0x", xpos) else xpos - 1
            end = start + 2
            while end < len(line) and line[end] in "0123456789abcdefABCDEF":
                end += 1
            return line[start:end].strip("│")

        # Find word boundaries
        start = xpos
        while start > 0 and not line[start - 1].isspace():
            start -= 1
        end = xpos
        while end < len(line) and not line[end].isspace():
            end += 1

        word = line[start:end]

        # Check for addresses only if '0x' is in the word
        if "0x" in word:
            # Find the address closest to the cursor without creating a list
            closest_start = closest_end = -1
            for match in self.address_regex.finditer(word):
                m_start, m_end = match.start(), match.end()
                if closest_start == -1 or abs(m_start - (xpos - start)) < abs(closest_start - (xpos - start)):
                    closest_start, closest_end = m_start, m_end

            if closest_start != -1 and start + closest_start <= xpos < start + closest_end:
                return word[closest_start:closest_end].strip("│")

        return word

    def _strip_count_suffix(self, text: str) -> str:
        """Strip a trailing '  (N)' artifact-count badge from a heading or
        category label so it matches the table_states / subtable_states keys.
        (Counts were added to those lines for at-a-glance magnitude.)"""
        return re.sub(r"\s*\(\d+\)\s*$", "", text).rstrip()

    def get_parent_table(self) -> Optional[str]:
        """
        Get name of table containing current line.

        Searches upward from the line under the mouse to find an enclosing
        table header. ``GetLineNo(mouse=1)`` returns ``-1`` when the mouse is
        not over any line — that sentinel is **truthy** in Python, so we must
        bail out explicitly rather than relying on ``while lineno:``.
        """
        lineno = self.GetLineNo(mouse=1)
        if lineno is None or lineno < 0:
            return None

        while lineno >= 0:
            result = self.GetLine(lineno)
            if not result or result[0] is None:
                return None
            line = result[0]
            # Heading lines look like "▾ NAME" / "▸ NAME" (optionally with a
            # trailing "  (N)" count). Parse robustly rather than by offset.
            clean = strip_color_codes(line).strip()
            if clean[:1] in ("▸", "▾"):
                candidate = self._strip_count_suffix(clean[1:].strip())
                if candidate in self.table_names or candidate in self.orphan_table_names:
                    return candidate
            lineno -= 1
        return None
