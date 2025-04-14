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

import re
import weakref
import ida_lines
import idc
import ida_kernwin
import idaapi
import ida_funcs
import asciinet
import traceback
from time import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union, Pattern
from collections import OrderedDict, defaultdict
from PyQt5 import QtCore, QtWidgets, QtGui
from networkx import NetworkXError

from xrefer.core.analyzer import XRefer
from xrefer.core.state_machine import *
from xrefer.core.helpers import *
from xrefer.core.action_handlers import *
from xrefer.legacy.shim import format_ribbon
from xrefer.core.help import ContextHelp
from xrefer.core.settings import XReferSettingsManager


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
                                        r'(?:^ {4,8}|[│┐└]\x02\x18\x20{3})'     # Match either standard indent or vertical line pattern
                                        r'\x01[^\x10]'                          # Start of color code. Exclude CREFTAIL for address
                                        r'(?:\x20{0,4}(?:[→↓]\x20)?)?'          # Optional arrow with spaces
                                        r'(.+?)'                                # The actual content (non-greedy)
                                        r'\x02.'                                # End of color code
                                        r'\x20*'                                # Any number of trailing spaces
                                    )
        self.address_regex: re.Pattern = re.compile(r'0x[0-9a-fA-F]+')
        self.table_states: OrderedDict[str, int] = OrderedDict([
            (self.xrefer_obj.table_names[2], 1),  # INDIRECT IMPORT XREFS
            (self.xrefer_obj.table_names[1], 1),  # INDIRECT LIBRARY XREFS
            (self.xrefer_obj.table_names[3], 1),  # INDIRECT STRING XREFS
            (self.xrefer_obj.table_names[4], 1),  # INDIRECT CAPA XREFS
            ('DIRECT XREFS', 1)
        ])
        self.table_names: List[str] = list(self.table_states.keys())
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
        self.table_index_offset: int = 4  # default state starts from direct xrefs
        self.table_count: int = len(self.table_states)
        self.indent: str = '        ' if is_windows_or_linux() else '    '
        self.INDENT: str = '    '  # Standard 4-space indentation
        self.peek_flag: bool = False
        self.last_boundary_scan_results: Optional[str] = None
        self.title: str = "XRefer - Navigator"
        self.focus_event_filter = None
        self.event_filter = None
        self.widget = None
        self.qt_widget = None
        self.dock_widget = None
        self.last_non_graph_width = None
        self.in_graph_view = False
        self._is_collapsed = False 
        self._from_double_click = False
        self._explicit_cluster_click = False

        if self.xrefer_obj.lang:
            self.create()

    def __del__(self):
        """
        Clean up resources when the object is destroyed.
        """
        self.cleanup()

    def cleanup(self):
        """Clean up resources and event handlers."""
        try:
            if hasattr(self, 'qt_widget'):
                if self.focus_event_filter:
                    self.qt_widget.removeEventFilter(self.focus_event_filter)
                if self.event_filter:
                    self.qt_widget.removeEventFilter(self.event_filter)
                    
            self.focus_event_filter = None
            self.event_filter = None
                
            if hasattr(self, 'collapse_indicator'):
                self.collapse_indicator.hide()
                self.collapse_indicator.setParent(None)
                self.collapse_indicator.deleteLater()
                delattr(self, 'collapse_indicator')
                
            if hasattr(self, 'resize_filter'):
                delattr(self, 'resize_filter')
                
            if hasattr(self, 'dock_widget'):
                if self.dock_widget:
                    self.dock_widget.setWidget(None)
                    self.dock_widget.close()
                    self.dock_widget.deleteLater()
                delattr(self, 'dock_widget')
                
            if self.qt_widget:
                self.qt_widget.setParent(None)
                self.qt_widget.deleteLater()
                self.qt_widget = None
                
        except Exception as e:
            log(f"Error during cleanup: {str(e)}")

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
                
            self.qt_widget = idaapi.PluginForm.TWidgetToPyQtWidget(self.widget)
            if not self.qt_widget:
                log("Failed to get Qt widget")
                return
                
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
                idaapi.jumpto(self.xrefer_obj.current_analysis_ep)
                self.update(ea=self.xrefer_obj.current_analysis_ep)
            else:
                self.update(ea=self.func_ea)
            
        except Exception as e:
            log(f"Error during create: {str(e)}")
            log(traceback.format_exc())
            self.cleanup()

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
            if self.qt_widget:
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
            if self.qt_widget:
                self.qt_widget.repaint()
        except Exception as e:
            log(f"Error showing custom window: {str(e)}")
            self.cleanup()

    def Show(self, *args) -> None:
        """
        Override Show to use our custom window handling.
        """
        self.show_custom_window()

    def setup_hooks(self):
        """
        Setup UI and rebase hooks.
        """
        class Hooks(idaapi.UI_Hooks):
            def __init__(self, v: 'XReferView'):
                ida_kernwin.UI_Hooks.__init__(self)
                self.hook()
                self.v: weakref.ReferenceType['XReferView'] = weakref.ref(v)

            def screen_ea_changed(self, ea: int, prev_ea: int) -> None:
                v: Optional['XReferView'] = self.v()
                if v is not None:
                    v.update(ea=ea)
                return super().screen_ea_changed(ea, prev_ea)

            def finish_populating_widget_popup(self, form: Any, popup: Any) -> None:
                menu_path: str = 'XRefer/'
                menu_id = 'XRefer:cluster_everything'
                tooltip = 'Cluster all functions with non-excluded artifacts'
                label = '(Re-)run Cluster Analysis on all Functions (default)'
                register_popup_action(form, popup, menu_path, menu_id, label, ClusterEverythingHandler(), tooltip)
                menu_id = 'XRefer:rerun_cluster_analysis'
                tooltip = 'Cluster only functions that have been filtered through LLM Artifact Analysis'
                label = '(Re-)run Cluster Analysis on Interesting Functions'
                register_popup_action(form, popup, menu_path, menu_id, label, ClusterInterestingFunctionsHandler(), tooltip)
                menu_id = 'XRefer:rerun_artifact_analysis'
                tooltip = '(Re-)run LLM analysis on artifacts'
                label = '(Re-)run Artifact Analysis'
                register_popup_action(form, popup, menu_path, menu_id, label, ArtifactAnalysisHandler(), tooltip)
                menu_id = 'XRefer:toggle_peek'
                tooltip = 'Enable peeking of downstream cross-references of a clicked function in disassembly/pseudocode view'
                label = 'Enable Peek View'
                register_popup_action(form, popup, menu_path, menu_id, label, PeekViewToggleHandler(), tooltip)
                menu_id = 'XRefer:copy_interesting_strings'
                tooltip = 'Copy all relevant strings to the clipboard'
                label = 'Copy all relevant strings to clipboard'
                register_popup_action(form, popup, menu_path, menu_id, label, CopyInterestingStringsHandler(), tooltip)
                menu_id = 'XRefer:copy_processed_strings'
                tooltip = 'Copy all processed strings to clipboard'
                label = 'Copy all processed strings to clipboard'
                register_popup_action(form, popup, menu_path, menu_id, label, CopyProcessedStringsHandler(), tooltip)

        class RebaseHook(ida_idp.IDB_Hooks):
            def __init__(self, xrefer_view: 'XReferView'):
                super().__init__()
                self.xrefer_view: 'XReferView' = xrefer_view

            def allsegs_moved(self, info) -> int:
                self.xrefer_view.xrefer_obj.sync_image_base(False)
                self.xrefer_view.update(True)
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
        if not hasattr(self, 'qt_widget') or not self.qt_widget:
            log("Qt widget not initialized")
            return

        # Find IDA's main window
        main_window = None
        for widget in QtWidgets.QApplication.topLevelWidgets():
            if widget.windowTitle().startswith('IDA - '):
                main_window = widget
                break

        if not main_window or not isinstance(main_window, QtWidgets.QMainWindow):
            log("Could not find IDA main window")
            return

        try:
            # Create new dock widget if it doesn't exist
            if not hasattr(self, 'dock_widget') or not self.dock_widget:
                self.dock_widget = QtWidgets.QDockWidget(self.title, main_window)
                self.dock_widget.setObjectName("XReferDockWidget")

                # Store reference to XReferView in dock widget
                self.dock_widget.xrefer_view = self
                
                # Configure dock widget properties
                self.dock_widget.setFeatures(
                    QtWidgets.QDockWidget.DockWidgetMovable |
                    QtWidgets.QDockWidget.DockWidgetFloatable |
                    QtWidgets.QDockWidget.DockWidgetClosable
                )
                
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
                    if hasattr(self, 'collapse_indicator'):
                        self.collapse_indicator.hide()
                    self.dock_widget.hide()
                    event.ignore()
                    
                self.close_handler = handle_close
                self.dock_widget.closeEvent = self.close_handler
                
                # Connect visibility change handler
                self.dock_widget.visibilityChanged.connect(self.handle_visibility_changed)
                
                # Show dock widget and ensure indicator is visible
                self.dock_widget.show()
                
                # Use multiple delayed repositioning attempts to ensure proper placement
                QtCore.QTimer.singleShot(50, lambda: (
                    self.collapse_indicator.show(),
                    self.collapse_indicator.reposition()
                ))
                QtCore.QTimer.singleShot(100, lambda: (
                    self.collapse_indicator.reposition(),
                    self.collapse_indicator.raise_()
                ))
                QtCore.QTimer.singleShot(200, self.collapse_indicator.reposition)
                
            else:
                # If dock widget exists but is hidden, show it
                self.dock_widget.show()
                if hasattr(self, 'collapse_indicator'):
                    QtCore.QTimer.singleShot(50, lambda: (
                        self.collapse_indicator.show(),
                        self.collapse_indicator.reposition()
                    ))
                    QtCore.QTimer.singleShot(100, lambda: (
                        self.collapse_indicator.reposition(),
                        self.collapse_indicator.raise_()
                    ))
                
        except Exception as e:
            log(f"Error creating dock widget: {str(e)}")
            self.cleanup()
            return
        
    def handle_visibility_changed(self, visible):
        """Handle dock widget visibility changes."""
        if visible and self.qt_widget:
            # Reinstall event filters if needed
            if not self.focus_event_filter:
                self.focus_event_filter = FocusEventFilter(self)
            if not self.event_filter:
                self.event_filter = KeyEventFilter(self)
                
            self.qt_widget.installEventFilter(self.focus_event_filter)
            self.qt_widget.installEventFilter(self.event_filter)
            
            # Show/reposition collapse indicator
            if hasattr(self, 'collapse_indicator'):
                self.collapse_indicator.show()
                self.collapse_indicator.reposition()
                
            self.update(True)
        elif not visible and hasattr(self, 'collapse_indicator'):
            self.collapse_indicator.hide()

    def handle_dock_close(self, event):
        """
        Handle dock widget close event to properly clean up resources.
        """
        # Clean up the dock widget
        if hasattr(self, 'dock_widget'):
            self.dock_widget.setWidget(None)
            self.dock_widget.deleteLater()
            delattr(self, 'dock_widget')
        
        # Clean up the widget
        if hasattr(self, 'qt_widget'):
            self.qt_widget.setParent(None)
            self.qt_widget.deleteLater()
            
        event.accept()

    def reset_size_constraints(self):
        """Reset size constraints to allow user resizing."""
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
        
        # Handle cluster navigation
        if self.state_machine.current_state in (
            self.state_machine.cluster_graphs,
            self.state_machine.pinned_cluster_graphs,
            self.state_machine.clusters,
            self.state_machine.base
        ):
            cluster_manager = self.state_machine.cluster_manager

            # If in cluster graph states, store current position before switching
            if self.state_machine.current_state not in (self.state_machine.base, self.state_machine.clusters):
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
        if word in ('→', '↓'):
            parent_table = self.get_parent_table()
            is_direct = parent_table.startswith('D')
            if is_direct or parent_table[9] == 'I':
                line: str = self.GetCurrentLine()
                _, api_name = self.extract_cell_item(line)
                if api_name:
                    self.toggle_api_expansion(api_name, is_direct)
                    self.update(True)
                    return True

        # Handle table expansions
        try:
            if word in ('[+]', '[-]'):
                line: str = self.GetCurrentLine()
                key: str = line[6:-2].strip()
                self.table_states[key] = not self.table_states[key]
                self.update(True)
                return True

            elif '(-)' in word or '(+)' in word:
                line: str = self.GetCurrentLine()
                key: str = line[14:-2].strip()
                table_name: Optional[str] = self.get_parent_table()
                if table_name:
                    self.subtable_states[table_name][key] = not self.subtable_states[table_name][key]
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
            idaapi.jumpto(addr)
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
            self.state_machine.pinned_cluster_graphs
        )
        
        is_graph_after = state_after_handling_key in (
            self.state_machine.graph,
            self.state_machine.pinned_graph,
            self.state_machine.simplified_graph,
            self.state_machine.pinned_simplified_graph,
            self.state_machine.clusters,
            self.state_machine.cluster_graphs,
            self.state_machine.pinned_cluster_graphs
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
                    analysis_data = find_cluster_analysis(
                        self.xrefer_obj.cluster_analysis, 
                        cluster_id
                    )

                    if analysis_data and all(key in analysis_data for key in ['label', 'description', 'relationships']):
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
                        matched_lines = self.xrefer_obj.entities[e_index][4]
                        all_repos = self.xrefer_obj.entities[e_index][5]
                        tooltip = self.generate_str_tooltip(matched_lines, all_repos)
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
        special_key_codes = { 
            161, 162, 163, 164, 165, 16, 17, 18, 9, 13, 27, 32, 33, 34, 35, 36, 37, 38, 
            39, 40, 45, 46, 91, 92, 93, *range(112, 124), 144, 145, 20, 8 }

        if vkey == 8:  # backspace
            self.state_machine.search_filter = self.state_machine.search_filter[:-1]
        elif isinstance(vkey, str) and vkey.isprintable():
            self.state_machine.search_filter += vkey.lower()
        elif vkey not in special_key_codes:
            self.state_machine.search_filter += chr(vkey).lower()

    def handle_key_specific_actions(self, vkey: int, shift: bool) -> bool:
        key_actions: Dict[int, Callable[[bool], bool]] = {
            ord('B'): self.handle_key_b,
            ord('C'): self.handle_key_c,
            ord('D'): self.handle_key_d,
            ord('E'): self.handle_key_e,
            ord('G'): self.handle_key_g,
            ord('H'): self.handle_key_h,
            ord('I'): self.handle_key_i,
            ord('J'): self.handle_key_j,
            ord('L'): self.handle_key_l,
            ord('N'): self.handle_key_n,
            ord('P'): self.handle_key_p,
            ord('R'): self.handle_key_r,
            ord('S'): self.handle_key_s,
            ord('T'): self.handle_key_t,
            ord('U'): self.handle_key_u,
            ord('X'): self.handle_key_x,
            13: self.handle_key_enter,
            27: self.handle_key_escape
        }

        key_handler: Callable[[bool], bool] = key_actions.get(vkey, self.handle_default)
        should_update = False
        
        try:
            should_update = key_handler(shift)
        except Exception as err:
            log(str(err))
            self.state_machine.to_base()      # Revert to base state on error
        
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
            if word.startswith('0x'):
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
        Handle 'd' key press for exclusions.
        
        Adds currently selected items to appropriate exclusions.
        
        Args:
            shift (bool): Whether shift key is pressed
            
        Returns:
            bool: True if exclusions was successful, False if not in appropriate state
        """
        if self.state_machine.current_state != self.state_machine.base:
            return False
        
        self.handle_exclusions()
        return True

    def handle_key_e(self, shift: bool) -> bool:
        """
        Handle 'e' key press for expand/collapse.
        
        Toggles expansion state of current table section.
        
        Args:
            shift (bool): Whether shift key is pressed
            
        Returns:
            bool: True if expansion state was toggled, False otherwise
        """
        if self.state_machine.current_state == self.state_machine.base:
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

        if current_state == self.state_machine.cluster_graphs:
            # Pin cluster graph
            return self.state_machine.toggle_pinned_cluster_graph()
        elif current_state == self.state_machine.pinned_cluster_graphs:
            # Unpin cluster graph
            return self.state_machine.toggle_unpinned_cluster_graph()

        # Handle regular graph pinning (existing logic)
        if current_state in (self.state_machine.graph, self.state_machine.pinned_graph,
                             self.state_machine.simplified_graph, self.state_machine.pinned_simplified_graph):
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
    
    def handle_key_i(self, shift: bool) -> bool:
        """
        Handle 'i' key press for interesting artifacts view.
        Now only handles toggling the interesting artifacts view on/off.
        
        Args:
            shift (bool): Whether shift key is pressed
                
        Returns:
            bool: True if state was changed
        """
        if self.state_machine.current_state == self.state_machine.base:
            return self.state_machine.start_interesting_artifacts()
        elif self.state_machine.current_state == self.state_machine.interesting_artifacts:
            return self.state_machine.to_base()
        return False
    
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
        if current_state in (self.state_machine.cluster_graphs, 
                            self.state_machine.pinned_cluster_graphs):
            

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
        Handle 'l' key press for last boundary results.
        
        Shows results from most recent boundary method scan.
        
        Args:
            shift (bool): Whether shift key is pressed
            
        Returns:
            bool: True if last results were shown
        """
        return self.state_machine.start_last_boundary_results()

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
            old_name: str = ''
            for xref in xrefs:
                try:
                    if not idc.func_contains(addr, xref.to):
                        old_name = idc.get_func_name(xref.to)
                        xref_to_func_ea = xref.to
                        break
                except:
                    pass

            if old_name:
                idaapi.jumpto(addr)
                new_name: str = idaapi.ask_str(old_name, 0, "Enter new function name:")
                if new_name:
                    if idaapi.set_name(xref_to_func_ea, new_name):
                        idaapi.refresh_idaview_anyway()
                        func_ea: int = idc.get_name_ea_simple(idc.get_func_name(addr))
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
        if self.state_machine.current_state not in (self.state_machine.cluster_graphs,
                                                self.state_machine.pinned_cluster_graphs,
                                                self.state_machine.clusters):
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
        if self.state_machine.current_state not in (self.state_machine.base, self.state_machine.trace_scope_function,
                                                self.state_machine.trace_scope_path, self.state_machine.trace_scope_full,
                                                self.state_machine.interesting_artifacts):
        
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
        if self.state_machine.current_state in (self.state_machine.cluster_graphs, 
                                                self.state_machine.pinned_cluster_graphs):
            cluster_manager = self.state_machine.cluster_manager
            
            # Store current position before navigation
            if current := cluster_manager.get_current_cluster():
                lineno, x, y = self.GetPos()
                cluster_manager.store_cursor_pos(current.cluster_id, (lineno, x, y))
                
                # Pop current cluster
                cluster_manager.pop_cluster()
                
                # Check if we should try to go back to relationship graph
                if not cluster_manager.get_current_cluster():  # History is empty
                    if len(self.xrefer_obj.clusters) == 1 and not self.xrefer_obj.clusters[0].subclusters:
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
            name = entity[1]      # Second item is the full name
            entity_type = entity[2]    # Third item is the type (1=lib, 2=api, 3=string, 4=capa)
            
            # Extract the name part after the last dot
            if entity_type == 2:       # 2=api
                name = name.split('.')[-1] if '.' in name else name
            
            # Map entity type to exclusions category
            type_to_category = {
                1: 'libs',
                2: 'apis',
                3: 'strings',
                4: 'capa'
            }
            
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
        cell_match: Optional[re.Match] = self.cell_regex.search(line)
        
        if cell_match:
            xref_cell: str = cell_match.group(1)
            xref_item: str = xref_cell.replace('\x04', '').strip()
            return xref_cell, xref_item

        return None, None

    def _add_expanded_calls(self, api_name: str, is_direct: bool) -> None:
        indent = '      ' if is_direct else f'{self.indent}  '
        if is_direct:
            calls = self.xrefer_obj.get_direct_calls(api_name, self.func_ea)
        else:
            calls = self.xrefer_obj.get_indirect_calls(api_name, self.func_ea)

        for call, count in calls:
            self.AddLine(f"{indent}{call} x {count}")

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
        is_direct = self.current_table.startswith('D')
        _, xref_item = self.extract_cell_item(line)
        if xref_item:
            expansion_type = "direct" if is_direct else "indirect"
            if self.api_expansion_state[self.func_ea][xref_item][expansion_type]:
                line = line.replace('→', '↓', 1)
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
                newline = wrap_substring_with_string(line, self.state_machine.search_filter, '\x04')

        else:
            newline = self.prepare_xref_colors(line, self.xref_coverage_dict[self.func_ea])
            
        
        if newline:
            if '→' in newline:
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
            self.last_boundary_scan_results = ['NO BOUNDARY METHODS FOUND']
            self.AddLine('')
            self.AddLine('    %s' % self.last_boundary_scan_results[0])
            self.Refresh()
            return

        self.ClearLines()
        self.print_ribbon()

        boundary_methods_names: List[str] = [idc.get_func_name(func_ea) for func_ea in boundary_methods]
        cols: List[List[Union[int, str]]] = [boundary_methods, boundary_methods_names]
        results_table: List[str] = create_colored_table_from_cols(
            ['BOUNDARY METHOD ADDRESS', 'BOUNDARY METHOD NAME'],
            cols, ida_lines.SCOLOR_DEMNAME)

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
            tag_index[self.xrefer_obj.color_tags[self.xrefer_obj.table_names[entity_type]]] = [start,
                                                                                               start + type_count[
                                                                                                   index]]
            start += type_count[index]

        rows: List[List[str]] = [[self.xrefer_obj.entities[x][1]] for x in sorted_entity_list]
        params_table: List[str] = create_xrefs_table_colored('BOUNDARY SCAN PARAMETERS', rows, tag_index)
        params_table[0] = '\x01' + ida_lines.SCOLOR_DEMNAME + params_table[0] + '\x02' + ida_lines.SCOLOR_DEMNAME
        params_table[1] = '\x01' + ida_lines.SCOLOR_DEMNAME + params_table[1] + '\x02' + ida_lines.SCOLOR_DEMNAME
        results_table += ['', '', ''] + params_table

        for line in results_table:
            self.AddLine('    %s' % line)

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
                self.AddLine('    %s' % line)
    
    def draw_interesting_artifacts(self) -> None:
        """Draw interesting artifacts view with consistent alignment and headers."""
        self.ClearLines()
        self.print_ribbon()
        
        interesting_indices = self.xrefer_obj.interesting_artifacts
        if not interesting_indices:
            self.AddLine('    NO INTERESTING ARTIFACTS FOUND')
            return

        # Group artifacts
        func_artifacts, orphan_func_artifacts, orphan_artifacts = self.xrefer_obj._group_interesting_artifacts(interesting_indices)
        
        # Calculate totals
        total_artifacts = len(self.xrefer_obj.entities)
        total_artifact_funcs = len(func_artifacts)

        if self.xrefer_obj.settings['enable_exclusions']:
            total_flagged_artifacts = len(interesting_indices - self.xrefer_obj.excluded_entities)
        else:
            total_flagged_artifacts = len(interesting_indices)

        # Draw main header with consistent indentation
        header_indent = "    "
        if total_artifact_funcs > 0:
            color_num = ida_lines.SCOLOR_VOIDOP  # Define color code separately
            header = (
                f'INTERESTING FUNCTIONS DISCOVERED → '
                f'{ida_lines.COLSTR(str(total_artifact_funcs), color_num)} '
                f'(FLAGGED {ida_lines.COLSTR(str(total_flagged_artifacts), color_num)} '
                f'OUT OF {ida_lines.COLSTR(str(total_artifacts), color_num)} '
                f'ARTIFACTS)'
            )
        else:
            header = 'INTERESTING ARTIFACTS'
        self.AddLine(f'{header_indent}{ida_lines.COLSTR(header, ida_lines.SCOLOR_DATNAME)}')
        
        self.AddLine('')
        self.print_llm_disclaimer(1)
        
        # Draw main artifacts table with proper coloring
        if func_artifacts:
            rows = prepare_interesting_artifacts_table_rows(func_artifacts, self.xrefer_obj)
            headings = ["Function Address", "Flagged Artifacts", "Function Name"]
            table = create_interesting_artifacts_table(headings, rows, ida_lines.SCOLOR_DATNAME)
            
            # Add padding for consistent indentation
            for line in table:
                if line.strip():  # Only add padding for non-empty lines
                    self.AddLine(f"{header_indent}{line}")
                else:
                    self.AddLine("")  # Empty lines don't need padding
        else:
            self.AddLine(f'{header_indent}NO INTERESTING ARTIFACTS FOUND')
        
        # Draw orphan sections with headers
        self.AddLine('')
        self.AddLine('')
        orphan_header = 'INTERESTING ORPHAN ARTIFACTS (WITH FUNCTIONS)'
        self.AddLine(f'{header_indent}{ida_lines.COLSTR(orphan_header, ida_lines.SCOLOR_DATNAME)}')
        self.AddLine('')
        
        # Orphan description with consistent indentation
        orphan_desc_lines = [
            '=> Orphan references are those for which a path has not yet been discovered to',
            'the entrypoint(s). Either they are connected to the entrypoint(s) via indirect',
            'calls not obvious statically or a different entrypoint needs to be analyzed <='
        ]
        for line in orphan_desc_lines:
            self.AddLine(f'{header_indent}{ida_lines.COLSTR(line, ida_lines.SCOLOR_VOIDOP)}')
        self.AddLine('')
        
        # Draw orphan artifacts table with headers
        if orphan_func_artifacts:
            rows = prepare_interesting_artifacts_table_rows(orphan_func_artifacts, self.xrefer_obj)
            headings = ["Function Address", "Flagged Artifacts", "Function Name"]
            table = create_interesting_artifacts_table(headings, rows, ida_lines.SCOLOR_DATNAME)
            for line in table:
                self.AddLine(f"{header_indent}{line}")
        else:
            self.AddLine(f'{header_indent}NO INTERESTING ORPHAN FUNCTION ARTIFACTS FOUND')
        
        # Draw completely orphaned artifacts section with header
        self.AddLine('')
        complete_orphan_header = 'INTERESTING ORPHAN ARTIFACTS (NO FUNCTIONS)'
        self.AddLine(f'{header_indent}{ida_lines.COLSTR(complete_orphan_header, ida_lines.SCOLOR_DATNAME)}')
        self.AddLine(f'{header_indent}{ida_lines.COLSTR("-" * len(complete_orphan_header), ida_lines.SCOLOR_DATNAME)}')
        
        if orphan_artifacts:
            self._print_artifact_list(sorted(orphan_artifacts, key=lambda x: (x[0], x[1])))
        else:
            self.AddLine(f'{header_indent}NO INTERESTING COMPLETELY ORPHANED ARTIFACTS FOUND')

    def _print_artifact_list(self, artifacts: List[Tuple[int, str]]) -> None:
        """
        Print formatted list of artifacts with appropriate coloring.
        
        Args:
            artifacts: List of tuples containing (artifact_type, artifact_name)
        """
        type_to_color = {
            1: self.xrefer_obj.color_tags[self.xrefer_obj.table_names[1]],  # Lib
            2: self.xrefer_obj.color_tags[self.xrefer_obj.table_names[2]],  # API
            3: self.xrefer_obj.color_tags[self.xrefer_obj.table_names[3]],  # String
            4: self.xrefer_obj.color_tags[self.xrefer_obj.table_names[4]]   # Capa
        }
        
        for artifact_type, artifact_name in artifacts:
            color = type_to_color[artifact_type]
            colored_name = f'\x01{color}{artifact_name}\x02{color}'
            self.AddLine(f'    {colored_name}')

    def draw_clusters(self) -> None:
        """Draw clusters view with comprehensive headers."""
        self.ClearLines()
        self.print_ribbon()

        LINE_WIDTH = 85  # Consistent width for all text blocks
        INDENT = "    "  # Standard 4-space indent

        # Count total clusters and functions
        total_functions = set()
        total_clusters = 0
        
        def count_cluster_stats(cluster):
            nonlocal total_clusters, total_functions
            total_clusters += 1
            total_functions.update(cluster.nodes)
            for subcluster in cluster.subclusters:
                count_cluster_stats(subcluster)
                
        for cluster in self.xrefer_obj.clusters:
            count_cluster_stats(cluster)

        # Add main heading with statistics
        header = (
            f'FUNCTION CLUSTERS DISCOVERED → '
            f'{ida_lines.COLSTR(str(total_clusters), ida_lines.SCOLOR_VOIDOP)} '
            f'(CONTAINING {ida_lines.COLSTR(str(len(total_functions)), ida_lines.SCOLOR_VOIDOP)} '
            f'UNIQUE FUNCTIONS)'
        )
        self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DATNAME}{header}\x02{ida_lines.SCOLOR_DATNAME}')
        self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DATNAME}{"=" * LINE_WIDTH}\x02{ida_lines.SCOLOR_DATNAME}')
        self.AddLine('')

        if self.print_llm_disclaimer():
            # Add separator matching disclaimer width
            self.AddLine(f'{INDENT}{"-" * LINE_WIDTH}')
            self.AddLine('')

        # Get cluster analysis data
        cluster_analysis = self.xrefer_obj.cluster_analysis
        if not cluster_analysis:
            self.AddLine(f'{INDENT}NO CLUSTER ANALYSIS AVAILABLE')
            return

        # Add binary information with proper alignment
        binary_cat = cluster_analysis.get('binary_category', 'Unknown')
        
         # Choose between description or report based on toggle
        if self.state_machine.cluster_manager.is_showing_report():
            binary_desc = cluster_analysis.get('binary_report', 'Not available')
            desc_label = "Binary Report: "
        else:
            binary_desc = cluster_analysis.get('binary_description', 'Not available')
            desc_label = "Binary Description: "
        
        # Print category on one line
        self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DNAME}Binary Category: \x02{ida_lines.SCOLOR_DNAME}'
                     f'\x01{ida_lines.SCOLOR_VOIDOP}{binary_cat}\x02{ida_lines.SCOLOR_VOIDOP}')

        # Print description with proper wrapping
        desc_label = "Binary Description: "
        desc_offset = len(desc_label)  # Length of the description label
        first_line_width = LINE_WIDTH - desc_offset  # Width for first line accounting for label
        
        # Handle first line - should appear after the label
        desc_lines = []
        remaining_desc = binary_desc
        
        # First line handling
        self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DNAME}{desc_label}\x02{ida_lines.SCOLOR_DNAME}'
                     f'\x01{ida_lines.SCOLOR_DSTR}{binary_desc[:first_line_width]}\x02{ida_lines.SCOLOR_DSTR}')
        
        # Handle remaining lines
        remaining_desc = binary_desc[first_line_width:]
        desc_indent = INDENT
        
        while remaining_desc:
            chunk = remaining_desc[:LINE_WIDTH]
            remaining_desc = remaining_desc[LINE_WIDTH:]
            self.AddLine(f'{desc_indent}\x01{ida_lines.SCOLOR_DSTR}{chunk}\x02{ida_lines.SCOLOR_DSTR}')
        
        self.AddLine(f'{INDENT}(Press R to toggle between binary description and report)')
        self.AddLine('')

        # Get formatted lines from helper
        lines = draw_cluster_hierarchy(
            self.xrefer_obj.clusters,
            cluster_analysis,
            self.xrefer_obj.paths
        )
        
        # Add lines to view
        for line in lines:
            self.AddLine(line)
        
        self.Jump(0, 0)
        self.Refresh()

    def _get_intermediate_paths_containing_function(self, func_ea: int) -> List[Tuple[int, List[int], int]]:
        """
        Find all intermediate paths containing a specific function.
        
        Args:
            func_ea: Address of function to find in intermediate paths
            
        Returns:
            List of tuples (source_node, path, target_node) where:
            - source_node: Address of source cluster node/interesting function
            - path: Complete path including intermediates
            - target_node: Address of target cluster node/interesting function
        """
        paths_with_func = []
        
        # Search all clusters for relevant intermediate paths
        def search_cluster(cluster):
            for (source, target), paths in cluster.intermediate_paths.items():
                for path in paths:
                    # Check if function is in this path (but not as source/target)
                    if func_ea in path and func_ea != path[0] and func_ea != path[-1]:
                        paths_with_func.append((source, list(path), target))
                        
            # Search subclusters recursively
            for subcluster in cluster.subclusters:
                search_cluster(subcluster)
        
        # Search all root clusters
        for cluster in self.xrefer_obj.clusters:
            search_cluster(cluster)
            
        return paths_with_func

    def draw_intermediate_function_graph(self, func_ea: int) -> None:
        """
        Draw specialized graph view for intermediate function navigation.
        Focuses on the selected intermediate node and only displays the subgraph
        connecting it to interesting nodes in both directions, with special handling
        for multi-cluster (shared) functions.

        If we encounter a multi-cluster function or any interesting node that isn't a single-cluster
        node, we keep searching along the path until we find a final single-cluster node.
        If none is found, we omit that path.
        """
        # Get all paths containing this function
        containing_paths = self._get_intermediate_paths_containing_function(func_ea)
        if not containing_paths:
            self.AddLine('    No intermediate paths found containing this function')
            return

        # Setup view with consistent styling
        self.ClearLines()
        self.print_ribbon()

        header = f"INTERMEDIATE FUNCTION PATHS (0x{func_ea:x})"
        self.AddLine(f'    \x01{ida_lines.SCOLOR_DATNAME}{header}\x02{ida_lines.SCOLOR_DATNAME}')
        self.AddLine(f'    {"-" * len(header)}')
        self.AddLine('')

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
            name = idc.get_func_name(addr)
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
                if cluster_data and cluster_data.get('label'):
                    cluster_label = f" - {cluster_data['label']}"
                    if len(cluster_label) > 30:
                        cluster_label = cluster_label[:27] + "..."

            # Determine if intermediate
            is_intermediate = (not is_interesting_node(addr))

            node_classifications[addr] = {
                'type': 'intermediate' if is_intermediate else 'normal',
                'cluster': cluster_id
            }

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
                    prev_label = format_node_label(path_segment[i-1])
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

            return segment if len(segment) > 1 or (is_interesting_node(segment[-1]) and is_final_cluster_node(segment[-1])) or (segment[-1] == path[start_index] and is_final_cluster_node(segment[-1])) else [path[start_index]]

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
                graph_lines = ["", "", *asciinet.graph_to_ascii(graph).splitlines(), "", ""]
            else:
                graph_lines = asciinet.graph_to_ascii(graph).splitlines()

            normal_count = sum(1 for info in node_classifications.values() if info['type'] == 'normal')
            intermediate_count = sum(1 for info in node_classifications.values() if info['type'] == 'intermediate')
            cluster_count = sum(1 for info in node_classifications.values() if info['cluster'] is not None)

            stats = (f"Graph contains {normal_count} direct nodes "
                    f"({cluster_count} in clusters) and {intermediate_count} intermediate nodes")
            self.AddLine(f'    \x01{ida_lines.SCOLOR_NUMBER}{stats}\x02{ida_lines.SCOLOR_NUMBER}')
            self.AddLine('')

            # Add graph section
            self.AddLine(f'    \x01{ida_lines.SCOLOR_DNAME}Intermediate Path Graph:\x02{ida_lines.SCOLOR_DNAME}')
            self.AddLine('')

            # Print graph with proper coloring
            for line in graph_lines:
                colored_line = self._format_cluster_graph_line(line, highlight_addr=func_ea)
                self.AddLine(f"        {colored_line}")

            # Add navigation help
            self.AddLine('')
            self.AddLine(f'    \x01{ida_lines.SCOLOR_DNAME}Navigation:\x02{ida_lines.SCOLOR_DNAME}')
            self.AddLine(f'    \x01{ida_lines.SCOLOR_SEGNAME}- Double-click addresses to navigate\x02{ida_lines.SCOLOR_SEGNAME}')
            self.AddLine(f'    \x01{ida_lines.SCOLOR_SEGNAME}- ESC to navigate back\x02{ida_lines.SCOLOR_SEGNAME}')

            # Add legend
            self.AddLine('')
            self.AddLine(f'    \x01{ida_lines.SCOLOR_DNAME}Legend:\x02{ida_lines.SCOLOR_DNAME}')
            self.AddLine(f'    \x01\x12■\x02\x12 Current Function')
            self.AddLine(f'    \x01{ida_lines.SCOLOR_DNAME}■\x02{ida_lines.SCOLOR_DNAME} Cluster Node')
            self.AddLine(f'    \x01{ida_lines.SCOLOR_VOIDOP}■\x02{ida_lines.SCOLOR_VOIDOP} Intermediate Node (i)')

        except Exception as e:
            log(f"Error creating intermediate path graph: {str(e)}")
            self.AddLine(f'    Error: {str(e)}')


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
                is_endpoint = (idx == 0 or idx == len(path) - 1)
                is_target = (node == func_ea)
                if is_target:
                    node_type = "current"
                elif is_endpoint:
                    node_type = "endpoint"
                else:
                    node_type = "intermediate"

                # Get cluster membership
                cluster_id = get_cluster_id(node)

                node_classifications[node] = {
                    "type": node_type,
                    "cluster": cluster_id
                }

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
                
                node_classifications[node] = {
                    "type": node_type,
                    "cluster": cluster_id
                }
                
        return node_classifications

    def draw_cluster_graph(self) -> None:
        """Draw cluster graph."""
        self.ClearLines()
        self.print_ribbon()

        LINE_WIDTH = 85
        INDENT = "    "

        # Count total clusters and subclusters 
        total_clusters = 0
        unique_functions = set()

        # If there's only one cluster with no subclusters, go directly to its individual view
        if len(self.xrefer_obj.clusters) == 1 and not self.xrefer_obj.clusters[0].subclusters:
            cluster = self.xrefer_obj.clusters[0]
            if not self.state_machine.cluster_manager.get_current_cluster():
                self.state_machine.cluster_manager.push_cluster(cluster.id)
            self.draw_individual_cluster_graph(cluster.id, self.func_ea)
            return
        
        def count_cluster_stats(cluster):
            nonlocal total_clusters
            total_clusters += 1
            unique_functions.update(cluster.nodes)
            for subcluster in cluster.subclusters:
                count_cluster_stats(subcluster)
                
        for cluster in self.xrefer_obj.clusters:
            count_cluster_stats(cluster)

        # Add main heading with enhanced statistics
        header = (
            f'CLUSTER GRAPH VIEW → {ida_lines.COLSTR(str(total_clusters), ida_lines.SCOLOR_VOIDOP)} '
            f'DISCOVERED CLUSTERS, {ida_lines.COLSTR(str(len(unique_functions)), ida_lines.SCOLOR_NUMBER)} FUNCTIONS'
        )
        self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DATNAME}{header}\x02{ida_lines.SCOLOR_DATNAME}')
        self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DATNAME}{"=" * LINE_WIDTH}\x02{ida_lines.SCOLOR_DATNAME}')
        self.AddLine('')

        if self.print_llm_disclaimer():
            self.AddLine(f'{INDENT}{"-" * LINE_WIDTH}')
            self.AddLine('')

        # Get cluster analysis data
        cluster_analysis = self.xrefer_obj.cluster_analysis
        if not cluster_analysis:
            self.AddLine(f'{INDENT}NO CLUSTER ANALYSIS AVAILABLE')
            return
        
        # Check for individual cluster view
        cluster_manager = self.state_machine.cluster_manager
        current_view = cluster_manager.get_current_cluster()

        if current_view:
            # Handle individual cluster view with enhanced dual-purpose support
            self.draw_individual_cluster_graph(current_view.cluster_id)
            return

        # Print binary analysis with enhanced formatting
        binary_cat = cluster_analysis.get('binary_category', 'Unknown')
        
         # Choose between description or report based on toggle
        if self.state_machine.cluster_manager.is_showing_report():
            binary_desc = cluster_analysis.get('binary_report', 'Not available')
            desc_label = "Binary Report: "
        else:
            binary_desc = cluster_analysis.get('binary_description', 'Not available')
            desc_label = "Binary Description: "
        
        # Print category with special highlighting for important classifications
        cat_color = ida_lines.SCOLOR_VOIDOP
        self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DNAME}Binary Category: \x02{ida_lines.SCOLOR_DNAME}'
                    f'\x01{cat_color}{binary_cat}\x02{cat_color}')

        # Print wrapped description
        desc_label = "Binary Description: "
        desc_offset = len(desc_label)
        first_line_width = LINE_WIDTH - desc_offset
        
        self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DNAME}{desc_label}\x02{ida_lines.SCOLOR_DNAME}'
                    f'\x01{ida_lines.SCOLOR_DSTR}{binary_desc[:first_line_width]}\x02{ida_lines.SCOLOR_DSTR}')
        
        remaining_desc = binary_desc[first_line_width:]
        while remaining_desc:
            chunk = remaining_desc[:LINE_WIDTH]
            remaining_desc = remaining_desc[LINE_WIDTH:]
            self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DSTR}{chunk}\x02{ida_lines.SCOLOR_DSTR}')
        
        self.AddLine(f'{INDENT}(Press R to toggle between binary description and report)')
        self.AddLine('')
                    
        try:
            graph = create_cluster_relationship_graph(
                self.xrefer_obj.clusters, 
                self.xrefer_obj.cluster_analysis
            )
            
            if not graph:
                self.AddLine(f'{INDENT}FAILED TO CREATE CLUSTER GRAPH')
                return
                
            # Add enhanced legend
            self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DNAME}Cluster Relationship Graph:\x02{ida_lines.SCOLOR_DNAME}')
            self.AddLine('')
            
            try:
                # For single node case, add some padding to make it visible
                if len(graph.nodes()) == 1:
                    graph_lines = ["", "", *asciinet.graph_to_ascii(graph).splitlines(), "", ""]
                else:
                    graph_lines = asciinet.graph_to_ascii(graph).splitlines()
                    
                for line in graph_lines:
                    colored_line = self._format_cluster_graph_line(line)
                    self.AddLine(f'{INDENT}    {colored_line}')
                    
                # Add navigation and interaction hints
                self.AddLine('')
                self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_DNAME}Navigation:\x02{ida_lines.SCOLOR_DNAME}')
                self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Click cluster IDs to explore details\x02{ida_lines.SCOLOR_SEGNAME}')
                self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Hover over cluster IDs to view cluster information\x02{ida_lines.SCOLOR_SEGNAME}')
                self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press C to toggle between cluster table and cluster graph view\x02{ida_lines.SCOLOR_SEGNAME}')
                if self.state_machine.cluster_sync_enabled:
                    self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press J to disable cluster sync (currently ON - following function navigation)\x02{ida_lines.SCOLOR_SEGNAME}')
                else:
                    self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press J to enable cluster sync (currently OFF)\x02{ida_lines.SCOLOR_SEGNAME}')
                self.AddLine(f'    \x01{ida_lines.SCOLOR_SEGNAME}- Press ESC to return to previous view\x02{ida_lines.SCOLOR_SEGNAME}')
                    
            except Exception as e:
                log(f"Error converting graph to ASCII: {str(e)}")
                self.AddLine(f'{INDENT}Error visualizing graph: {str(e)}')
                
        except NetworkXError as e:
            log(f"NetworkX error: {str(e)}")
            self.AddLine(f'{INDENT}Error creating graph: {str(e)}')
        except Exception as e:
            log(f"Error in cluster graph generation: {str(e)}")
            self.AddLine(f'{INDENT}Unexpected error: {str(e)}')

    def _format_cluster_graph_line(self, line: str, highlight_addr: Optional[int] = None, format_type: str = 'default') -> str:
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
        colored_line = f'\x01{ida_lines.SCOLOR_LIBNAME}{line}\x02{ida_lines.SCOLOR_LIBNAME}'
        
        # Color cluster IDs and their labels
        colored_line = re.sub(
            r'(cluster\.id\.\d{4}(?:\s*-\s*[^\n│─└┌┐]*)?)',  # Match ID and optional label
            lambda m: f'\x01{ida_lines.SCOLOR_DEMNAME}{m.group(1)}\x02{ida_lines.SCOLOR_DEMNAME}',
            colored_line
        )
        
        # Handle function addresses and names with proper coloring
        def format_function_text(match):
            addr_str = match.group(1)
            remainder = match.group(2) or ''  # Get any remaining text (function name, etc)
            
            # If this is a known hex address, try to highlight it
            if addr_str.startswith('0x'):
                try:
                    addr = int(addr_str, 16)
                    # Check if this is the highlighted address
                    if highlight_addr is not None and addr == highlight_addr:
                        return f'\x01\x12{addr_str}{remainder}\x02\x12'
                    
                    # Only apply intermediate node coloring in intermediate graph mode
                    if format_type == 'intermediate' and '(i)' in remainder:
                        return f'\x01{ida_lines.SCOLOR_VOIDOP}{addr_str}{remainder}\x02{ida_lines.SCOLOR_VOIDOP}'
                    
                except ValueError:
                    pass
                    
            # Regular function coloring
            return f'\x01{ida_lines.SCOLOR_DNAME}{addr_str}{remainder}\x02{ida_lines.SCOLOR_DNAME}'
                
        # Color addresses and function names
        colored_line = re.sub(
            r'(0x[0-9a-fA-F]+)((?:\s*-\s*[^\n│─└┌┐]*)?)',  # Match addr and optional name/desc
            format_function_text,
            colored_line
        )
        
        return colored_line
    
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
        colored_line = f'\x01{ida_lines.SCOLOR_LIBNAME}{line}\x02{ida_lines.SCOLOR_LIBNAME}'
        
        # Color cluster IDs and add dual-purpose indicators
        colored_line = re.sub(
            r'(cluster\.id\.\d+)',
            lambda m: self._format_cluster_id(m.group(1)),
            colored_line
        )
        
        # Color labels differently
        colored_line = re.sub(
            r'([^\n│─└┌┐]+)$',  # Match text at end of line that isn't a graph character
            lambda m: f'\x01{ida_lines.SCOLOR_DSTR}{m.group(1)}\x02{ida_lines.SCOLOR_DSTR}',
            colored_line
        )
        
        # Color addresses and indicate intermediates
        colored_line = re.sub(
            r'(0x[0-9a-fA-F]+)(\s*\(i\))?',
            lambda m: (f'\x01{ida_lines.SCOLOR_VOIDOP}{m.group(1)}{m.group(2) or ""}\x02{ida_lines.SCOLOR_VOIDOP}' 
                    if m.group(2) else  # If has (i) suffix, use VOIDOP color
                    f'\x01{ida_lines.SCOLOR_CREFTAIL}{m.group(1)}\x02{ida_lines.SCOLOR_CREFTAIL}'),
            colored_line
        )
        
        return colored_line
    
    def _format_cluster_id(self, cluster_id_str: str) -> str:
        """Format cluster ID"""
        return f'\x01{ida_lines.SCOLOR_DEMNAME}{cluster_id_str}\x02{ida_lines.SCOLOR_DEMNAME}'
    
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
        direct_memberships = []     # Regular node membership
        intermediate_memberships = [] # Intermediate node membership
        root_memberships = []       # Root node membership
        
        # Helper to format cluster info consistently
        def format_cluster_info(cluster_id: int) -> str:
            """Format cluster ID and label with consistent styling."""
            cluster_str = f"cluster.id.{cluster_id:04d}"
            
            # Get cluster data
            cluster_data = find_cluster_analysis(
                self.xrefer_obj.cluster_analysis, 
                cluster_id
            )
            
            if cluster_data and cluster_data.get('label'):
                cluster_str += f" - {cluster_data['label']}"
                
            return cluster_str

        # Check all clusters and subclusters
        def check_cluster(cluster, parent_id=None):
            cluster_info = format_cluster_info(cluster.id)
            
            # First check if function is root node
            if func_ea == cluster.root_node:
                root_memberships.append((cluster_info, parent_id))
            # Check if function is regular node (but not root node)
            elif func_ea in cluster.nodes:  # Only add as regular node if not root
                direct_memberships.append((cluster_info, parent_id))
            
            found_intermediate = False
            for _, paths in cluster.intermediate_paths.items():
                if found_intermediate:
                    break
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
        self.AddLine('')  # Add spacing
        
        # Composite header indicating all roles
        roles = []
        if root_memberships:
            roles.append("root node")
        if direct_memberships:
            roles.append("node")
        if intermediate_memberships:
            roles.append("intermediary node")
            
        header = f"This function serves following roles in clusters:"
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
            self.AddLine('')
            
        # Print direct memberships if any
        if direct_memberships:
            self.AddLine(f"    \x01{ida_lines.SCOLOR_DEMNAME}As regular node in:\x02{ida_lines.SCOLOR_DEMNAME}")
            for info, parent_id in direct_memberships:
                prefix = "└──" if parent_id else "●"
                cluster_text = f"    {prefix} \x01{ida_lines.SCOLOR_DEMNAME}{info}\x02{ida_lines.SCOLOR_DEMNAME}"
                if parent_id:
                    cluster_text += f" \x01{ida_lines.SCOLOR_DSTR}(subcluster)\x02{ida_lines.SCOLOR_DSTR}"
                self.AddLine(cluster_text)
            self.AddLine('')
            
        # Print intermediate memberships if any
        if intermediate_memberships:
            self.AddLine(f"    \x01{ida_lines.SCOLOR_ALTOP}As intermediary node in:\x02{ida_lines.SCOLOR_ALTOP}")
            for info, parent_id in intermediate_memberships:
                prefix = "└──" if parent_id else "●"
                cluster_text = f"    {prefix} \x01{ida_lines.SCOLOR_ALTOP}{info}\x02{ida_lines.SCOLOR_ALTOP}"
                if parent_id:
                    cluster_text += f" \x01{ida_lines.SCOLOR_DSTR}(subcluster)\x02{ida_lines.SCOLOR_DSTR}"
                self.AddLine(cluster_text)
            
        # Add final spacing
        self.AddLine('')
    
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
                self.AddLine(f'{self.INDENT}ERROR: Could not find cluster {cluster_id}')
                return

            current = self.state_machine.cluster_manager.get_current_cluster()
            if not current:
                return

            cluster_data = find_cluster_analysis(self.xrefer_obj.cluster_analysis, cluster_id)

            # Gather all nodes (including subclusters)
            def gather_all_cluster_nodes(c, node_set):
                node_set.update(c.nodes)
                node_set.add(c.root_node)
                node_set.update(c.cluster_refs.keys())
                for sc in c.subclusters:
                    gather_all_cluster_nodes(sc, node_set)

            all_nodes = set()
            gather_all_cluster_nodes(cluster, all_nodes)

            # Also gather global nodes from all top-level clusters
            global_all_nodes = set()
            for top_c in self.xrefer_obj.clusters:
                gather_all_cluster_nodes(top_c, global_all_nodes)

            # If cluster sync is on, see if current func belongs here
            if self.state_machine.cluster_sync_enabled and self.func_ea:
                if self.func_ea not in all_nodes:
                    if self.func_ea not in global_all_nodes:
                        # Possibly an intermediate function
                        containing_paths = self._get_intermediate_paths_containing_function(self.func_ea)
                        if containing_paths:
                            # Show specialized intermediate function graph
                            self.draw_intermediate_function_graph(self.func_ea)
                            return

                    # If we reach here, the function is not recognized in the new cluster
                    # Decide if we skip or show "FUNCTION NOT FOUND"

                    if self._explicit_cluster_click:
                        # We specifically clicked on this cluster's ID, so we skip "not found"
                        # and proceed to show the cluster. Then reset the flag for next time.
                        self._explicit_cluster_click = False
                    else:
                        # We are just browsing around with cluster sync on
                        self.AddLine('')
                        self.AddLine(f'{self.INDENT}FUNCTION NOT FOUND IN ANY DISCOVERED CLUSTERS OR INTERMEDIATE NODES')
                        return

            # If we get here, either the function is recognized or user explicitly clicked.
            # Proceed to show the cluster as normal.

            # 1) Print the cluster's header
            self._print_cluster_header(cluster, cluster_data)

            # 2) Print cross-references to cluster root
            self.print_cluster_xrefs(cluster, self.INDENT)

            # 3) Draw cluster's internal graph and subclusters
            self._draw_cluster_nodes(cluster, self.func_ea)

        except Exception as e:
            log(f"Error drawing cluster graph: {str(e)}")
            self.AddLine(f'{self.INDENT}Error: {str(e)}')

    def _print_cluster_header(self, cluster: "FunctionalCluster", cluster_data: Dict) -> None:
        """Print cluster header with wrapped text."""
        header = f"Cluster {cluster.id_str}"
        if cluster_data and cluster_data.get("label"):
            header += f" - {cluster_data['label']}"
        self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_DEMNAME}{header}\x02{ida_lines.SCOLOR_DEMNAME}')
        
        # Add separator
        self.AddLine(f'{self.INDENT}{"=" * len(header)}')
        self.AddLine('')
        
        # Show cluster metadata with text wrapping
        if cluster_data:
            if desc := cluster_data.get('description'):
                self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_DATNAME}Description:\x02{ida_lines.SCOLOR_DATNAME}')
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
                        self.AddLine(f'{self.INDENT}  \x01{ida_lines.SCOLOR_DSTR}{" ".join(line)}\x02{ida_lines.SCOLOR_DSTR}')
                        line = [word]
                        line_length = len(word)
                if line:
                    self.AddLine(f'{self.INDENT}  \x01{ida_lines.SCOLOR_DSTR}{" ".join(line)}\x02{ida_lines.SCOLOR_DSTR}')
            
            if rels := cluster_data.get('relationships'):
                self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_DATNAME}Relationships:\x02{ida_lines.SCOLOR_DATNAME}')
                
                # First, color all cluster IDs in the entire text
                processed_rels = re.sub(
                    r'(cluster\.id\.\d{4})',
                    lambda m: f'\x01{ida_lines.SCOLOR_DATNAME}{m.group(1)}\x02{ida_lines.SCOLOR_DATNAME}',
                    rels
                )
                
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
                        self.AddLine(f'{self.INDENT}  \x01{ida_lines.SCOLOR_DSTR}{wrapped_line}\x02{ida_lines.SCOLOR_DSTR}')
                        line = [word]
                        line_length = word_length
                
                if line:
                    wrapped_line = " ".join(line)
                    self.AddLine(f'{self.INDENT}  \x01{ida_lines.SCOLOR_DSTR}{wrapped_line}\x02{ida_lines.SCOLOR_DSTR}')
                    
            self.AddLine('')

    def _calculate_header_lines(self, analysis_data: Dict, cluster: "FunctionalCluster") -> int:
        """
        Calculate number of header lines before graph content for accurate scrolling.
        
        Args:
            analysis_data: Analysis data for the cluster
            cluster: The cluster being displayed
            
        Returns:
            int: Number of header lines
        """
        header_offset = 4  # Base offset: mode line + node count + empty line + graph start
        
        if analysis_data:
            header_offset += 2  # Cluster ID and separator
            if analysis_data.get('label'): 
                header_offset += 1
            if analysis_data.get('description'): 
                # Count wrapped lines in description
                desc_lines = len(analysis_data['description'].split('\n'))
                header_offset += 1 + desc_lines  # Title + content
            if analysis_data.get('relationships'): 
                # Count wrapped lines in relationships
                rel_lines = len(analysis_data['relationships'].split('\n'))
                header_offset += 1 + rel_lines  # Title + content
                
        # Add spacing before graph
        header_offset += 1
        
        log(f"Calculated header offset: {header_offset} lines")
        return header_offset
    
    def print_cluster_xrefs(self, cluster: "FunctionalCluster", indent: str = "    ") -> None:
        """Print xrefs to cluster root node with comprehensive membership information."""
        # Group xrefs by function
        func_xrefs = defaultdict(list)
        for xref in idautils.XrefsTo(cluster.root_node):
            if ida_bytes.is_code(ida_bytes.get_full_flags(xref.frm)):
                func = ida_funcs.get_func(xref.frm)
                if func:
                    func_xrefs[func.start_ea].append(xref.frm)
        
        if not func_xrefs:
            return
            
        self.AddLine(f'{indent}\x01{ida_lines.SCOLOR_DEMNAME}Cross-references to cluster root:\x02{ida_lines.SCOLOR_DEMNAME}')
        
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
                    memberships.append((cluster.id, data.get('label', ''), 'root'))
                    membership_found = True
                # Check direct membership
                elif func_ea in cluster.nodes:
                    memberships.append((cluster.id, data.get('label', ''), 'member'))
                    membership_found = True
                # Check intermediate paths
                else:
                    for _, paths in cluster.intermediate_paths.items():
                        for path in paths:
                            if func_ea in path and func_ea != path[0] and func_ea != path[-1]:
                                memberships.append((cluster.id, data.get('label', ''), 'intermediate'))
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
                        'root': '★',        # Star for root nodes
                        'member': '●',       # Filled circle for direct members
                        'intermediate': '○'  # Empty circle for intermediate nodes
                    }[role]
                    
                    # Format cluster reference
                    if label:
                        cluster_info.append(f"{role_indicator} cluster.id.{cluster_id:04d} - {label}")
                    else:
                        cluster_info.append(f"{role_indicator} cluster.id.{cluster_id:04d}")
            
            # Print function with membership info
            self.AddLine(f'{indent}  \x01{ida_lines.SCOLOR_DEMNAME}{func_name}\x02{ida_lines.SCOLOR_DEMNAME}')
            
            if cluster_info:
                # Print cluster memberships with proper color
                for info in cluster_info:
                    self.AddLine(f'{indent}    \x01{ida_lines.SCOLOR_ALTOP}{info}\x02{ida_lines.SCOLOR_ALTOP}')
            
            # Print xref addresses
            last_idx = len(xrefs) - 1
            for idx, xref in enumerate(sorted(xrefs)):
                prefix = "└──" if idx == last_idx else "├──"
                self.AddLine(f'{indent}      \x01{ida_lines.SCOLOR_CREFTAIL}{prefix} 0x{xref:x}\x02{ida_lines.SCOLOR_CREFTAIL}')
            
        self.AddLine('')

    def _draw_cluster_nodes(self, cluster: "FunctionalCluster", func_ea: int) -> None:
        """
        Draw cluster showing its constituent nodes and relationships.
        Auto-scrolls to highlighted function when cluster sync is enabled.
        
        Args:
            cluster: FunctionalCluster object to visualize
            func_ea: Optional function EA to highlight in the graph
        """
        
        # Get view mode from cluster manager
        current = self.state_machine.cluster_manager.get_current_cluster()
        simplified = True
        
        # Create graph based on view mode
        graph = cluster.to_graph(
            cluster_analysis=self.xrefer_obj.cluster_analysis,
            include_intermediate=not simplified
        )
        
        # Add xrefs node before root node
        xref_addrs = set()
        for xref in idautils.XrefsTo(cluster.root_node):
            # Only include code references
            if ida_bytes.is_code(ida_bytes.get_full_flags(xref.frm)):
                xref_addrs.add(xref.frm)
        
        # # Show current view mode
        # mode_str = "SIMPLIFIED" if simplified else "FULL"
        # self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_DNAME}{mode_str} VIEW MODE - Press S to toggle\x02{ida_lines.SCOLOR_DNAME}')
        
        # Show node counts
        interesting_count = len(cluster.nodes)
        if simplified:
            self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_NUMBER}Simplified graph showing {interesting_count} nodes\x02{ida_lines.SCOLOR_NUMBER}')
        self.AddLine('')
        
        # Calculate header offset by counting actual header lines
        analysis_data = find_cluster_analysis(self.xrefer_obj.cluster_analysis, cluster.id)
        
        try:
            # Convert to ASCII and display
            graph_lines = asciinet.graph_to_ascii(graph).splitlines()
            highlighted_position = None
            
            for i, line in enumerate(graph_lines):
                # Format line with proper coloring
                colored_line = self._format_cluster_graph_line(line, highlight_addr=func_ea)
                
                # Track line with highlighted address for auto-scrolling
                if func_ea is not None:
                    func_addr = f'0x{func_ea:x}'
                    if func_addr in line and '\x01\x12' in colored_line:
                        # Find exact column position of the address
                        clean_line = strip_color_codes(line)
                        addr_column = clean_line.find(func_addr)
                        highlighted_position = (i, addr_column)
                        
                self.AddLine(f'{self.INDENT}    {colored_line}')
                
            # Auto-scroll to highlighted line and ensure address is visible
            if (highlighted_position is not None and 
                self.state_machine.cluster_sync_enabled and
                not self._from_double_click):  # Do not adjust view if we are coming from a double click navigation
                
                try:
                    line_num, column = highlighted_position
                    total_line_offset = line_num + self._calculate_header_lines(analysis_data, cluster)
                    scroll_column = column + 100
                    self.Jump(total_line_offset, scroll_column)
                    
                except Exception as e:
                    self.Jump(total_line_offset, 0)
                    
        except Exception as e:
            log(f"Error drawing cluster nodes: {str(e)}")

            self.AddLine(f'{self.INDENT}Error visualizing nodes: {str(e)}')

        # Add navigation hints
        self.AddLine('')
        self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_DNAME}Navigation:\x02{ida_lines.SCOLOR_DNAME}')
        
        # Interactive elements
        if cluster.subclusters:
            self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Click cluster IDs to explore subclusters\x02{ida_lines.SCOLOR_SEGNAME}')
        self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Hover over cluster IDs to view cluster information\x02{ida_lines.SCOLOR_SEGNAME}')
        self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Hover over addresses to view function details\x02{ida_lines.SCOLOR_SEGNAME}')
        self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Double-click addresses to navigate to their location\x02{ida_lines.SCOLOR_SEGNAME}')
        
        # View controls
        # self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press S to toggle between simplified/full views\x02{ida_lines.SCOLOR_SEGNAME}')
        if self.state_machine.current_state == self.state_machine.pinned_cluster_graphs:
            self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press G to unpin graph (graph view will disappear when navigating to a new function)\x02{ida_lines.SCOLOR_SEGNAME}')
        else:
            self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press G to pin graph (graph view will not disappear when navigating to a new function)\x02{ida_lines.SCOLOR_SEGNAME}')

        # Updated sync status message
        if self.state_machine.cluster_sync_enabled:
            self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press J to disable cluster sync (currently ON - following function navigation)\x02{ida_lines.SCOLOR_SEGNAME}')
        else:
            self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press J to enable cluster sync (currently OFF)\x02{ida_lines.SCOLOR_SEGNAME}')

        self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press C to toggle between cluster table and cluster graph view\x02{ida_lines.SCOLOR_SEGNAME}')
        self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- Press R to go back to cluster relationship graph\x02{ida_lines.SCOLOR_SEGNAME}')
        self.AddLine(f'{self.INDENT}\x01{ida_lines.SCOLOR_SEGNAME}- ESC to navigate back\x02{ida_lines.SCOLOR_SEGNAME}')

    def draw_entity_xrefs(self) -> None:
        e_index = self.state_machine.selected_index
        entity: Tuple[str, str, int] = self.xrefer_obj.entities[e_index]
        table_name: str = self.xrefer_obj.table_names[entity[2]]
        entity_content: str = entity[1]
        entity_color_tag: int = self.xrefer_obj.color_tags[table_name]
        xref_items: List[List[Union[int, str]]] = self.xrefer_obj.generate_entity_xrefs_listing(e_index)
        results_table: List[str] = create_colored_table_from_cols(['XREF METHOD ADDRESS', 'ORPHAN', 'XREF METHOD NAME'], xref_items, ida_lines.SCOLOR_DEMNAME)
        self.ClearLines()
        self.print_ribbon()
        heading: str = f'    \x01{ida_lines.SCOLOR_DEMNAME}XREFS (\x01{entity_color_tag}{entity_content}\x02' \
                       f'{entity_color_tag})\x02{ida_lines.SCOLOR_DEMNAME}'
        self.AddLine(heading)
        self.AddLine('')

        for line in results_table:
            self.AddLine('    %s' % line)

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
            if (self.state_machine.cluster_sync_enabled and 
                self.state_machine.current_state in (self.state_machine.cluster_graphs, 
                                                self.state_machine.pinned_cluster_graphs)):
                
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

            elif self.peek_flag:
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
                        if (target_func and 
                            op_addr == target_func.start_ea and 
                            (not current_func or target_func.start_ea != current_func.start_ea)):
                            has_func_operand = True
                            break

                if has_func_operand:
                    self.state_machine.start_call_focus()
                    self.state_machine.address_filter = f'0x{ea:x}'
                    force = True
            
                else:
                    self.state_machine.to_base()
                    self.state_machine.address_filter = ''
                    force = True

                self.func_ea = func_ea

        else:
            func_ea = self.func_ea

        if ea and func_ea != self.func_ea or force:
            if not force and self.state_machine.current_state:
                if self.state_machine.current_state != self.state_machine.pinned_cluster_graphs:
                    self.state_machine.to_base()
                self.func_ea = func_ea

            if func_ea not in self.xref_coverage_dict:
                self.xref_coverage_dict[func_ea] = self.generate_xref_coverage_dict(func_ea)

            self.load_function_context()

    def print_context_help(self) -> None:
        """Print context-sensitive help with properly aligned borders."""
        if not self.xrefer_obj.settings["display_options"]["show_help_banner"]:
            return
        
        current_state = self.state_machine.current_state.name
        
        # Get view width in characters, ensuring proper right border alignment
        try:
            width = (self.qt_widget.width() // 10) + 15  # Added +1 for right border alignment
        except:
            width = 80
        
        help_lines = self.context_help.format_help_text(current_state, width)
        
        # Add consistent indentation
        indent = "    "
        for line in help_lines:
            self.AddLine(f"{indent}{line}")
        self.AddLine("")  # Add spacing after help box

    def print_ribbon(self) -> None:
        """Print status ribbon and aligned context help."""
        ribbon = self.generate_ribbon_text()
        ribbon = f'{ribbon.ljust(500, " ")}'
        formatted_ribbon, bg_color = format_ribbon(ribbon)
        self.AddLine(formatted_ribbon, bgcolor=bg_color)
        self.AddLine('')
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
        h_str: str = "[ H for help ]"
        exclusions_str: str = f"[ exclusions: {'on' if self.xrefer_obj.settings['enable_exclusions'] else 'off'} ]"
        content: str = ""

        current_state = self.state_machine.current_state
        func_name = idc.get_func_name(self.func_ea)
        if not func_name:
            func_name = '<none>'

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
        elif current_state in (self.state_machine.graph, self.state_machine.pinned_graph, self.state_machine.simplified_graph, self.state_machine.pinned_simplified_graph,
                            self.state_machine.cluster_graphs, self.state_machine.pinned_cluster_graphs):
            # Graph-related states show graph info plus ESC/Help
            content = f"{self.get_graph_ribbon_content()}{esc_str}{h_str}"
        elif current_state == self.state_machine.call_focus:
            # Call focus shows func info, exclusions, back/help
            content = f"[ func_ea: 0x{self.func_ea:x} ][ call focus ][ func_name: {func_name} ]{exclusions_str}{esc_str}{h_str}"
        elif current_state == self.state_machine.search:
            # Search shows current filter text
            content = f"[ search ]: {self.state_machine.search_filter}"
        elif current_state == self.state_machine.interesting_artifacts:
            # Added handling for interesting_artifacts
            content = f"[ interesting artifacts ]{esc_str}{h_str}"
        elif current_state == self.state_machine.clusters:
            # Added handling for clusters state (cluster table view)
            content = f"[ clusters ]{esc_str}{h_str}"
        else:
            # Default if no matching state: show func info, exclusions, help
            content = f"[ func_ea: 0x{self.func_ea:x} ][ func_name: {func_name} ]{exclusions_str}{h_str}"

        return f"{base_text}{content}"

    def get_trace_ribbon_content(self) -> str:
        current_state = self.state_machine.current_state
        trace_info: str = f"[ func_ea: 0x{self.func_ea:x} ][ trace "
        if current_state == self.state_machine.trace_scope_function:
            trace_info = f'{trace_info}scope=function ]'
        elif current_state == self.state_machine.trace_scope_path:
            trace_info = f'{trace_info}scope=path ]'
        elif current_state == self.state_machine.trace_scope_full:
            trace_info = f'{trace_info}scope=full ]'
        return trace_info

    def get_graph_ribbon_content(self) -> str:
        graph_type = []
        
        if self.state_machine.is_simplified_graph():
            graph_type.append("simplified")
        if self.state_machine.is_pinned_graph():
            graph_type.append("pinned")
        
        if self.state_machine.current_state in (self.state_machine.cluster_graphs, self.state_machine.pinned_cluster_graphs):
            graph_type.append('cluster graph')
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
        if not hasattr(self, 'dock_widget') or not self.dock_widget:
            return
        
        # Only resize for specific states
        is_graph_view = self.state_machine.current_state in (
            self.state_machine.graph,
            self.state_machine.pinned_graph,
            self.state_machine.simplified_graph,
            self.state_machine.pinned_simplified_graph,
            self.state_machine.clusters,
            self.state_machine.cluster_graphs,
            self.state_machine.pinned_cluster_graphs
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
            
        if not hasattr(self, 'qt_widget') or not self.qt_widget or not hasattr(self, 'dock_widget') or not self.dock_widget:
            return
            
        # Store current width before entering graph view if not already in it
        if not self.in_graph_view:
            self.last_non_graph_width = self.dock_widget.width()
            self.in_graph_view = True

        # Find IDA's main window
        main_window = None
        for widget in QtWidgets.QApplication.topLevelWidgets():
            if widget.windowTitle().startswith('IDA - '):
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
            line_width = (len(clean_line) * 8)  # Approximate pixel width based on character count
            max_width = max(max_width, line_width)

        # Cap width to maximum allowed
        max_width = min(max_width, max_allowed_width)

        self.dock_widget.setMinimumWidth(max_width)
        self.dock_widget.setMaximumWidth(max_width)
        self.dock_widget.updateGeometry()
        QtCore.QTimer.singleShot(100, self.reset_size_constraints)

    def print_llm_disclaimer(self, disclaimer_index: int=0) -> bool:
        """Print LLM disclaimer if not hidden in settings."""
        if self.xrefer_obj.settings["display_options"]["hide_llm_disclaimer"]:
            return False
            
        disclaimer_lines = [(
            '===> Some aspects of cluster analysis use LLM processing to enhance code relationship',
            's with semantic context. Results may be inconsistent or incomplete, and thus the anal',
            'ysis provided is considered low confidence. Right-click to re-run analysis if current',
            'results appear inaccurate. Always verify findings through manual inspection. <==='),
        (
            '===> Do not solely rely on this listing. These artifacts are bubbled up',
            'via an LLM which can be inconsistent, miss indicators and be in need of',
            'further prompt tuning. This is meant to jump start triage analysis <===')
        ]
        INDENT = "    "  # Standard 4-space indent
        for line in disclaimer_lines[disclaimer_index]:
            self.AddLine(f'{INDENT}\x01{ida_lines.SCOLOR_VOIDOP}{line}\x02{ida_lines.SCOLOR_VOIDOP}')
        self.AddLine('')
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
            self.state_machine.interesting_artifacts: self.draw_interesting_artifacts,
            self.state_machine.clusters: self.draw_clusters,
            self.state_machine.cluster_graphs: self.draw_cluster_graph,
            self.state_machine.pinned_cluster_graphs: self.draw_cluster_graph,
            self.state_machine.trace_scope_function: self.handle_trace_scope_function,
            self.state_machine.trace_scope_path: self.handle_trace_scope_path,
            self.state_machine.trace_scope_full: self.handle_trace_scope_full,
            self.state_machine.xref_listing: self.draw_entity_xrefs,
            self.state_machine.help: self.draw_help
        }

        # Get appropriate handler or use default table context
        state_handler = state_actions.get(self.state_machine.current_state, self.handle_table_context)
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
        api_suffix = api_name.split('.')[-1].lower()
        
        # Check against exclusions
        exclusions = self.xrefer_obj.settings_manager.load_exclusions()
        return api_suffix in (name.lower() for name in exclusions['apis'])

    def filter_api_calls(self, calls: List[str]) -> List[str]:
        """
        Filter API calls based on exclusions settings.
        
        Removes excluded API calls from the provided list.
        
        Args:
            calls (List[str]): List of API call strings to filter
            
        Returns:
            List[str]: Filtered list with excluded calls removed
        """
        if not self.xrefer_obj.settings["enable_exclusions"]:
            return calls
            
        filtered_calls = []
        for call in calls:
            # Extract API name from the call string
            # Format is typically: "0x123456: ApiName(args) = result"
            try:
                api_name = call.split(':')[1].strip().split('(')[0].strip()
                api_name_cleaned = api_name.split('"')[1].strip()[:-1]

                if not self.is_api_excluded(api_name_cleaned):
                    filtered_calls.append(call)
            except IndexError:
                # If we can't parse the call string, include it
                filtered_calls.append(call)
                
        return filtered_calls

    def handle_trace_scope_function(self) -> None:
        """
        Handle function-scope trace display.
        
        Shows API calls made directly from the current function,
        applying exclusions filtering if enabled.
        """
        self.ClearLines()
        self.print_ribbon()
        calls = self.xrefer_obj.gather_sorted_function_api_calls(self.func_ea)
        
        if not calls:
            self.AddLine('    NO API CALLS FOUND FOR CURRENT FUNCTION')
            return
            
        filtered_calls = self.filter_api_calls(calls)
        if not filtered_calls:
            self.AddLine('    ALL API CALLS ARE EXCLUDED')
            return
            
        for call in filtered_calls:
            self.AddLine(call)

    def handle_trace_scope_path(self) -> None:
        """
        Handle path-scope trace display.
        
        Shows API calls made from current function and all functions
        called along paths from it, applying exclusions filtering.
        """
        self.ClearLines()
        self.print_ribbon()
        calls = self.xrefer_obj.gather_sorted_path_api_calls(self.func_ea)
        
        if not calls:
            self.AddLine('    NO API CALLS FOUND FOR CURRENT PATH')
            return
            
        filtered_calls = self.filter_api_calls(calls)
        if not filtered_calls:
            self.AddLine('    ALL API CALLS ARE EXCLUDED')
            return
            
        for call in filtered_calls:
            self.AddLine(call)

    def handle_trace_scope_full(self) -> None:
        """
        Handle full-scope trace display.
        
        Shows all API calls in the trace file, applying exclusions
        filtering if enabled.
        """
        self.ClearLines()
        self.print_ribbon()
        calls = self.xrefer_obj.gather_sorted_full_api_calls()
        
        if not calls:
            self.AddLine('    NO API CALLS FOUND IN DATABASE')
            return
            
        filtered_calls = self.filter_api_calls(calls)
        if not filtered_calls:
            self.AddLine('    ALL API CALLS ARE EXCLUDED')
            return
            
        for call in filtered_calls:
            self.AddLine(call)

    def handle_no_context_available(self) -> None:
        """
        Handle case when no function context is available.
        
        Displays message indicating no context is available for
        current function address.
        """
        self.AddLine(f' [0x{self.func_ea:x}] NO FUNCTION CONTEXT AVAILABLE')

    def handle_table_context(self) -> None:
        """
        Handle display of function context tables.
        
        Displays appropriate tables showing cross-references, imports, strings,
        and other relevant information for current function.
        """
        self.ClearLines()
        self.print_ribbon()

        if idaapi.get_func(self.func_ea):
            if self.func_ea in self.xrefer_obj.global_xrefs:
                self.print_cluster_membership(self.func_ea)
                self.draw_function_context_tables(self.func_ea)
            else:
                self.handle_no_context_available()

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

        for table_index in range(self.table_count):
            table_start_index: int = (table_index + self.table_index_offset) % self.table_count
            table_name: str = self.table_names[table_start_index]
            try:
                table_data = self.xrefer_obj.table_data[func_ea][table_name]
            except KeyError:
                self.xrefer_obj.table_data[func_ea] = self.xrefer_obj.create_sorted_table(func_ea)
                table_data = self.xrefer_obj.table_data[func_ea][table_name]
            
            if table_data:
                printed = True
                if self.table_states[table_name] or self.state_machine.current_state in (
                self.state_machine.call_focus, self.state_machine.search):
                    self.draw_function_context_table(func_ea, table_name)
                else:
                    self.draw_function_context_table_heading(func_ea, table_name, '[+] %s')
                    self.AddLine('')

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

        for inner_table_key, inner_table in self.xrefer_obj.table_data[func_ea][table_name]['rows'].items():
            is_expanded: bool = subtable_states.setdefault(inner_table_key, False)

            if is_expanded or table_name.startswith('D') or self.state_machine.current_state in (
            self.state_machine.call_focus, self.state_machine.search):
                self.display_function_context_table_contents(table_name, inner_table_key, inner_table)
            else:
                self.AddLine(ida_lines.COLSTR('    %s %s' % (ida_lines.COLSTR('(+)', ida_lines.SCOLOR_DATNAME),
                                                             inner_table_key), ida_lines.SCOLOR_ASMDIR))
        
        if self.xrefer_obj.table_data[func_ea][table_name]['rows']:
            self.AddLine('')

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
        if not table_name.startswith('D') and not self.state_machine.current_state == self.state_machine.call_focus:
            self.AddLine(ida_lines.COLSTR('    %s %s' % (ida_lines.COLSTR('(-)', ida_lines.SCOLOR_DATNAME),
                                                         inner_table_key), ida_lines.SCOLOR_ASMDIR))

        line_prefix: str = '    ' if table_name.startswith('D') else self.indent

        for line in inner_table:
            self.print_xref_item(f'{line_prefix}{line}', self.state_machine.address_filter)

    def draw_function_context_table_heading(self, func_ea: int, table_name: str, fmt: str = '[-] %s') -> None:
        """
        Print formatted table heading.
        
        Displays table header with appropriate formatting and expansion indicators.
        
        Args:
            func_ea (int): Function address table belongs to
            table_name (str): Name of table to create heading for
            fmt (str): Format string for heading (default: '[-] %s')
        """
        try:
            if not self.xrefer_obj.table_data[func_ea][table_name]['heading']:
                return
        except KeyError:
            return

        heading_line: str = self.xrefer_obj.table_data[func_ea][table_name]['heading'][0]
        hline: str = ida_lines.COLSTR(fmt % heading_line, ida_lines.SCOLOR_DATNAME)
        self.AddLine(hline)
        heading_line = self.xrefer_obj.table_data[func_ea][table_name]['heading'][1]
        if is_windows_or_linux() and not table_name.startswith('D'):
            hline = ida_lines.COLSTR(f'    ----{heading_line}', ida_lines.SCOLOR_DATNAME)
        else:
            hline = ida_lines.COLSTR(f'    {heading_line}', ida_lines.SCOLOR_DATNAME)
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
            if idc.func_contains(xref_to, xref_to):
                if idc.get_func_name(xref_to).startswith('sub_'):
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
            line = set_xref_coverage_color(line, '0x%x' % xref_frm, xref_coverage_dict[xref_frm])

        return line

    def select_cell(self, cell: str) -> None:
        """
        Mark a table cell as selected.
        
        Updates internal state and visual representation to show cell as selected.
        
        Args:
            cell (str): Cell content to mark as selected
        """
        if self.state_machine.current_state == self.state_machine.search:
            cell = cell.replace('\x04', '')

        for table_name in self.xrefer_obj.table_data[self.func_ea]:
            for inner_table_key, inner_table in self.xrefer_obj.table_data[self.func_ea][table_name]['rows'].items():
                for i in range(0, len(inner_table)):
                    row: str = inner_table[i]
                    orig_row_length: int = len(row)
                    replaced: str = wrap_substring_with_string(row, cell, '\x04', case=True)
                    if len(replaced) == orig_row_length:
                        continue

                    self.xrefer_obj.table_data[self.func_ea][table_name]['rows'][inner_table_key][i] = replaced

    def deselect_cell(self, cell: str) -> None:
        """
        Remove selection from a table cell.
        
        Updates internal state and visual representation to remove selection.
        
        Args:
            cell (str): Cell content to deselect
        """
        if self.state_machine.current_state == self.state_machine.search:
            parts: List[str] = cell.split('\x04')
            if len(parts) > 3:
                cell = '\x04'.join([parts[0], ''.join(parts[1:-1]), parts[-1]])

        for table_name in self.xrefer_obj.table_data[self.func_ea]:
            for inner_table_key, inner_table in self.xrefer_obj.table_data[self.func_ea][table_name]['rows'].items():
                for i in range(0, len(inner_table)):
                    row: str = inner_table[i]
                    if cell in row:
                        self.xrefer_obj.table_data[self.func_ea][table_name]['rows'][inner_table_key][i] = row.replace('\x04', '')

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
        tooltip: str = ''
        func_trunc_length: int = 60
        func_name: str = idc.get_func_name(func_ea)
        if len(func_name) > func_trunc_length:
            func_name = f'{func_name[:func_trunc_length]}...'
        func_name = f'\x01{ida_lines.SCOLOR_DEMNAME}{func_name}\x02{ida_lines.SCOLOR_DEMNAME}\n'

        if func_ea in self.tooltip_cache:
            _line_count, _tooltip = self.tooltip_cache[func_ea]
            if func_ea != _tooltip[0]:
                _tooltip = _tooltip.splitlines()
                _tooltip[0] = func_name[:-1]
                _tooltip = '\n'.join(_tooltip)
                self.tooltip_cache[func_ea] = _line_count, _tooltip
            return self.tooltip_cache[func_ea]

        try:
            direct_xref_entities: Dict[str, Set[int]] = self.xrefer_obj.global_xrefs[func_ea][0]
        except:
            return None

        func_name_len: int = len(func_name)

        for _type in 'libs', 'imports', 'strings', 'capa':
            for e_index in direct_xref_entities[_type]:
                entity: Tuple[str, str, int] = self.xrefer_obj.entities[e_index]
                table_name: str = self.xrefer_obj.table_names[entity[2]]
                entity_content: str = entity[1]
                entity_color_tag: int = self.xrefer_obj.color_tags[table_name]
                if _type == 'imports':
                    api_calls = self.xrefer_obj.get_direct_calls(entity_content, func_ea)
                    total_calls = sum(count for _, count in api_calls)
                    total_lines = len(api_calls)
                    displayed_calls = api_calls[:3]  # Limit to 3 calls

                    # Add "(x more)" if there are more than 3 calls
                    if total_lines > 3:
                        sum_of_first_three_calls = sum(count for _, count in api_calls[:3])
                        entity_content += f"\x02  ({total_calls - sum_of_first_three_calls} more)"

                    tooltip += f'\x01{entity_color_tag}{entity_content}\x02{entity_color_tag}\n'
                    line_count += 1

                    if displayed_calls:
                        for call, _ in displayed_calls:
                            # Limit the length of the call string and add "..." if truncated
                            if len(call) > 150:
                                call = call[:150] + "..."
                            tooltip += f'  {call}\n'
                            line_count += 1
                else:
                    tooltip += f'\x01{entity_color_tag}{entity_content}\x02{entity_color_tag}\n'
                    line_count += 1

        sep_len: int = longest_line_length(tooltip)
        sep_len = sep_len - 4 if sep_len >= func_name_len else func_name_len - 4
        sep: str = '-' * sep_len
        func_name += f'\x01{ida_lines.SCOLOR_DEMNAME}{sep}\x02{ida_lines.SCOLOR_DEMNAME}\n'
        tooltip = func_name + tooltip
        line_count += 2

        if line_count > 2:
            self.tooltip_cache[func_ea] = line_count, tooltip
        else:
            s_no_xrefs: str = ida_lines.COLSTR('No Direct XRefs', ida_lines.SCOLOR_DEMNAME)
            tooltip += f'{s_no_xrefs}\n'
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
        tooltip = ''

        # Iterate over line_dict items sorted by line number
        for line_number, line_text in sorted(line_dict.items(), key=lambda x: int(x[0])):
            # Colorize the line number
            line_num_str = f'\x01{ida_lines.SCOLOR_KEYWORD}{line_number}\x02{ida_lines.SCOLOR_KEYWORD}'
            # Colorize the line text
            line_text_str = f'\x01{ida_lines.SCOLOR_DEMNAME}{line_text}\x02{ida_lines.SCOLOR_DEMNAME}'
            # Combine them into a single line
            tooltip_line = f'{line_num_str}: {line_text_str}\n'
            tooltip += tooltip_line
            line_count += 1

        # If repo_names is not empty, add separator and additional repository hits
        if repo_names:
            # Add separator
            sep = '-' * 20
            tooltip += f'{sep}\n'
            line_count += 1

            # Add "Additional repository hits:" header
            header_str = f'\x01{ida_lines.SCOLOR_KEYWORD}Matched Repos:\x02{ida_lines.SCOLOR_KEYWORD}\n'
            tooltip += header_str
            line_count += 1

            # List each repository name with its index
            for idx, repo_name in enumerate(repo_names, start=1):
                # Colorize the repository name
                repo_name_str = f'\x01{ida_lines.SCOLOR_IMPNAME}{repo_name}\x02{ida_lines.SCOLOR_IMPNAME}'
                repo_line = f'{idx}- {repo_name_str}\n'
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
            tooltip.append(f'\x01{ida_lines.SCOLOR_DEMNAME}{header}\x02{ida_lines.SCOLOR_DEMNAME}')
            
            # Add separator
            separator = "=" * len(header)
            tooltip.append(f'\x01{ida_lines.SCOLOR_DEMNAME}{separator}\x02{ida_lines.SCOLOR_DEMNAME}')
            
            # Add basic cluster info
            if analysis_data:
                # Label (if available)
                if label := analysis_data.get('label'):
                    tooltip.append(f'\x01{ida_lines.SCOLOR_DEMNAME}Label:\x02{ida_lines.SCOLOR_DEMNAME} \x01{ida_lines.SCOLOR_IMPNAME}{label}\x02{ida_lines.SCOLOR_IMPNAME}')
                    
                # Description (if available)
                if desc := analysis_data.get('description'):
                    tooltip.append(f'\x01{ida_lines.SCOLOR_DEMNAME}Description:\x02{ida_lines.SCOLOR_DEMNAME}')
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
                            tooltip.append(f'\x01{ida_lines.SCOLOR_DSTR}  {" ".join(line)}\x02{ida_lines.SCOLOR_DSTR}')
                            line = [word]
                            line_length = len(word)
                    if line:
                        tooltip.append(f'\x01{ida_lines.SCOLOR_DSTR}  {" ".join(line)}\x02{ida_lines.SCOLOR_DSTR}')
                
                # Relationships (if available)
                if rels := analysis_data.get('relationships'):
                    tooltip.append(f'\x01{ida_lines.SCOLOR_DEMNAME}Relationships:\x02{ida_lines.SCOLOR_DEMNAME}')
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
                            tooltip.append(f'\x01{ida_lines.SCOLOR_DSTR}  {" ".join(line)}\x02{ida_lines.SCOLOR_DSTR}')
                            line = [word]
                            line_length = len(word)
                    if line:
                        tooltip.append(f'\x01{ida_lines.SCOLOR_DSTR}  {" ".join(line)}\x02{ida_lines.SCOLOR_DSTR}')
            
            # Add function count and artifacts
            tooltip.append('')  # Add spacing
            tooltip.append(f'\x01{ida_lines.SCOLOR_DEMNAME}Functions: \x02{ida_lines.SCOLOR_DEMNAME}\x01{ida_lines.SCOLOR_NUMBER}{len(cluster.nodes)}\x02{ida_lines.SCOLOR_NUMBER}')

            line_count = len(tooltip)
            return line_count, '\n'.join(tooltip)
    
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
        entity_wrap_start: str = f'\x01{entity_color_tag}'
        entity_wrap_end: str = f'\x02{entity_color_tag}'
        colored_entity: str = f'{entity_wrap_start}{entity_content}{entity_wrap_end}'
        
        # Update heading based on graph type
        is_simplified = self.state_machine.is_simplified_graph()
        graph_type = "SIMPLIFIED " if is_simplified else ""
        heading: str = f'    \x01{ida_lines.SCOLOR_DEMNAME}{graph_type}PATHS (entry_point(s) -> {colored_entity})\x02{ida_lines.SCOLOR_DEMNAME}'
        
        heading_len: int = len(heading) - 12
        heading_underline: str = f'    \x01{ida_lines.SCOLOR_DEMNAME}{"-" * heading_len}\x02{ida_lines.SCOLOR_DEMNAME}'
        g_paths: List[List[int]] = []
        _graph: Optional[List[bytes]] = None
        
        # Use different cache keys for normal and simplified graphs
        cache_key = f"simplified_{e_index}" if is_simplified else e_index
        
        if cache_key in self.xrefer_obj.graph_cache:
            _graph, num_original_nodes, num_simplified_nodes = self.xrefer_obj.graph_cache[cache_key]
        else:
            # Collect paths and track unique nodes
            original_nodes = set()
            simplified_nodes = set()
            
            for xref in xrefs:
                xref_func: ida_funcs.func_t = idaapi.get_func(xref)
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
                            graph.add_edge(f'ENTRYPOINT\n0x{path[i]:x}', f'0x{path[i + 1]:x}')
                        else:
                            graph.add_edge(f'0x{path[i]:x}', f'0x{path[i + 1]:x}')
                    graph.add_edge(f'0x{path[-1]:x}', entity_content)
                
                def is_entrypoint_node(node: str) -> bool:
                    return node.startswith('ENTRYPOINT\n0x')

                def is_function_node(node: str) -> bool:
                    if is_entrypoint_node(node):
                        return True
                    if node.startswith('0x'):
                        try:
                            int(node[2:], 16)
                            return True
                        except:
                            return False
                    return False

                def get_function_ea(node: str) -> int:
                    if is_entrypoint_node(node):
                        # node like "ENTRYPOINT\n0x401000"
                        lines = node.split('\n')
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
                        # Truncate function name at 16 chars
                        if len(func_name) > 12:
                            func_name = func_name[:12] + '..'

                        addr_str = f'0x{ea:x}'

                        if is_entrypoint_node(node):
                            # Three lines: ENTRYPOINT, addr, func_name
                            lines = ["ENTRYPOINT", addr_str, func_name]
                        else:
                            # Two lines: addr, func_name
                            lines = [addr_str, func_name]

                        # Determine this node's max line length
                        node_max_len = max(len(line) for line in lines)

                        # Center each line individually for this node
                        centered_lines = [f"{line:^{node_max_len}}" for line in lines]
                        new_label = "\n".join(centered_lines)

                        func_nodes.append((node, new_label))

                if func_nodes:
                    mapping = {node: new_label for node, new_label in func_nodes}
                    graph = nx.relabel_nodes(graph, mapping, copy=True)

                _graph = asciinet.graph_to_ascii(graph).splitlines()
                self.xrefer_obj.graph_cache[cache_key] = (_graph, num_original_nodes, num_simplified_nodes)
            except:
                self.state_machine.go_back()
                self.update(True)
                log(f'Graph too large to draw')
                return

        self.ClearLines()
        self.print_ribbon()
        self.AddLine(heading)
        self.AddLine(heading_underline)
        
        # Add node reduction info if in simplified mode
        if is_simplified and num_original_nodes > num_simplified_nodes:
            reduction = ((num_original_nodes - num_simplified_nodes) / num_original_nodes * 100)
            reduction_str = f'    \x01{ida_lines.SCOLOR_NUMBER}Graph reduced from {num_original_nodes} to {num_simplified_nodes} nodes ({reduction:.1f}% reduction)\x02{ida_lines.SCOLOR_NUMBER}'
            self.AddLine(reduction_str)
            
        self.AddLine('')
        func_ea: str = f'0x{self.func_ea:x}'

        for line in _graph:
            line: str = line
            line = ida_lines.COLSTR(line, ida_lines.SCOLOR_DEMNAME)
            line = wrap_substring_with_string(line, func_ea, '\x01\x12', '\x02\x12', case=True)
            line = wrap_substring_with_string(line, entity_content, entity_wrap_start, entity_wrap_end, True)
            self.AddLine(f'        {line}')

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
        line = line.replace('\x01\x22', '').replace('\x02\x22', '')

        # Remove non-displayable characters
        line = remove_non_displayable(line)

        # Adjust xpos if characters before it were removed
        xpos = min(xpos, len(line) - 1)

        # Fast path: check if cursor is directly on '0x'
        if line.startswith('0x', xpos) or (xpos > 0 and line.startswith('0x', xpos - 1)):
            start = xpos if line.startswith('0x', xpos) else xpos - 1
            end = start + 2
            while end < len(line) and line[end] in '0123456789abcdefABCDEF':
                end += 1
            return line[start:end].strip('│')

        # Find word boundaries
        start = xpos
        while start > 0 and not line[start - 1].isspace():
            start -= 1
        end = xpos
        while end < len(line) and not line[end].isspace():
            end += 1

        word = line[start:end]

        # Check for addresses only if '0x' is in the word
        if '0x' in word:
            # Find the address closest to the cursor without creating a list
            closest_start = closest_end = -1
            for match in self.address_regex.finditer(word):
                m_start, m_end = match.start(), match.end()
                if closest_start == -1 or abs(m_start - (xpos - start)) < abs(closest_start - (xpos - start)):
                    closest_start, closest_end = m_start, m_end

            if closest_start != -1 and start + closest_start <= xpos < start + closest_end:
                return word[closest_start:closest_end].strip('│')

        return word

    def get_parent_table(self) -> Optional[str]:
        """
        Get name of table containing current line.
        
        Searches upward from current line to find enclosing table header.
        
        Returns:
            Optional[str]: Name of parent table, or None if not found
        """
        lineno: int = self.GetLineNo(mouse=1)
        table_name: Optional[str] = None

        while lineno:
            line, _, _ = self.GetLine(lineno)
            _table_name: str = line[6:-2].strip()
            if _table_name in self.table_names:
                table_name = _table_name
                break
            lineno -= 1

        return table_name
