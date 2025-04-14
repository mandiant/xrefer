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

from typing import Any, Dict
import idaapi
import idc
from pprint import pprint

from xrefer.core.helpers import *
from xrefer.core.settings import XReferSettingsDialog

class PeekViewToggleHandler(idaapi.action_handler_t):
    """
    Handler for toggling peek view functionality.
    
    When activated, enables/disables peeking at cross-references when clicking
    functions in the disassembly/pseudocode view.
    """
    def activate(self, ctx: Any) -> bool:
        from xrefer.plugin import plugin_instance
        plugin_instance.xrefer_view.peek_flag = not plugin_instance.xrefer_view.peek_flag
        state: str = 'enabled' if plugin_instance.xrefer_view.peek_flag else 'disabled'
        
        # Update the action label to reflect current state
        action_desc = idaapi.action_desc_t(
            'XRefer:toggle_peek',  # Action name
            f'{"Disable" if plugin_instance.xrefer_view.peek_flag else "Enable"} Peek View',  # Updated label with checkmark
            self  # Handler instance
        )
        idaapi.update_action_label('XRefer:toggle_peek', action_desc.label)
        
        if plugin_instance.xrefer_view.peek_flag:
            plugin_instance.xrefer_view.update(ea=idc.get_screen_ea())
        elif plugin_instance.xrefer_view.state_machine.current_state == plugin_instance.xrefer_view.state_machine.call_focus:
            plugin_instance.xrefer_view.state_machine.go_back()
            plugin_instance.xrefer_view.update(True)
        
        log(f'Peek view {state}')
        return True

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS to indicate action should always be enabled
        """
        return idaapi.AST_ENABLE_ALWAYS

    
class ArtifactAnalysisHandler(idaapi.action_handler_t):
    """
    Handler for re-running LLM analysis on artifacts.
    Forces a fresh analysis of all artifacts regardless of existing results.
    """
    
    def activate(self, ctx: Any) -> bool:
        """
        Handle re-run artifact analysis action.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True after analysis is complete
        """
        from xrefer.plugin import plugin_instance
        
        try:
            idaapi.show_wait_box(f'HIDECANCEL\n')
            log("Running artifact analysis...")
            xrefer_obj = plugin_instance.xrefer_view.xrefer_obj
            xrefer_obj.find_interesting_artifacts()
            xrefer_obj.save_analysis()
            
            # Force view update
            current_state = plugin_instance.xrefer_view.state_machine.current_state
            if current_state == plugin_instance.xrefer_view.state_machine.interesting_artifacts:
                plugin_instance.xrefer_view.update(True)
                
            log("Artifact analysis complete")
            idaapi.hide_wait_box()
            return True
            
        except Exception as e:
            idaapi.hide_wait_box()
            log(f"Error during artifact analysis: {str(e)}")
            return False

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS if view exists, AST_DISABLE otherwise
        """
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE


class ClusterInterestingFunctionsHandler(idaapi.action_handler_t):
    """
    Handler for running LLM analysis on interesting function clusters.
    Forces a fresh analysis of cluster relationships and behaviors.
    """
    
    def activate(self, ctx: Any) -> bool:
        """
        Handle re-run cluster analysis action.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True after analysis is complete
        """
        from xrefer.plugin import plugin_instance
        
        try:
            idaapi.show_wait_box("HIDECANCEL")
            log("\nRunning Cluster Analysis on Interesting Functions...")

            if plugin_instance.xrefer_view.xrefer_obj.interesting_artifacts:
                plugin_instance.xrefer_view.state_machine.clear_cluster_history()
                xrefer_obj = plugin_instance.xrefer_view.xrefer_obj
                xrefer_obj.analyze_clusters(xrefer_obj.interesting_artifacts)
                xrefer_obj.save_analysis()
            else:
                log('No Interesting Artifacts found for clustering. Please run Artifact Analysis first.')
            
            # Force view update
            current_state = plugin_instance.xrefer_view.state_machine.current_state
            if current_state in (plugin_instance.xrefer_view.state_machine.clusters,
                plugin_instance.xrefer_view.state_machine.cluster_graphs):
                plugin_instance.xrefer_view.update(True)
            
            log("Cluster analysis complete.")
            idaapi.hide_wait_box()
            return True
            
        except Exception as e:
            idaapi.hide_wait_box()
            log(f"Error during cluster analysis: {str(e)}")
            return False
            

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS if view exists, AST_DISABLE otherwise
        """
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE
        

class ClusterEverythingHandler(idaapi.action_handler_t):
    """
    Handler for running LLM analysis on all function clusters.
    Forces a fresh analysis of cluster relationships and behaviors.
    """
    
    def activate(self, ctx: Any) -> bool:
        """Handle cluster everything action."""
        from xrefer.plugin import plugin_instance
        
        try:
            idaapi.show_wait_box("HIDECANCEL\n")
            log("Running Cluster Analysis on all function clusters...")
            
            # Run clustering for all non-excluded artifact functions
            xrefer_obj = plugin_instance.xrefer_view.xrefer_obj
            plugin_instance.xrefer_view.state_machine.clear_cluster_history()
            xrefer_obj.cluster_all_non_excluded()
            
            # Update view if in cluster-related view
            current_state = plugin_instance.xrefer_view.state_machine.current_state
            if current_state in (
                plugin_instance.xrefer_view.state_machine.clusters,
                plugin_instance.xrefer_view.state_machine.cluster_graphs):
                plugin_instance.xrefer_view.update(True)
            
            log("Cluster analysis complete")
            idaapi.hide_wait_box()
            return True
            
        except Exception as e:
            idaapi.hide_wait_box()
            log(f"Error during full cluster analysis: {str(e)}")
            return False

    def update(self, ctx: Any) -> int:
        """Enable if view exists."""
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE
        

class AboutDialogHandler(idaapi.action_handler_t):
    """
    Handler for showing XRefer About dialog.
    
    Displays a compact dialog that respects IDA's current theme settings.
    """
    
    def _create_logo_widget(self) -> QtWidgets.QLabel:
        """Create widget containing the scaled XRefer logo with proper aspect ratio."""
        logo_path = os.path.join(idaapi.get_user_idadir(), "plugins", "xrefer", "data", "xrefer_logo.png")
        
        # Create logo container
        logo_container = QtWidgets.QWidget()
        logo_layout = QtWidgets.QHBoxLayout(logo_container)
        logo_layout.setContentsMargins(0, 0, 0, 0)
        
        logo_label = QtWidgets.QLabel()
        
        try:
            pixmap = QtGui.QPixmap(logo_path)
            if not pixmap.isNull():
                # Set desired width
                target_width = 200  # slightly larger to accommodate aspect ratio
                # Calculate height that maintains aspect ratio
                aspect_ratio = pixmap.width() / pixmap.height()
                target_height = int(target_width / aspect_ratio)
                
                scaled_pixmap = pixmap.scaled(target_width, target_height, 
                                            QtCore.Qt.KeepAspectRatio, 
                                            QtCore.Qt.SmoothTransformation)
                logo_label.setPixmap(scaled_pixmap)
                logo_label.setFixedSize(target_width, target_height)
            else:
                log("Failed to load logo pixmap")
                logo_label.setText("XR")
        except Exception as e:
            log(f"Error loading logo: {str(e)}")
            logo_label.setText("XR")
            
        # Center the logo
        logo_layout.addStretch(1)
        logo_layout.addWidget(logo_label)
        logo_layout.addStretch(1)
            
        return logo_container

    def activate(self, ctx: Any) -> bool:
        """
        Handle about dialog action.
        
        Creates and shows modal About dialog that follows IDA's theme.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True after dialog is closed
        """
        dialog = QtWidgets.QDialog()
        dialog.setWindowTitle("About XRefer")
        dialog.setFixedSize(250, 250)
        
        # Only style the separator and button to maintain consistency
        # while letting the rest inherit from IDA's theme
        dialog.setStyleSheet("""
            QPushButton {
                padding: 5px 15px;
            }
            QFrame[frameShape="4"] {
                height: 1px;
            }
        """)
        
        # Center dialog
        frame_geom = dialog.frameGeometry()
        center_point = QtWidgets.QApplication.primaryScreen().availableGeometry().center()
        frame_geom.moveCenter(center_point)
        dialog.move(frame_geom.topLeft())
        
        # Create main layout
        layout = QtWidgets.QVBoxLayout(dialog)
        layout.setSpacing(5)
        layout.setContentsMargins(20, 15, 20, 15)
        
        # Add centered logo container
        logo_container = self._create_logo_widget()
        layout.addWidget(logo_container)
        
        # Add title
        title_label = QtWidgets.QLabel("XRefer: The Binary Navigator")
        title_font = title_label.font()
        title_font.setPointSize(9)
        title_label.setFont(title_font)
        title_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Add version
        version_label = QtWidgets.QLabel("Version 1.0.2")
        version_font = version_label.font()
        version_font.setPointSize(9)
        version_label.setFont(version_font)
        version_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(version_label)
        
        # Add separator line
        separator = QtWidgets.QFrame()
        separator.setFrameShape(QtWidgets.QFrame.HLine)
        separator.setFrameShadow(QtWidgets.QFrame.Plain)
        layout.addWidget(separator)
        
        # Add "Developed by"
        team_label = QtWidgets.QLabel("Developed by")
        team_label.setAlignment(QtCore.Qt.AlignCenter)
        team_font = team_label.font()
        team_font.setPointSize(9)
        team_label.setFont(team_font)
        layout.addWidget(team_label)
        
        # Add FLARE
        flare_label = QtWidgets.QLabel("FLARE")
        flare_font = flare_label.font()
        flare_font.setPointSize(9)
        flare_label.setFont(flare_font)
        flare_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(flare_label)
        
        # Add spacing
        layout.addStretch()
        
        # Add close button
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.setContentsMargins(20, 0, 20, 0)  # Left and right margins only

        close_button = QtWidgets.QPushButton("Close")
        close_button.setFixedHeight(25)
        close_button.clicked.connect(dialog.accept)
        close_button.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)  # Allow horizontal expansion

        # Add button without stretching
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)
        
        dialog.exec_()
        return True

    def update(self, ctx: Any) -> int:
        """Update handler state."""
        return idaapi.AST_ENABLE_ALWAYS


class StartHandler(idaapi.action_handler_t):
    """
    Handler for starting XRefer analysis with default entry point.
    
    Initializes XRefer's main view and starts analysis using the default
    entry point identified in the binary.
    """

    def activate(self, ctx: Any) -> bool:
        """
        Handle start analysis action.
        
        Initializes view if needed and starts analysis from default entry point.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True to indicate successful handling
        """
        from xrefer.plugin import plugin_instance
        msg = 'Default entrypoint selected for primary analysis'
        
        if not plugin_instance.xrefer_view:
            log(msg)
            plugin_instance.start()
        elif not plugin_instance.xrefer_view.xrefer_obj.lang:
            log(msg)
            plugin_instance.xrefer_view.xrefer_obj.load_analysis()
        
        if plugin_instance.xrefer_view.xrefer_obj.lang:
            plugin_instance.xrefer_view.create()

        return True

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS to indicate action should always be enabled
        """
        return idaapi.AST_ENABLE_ALWAYS
    

class CopyInterestingStringsHandler(idaapi.action_handler_t):
    """
    Handler for copying all interesting strings to clipboard.
    
    When activated, copies all full strings marked as interesting 
    to the system clipboard.
    """
    
    def activate(self, ctx: Any) -> bool:
        """
        Handle copying interesting strings to clipboard.
        
        Collects all interesting strings and copies their full versions
        to the system clipboard if any are available.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True if operation completed successfully
        """
        from xrefer.plugin import plugin_instance
        
        try:
            interesting_strings = []
            
            # Collect interesting strings from artifacts
            for idx in plugin_instance.xrefer_view.xrefer_obj.interesting_artifacts:
                entity = plugin_instance.xrefer_view.xrefer_obj.entities[idx]
                # Check if it's a string (type 3) and has full version
                if entity[2] == 3:  # String type
                    if len(entity) > 6:  # Has full string
                        interesting_strings.append(entity[6])  # Get full string
                    else:
                        interesting_strings.append(entity[1])  # Fallback to truncated version
            
            if not interesting_strings:
                log("No interesting strings available for copy")
                return False
                
            # Copy to clipboard using Qt
            text = '\n'.join(interesting_strings)
            clipboard = QtWidgets.QApplication.clipboard()
            clipboard.setText(text)
            
            log(f"{len(interesting_strings)} interesting strings copied to clipboard")
            return True
            
        except Exception as e:
            log(f"Error copying strings to clipboard: {str(e)}")
            return False

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS if view exists, AST_DISABLE otherwise
        """
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE

class CopyProcessedStringsHandler(idaapi.action_handler_t):
    """
    Handle copying all processed strings to clipboard.
    
    Collects all processed strings and copies their full versions
    to the system clipboard if any are available.
    
    Args:
        ctx (Any): IDA context (unused)
        
    Returns:
        bool: True if operation completed successfully
    """
    def activate(self, ctx: Any) -> bool:
        from xrefer.plugin import plugin_instance

        try:
            all_strings = []

            for entity in plugin_instance.xrefer_view.xrefer_obj.entities:
                # Check if it's a string (type 3) and has full version
                if entity[2] == 3: # String type
                    if len(entity) > 6:
                        all_strings.append(entity[6])  # Get full string
                    else:
                        all_strings.append(entity[1])  # Fallback to truncated version

            if not all_strings:
                log("No strings found in entities.")
                return False

            text = '\n'.join(all_strings)
            QtWidgets.QApplication.clipboard().setText(text)

            log(f"{len(all_strings)} total strings copied to clipboard")
            return True

        except Exception as e:
            log(f"Error copying all processed strings: {e}")
            return False

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS if view exists, AST_DISABLE otherwise
        """
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE

class StartHandlerCustomEntrypoint(idaapi.action_handler_t):
    """
    Handler for starting XRefer analysis with custom entry point.
    
    Prompts user to select a function to use as entry point for analysis
    instead of using the default entry point.
    """
    
    def activate(self, ctx: Any) -> bool:
        """
        Handle custom entry point analysis action.
        
        Prompts user to select an entry point function and starts analysis.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True if analysis started successfully, False otherwise
        """
        from xrefer.plugin import plugin_instance
        custom_ep: int = idc.choose_func('[XRefer] Choose an entrypoint function for analysis')
        return handle_entrypoint_selection(plugin_instance, custom_ep)
    
    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS to indicate action should always be enabled
        """
        return idaapi.AST_ENABLE_ALWAYS
    

class AddEntrypointHandler(idaapi.action_handler_t):
    """
    Handler for adding current function as analysis entry point.
    
    Allows user to select the currently viewed function as a new entry point
    for additional analysis paths.
    """

    def activate(self, ctx: Any) -> bool:
        """
        Handle add entry point action.
        
        Uses currently selected function as new analysis entry point.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True if entry point was successfully added, False otherwise
        """
        from xrefer.plugin import plugin_instance
        current_ea: int = idc.get_screen_ea()
        if current_ea != idc.BADADDR:
            current_func = idaapi.get_func(current_ea)
            if current_func:
                custom_ep: int = current_func.start_ea
                return handle_entrypoint_selection(plugin_instance, custom_ep)
        return True
    
    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS to indicate action should always be enabled
        """
        return idaapi.AST_ENABLE_ALWAYS


class RustRenameHandler(idaapi.action_handler_t):
    """
    Handler for renaming Rust functions.
    
    Processes all functions identified as Rust-related and applies appropriate
    naming schemes based on analysis results.
    """

    def activate(self, ctx: Any) -> bool:
        """
        Handle Rust function renaming action.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True if renaming was successful
        """
        from xrefer.plugin import plugin_instance
        plugin_instance.xrefer_view.xrefer_obj.lang.rename_functions(plugin_instance.xrefer_view.xrefer_obj)
        return True

    def update(self, ctx: Any) -> int:
        """
        Update handler state based on language detection.
        
        Only enables action if current binary is identified as Rust.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS if Rust binary, AST_DISABLE otherwise
        """
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view and plugin_instance.xrefer_view.xrefer_obj.lang \
            and plugin_instance.xrefer_view.xrefer_obj.lang.id == 'lang_rust':
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE
        

class ClusterRenameHandler(idaapi.action_handler_t):
    """
    Handler for renaming functions based on cluster analysis.
    Applies standardized prefixes based on function roles and cluster membership.
    """

    def activate(self, ctx: Any) -> bool:
        from xrefer.plugin import plugin_instance
        try:
            plugin_instance.xrefer_view.xrefer_obj.rename_cluster_functions()
            return True
        except Exception as e:
            log(f"Error during cluster-based renaming: {str(e)}")
            return False

    def update(self, ctx: Any) -> int:
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view and plugin_instance.xrefer_view.xrefer_obj.clusters:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE


class SyncImageBaseHandler(idaapi.action_handler_t):
    """
    Handler for synchronizing image base addresses.
    
    Synchronizes XRefer's stored image base with IDA's current image base
    when binary is rebased.
    """

    def activate(self, ctx: Any) -> bool:
        """
        Handle image base synchronization action.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True after synchronization is complete
        """
        from xrefer.plugin import plugin_instance
        plugin_instance.xrefer_view.xrefer_obj.sync_image_base()
        return True

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS if XRefer view exists, AST_DISABLE otherwise
        """
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE


class DumpIndirectCallsHandler(idaapi.action_handler_t):
    """
    Handler for dumping indirect call information.
    
    Exports all identified indirect call sites to a file for analysis
    or processing by other tools.
    """
    
    def activate(self, ctx: Any) -> bool:
        """
        Handle indirect calls dump action.
        
        Creates a file named <idb_path>_indirect_calls.txt containing
        all identified indirect call sites.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True after dump is complete
        """
        path: str = f'{idc.get_idb_path()}_indirect_calls.txt'
        dump_indirect_calls(path)
        return True

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS to indicate action should always be enabled
        """
        return idaapi.AST_ENABLE_ALWAYS


class ShowWindowHandler(idaapi.action_handler_t):
    def activate(self, ctx: Any) -> bool:
        """
        Handle show window action.
        """
        from xrefer.plugin import plugin_instance
        # Create a fresh view if needed, otherwise reuse existing
        if plugin_instance.xrefer_view:
            # Clear old dock widget if it exists
            if hasattr(plugin_instance.xrefer_view, 'dock_widget'):
                plugin_instance.xrefer_view.dock_widget.setWidget(None)
                plugin_instance.xrefer_view.dock_widget.deleteLater()
                delattr(plugin_instance.xrefer_view, 'dock_widget')
            
            # Show and update
            plugin_instance.xrefer_view.create()
            
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS if XRefer view exists, AST_DISABLE otherwise
        """
        from xrefer.plugin import plugin_instance
        if plugin_instance.xrefer_view:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE
        

class XReferSettingsHandler(idaapi.action_handler_t):
    """
    Handler for showing XRefer settings dialog.
    
    Opens the configuration dialog allowing users to modify XRefer settings
    including paths, exclusions, and analysis options.
    """

    def activate(self, ctx: Any) -> bool:
        """
        Handle settings dialog action.
        
        Creates and shows settings dialog modal.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            bool: True after dialog is closed
        """

        dialog = XReferSettingsDialog()
        dialog.exec_()
        return True

    def update(self, ctx: Any) -> int:
        """
        Update handler state.
        
        Args:
            ctx (Any): IDA context (unused)
            
        Returns:
            int: AST_ENABLE_ALWAYS to indicate action should always be enabled
        """
        return idaapi.AST_ENABLE_ALWAYS
        
