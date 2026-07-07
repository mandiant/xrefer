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

import os
from typing import Any

import ida_funcs
import idaapi
import idc
from qtpy import QtCore, QtGui, QtWidgets

from xrefer.gui.helpers import dump_indirect_calls, handle_entrypoint_selection, log
from xrefer.gui.settings import XReferSettingsDialog


class PeekViewToggleHandler(idaapi.action_handler_t):
    """
    Handler for toggling peek view functionality.

    When activated, enables/disables peeking at cross-references when clicking
    functions in the disassembly/pseudocode view.
    """

    def activate(self, ctx: Any) -> bool:
        from xrefer.plugin import plugin_instance

        plugin_instance.xrefer_view.peek_flag = not plugin_instance.xrefer_view.peek_flag
        state: str = "enabled" if plugin_instance.xrefer_view.peek_flag else "disabled"

        # Update the action label to reflect current state
        action_desc = idaapi.action_desc_t(
            "XRefer:toggle_peek",  # Action name
            f"{'Disable' if plugin_instance.xrefer_view.peek_flag else 'Enable'} Peek View",  # Updated label with checkmark
            self,  # Handler instance
        )
        idaapi.update_action_label("XRefer:toggle_peek", action_desc.label)

        view = plugin_instance.xrefer_view
        sm = view.state_machine
        if view.peek_flag:
            # Enabling peek only ARMS the mode for future clicks. Forcing an
            # immediate sync from a deliberately-navigated view (a graph, a
            # trace, a deep cluster stack) would let the peek branch hijack
            # it — usually tearing it down to base — on a menu toggle whose
            # only advertised effect is arming. Apply it now only where peek
            # legitimately owns the panel; otherwise the next real cursor
            # event applies it.
            if sm.current_state in (sm.base, sm.call_focus):
                view.update(ea=idc.get_screen_ea())
        elif sm.current_state == sm.call_focus:
            sm.go_back()
            view.update(True)

        log(f"Peek view {state}")
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


class ClusterEverythingHandler(idaapi.action_handler_t):
    """
    Handler for running LLM analysis on all function clusters.
    Forces a fresh analysis of cluster relationships and behaviors,
    and bypasses the LLM response cache so the model re-generates its
    response instead of replaying a cached one — the whole point of
    an explicit re-run.
    """

    def activate(self, ctx: Any) -> bool:
        """Handle cluster everything action."""
        import ida_kernwin

        from xrefer.plugin import plugin_instance

        # No-LLM pre-flight: clustering REQUIRES a model, and without this
        # check the run just logs a line and "completes" empty. Offer the
        # Configure dialog right here; saving it re-runs
        # configure_llm_and_lookups, so a fixed config proceeds immediately.
        _obj = plugin_instance.xrefer_view.xrefer_obj
        if not getattr(_obj, "llm_lookups", False):
            choice = ida_kernwin.ask_buttons(
                "Configure", "Cancel", "", ida_kernwin.ASKBTN_YES,
                "HIDECANCEL\nCluster analysis needs an LLM, but none is configured.\n"
                "Set a model and API key now?",
            )
            if choice != ida_kernwin.ASKBTN_YES:
                return True
            from xrefer.gui.settings import XReferSettingsDialog
            XReferSettingsDialog().exec_()
            if not getattr(_obj, "llm_lookups", False):
                log("LLM still not configured — cluster analysis not run")
                return True

        try:
            idaapi.show_wait_box("HIDECANCEL\n")
            log("Running Cluster Analysis on all function clusters (LLM cache bypassed)...")

            # Run clustering for all non-excluded artifact functions
            xrefer_obj = plugin_instance.xrefer_view.xrefer_obj
            plugin_instance.xrefer_view.state_machine.clear_cluster_history()
            xrefer_obj.cluster_all_non_excluded(force_no_cache=True)
            # Cluster membership and labels may have changed wholesale; drop
            # the view's cached cluster layouts and func->cluster map.
            plugin_instance.xrefer_view._invalidate_cluster_render_caches()

            # Update view if in cluster-related view
            current_state = plugin_instance.xrefer_view.state_machine.current_state
            if current_state in (plugin_instance.xrefer_view.state_machine.clusters, plugin_instance.xrefer_view.state_machine.cluster_graphs):
                plugin_instance.xrefer_view.update(True)

            if getattr(xrefer_obj, "cluster_token_budget_exceeded", None):
                log("Cluster analysis skipped — request exceeds the model's context window")
            elif getattr(xrefer_obj, "cluster_analysis_failure", None):
                _f = xrefer_obj.cluster_analysis_failure
                log("Cluster analysis cancelled" if _f.get("cancelled")
                    else "Cluster analysis completed partially" if _f.get("severity") == "partial"
                    else "Cluster analysis FAILED")
            else:
                log("Cluster analysis complete")
            idaapi.hide_wait_box()

            # Surface what actually happened. After hide_wait_box so the
            # modal isn't stacked under the wait box: the budget bar if the
            # run was blocked for window overflow, or the failure dialog if
            # it failed / completed partially (mutually exclusive flags).
            from xrefer.gui.token_estimate import show_budget_block_if_pending, show_cluster_failure_if_pending
            show_budget_block_if_pending(xrefer_obj)
            show_cluster_failure_if_pending(xrefer_obj)
            return True

        except Exception as e:
            idaapi.hide_wait_box()
            log(f"[-] Error during full cluster analysis: {str(e)}")
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

                scaled_pixmap = pixmap.scaled(target_width, target_height, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
                logo_label.setPixmap(scaled_pixmap)
                logo_label.setFixedSize(target_width, target_height)
            else:
                log("Failed to load logo pixmap")
                logo_label.setText("XR")
        except Exception as e:
            log(f"[-] Error loading logo: {str(e)}")
            logo_label.setText("XR")

        # Center the logo
        logo_layout.addStretch(1)
        logo_layout.addWidget(logo_label)
        logo_layout.addStretch(1)

        return logo_container

    def activate(self, ctx: Any) -> bool:
        """
        Handle about dialog action.

        Creates and shows modal About dialog that matches the
        XReferSettingsDialog aesthetic: palette-aware QSS (accent
        color, card backgrounds, heading typography), separator
        above the button row, right-aligned primary Close button.
        """
        # Pull xrefer's real package version so the dialog stays
        # honest as releases ship. Falls back to a string literal
        # if the import dance fails for any reason.
        try:
            from xrefer import __version__ as xrefer_version
        except Exception:
            xrefer_version = "unknown"

        # Reuse the settings dialog's palette-aware stylesheet so
        # the About dialog inherits the same accent color, card
        # backgrounds, focus borders, etc. — a single source of
        # truth for the plugin's visual language.
        from xrefer.gui.settings import _build_dialog_qss

        dialog = QtWidgets.QDialog()
        dialog.setWindowTitle("About XRefer")
        # Sized to just fit the content (logo + 4 lines + button bar)
        # with a small amount of breathing room. Earlier 420px height
        # left ~200px of empty space under FLARE.
        dialog.setFixedSize(400, 320)
        dialog.setStyleSheet(_build_dialog_qss())

        # Center on screen
        frame_geom = dialog.frameGeometry()
        center_point = QtWidgets.QApplication.primaryScreen().availableGeometry().center()
        frame_geom.moveCenter(center_point)
        dialog.move(frame_geom.topLeft())

        # Root: zero-margin so the separator+button-bar can sit
        # flush at the bottom edge, matching settings dialog.
        root = QtWidgets.QVBoxLayout(dialog)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Content area ────────────────────────────────────────
        content_widget = QtWidgets.QWidget()
        content = QtWidgets.QVBoxLayout(content_widget)
        # Tight padding all around — the goal is to fit the content
        # compactly. The dialog is sized to match, so no extra
        # ``addSpacing()`` calls between widgets either; everything
        # rides on the uniform ``setSpacing()`` below.
        content.setContentsMargins(20, 16, 20, 10)
        content.setSpacing(5)

        # Logo
        content.addWidget(self._create_logo_widget())

        # Title + version pair, rendered as a SINGLE QLabel with HTML
        # ``<br>`` between the two lines. We use one QLabel rather
        # than two-stacked-in-a-tight-VBox because Qt's layout system
        # enforces a style-driven minimum vertical spacing between
        # widgets that overrides ``QLayout.setSpacing()`` on at least
        # some IDA + macOS + Qt-style combinations (verified
        # empirically — setting setSpacing(2) on a sub-layout had
        # zero visible effect inside IDA, even though it worked in a
        # standalone test harness). Inline HTML sidesteps that path:
        # the line spacing between ``<br>``-separated lines is the
        # font's natural line-height, which renders tighter than
        # the inter-widget gap Qt enforces between layout items.
        #
        # ``setPointSize(11)`` keeps the label readable without
        # being as large as IDA's default ~13pt font, which made
        # the dialog feel bigger than necessary.
        _title_font = QtGui.QFont()
        _title_font.setPointSize(11)

        # Soft/muted text color used for the secondary "Version" line
        # and the "DEVELOPED BY" caption. Matches the ``soft_text``
        # shade used by the settings dialog's QSS for read-only path
        # text + group-box titles: a 72% WindowText / 28% Window
        # blend, which renders clearly readable but visibly recessive
        # so the eye lands on the primary title and FLARE name first.
        _pal = QtWidgets.QApplication.palette()
        _w = _pal.color(QtGui.QPalette.Window)
        _t = _pal.color(QtGui.QPalette.WindowText)
        muted = QtGui.QColor(
            int(_t.red() * 0.72 + _w.red() * 0.28),
            int(_t.green() * 0.72 + _w.green() * 0.28),
            int(_t.blue() * 0.72 + _w.blue() * 0.28),
        ).name()

        title_label = QtWidgets.QLabel(
            f'<div align="center">'
            f'<span style="font-size: 13pt; font-weight: 700; letter-spacing: 0.3px;">'
            f'XRefer: The Binary Navigator'
            f'</span><br>'
            f'<span style="font-size: 2pt;">&nbsp;</span><br>'
            f'<span style="color: {muted};">Version {xrefer_version}</span>'
            f'</div>'
        )
        title_label.setTextFormat(QtCore.Qt.RichText)
        title_label.setAlignment(QtCore.Qt.AlignCenter)
        title_label.setFont(_title_font)
        content.addWidget(title_label)

        # "DEVELOPED BY" caption + FLARE name. The caption gets the
        # classic small-uppercase-letterspaced treatment used for
        # section labels (same shape as the group titles in the
        # settings dialog) so it reads as a *label* for FLARE rather
        # than as a peer line. FLARE itself stays bold + letter-
        # spaced like the title.
        attribution_label = QtWidgets.QLabel(
            f'<div align="center">'
            f'<span style="font-size: 8pt; letter-spacing: 1.2px; color: {muted};">'
            f'DEVELOPED BY'
            f'</span><br>'
            f'<span style="font-size: 2pt;">&nbsp;</span><br>'
            f'<span style="font-weight: 700; letter-spacing: 0.3px;">'
            f'FLARE'
            f'</span>'
            f'</div>'
        )
        attribution_label.setTextFormat(QtCore.Qt.RichText)
        attribution_label.setAlignment(QtCore.Qt.AlignCenter)
        attribution_label.setFont(_title_font)
        content.addWidget(attribution_label)

        # No addStretch() — the dialog is sized to fit the content
        # naturally. A stretch here would reopen the empty-space
        # gap the height reduction was meant to close.

        root.addWidget(content_widget, 1)

        # ── Separator + bottom button bar (matches settings) ────
        sep = QtWidgets.QFrame()
        sep.setFrameShape(QtWidgets.QFrame.HLine)
        sep.setProperty("separator", True)
        root.addWidget(sep)

        button_bar = QtWidgets.QHBoxLayout()
        button_bar.setContentsMargins(16, 12, 16, 20)
        button_bar.setSpacing(8)
        button_bar.addStretch()

        close_button = QtWidgets.QPushButton("Close")
        close_button.setProperty("primary", True)
        close_button.setDefault(True)  # Enter dismisses
        close_button.clicked.connect(dialog.accept)
        button_bar.addWidget(close_button)

        root.addLayout(button_bar)

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

        msg = "Default entrypoint selected for primary analysis"

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


class CopySelectedArtifactsHandler(idaapi.action_handler_t):
    """Copy every selected artifact (across ALL functions) to the clipboard.

    B / D and the ribbon chip consume selections per current function; this
    is the aggregate view of the selection set — type-prefixed, with the
    selecting function's address — for pasting into notes or a report.
    """

    _TYPE_NAMES = {1: "lib", 2: "import", 3: "string", 4: "capa"}

    def activate(self, ctx: Any) -> bool:
        from xrefer.plugin import plugin_instance

        try:
            view = plugin_instance.xrefer_view
            if view is None or getattr(view, "xrefer_obj", None) is None:
                log("XRefer analysis not loaded")
                return False
            obj = view.xrefer_obj
            lines = []
            for func_ea in sorted(getattr(obj, "selected_refs", {}) or {}):
                for e_index in sorted(obj.selected_refs[func_ea]):
                    try:
                        entity = obj.entities[e_index]
                    except (IndexError, TypeError):
                        continue
                    if isinstance(entity, tuple):
                        type_name = self._TYPE_NAMES.get(int(entity[2]), "artifact")
                        name = entity[1]
                    else:
                        type_name, name = "string", str(entity)
                    lines.append(f"{type_name}\t{name}\t0x{func_ea:x}")
            if not lines:
                log("No artifacts selected (double-click rows in the base view to select)")
                return False
            QtWidgets.QApplication.clipboard().setText("\n".join(lines))
            log(f"{len(lines)} selected artifact(s) copied to clipboard")
            return True
        except Exception as e:
            log(f"[-] Error copying selected artifacts: {str(e)}")
            return False

    def update(self, ctx: Any) -> int:
        return idaapi.AST_ENABLE_ALWAYS


class _CopyStringsHandlerBase(idaapi.action_handler_t):
    """Base for the right-click "Copy ... strings to clipboard" actions.

    Subclasses set ``category`` (forwarded to ``XRefer.collect_strings``)
    and ``noun`` (used in the status log). The classification itself
    lives in the backend-agnostic core layer; this only joins the
    results and pushes them onto the Qt clipboard.
    """

    category: str = "all"
    noun: str = "strings"

    def activate(self, ctx: Any) -> bool:
        from xrefer.plugin import plugin_instance

        try:
            view = plugin_instance.xrefer_view
            if view is None or getattr(view, "xrefer_obj", None) is None:
                log("XRefer analysis not loaded")
                return False
            strings = view.xrefer_obj.collect_strings(self.category)
            if not strings:
                log(f"No {self.noun} available for copy")
                return False
            QtWidgets.QApplication.clipboard().setText("\n".join(strings))
            log(f"{len(strings)} {self.noun} copied to clipboard")
            return True
        except Exception as e:
            log(f"[-] Error copying strings to clipboard: {str(e)}")
            return False

    def update(self, ctx: Any) -> int:
        from xrefer.plugin import plugin_instance

        return idaapi.AST_ENABLE_ALWAYS if plugin_instance.xrefer_view else idaapi.AST_DISABLE


class CopyAllStringsHandler(_CopyStringsHandlerBase):
    category = "all"
    noun = "strings"


class CopyDirectStringsHandler(_CopyStringsHandlerBase):
    category = "direct"
    noun = "directly referenced strings"


class CopyDirectIndirectStringsHandler(_CopyStringsHandlerBase):
    category = "direct_indirect"
    noun = "directly/indirectly referenced strings"


class CopyOrphanStringsHandler(_CopyStringsHandlerBase):
    category = "orphan"
    noun = "orphan strings"


class CopyUncategorizedStringsHandler(_CopyStringsHandlerBase):
    category = "uncategorized"
    noun = "uncategorized strings"


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

        custom_ep: int = idc.choose_func("[XRefer] Choose an entrypoint function for analysis")
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
            current_func = ida_funcs.get_func(current_ea)
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

        if plugin_instance.xrefer_view and plugin_instance.xrefer_view.xrefer_obj.lang and plugin_instance.xrefer_view.xrefer_obj.lang.id == "lang_rust":
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
            idaapi.show_wait_box("HIDECANCEL\nRenaming cluster functions...")
            try:
                plugin_instance.xrefer_view.xrefer_obj.rename_cluster_functions()
            finally:
                idaapi.hide_wait_box()
            return True
        except Exception as e:
            log(f"[-] Error during cluster-based renaming: {str(e)}")
            import traceback

            traceback.print_exc()
            return False

    def update(self, ctx: Any) -> int:
        from xrefer.plugin import plugin_instance

        if plugin_instance.xrefer_view and plugin_instance.xrefer_view.xrefer_obj.clusters:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE


class OrganizeFoldersHandler(idaapi.action_handler_t):
    """Organize the Functions window into library/user folders.

    Applies ``XRefer.compute_function_folders()`` to IDA's function dirtree:
    FUNC_LIB / library-cluster functions go under ``/Library``, user-cluster
    functions under ``/User`` (cluster-nested), multi-cluster functions at the
    bare origin root, and everything unclassified is left at the IDB root.
    Re-runnable and reversible (see RemoveAllFoldersHandler). Enabled only once
    cluster *analysis* data exists, since the verdict needs the LLM's
    is_library + labels (not just the structural clusters).
    """

    def activate(self, ctx: Any) -> bool:
        from xrefer.gui.foldering import apply_function_folders
        from xrefer.plugin import plugin_instance

        try:
            idaapi.show_wait_box("HIDECANCEL\nOrganizing functions into folders...")
            try:
                apply_function_folders(plugin_instance.xrefer_view.xrefer_obj)
            finally:
                idaapi.hide_wait_box()
            return True
        except Exception as e:
            log(f"[-] Error organizing functions into folders: {str(e)}")
            import traceback

            traceback.print_exc()
            return False

    def update(self, ctx: Any) -> int:
        from xrefer.plugin import plugin_instance

        view = plugin_instance.xrefer_view
        if view and view.xrefer_obj.clusters and view.xrefer_obj.cluster_analysis:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE


class RemoveAllFoldersHandler(idaapi.action_handler_t):
    """Flatten the entire Functions-window folder tree back to the root.

    Broader than xrefer's own folders on purpose: xrefer's roots use the
    generic names Library/User and can't be reliably told apart from folders
    the user made by hand, so the honest "reset to a flat list" removes them
    all. Reverses OrganizeFoldersHandler (and any other foldering)."""

    def activate(self, ctx: Any) -> bool:
        from xrefer.gui.foldering import remove_all_folders

        try:
            idaapi.show_wait_box("HIDECANCEL\nRemoving all function folders...")
            try:
                remove_all_folders()
            finally:
                idaapi.hide_wait_box()
            return True
        except Exception as e:
            log(f"[-] Error removing function folders: {str(e)}")
            import traceback

            traceback.print_exc()
            return False

    def update(self, ctx: Any) -> int:
        from xrefer.plugin import plugin_instance

        if plugin_instance.xrefer_view:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE


class ViewAttackMatrixHandler(idaapi.action_handler_t):
    """Open the ATT&CK matrix heat-grid popup (Navigator-style) for the current
    clusters' MITRE ATT&CK mappings.

    Delegates to ``XReferView.open_attack_matrix_popup`` (the same path the
    in-view ``G`` key uses), so the menu/context entry and the key stay in
    sync. Enabled only once cluster analysis has produced at least one mapped
    technique (a non-empty matrix), so the action greys out when there's
    nothing to render.
    """

    def activate(self, ctx: Any) -> bool:
        from xrefer.plugin import plugin_instance

        view = plugin_instance.xrefer_view
        if not (view and view.xrefer_obj and view.xrefer_obj.clusters
                and view.xrefer_obj.cluster_analysis):
            log("[-] ATT&CK matrix: run cluster analysis first.")
            return False
        try:
            view.open_attack_matrix_popup()
            return True
        except Exception as e:
            log(f"[-] Error opening ATT&CK matrix: {str(e)}")
            return False

    def update(self, ctx: Any) -> int:
        from xrefer.core.mitre import has_any_techniques
        from xrefer.plugin import plugin_instance

        view = plugin_instance.xrefer_view
        if (view and view.xrefer_obj and view.xrefer_obj.clusters
                and view.xrefer_obj.cluster_analysis
                and has_any_techniques(view.xrefer_obj.cluster_analysis)):
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE


class EstimateClusterTokensHandler(idaapi.action_handler_t):
    """Show a pre-flight token-budget estimate for cluster analysis.

    Renders the real stage-1 DSPy request for the current clusters,
    counts request + max-response tokens against the configured model's
    context window, and shows a budget-bar dialog that warns when the
    projected total approaches or exceeds the window. Read-only: makes no
    LLM call and needs no API key. Enabled once clustering has produced
    clusters (the analysis verdict isn't required — this is meant to be
    run *before* analysis to decide whether the request will fit).
    """

    def activate(self, ctx: Any) -> bool:
        from xrefer.gui.settings import _curated_llm_models
        from xrefer.gui.token_estimate import show_token_estimate_dialog
        from xrefer.llm.cluster_analyzer import ClusterAnalyzer
        from xrefer.plugin import plugin_instance

        view = plugin_instance.xrefer_view
        if not (view and view.xrefer_obj and view.xrefer_obj.clusters):
            log("[-] Token estimate: no clusters yet — run cluster analysis first.")
            return False

        try:
            idaapi.show_wait_box("HIDECANCEL\nEstimating token usage...")
            try:
                xobj = view.xrefer_obj
                # Build the model-independent requests ONCE (full + hierarchical
                # shapes); the dialog's model dropdown re-estimates per model
                # cheaply, picking the shape that model would actually run under
                # (local always hierarchical; commercial full-if-it-fits).
                full_ctx = ClusterAnalyzer.build_estimate_context(xobj.clusters, xobj)
                hier_ctx = ClusterAnalyzer.build_hier_estimate_context(xobj.clusters, xobj)
                try:
                    _mode_setting = xobj.settings.get("analysis_options", {}).get("cluster_context_mode", "auto")
                except Exception:
                    _mode_setting = "auto"

                def _estimate_for(m):
                    from xrefer.llm.cluster_analyzer import exceeds_context_window
                    from xrefer.llm.ollama import is_ollama_model
                    ms = (_mode_setting or "auto").strip().lower()
                    if ms == "hierarchical" or (ms == "auto" and is_ollama_model(m)):
                        return ClusterAnalyzer.estimate_for_model(hier_ctx, m)
                    fe = ClusterAnalyzer.estimate_for_model(full_ctx, m)
                    if ms == "full" or not exceeds_context_window(fe):
                        return fe
                    return ClusterAnalyzer.estimate_for_model(hier_ctx, m)
                # Current model = the configured one (current_config or settings).
                current_model = None
                cfg = ClusterAnalyzer.current_config
                if cfg and getattr(cfg, "model_id", None):
                    current_model = cfg.model_id
                if not current_model:
                    try:
                        current_model = xobj.settings.get("llm_model_id") or None
                    except Exception:
                        current_model = None
                # Curated dropdown list; keep the current model present + first
                # so the initial render matches the selection, and default to
                # the first model when nothing is configured yet.
                models = _curated_llm_models()
                if current_model and current_model not in models:
                    models = [current_model] + models
                if not current_model and models:
                    current_model = models[0]
                initial = _estimate_for(current_model)
            finally:
                idaapi.hide_wait_box()
            show_token_estimate_dialog(
                initial,
                recompute=_estimate_for,
                models=models,
                current_model=current_model,
            )
            return True
        except Exception as e:
            log(f"[-] Error estimating token usage: {str(e)}")
            import traceback

            traceback.print_exc()
            return False

    def update(self, ctx: Any) -> int:
        from xrefer.plugin import plugin_instance

        view = plugin_instance.xrefer_view
        if view and view.xrefer_obj and view.xrefer_obj.clusters:
            return idaapi.AST_ENABLE_ALWAYS
        else:
            return idaapi.AST_DISABLE


class GenerateHtmlReportHandler(idaapi.action_handler_t):
    """
    Handler for generating the standalone HTML report.

    Enabled only once cluster analysis has produced both clusters and
    cluster_analysis (matches the gating used by the auto-trigger in
    XRefer.analyze_clusters). Writes the report to <binary_path>_report.html
    and logs the destination via the IDA Output window.
    """

    def activate(self, ctx: Any) -> bool:
        from xrefer.plugin import plugin_instance

        try:
            plugin_instance.xrefer_view.xrefer_obj.generate_html_report()
            return True
        except Exception as e:
            log(f"[-] Error generating HTML report: {str(e)}")
            import traceback

            traceback.print_exc()
            return False

    def update(self, ctx: Any) -> int:
        from xrefer.plugin import plugin_instance

        if (
            plugin_instance.xrefer_view
            and plugin_instance.xrefer_view.xrefer_obj.clusters
            and plugin_instance.xrefer_view.xrefer_obj.cluster_analysis
        ):
            return idaapi.AST_ENABLE_ALWAYS
        return idaapi.AST_DISABLE


class GenerateAgentAnatomyHandler(idaapi.action_handler_t):
    """
    Export the agent-facing "binary anatomy" JSON (single file) to
    <binary_path>_anatomy.json, for an external malware-analysis agent
    (radare2 / format_binary). Works with or without the LLM layer: if cluster
    analysis has not run, a valid static-only map is still emitted.
    """

    def activate(self, ctx: Any) -> bool:
        from xrefer.plugin import plugin_instance

        try:
            from xrefer.core.agent_map import export_anatomy

            xo = plugin_instance.xrefer_view.xrefer_obj
            out_path = f"{xo._backend.path}_anatomy.json"
            export_anatomy(xo, out_path)
            log(f"[+] Agent anatomy written to: {out_path}")
            return True
        except Exception as e:
            log(f"[-] Error exporting agent anatomy: {str(e)}")
            import traceback

            traceback.print_exc()
            return False

    def update(self, ctx: Any) -> int:
        from xrefer.plugin import plugin_instance

        if plugin_instance.xrefer_view and getattr(plugin_instance.xrefer_view, "xrefer_obj", None):
            return idaapi.AST_ENABLE_ALWAYS
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

        Creates a file named <sample>_indirect_calls.txt containing
        all identified indirect call sites.

        Args:
            ctx (Any): IDA context (unused)

        Returns:
            bool: True after dump is complete
        """
        path: str = f"{idaapi.get_input_file_path()}_indirect_calls.txt"
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
        """Show the XRefer window, rebuilding the view from scratch.

        ``view.create()`` calls ``view.cleanup()`` first, which already
        tears down any prior dock widget, qt widget, event filters, etc.
        Don't reach into the view's internal Qt state from here.
        """
        from xrefer.plugin import plugin_instance

        if plugin_instance.xrefer_view:
            plugin_instance.xrefer_view.create()
            return idaapi.AST_ENABLE_ALWAYS
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
