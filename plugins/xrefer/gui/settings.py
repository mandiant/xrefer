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

import copy
import os
import re
from typing import TYPE_CHECKING, Dict, List

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QFontMetrics
from PyQt5.QtWidgets import (QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QMessageBox,
                             QPushButton, QScrollArea, QSizePolicy, QSpinBox, QTabWidget, QVBoxLayout, QWidget)

from xrefer.core.settings import XReferSettingsManager

if TYPE_CHECKING:
    from xrefer.core.settings import ExclusionData

# Constants
TAB_WIDTH = 550
DIALOG_WIDTH = 1100
DIALOG_HEIGHT = 650
BUTTON_SIZE = 24
MAX_WILDCARD_MATCHES = 10

# File filter constants
FILE_FILTERS = {
    "trace": "Zip Files (*.zip);;JSON Files (*.json);;Tag Files (*.tag);;All Files (*.*)",
    "capa": "JSON Files (*.json);;All Files (*.*)",
    "analysis": "XRefer Files (*.xrefer);;All Files (*.*)",
    "exclusions": "JSON Files (*.json);;All Files (*.*)",
    "default": "All Files (*.*)",
}

# Available LLM models
LLM_MODELS = {
    "google": [
        "gemini-flash-latest",
        "gemini-2.5-flash-preview-05-20",
        "gemini-2.5-pro",
        "gemini-2.5-pro-preview-05-06",
        "gemini-2.5-pro-preview-06-05",
    ],
    "openai": ["gpt-5", "gpt-5-mini", "gpt-5-nano"]  # openai models have much smaller (128K) context windows, that are not ideal for cluster analysis of large binaries. disabling these models for the time being
}


class CustomTabWidget(QTabWidget):
    """
    Customized QTabWidget with equal width tabs.

    Provides a tab widget with fixed-width tabs and custom styling for the
    XRefer settings dialog.

    Class Attributes:
        TAB_WIDTH (int): Fixed width for each tab (550px)
    """

    def __init__(self):
        super().__init__()
        self.setUsesScrollButtons(False)
        self.tabBar().setExpanding(True)

        self.setStyleSheet("""
            QTabWidget::pane {
                border: none;
                top: 1px;
            }
            QTabWidget::tab-bar {
                alignment: left;
                left: 0px;
            }
            QTabBar::tab {
                padding: 4px 0px;  /* Removed horizontal padding */
                min-width: 550px;  /* Exactly half of 1100px */
                max-width: 550px;  /* Force exact width */
                margin: 1px;       /* Remove margins */
            }
        """)


class ReadOnlyLineEdit(QLineEdit):
    """
    Custom QLineEdit that allows scrolling in read-only mode.

    Modifies standard QLineEdit behavior to maintain text selection and scrolling
    capabilities while preventing edits when in read-only mode.

    Attributes:
        _read_only (bool): Internal read-only state tracking
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._read_only = False

    def setReadOnly(self, state):
        self._read_only = state
        super().setReadOnly(state)
        self.setCursor(Qt.IBeamCursor)

    def mouseDoubleClickEvent(self, event):
        if not self._read_only:
            super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.setCursor(Qt.IBeamCursor)


class ExclusionsList(QFrame):
    """
    Custom list widget for managing excluded items.

    Provides interface for adding/removing exclusions entries with wildcard support
    and duplicate checking.

    Attributes:
        title (str): Title of the exclusions category
        entity_type (int): Type identifier for entities (1=libs, 2=APIs, etc.)
        list_widget (QListWidget): Widget containing exclusions entries
        remove_btn (QPushButton): Button for removing selected entries
    """

    def __init__(self, title, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Header with title and buttons
        header = QHBoxLayout()
        header.addWidget(QLabel(title))
        header.addStretch()

        add_btn = QPushButton("+")
        add_btn.setFixedSize(24, 24)
        add_btn.setToolTip(f"Add new {title}")

        self.remove_btn = QPushButton("-")  # Make remove_btn an instance variable
        self.remove_btn.setFixedSize(24, 24)
        self.remove_btn.setToolTip(f"Remove selected {title}")
        self.remove_btn.setEnabled(False)  # Initially disabled

        header.addWidget(add_btn)
        header.addWidget(self.remove_btn)
        layout.addLayout(header)

        # List widget
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.ExtendedSelection)
        self.list_widget.itemSelectionChanged.connect(self.update_remove_button)
        layout.addWidget(self.list_widget)

        # Connect signals
        add_btn.clicked.connect(self.add_item)
        self.remove_btn.clicked.connect(self.remove_selected)

        # Store title and determine entity type based on title
        self.title = title
        if "API" in title:
            self.entity_type = 2  # APIs
        elif "Lib" in title:
            self.entity_type = 1  # Libraries
        elif "String" in title:
            self.entity_type = 3  # Strings
        elif "Capa" in title:
            self.entity_type = 4  # Capa
        else:
            self.entity_type = None

    def get_entities_for_type(self, xrefer) -> List[str]:
        """
        Get list of entities matching this exclusions's type.

        Args:
            xrefer: XRefer object containing known entities

        Returns:
            List[str]: List of entity names that match this exclusions's type
        """
        entities = []

        if not self.entity_type:
            return entities

        for entity in xrefer.entities:
            if entity[2] != self.entity_type:  # Check entity type matches
                continue

            if self.entity_type == 2:  # APIs
                # For APIs, only match the name part after module
                name = entity[1].split(".")[-1]
            else:
                name = entity[1]

            entities.append(name)

        return entities

    def expand_wildcard_pattern(self, pattern: str) -> List[str]:
        """
        Expand a wildcard pattern to matching entity names.

        Converts wildcard pattern to regex and finds all matching entities,
        with confirmation for large match sets.

        Args:
            pattern (str): Pattern string with optional * wildcards

        Returns:
            List[str]: List of entity names matching the pattern
        """
        # Import here to avoid circular imports
        from xrefer.plugin import plugin_instance

        if not plugin_instance or not plugin_instance.xrefer_view:
            return [pattern]

        xrefer = plugin_instance.xrefer_view.xrefer_obj

        # Convert pattern to regex pattern
        regex_pattern = pattern.replace("*", ".*")
        if not pattern.startswith("*"):
            regex_pattern = "^" + regex_pattern
        if not pattern.endswith("*"):
            regex_pattern = regex_pattern + "$"

        try:
            matcher = re.compile(regex_pattern, re.IGNORECASE)

            # Get entities for this specific type
            all_entities = self.get_entities_for_type(xrefer)

            # Find matches
            matches = sorted(set(item for item in all_entities if matcher.search(item)))

            if not matches:
                QMessageBox.information(self, "No Matches", f"No matches found for pattern '{pattern}'", QMessageBox.Ok)
                return []

            # If there are a lot of matches, ask for confirmation
            if len(matches) > 10:
                msg = f"Pattern '{pattern}' matches {len(matches)} items.\n\nFirst 10 matches:\n" + "\n".join(f"- {m}" for m in matches[:10]) + "\n\nDo you want to add all matches?"

                confirm = QMessageBox.question(self, "Confirm Addition", msg, QMessageBox.Yes | QMessageBox.No)

                if confirm != QMessageBox.Yes:
                    return []

            return matches

        except re.error as e:
            QMessageBox.warning(self, "Invalid Pattern", f"Invalid wildcard pattern: {str(e)}", QMessageBox.Ok)
            return []

    def _item_exists(self, text: str) -> bool:
        """
        Check if item already exists in exclusions.

        Performs case-insensitive check for duplicate entries.

        Args:
            text (str): Text to check for duplicates

        Returns:
            bool: True if item exists (case-insensitive), False otherwise
        """
        text = text.lower()
        for i in range(self.list_widget.count()):
            if self.list_widget.item(i).text().lower() == text:
                return True
        return False

    def add_item(self):
        """Add new item(s) with wildcard support and duplicate checking"""
        text, ok = QInputDialog.getText(self, "Add Entry", "Enter new entry (use * for wildcards):")

        if not ok or not text.strip():
            return

        text = text.strip()

        # Check for wildcards
        if "*" in text:
            matches = self.expand_wildcard_pattern(text)
            for match in matches:
                if not self._item_exists(match):
                    self.list_widget.addItem(match)
        else:
            if self._item_exists(text):
                QMessageBox.warning(self, "Duplicate Entry", f"The entry '{text}' already exists in the list.", QMessageBox.Ok)
                return

            self.list_widget.addItem(text)

        # Sort items after addition
        self.sort_items()

    def sort_items(self) -> None:
        """
        Sort exclusions items alphabetically.

        Clears and repopulates list widget with sorted items.
        """
        items = [self.list_widget.item(i).text() for i in range(self.list_widget.count())]
        items.sort()
        self.list_widget.clear()
        self.list_widget.addItems(items)

    def update_remove_button(self):
        """Update remove button enabled state based on selection"""
        self.remove_btn.setEnabled(bool(self.list_widget.selectedItems()))

    def remove_selected(self):
        """Remove selected items and auto-select next item"""
        rows_to_remove = []
        for item in self.list_widget.selectedItems():
            rows_to_remove.append(self.list_widget.row(item))

        if not rows_to_remove:
            return

        # Sort rows in descending order to remove from bottom up
        rows_to_remove.sort(reverse=True)

        # Get the row to select after removal
        next_row = rows_to_remove[-1]  # Get smallest row number (will be our anchor point)

        # Remove items
        for row in rows_to_remove:
            self.list_widget.takeItem(row)

        # Select next item
        new_total = self.list_widget.count()
        if new_total > 0:
            # If we removed the last item(s), select the new last item
            if next_row >= new_total:
                next_row = new_total - 1
            # Select and ensure visible
            self.list_widget.setCurrentRow(next_row)
            self.list_widget.scrollToItem(self.list_widget.item(next_row))

    def get_items(self) -> List[str]:
        """
        Get all items in the exclusions.

        Returns:
            List[str]: All current exclusions entries
        """
        return [self.list_widget.item(i).text() for i in range(self.list_widget.count())]

    def set_items(self, items: List[str]) -> None:
        """
        Replace all exclusions items with new set.

        Args:
            items (List[str]): New items to populate exclusions with
        """
        self.list_widget.clear()
        self.list_widget.addItems(sorted(items))  # Add items in sorted order


class XReferSettingsDialog(QDialog):
    """
    Main dialog for configuring XRefer settings.

    Provides interface for modifying all XRefer settings including paths,
    exclusions, LLM configuration, and analysis options.

    Attributes:
        settings_manager (XReferSettingsManager): Manager for persisting settings
        settings (Dict): Current settings dictionary
        exclusions (Dict): Current exclusions dictionary
        original_exclusions (Dict): Copy of exclusions for change detection
        llm_models (Dict[str, List[str]]): Available models for each LLM provider
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings_manager = XReferSettingsManager()
        self.settings = self.settings_manager.load_settings()
        self.exclusions = self.settings_manager.load_exclusions()
        self.original_exclusions = copy.deepcopy(self.exclusions)

        self.llm_models = LLM_MODELS

        self.setFixedSize(DIALOG_WIDTH, DIALOG_HEIGHT)
        self._center_on_screen()
        self.initUI()

    def _center_on_screen(self) -> None:
        """Center dialog on screen"""
        frame_geom = self.frameGeometry()
        center_point = QApplication.primaryScreen().availableGeometry().center()
        frame_geom.moveCenter(center_point)
        self.move(frame_geom.topLeft())

    def showEvent(self, event):
        """Re-center dialog when shown"""
        super().showEvent(event)
        frame_geom = self.frameGeometry()
        screen_center = QApplication.primaryScreen().geometry().center()
        frame_geom.moveCenter(screen_center)
        self.move(frame_geom.topLeft())

    def initUI(self):
        self.setWindowTitle("Configure XRefer")
        self.setGeometry(300, 300, 1100, 600)

        layout = QVBoxLayout(self)

        # Create tab widget
        tabs = CustomTabWidget()
        general_tab = QWidget()
        exclusion_tab = QWidget()
        tabs.addTab(general_tab, "General")
        tabs.addTab(exclusion_tab, "Exclusions")

        self.setup_general_tab(general_tab)
        self.setup_exclusion_tab(exclusion_tab)

        layout.addWidget(tabs)

        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.save_settings)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

    def setup_general_tab(self, tab) -> None:
        """
        Initialize the general settings tab.

        Sets up UI elements for LLM configuration, paths, and general options.

        Args:
            tab: Tab widget to populate with settings controls
        """
        layout = QVBoxLayout(tab)

        # Options group
        options_group = QGroupBox("Options")
        options_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        options_layout = QVBoxLayout(options_group)

        # Checkboxes
        self.llm_checkbox = QCheckBox("LLM Lookups")
        self.llm_checkbox.setToolTip("Enable llm-based categorization of APIs and libraries")
        self.llm_checkbox.setChecked(self.settings["llm_lookups"])
        self.llm_checkbox.stateChanged.connect(self.toggle_llm_options)

        # LLM Options
        llm_grid = QGridLayout()

        self.llm_origin_combo = QComboBox()
        # self.llm_origin_combo.addItems(["google", "openai"])
        self.llm_origin_combo.addItems(["google"])
        self.llm_origin_combo.setCurrentText(self.settings["llm_origin"])
        self.llm_origin_combo.setEnabled(self.settings["llm_lookups"])
        self.llm_origin_combo.setToolTip("Select LLM provider")
        self.llm_origin_combo.currentTextChanged.connect(self.update_model_list)

        self.llm_model_combo = QComboBox()
        self.update_model_list(self.settings["llm_origin"])
        self.llm_model_combo.setCurrentText(self.settings["llm_model"])
        self.llm_model_combo.setEnabled(self.settings["llm_lookups"])
        self.llm_model_combo.setToolTip("Select the specific LLM model to use")

        self.api_key_edit = QLineEdit(self.settings["api_key"])
        self.api_key_edit.setEnabled(self.settings["llm_lookups"])
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        self.api_key_edit.setToolTip("API key for the selected LLM provider")

        llm_grid.addWidget(QLabel("LLM Origin:"), 0, 0)
        llm_grid.addWidget(self.llm_origin_combo, 0, 1)
        llm_grid.addWidget(QLabel("LLM Model:"), 1, 0)
        llm_grid.addWidget(self.llm_model_combo, 1, 1)
        llm_grid.addWidget(QLabel("API Key:"), 2, 0)
        llm_grid.addWidget(self.api_key_edit, 2, 1)

        options_layout.addWidget(self.llm_checkbox)
        options_layout.addLayout(llm_grid)

        self.git_checkbox = QCheckBox("Enable Git lookups for strings")
        self.git_checkbox.setToolTip("Enable Git repository-based string categorization")
        self.git_checkbox.setChecked(self.settings["git_lookups"])

        self.prompt_checkbox = QCheckBox("Disable prompts for missing API trace and Capa files")
        self.prompt_checkbox.setToolTip("Disable prompts when Capa results or API trace files are missing")
        self.prompt_checkbox.setChecked(self.settings["suppress_notifications"])

        options_layout.addWidget(self.git_checkbox)
        options_layout.addWidget(self.prompt_checkbox)
        layout.addWidget(options_group)

        # Add Display Options group
        display_group = QGroupBox("Display Options")
        display_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        display_layout = QGridLayout(display_group)
        display_layout.setHorizontalSpacing(50)  # Space between columns

        # Left column options
        self.auto_size_graphs = QCheckBox("Enable auto-resizing for graphs")
        self.auto_size_graphs.setToolTip("Automatically resize view when displaying graphs and clusters")
        self.auto_size_graphs.setChecked(self.settings["display_options"]["auto_size_graphs"])

        self.hide_llm_disclaimer = QCheckBox("Hide LLM disclaimers")
        self.hide_llm_disclaimer.setToolTip("Hide disclaimers about LLM-based analysis in views")
        self.hide_llm_disclaimer.setChecked(self.settings["display_options"]["hide_llm_disclaimer"])

        # Right column options
        self.show_help_banner = QCheckBox("Show help banner")
        self.show_help_banner.setToolTip("Show help banner with keyboard shortcuts at top of views")
        self.show_help_banner.setChecked(self.settings["display_options"]["show_help_banner"])

        # Panel width layout for right column
        width_layout = QHBoxLayout()
        width_layout.addWidget(QLabel("Default Panel Width: "))
        self.panel_width_spin = QSpinBox()
        self.panel_width_spin.setRange(400, 2000)  # Reasonable range for panel width
        self.panel_width_spin.setValue(self.settings["display_options"]["default_panel_width"])
        self.panel_width_spin.setSuffix(" px")
        self.panel_width_spin.setToolTip("Default width of the XRefer panel in pixels")
        width_layout.addWidget(self.panel_width_spin)
        width_layout.addStretch()

        # Create spacer columns to properly position the content
        display_layout.setColumnStretch(0, 1)  # Left content column
        display_layout.setColumnStretch(1, 1)  # Middle spacing
        display_layout.setColumnStretch(2, 1)  # Right content column
        display_layout.setColumnStretch(3, 1)  # Right margin

        # Add widgets to grid layout - using columns 0 and 2 to leave column 1 as spacing
        display_layout.addWidget(self.auto_size_graphs, 0, 0)
        display_layout.addWidget(self.hide_llm_disclaimer, 1, 0)
        display_layout.addWidget(self.show_help_banner, 0, 2)
        display_layout.addLayout(width_layout, 1, 2)

        layout.addWidget(display_group)

        # Paths group
        paths_group = QGroupBox("Paths")
        paths_group.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        paths_layout = QGridLayout(paths_group)

        # Path configuration
        path_configs = [("analysis", "Analysis Path"), ("trace", "API Trace Path"), ("capa", "Capa Results Path"), ("xrefs", "Indirect XRefs Path"), ("categories", "Categories Cache Path")]

        self.path_widgets = {}
        row = 0
        for path_type, label in path_configs:
            paths_layout.addWidget(QLabel(label), row, 0)

            # Path edit
            path_edit = ReadOnlyLineEdit(self.settings["paths"][path_type])
            font = path_edit.font()
            font.setPointSize(font.pointSize() - 1)
            path_edit.setFont(font)
            path_edit.setToolTip(f"Path for {label}")
            if self.settings["use_default_paths"][path_type]:
                path_edit.setReadOnly(True)
            paths_layout.addWidget(path_edit, row, 1)

            # Default checkbox
            default_check = QCheckBox("Default")
            default_check.setChecked(self.settings["use_default_paths"][path_type])
            default_check.setToolTip("Use default path")
            paths_layout.addWidget(default_check, row, 2)

            # Browse button
            browse_btn = QPushButton("Browse")
            browse_btn.setEnabled(not self.settings["use_default_paths"][path_type])
            browse_btn.setToolTip("Browse for file")
            paths_layout.addWidget(browse_btn, row, 3)

            self.path_widgets[path_type] = {"edit": path_edit, "check": default_check, "browse": browse_btn, "default_path": self.settings["paths"][path_type]}

            default_check.stateChanged.connect(lambda state, t=path_type: self.toggle_path_default(t, state))
            browse_btn.clicked.connect(lambda _, t=path_type: self.browse_path(t))

            row += 1

        layout.addWidget(paths_group)

    def setup_exclusion_tab(self, tab) -> None:
        """
        Initialize the exclusions management tab.

        Sets up UI elements for managing different types of exclusions.

        Args:
            tab: Tab widget to populate with exclusions controls
        """
        layout = QVBoxLayout(tab)

        # Enable Exclusions checkbox
        self.enable_exclusion_checkbox = QCheckBox("Enable Exclusions")
        self.enable_exclusion_checkbox.setToolTip("Enable/disable exclusions filtering of results")
        self.enable_exclusion_checkbox.setChecked(self.settings["enable_exclusions"])
        layout.addWidget(self.enable_exclusion_checkbox)

        # Path selection
        path_layout = QGridLayout()
        path_layout.addWidget(QLabel("Exclusions Path:"), 0, 0)

        self.exclusion_path_edit = ReadOnlyLineEdit(self.settings["paths"]["exclusions"])
        font = self.exclusion_path_edit.font()
        font.setPointSize(font.pointSize() - 1)
        self.exclusion_path_edit.setFont(font)
        self.exclusion_path_edit.setToolTip("Path to exclusions configuration file")
        if self.settings["use_default_paths"]["exclusions"]:
            self.exclusion_path_edit.setReadOnly(True)
        path_layout.addWidget(self.exclusion_path_edit, 0, 1)

        self.exclusion_default_check = QCheckBox("Default")
        self.exclusion_default_check.setToolTip("Use default exclusions path")
        self.exclusion_default_check.setChecked(self.settings["use_default_paths"]["exclusions"])
        path_layout.addWidget(self.exclusion_default_check, 0, 2)

        self.exclusion_browse_btn = QPushButton("Browse")
        self.exclusion_browse_btn.setToolTip("Browse for exclusions file")
        self.exclusion_browse_btn.setEnabled(not self.settings["use_default_paths"]["exclusions"])
        path_layout.addWidget(self.exclusion_browse_btn, 0, 3)

        layout.addLayout(path_layout)

        # Exclusions lists configuration
        exclusion_configs = [("apis", "API References"), ("libs", "Lib References"), ("strings", "String References"), ("capa", "Capa References")]

        lists_layout = QGridLayout()
        self.exclusion_lists = {}

        for col, (list_type, title) in enumerate(exclusion_configs):
            list_widget = ExclusionsList(title)
            list_widget.set_items(self.exclusions[list_type])
            lists_layout.addWidget(list_widget, 0, col)
            self.exclusion_lists[list_type] = list_widget

        layout.addLayout(lists_layout)

        # Connect exclusions path controls
        self.exclusion_default_check.stateChanged.connect(lambda state: self.toggle_path_default("exclusions", state))
        self.exclusion_browse_btn.clicked.connect(lambda: self.browse_path("exclusions"))

    def update_model_list(self, origin: str) -> None:
        """
        Update available models based on selected LLM provider.

        Args:
            origin (str): Selected provider ('google' or 'openai')
        """
        self.llm_model_combo.clear()
        self.llm_model_combo.addItems(self.llm_models[origin])

    def toggle_llm_options(self, state):
        """Toggle LLM-related controls based on checkbox state"""
        enabled = state == Qt.Checked
        self.llm_origin_combo.setEnabled(enabled)
        self.llm_model_combo.setEnabled(enabled)
        self.api_key_edit.setEnabled(enabled)

    def toggle_path_default(self, path_type, state):
        """Toggle path edit read-only state based on Default checkbox"""
        if path_type == "exclusions":
            self.exclusion_browse_btn.setEnabled(not state)
            self.exclusion_path_edit.setReadOnly(state)
            if state:
                self.exclusion_path_edit.setText(self.settings["paths"]["exclusions"])
            else:
                self.exclusion_path_edit.clear()
        else:
            widgets = self.path_widgets[path_type]
            widgets["browse"].setEnabled(not state)
            widgets["edit"].setReadOnly(state)
            if state:
                widgets["edit"].setText(widgets["default_path"])
            else:
                widgets["edit"].clear()

    def browse_path(self, path_type: str) -> None:
        """Handle browse button clicks for path selection"""
        file_filter = FILE_FILTERS.get(path_type, FILE_FILTERS["default"])
        dialog_title = f"Select {path_type.title()} File"

        path, _ = QFileDialog.getOpenFileName(self, dialog_title, "", file_filter)
        if not path:
            return

        if path_type == "exclusions":
            self.exclusion_path_edit.setText(path)
        else:
            self.path_widgets[path_type]["edit"].setText(path)

    def save_settings(self) -> None:
        """
        Save current settings and exclusions to disk.

        Updates both settings and exclusions files, handles exclusions state changes,
        and triggers necessary UI updates.
        """
        exclusions_was_enabled = self.settings.get("enable_exclusions", True)
        exclusions_now_enabled = self.enable_exclusion_checkbox.isChecked()
        exclusions_state_changed = exclusions_was_enabled != exclusions_now_enabled

        settings = {
            "llm_lookups": self.llm_checkbox.isChecked(),
            "git_lookups": self.git_checkbox.isChecked(),
            "suppress_notifications": self.prompt_checkbox.isChecked(),
            "llm_origin": self.llm_origin_combo.currentText(),
            "llm_model": self.llm_model_combo.currentText(),
            "api_key": self.api_key_edit.text(),
            "enable_exclusions": self.enable_exclusion_checkbox.isChecked(),
            # Add display options
            "display_options": {
                "auto_size_graphs": self.auto_size_graphs.isChecked(),
                "hide_llm_disclaimer": self.hide_llm_disclaimer.isChecked(),
                "show_help_banner": self.show_help_banner.isChecked(),
                "default_panel_width": self.panel_width_spin.value(),
            },
            "use_default_paths": {"exclusions": self.exclusion_default_check.isChecked()},
            "paths": {"exclusions": self.exclusion_path_edit.text()},
        }

        for path_type in self.path_widgets:
            settings["use_default_paths"][path_type] = self.path_widgets[path_type]["check"].isChecked()
            settings["paths"][path_type] = self.path_widgets[path_type]["edit"].text()

        # Get current exclusions
        exclusions: ExclusionData = {list_type: list_widget.get_items() for list_type, list_widget in self.exclusion_lists.items()}

        # Check if exclusions have changed
        exclusions_changed = False
        for list_type in exclusions:
            if set(exclusions[list_type]) != set(self.original_exclusions.get(list_type, [])):
                exclusions_changed = True
                break

        # Store both settings and exclusions
        self.settings_manager.save_settings(settings)
        self.settings_manager.save_exclusions(exclusions)

        # Import here instead of at the top to avoid a partial import
        from xrefer.plugin import plugin_instance

        if plugin_instance and plugin_instance.xrefer_view:
            plugin_instance.xrefer_view.xrefer_obj.reload_settings()

            # Repopulate tables if either exclusions changed or exclusions state changed
            if exclusions_changed or exclusions_state_changed:
                plugin_instance.xrefer_view.xrefer_obj.clear_affected_function_tables()
                plugin_instance.xrefer_view.update(True)

        self.accept()


class MissingFilesDialog(QDialog):
    """
    Dialog for handling missing required files.

    Displays information about missing analysis files (trace, CAPA, etc.)
    and allows user to choose whether to proceed with analysis.

    Attributes:
        missing_files (Dict[str, str]): Dictionary mapping file types to missing paths
    """

    def __init__(self, missing_files: Dict[str, str], parent=None):
        super().__init__(parent)
        self.missing_files = missing_files
        self.initUI()

    def format_path(self, path: str, max_width: int = 500) -> str:
        """Format path to fit within specified width with ellipsis"""
        if not path:
            return ""

        metrics = QFontMetrics(QFont("Arial", 9))
        if metrics.horizontalAdvance(path) <= max_width:
            return path

        dir_name = os.path.dirname(path)
        file_name = os.path.basename(path)
        ellipsis_text = "/.../"

        # Calculate available space for directory
        ellipsis_width = metrics.horizontalAdvance(ellipsis_text)
        filename_width = metrics.horizontalAdvance(file_name)
        available_width = max_width - ellipsis_width - filename_width

        if available_width <= 0:
            return "..." + file_name[-30:]

        # Progressively truncate directory parts
        parts = dir_name.split(os.sep)
        while len(parts) > 1 and metrics.horizontalAdvance(os.sep.join(parts)) > available_width:
            if len(parts) > 3:
                parts = parts[:2] + ["..."] + parts[-1:]
            else:
                parts = ["..."] + parts[-1:]
            if len(parts) <= 2:
                break

        return f"{os.sep.join(parts)}{ellipsis_text}{file_name}"

    def initUI(self) -> None:
        """
        Initialize dialog user interface.

        Creates layout with missing file information, explanations of
        file purposes, and proceed/cancel buttons. Handles scrolling
        for many missing files.
        """
        # Set window properties
        self.setWindowTitle("XRefer Configuration Notice")
        self.setMinimumSize(650, 200)
        self.setMaximumSize(800, 600)  # Maximum reasonable size

        # Create main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # Create scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        # Create content widget
        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setSpacing(15)
        layout.setContentsMargins(0, 0, 0, 0)

        # Add main message
        message = QLabel(
            "XRefer is a binary navigation tool that provides a context aware navigation "
            "interface by ingestion and processing of multiple data sources. Some of this "
            "data (strings, apis, libs etc) is extracted from within the IDB, while some "
            "can be ingested from external files. The more data available to XRefer, the "
            "better results it will produce. Following external files were found missing:"
        )
        message.setWordWrap(True)
        message.setFont(QFont("Arial", 10))
        layout.addWidget(message)

        # Create frame for missing files
        frame = QFrame()
        frame.setFrameStyle(QFrame.StyledPanel | QFrame.Sunken)
        frame_layout = QVBoxLayout(frame)
        frame_layout.setSpacing(10)
        frame_layout.setContentsMargins(15, 15, 15, 15)

        # Add missing file descriptions
        descriptions = {
            "trace": (
                "API Trace File Missing",
                "Analysis archive from VMRay (archive.zip) or Cape Sandbox (*.json) "
                "can be ingested. These enable enrichment of the cluster analysis and"
                "navigation interface with API call information.",
            ),
            "capa": ("CAPA Analysis File Missing", "CAPA capability analysis (*.json) results allow XRefer to further enrich the function contexts with semantic behaviour descriptions."),
            "xrefs": (
                "User XRefs File Missing",
                "Addresses of indirect call targets (e.g., C++ virtual functions, function "
                "pointers) can be provided to XRefer to build complete call paths where "
                "static analysis alone cannot determine the target. This is particularly "
                "useful for C++ binaries using virtual dispatch or callback-based designs.",
            ),
        }

        first = True
        for file_type in self.missing_files:
            if file_type in descriptions:
                if not first:
                    separator = QFrame()
                    separator.setFrameShape(QFrame.HLine)
                    separator.setFrameShadow(QFrame.Sunken)
                    frame_layout.addWidget(separator)
                first = False

                container = QWidget()
                container_layout = QVBoxLayout(container)
                container_layout.setSpacing(5)
                container_layout.setContentsMargins(0, 0, 0, 0)

                title, desc = descriptions[file_type]

                # Title
                title_label = QLabel(f"<b>{title}</b>")
                title_label.setFont(QFont("Arial", 9))
                container_layout.addWidget(title_label)

                # Path
                path = self.missing_files[file_type]
                formatted_path = self.format_path(path)
                path_label = QLabel(f"Path: {formatted_path}")
                path_label.setFont(QFont("Arial", 9))
                path_label.setStyleSheet("color: #888888;")
                container_layout.addWidget(path_label)

                # Description
                desc_label = QLabel(desc)
                desc_label.setWordWrap(True)
                desc_label.setFont(QFont("Arial", 9))
                desc_label.setStyleSheet("color: #888888;")
                desc_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
                container_layout.addWidget(desc_label)

                frame_layout.addWidget(container)

        layout.addWidget(frame)
        layout.addSpacing(2)

        # Add note about proceeding
        note = QLabel("You can either cancel the current analysis to configure these files, or proceed with available data.")
        note.setWordWrap(True)
        note.setFont(QFont("Arial", 10))
        layout.addWidget(note)

        # Set the content widget to scroll area
        scroll.setWidget(content_widget)
        main_layout.addWidget(scroll)

        # Add buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        cancel_button = QPushButton("Cancel Analysis")
        cancel_button.setMinimumWidth(120)
        cancel_button.clicked.connect(self.reject)

        proceed_button = QPushButton("Proceed Anyway")
        proceed_button.setMinimumWidth(120)
        proceed_button.clicked.connect(self.accept)

        button_layout.addStretch()
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(proceed_button)
        main_layout.addLayout(button_layout)

        # Let the dialog size itself based on content
        self.adjustSize()
