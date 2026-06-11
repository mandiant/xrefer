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
import time
from functools import wraps
from time import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import ida_bytes
import ida_idp
import ida_kernwin
import ida_lines
import ida_nalt
import ida_ua
import idaapi
import idc
import ida_idaapi
import networkx as nx
from qtpy import QtCore, QtWidgets
from tabulate import tabulate

from xrefer.core.analyzer import ApiCall


def qt_object_alive(obj) -> bool:
    """Return True if ``obj`` is a Python wrapper around a still-live Qt C++ object.

    Qt+Python lifetime: when the underlying C++ object is destroyed, the
    Python wrapper survives but any method call on it raises
    ``RuntimeError: Internal C++ object … already deleted``. Use this check
    before touching any cached widget reference.

    Probes the active binding's introspection module (``shiboken6`` for
    PySide6, ``shiboken2`` for PySide2, ``sip`` for PyQt5/6). If none is
    importable we err on the side of "alive" — caller still gets a
    ``RuntimeError`` if the access turns out to be invalid.
    """
    if obj is None:
        return False
    try:
        from shiboken6 import isValid
        return bool(isValid(obj))
    except ImportError:
        pass
    try:
        from shiboken2 import isValid
        return bool(isValid(obj))
    except ImportError:
        pass
    try:
        from PyQt5 import sip
        return not sip.isdeleted(obj)
    except (ImportError, TypeError):
        pass
    try:
        from PyQt6 import sip
        return not sip.isdeleted(obj)
    except (ImportError, TypeError):
        pass
    return True


def twidget_to_qt(twidget):
    """Convert an IDA TWidget* into a QWidget of the active Qt binding.

    IDA 9.3 ships two bridge implementations on PluginForm:

    - ``TWidgetToQtPythonWidget`` (canonical name; aliased as
      ``TWidgetToPyQtWidget`` and ``FormToPyQtWidget``): PySide6-native via
      ``shiboken6.Shiboken.wrapInstance``. Returns a PySide6 widget regardless
      of whether the PyQt5 shim is active. Reads no module-level state. This
      is the function we always want.
    - ``TWidgetToPySideWidget`` (aliased as ``FormToPySideWidget``): broken in
      9.3 — it dereferences ``__main__.QtGui.QWidget``, which is undefined for
      vanilla PySide6 (``QWidget`` lives in ``QtWidgets``). It looks vestigial
      from the Qt4 era and cannot be rescued by planting modules. Do not call.

    Older IDA (8.x) exposes only ``TWidgetToPyQtWidget``; under those versions
    the return type is a PyQt5 widget. Either way, the canonical lookup below
    resolves to the right implementation.
    """
    plugin_form = idaapi.PluginForm
    bridge = (
        getattr(plugin_form, "TWidgetToQtPythonWidget", None)
        or plugin_form.TWidgetToPyQtWidget
    )
    return bridge(twidget)


class FocusEventFilter(QtCore.QObject):
    """
    Event filter for handling focus events in XRefer view.

    Manages IDA shortcut overrides when XRefer view gains or loses focus
    to prevent conflicts with XRefer's keyboard handling.

    Attributes:
        xrefer_view: Reference to parent XRefer view instance
    """

    def __init__(self, xrefer_view):
        super().__init__()
        self.xrefer_view = xrefer_view

    def eventFilter(self, obj: Any, event: QtCore.QEvent) -> bool:
        """
        Filter focus events and manage shortcuts.

        Override or restore IDA shortcuts based on focus changes.

        Args:
            obj: Qt object receiving the event
            event: Qt event to filter

        Returns:
            bool: False to allow event propagation
        """
        if event.type() == QtCore.QEvent.FocusIn:
            self.xrefer_view.override_ida_shortcuts()
        elif event.type() == QtCore.QEvent.FocusOut:
            self.xrefer_view.restore_ida_shortcuts()
        return False  # Allow other handlers to process the event


class KeyEventFilter(QtCore.QObject):
    """
    Event filter for handling keyboard events in XRefer view.

    Captures and processes non-alphanumeric printable characters that
    Qt might otherwise not handle properly.

    Attributes:
        xrefer_view: Reference to parent XRefer view instance
    """

    def __init__(self, xrefer_view):
        super(KeyEventFilter, self).__init__()
        self.xrefer_view = xrefer_view  # Reference to the XReferView instance

    def eventFilter(self, obj: Any, event: QtCore.QEvent) -> bool:
        """
        Filter keyboard events for special character handling.

        Processes printable non-alphanumeric characters and passes them
        to XRefer's keyboard handler.

        Args:
            obj: Qt object receiving the event
            event: Qt event to filter

        Returns:
            bool: True if event was handled, False to allow propagation
        """
        if event.type() == QtCore.QEvent.KeyPress:
            _char = event.text()
            if _char and _char.isprintable() and not _char.isalnum():
                # Pass printable non-alphanumeric character to OnKeydown
                self.xrefer_view.OnKeydown(_char, False)
                event.accept()
                return True  # Accept the event to prevent further propagation

        return False  # Let other events propagate


class CollapseEventFilter(QtCore.QObject):
    def __init__(self, collapse_indicator):
        super().__init__()
        self.collapse_indicator = collapse_indicator
        self.reposition_timer = QtCore.QTimer()
        self.reposition_timer.setSingleShot(True)
        self.reposition_timer.timeout.connect(self.collapse_indicator.reposition)

    def eventFilter(self, obj, event):
        if event.type() in (QtCore.QEvent.Resize, QtCore.QEvent.Move):
            # Debounce repositioning to prevent rapid updates
            self.reposition_timer.start(50)
        elif event.type() == QtCore.QEvent.Hide:
            self.collapse_indicator.hide()
        elif event.type() == QtCore.QEvent.Show:
            self.reposition_timer.start(50)
        return False


class CollapseIndicator(QtWidgets.QWidget):
    def __init__(self, dock_widget, original_width):
        super().__init__(dock_widget)

        self.dock_widget = dock_widget
        self.is_collapsed = False
        self.original_width = original_width
        self.minimum_width = 400

        # Store positions
        self.last_expanded_x = None
        self.last_expanded_y = None
        self.last_expanded_width = None

        self.setup_ui()

        # Ensure indicator stays on top
        self.setWindowFlags(QtCore.Qt.ToolTip | QtCore.Qt.FramelessWindowHint)

        # Ensure indicator stays on top within the application
        self.setAttribute(QtCore.Qt.WA_AlwaysStackOnTop, True)

        # Connect to application focus changes
        QtWidgets.QApplication.instance().focusChanged.connect(self.on_focus_changed)

    def on_focus_changed(self, old, now):
        """Hide/show the indicator based on application focus."""
        active_window = QtWidgets.QApplication.activeWindow()
        if active_window is None:
            self.hide()
        else:
            self.show()

    def setup_ui(self):
        self.setFixedSize(20, 20)
        self.setStyleSheet(
            """
            QWidget {
                background-color: #2d2d2d;
                border-radius: 3px;
                border: 1px solid #3d3d3d;
            }
            QWidget:hover {
                background-color: #3d3d3d;
            }
        """
        )

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.arrow_label = QtWidgets.QLabel("⟩")
        self.arrow_label.setStyleSheet("color: white; border: none;")
        self.arrow_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(self.arrow_label)

        self.setCursor(QtCore.Qt.PointingHandCursor)

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self.toggle_collapsed()

    def toggle_collapsed(self):
        if not self.is_collapsed:
            # Store the expanded position and width before collapsing
            self.last_expanded_x = self.x()
            self.last_expanded_y = self.y()
            self.last_expanded_width = self.dock_widget.width()

            # Collapsing
            self.is_collapsed = True

            # Set minimum and maximum width to 0 to collapse
            self.dock_widget.setMinimumWidth(0)
            self.dock_widget.setMaximumWidth(0)
            self.arrow_label.setText("⟨")

            # Notify XReferView of collapse
            if hasattr(self.dock_widget, "xrefer_view"):
                self.dock_widget.xrefer_view.toggle_collapsed_state(True)
        else:
            # Expanding
            self.is_collapsed = False

            # Notify XReferView of expand
            if hasattr(self.dock_widget, "xrefer_view"):
                self.dock_widget.xrefer_view.toggle_collapsed_state(False)

            # Temporarily set minimum and maximum width to desired width to force expansion
            restore_width = self.last_expanded_width if self.last_expanded_width else self.original_width
            self.dock_widget.setMinimumWidth(restore_width)
            self.dock_widget.setMaximumWidth(restore_width)

            # Force the dock widget to adjust its size
            self.dock_widget.updateGeometry()

            # After a short delay, reset the size constraints to allow user resizing
            QtCore.QTimer.singleShot(100, self.reset_size_constraints)

            self.arrow_label.setText("⟩")

        # Update layouts
        self.dock_widget.updateGeometry()
        if self.dock_widget.widget():
            self.dock_widget.widget().updateGeometry()

        # Immediate reposition
        self.reposition()
        # Delayed reposition to ensure proper placement
        QtCore.QTimer.singleShot(50, self.reposition)

    def reset_size_constraints(self):
        """Reset size constraints to allow user resizing."""
        self.dock_widget.setMinimumWidth(0)
        self.dock_widget.setMaximumWidth(16777215)  # Qt's QWIDGETSIZE_MAX
        self.dock_widget.updateGeometry()

    def reposition(self):
        """Update the indicator position based on dock widget state."""
        if not self.dock_widget or not self.dock_widget.isVisible():
            self.hide()
            return

        try:
            # Get current dock position and screen
            dock_pos = self.dock_widget.mapToGlobal(QtCore.QPoint(0, 0))
            dock_geo = self.dock_widget.geometry()
            screen = QtWidgets.QApplication.screenAt(dock_pos)

            if not screen:  # Fallback to primary screen if screen not found
                screen = QtWidgets.QApplication.primaryScreen()

            screen_geo = screen.geometry()

            if self.is_collapsed:
                # When collapsed, use the last known expanded x position
                if self.last_expanded_x is not None:
                    x = self.last_expanded_x
                    y = self.last_expanded_y
                else:
                    # Fallback if no stored position
                    x = dock_pos.x() + dock_geo.width() - self.width() - 2
                    y = dock_pos.y() + (dock_geo.height() // 2) - (self.height() // 2)
            else:
                # When expanded, always position on the right edge
                x = dock_pos.x() + dock_geo.width() - self.width() - 2
                y = dock_pos.y() + (dock_geo.height() // 2) - (self.height() // 2)

                # Store this position
                self.last_expanded_x = x
                self.last_expanded_y = y
                self.last_expanded_width = dock_geo.width()

            # Ensure position is within screen bounds
            x = max(screen_geo.left(), min(x, screen_geo.right() - self.width()))
            y = max(screen_geo.top(), min(y, screen_geo.bottom() - self.height()))

            # Move to new position
            self.move(x, y)
            self.show()
            self.raise_()

        except Exception as e:
            log(f"[-] Error in reposition: {str(e)}")

    def showEvent(self, event):
        super().showEvent(event)
        self.reposition()


from xrefer.core.clusters import cluster_subtree_matches
from xrefer.core.helpers import convert_int_to_hex, create_table_from_rows, enrich_string_data_core, find_cluster_analysis, get_visible_width, in_cancellable_phase, render_markdown_segments, set_progress_function, sort_clusters, strip_cluster_citations, word_wrap_text, set_log_function


def render_markdown_report_lines(md: str, width: int = 85, indent: str = "") -> List[str]:
    """Render the ``binary_report`` markdown into IDA-colored lines for
    the custom viewer.

    Maps the style vocabulary from
    :func:`xrefer.core.helpers.render_markdown_segments` to ``SCOLOR_*``
    codes and prefixes each line with ``indent``. Returns lines ready
    for ``simplecustviewer_t.AddLine`` -- headings, bullets and
    ``**bold**``/```code``` spans become colored runs so the report
    reads as structured text instead of an unbroken blob. Prose renders
    in the string color; HTML-only ``[c5]``/``[c4, c6]`` cluster
    citations are stripped first. The parsing is backend-agnostic; only
    the color mapping lives here.
    """
    md = strip_cluster_citations(md)
    style_color = {
        "h2": ida_lines.SCOLOR_DATNAME,
        "h3": ida_lines.SCOLOR_DNAME,
        "h4": ida_lines.SCOLOR_PREFIX,
        "rule": ida_lines.SCOLOR_AUTOCMT,
        "bold": ida_lines.SCOLOR_VOIDOP,
        "code": ida_lines.SCOLOR_DEMNAME,
        "bullet": ida_lines.SCOLOR_SYMBOL,
        "plain": ida_lines.SCOLOR_DSTR,
    }
    inner_width = max(20, width - len(indent))
    lines: List[str] = []
    for seg_line in render_markdown_segments(md, inner_width):
        if not seg_line:
            lines.append("")
            continue
        # Coalesce consecutive same-color segments so each run is wrapped
        # in a single COLSTR (fewer color toggles, shorter lines).
        parts = []
        buf_text = ""
        buf_color = None
        for style, text in seg_line:
            if not text:
                continue
            color = style_color.get(style)
            if buf_text and color == buf_color:
                buf_text += text
            else:
                if buf_text:
                    parts.append(ida_lines.COLSTR(buf_text, buf_color) if buf_color else buf_text)
                buf_text, buf_color = text, color
        if buf_text:
            parts.append(ida_lines.COLSTR(buf_text, buf_color) if buf_color else buf_text)
        lines.append(f"{indent}{''.join(parts)}")
    return lines


def enrich_string_data(str_indexes: List[int], entity_list: List[str], lookup: bool = True, max_threads: int = 12) -> List[Tuple[str, str, int, str, dict, list]]:
    """
    Enrich string information by searching public GitHub code.

    Performs parallel queries to the Grep MCP server (the supported successor to
    the old grep.app HTTP API) to find string usage in public repositories.
    Enriches strings with repository context and matched code lines.

    Args:
        str_indexes (List[int]): List of string indexes to process
        entity_list (List[str]): List of strings to enrich
        lookup (bool): Whether to perform Git lookups
        max_threads (int): Maximum number of threads for parallel processing

    Returns:
        List[Tuple[str, str, int, str, dict, list]]: List of enriched string information tuples:
            - repo_name: Name of selected repository or 'UNCATEGORIZED'
            - original_string: Original string content
            - entity_type: Constant value 3 (strings)
            - repo_path: Path in selected repository
            - matched_lines: Dictionary mapping line numbers to code lines
            - all_repos: List of all repositories where string was found
    """
    if lookup:
        log("Querying strings in git repositories...")
    return enrich_string_data_core(str_indexes, entity_list, lookup, max_threads)


def create_colored_table_from_cols(headings: List[str], columns: List[List[Any]], color_tag: int) -> List[str]:
    """
    Create a colored formatted table from headings and column data.

    Similar to create_table_from_cols but applies IDA color tags to the output.
    The first column is colored differently from the rest for visual distinction.

    Args:
        headings (List[str]): List of column headers
        columns (List[List[Any]]): List of columns, where each column is a list of values
        color_tag (int): IDA color tag to apply to the table

    Returns:
        List[str]: List of colored table rows as strings with IDA color codes
    """
    max_column_length = max(len(column) for column in columns)
    rows = []
    for i in range(max_column_length):
        row = []
        for column in columns:
            if i < len(column):
                row.append(convert_int_to_hex(column[i]))
            else:
                row.append("")
        rows.append(row)

    table = tabulate(rows, headers=headings, tablefmt="simple").splitlines()
    table_length = len(table)
    zeroth_col_length = len(table[1].split(" ")[0])

    for index in range(0, 2):
        table[index] = f"\x01{color_tag}{table[index]}\x02{color_tag}"

    for index in range(2, table_length):
        table[index] = f"\x01{ida_lines.SCOLOR_CREFTAIL}{table[index][:zeroth_col_length]}\x02{ida_lines.SCOLOR_CREFTAIL}\x01{color_tag}{table[index][zeroth_col_length:]}\x02{color_tag}"

    return table


def create_xrefs_table_colored(heading: str, xrefs_rows: List[List[Any]], color_tags: Union[int, Dict[int, List[int]]]) -> List[str]:
    """
    Create a colored cross-references table.

    Creates a table showing cross-references with appropriate coloring for different
    types of references (imports, strings, etc). Supports both single color and
    multi-color tables through color_tags parameter.

    Args:
        heading (str): Table heading text
        xrefs_rows (List[List[Any]]): List of cross-reference rows to display
        color_tags (Union[int, Dict[int, List[int]]]): Either a single color tag or
            a dictionary mapping color tags to row ranges

    Returns:
        List[str]: List of colored table rows as strings, including header and footer lines
    """
    _table = create_table_from_rows([heading], xrefs_rows).splitlines()
    zeroth_col_length = len(_table[1].split(" ")[0])
    table_length = len(_table)

    if not isinstance(color_tags, dict):
        for index in range(2, table_length):
            _table[index] = f"\x01{color_tags}{_table[index][:zeroth_col_length]}\x02{color_tags}{_table[index][zeroth_col_length:]}"
    else:
        for tag in color_tags.keys():
            for index in range(color_tags[tag][0], color_tags[tag][1]):
                _table[index] = f"\x01{tag}{_table[index][:zeroth_col_length]}\x02{tag}{_table[index][zeroth_col_length:]}"

    return [""] + _table + ["", ""]


def set_xref_coverage_color(line: str, xref_str: str, covered: bool = False) -> str:
    """
    Apply color to a cross-reference string based on coverage status.

    Args:
        line (str): The line containing the cross-reference
        xref_str (str): The cross-reference string to color
        covered (bool): Whether the cross-reference is covered by analysis

    Returns:
        str: Line with appropriate IDA color codes applied to the cross-reference string
    """
    if covered:
        line = line.replace(xref_str, ida_lines.COLSTR(xref_str, ida_lines.SCOLOR_LIBNAME))
    else:
        line = line.replace(xref_str, ida_lines.COLSTR(xref_str, ida_lines.SCOLOR_CREFTAIL))
    return line


def _update_wait_box(string: str) -> None:
    """Box-only progress sink (no Output print) — the high-frequency half
    of core's log_progress. During a cancellable phase the update must not
    re-assert HIDECANCEL, or a progress line would strip the Cancel button
    the phase relies on."""
    if in_cancellable_phase():
        idaapi.replace_wait_box(string)
    else:
        idaapi.replace_wait_box(f"HIDECANCEL\n{string}")


def log(string: str) -> None:
    """
    Log message to IDA's output window with XRefer prefix.

    Also updates the wait box message if one is active.

    Args:
        string (str): Message to log
    """
    print(f"[XRefer] {string}")
    _update_wait_box(string)


# Route the core layer's logging and progress sinks through the IDA
# implementations at import time (module level, not inside log() — the old
# in-body registration only took effect after the first GUI log call and
# re-registered on every call).
set_log_function(log)
set_progress_function(_update_wait_box)

def log_elapsed_time(msg: str, start_time: float) -> None:
    """
    Log elapsed time for an operation.

    Calculates and logs time elapsed since start_time in hours,
    minutes, and seconds format.

    Args:
        msg (str): Description of the operation
        start_time (float): Start time from time.time()
    """
    end_time = time()
    elapsed_time = end_time - start_time
    hours = int(elapsed_time // 3600)
    minutes = int((elapsed_time % 3600) // 60)
    seconds = int(elapsed_time % 60)
    log(f"[{msg}] {hours} hours, {minutes} minutes, {seconds} seconds")


def dump_indirect_calls(path: str) -> None:
    """
    Export list of indirect call sites to a file.

    Scans all functions in the IDB for indirect calls (calls through registers or memory)
    and writes their addresses to the specified file.

    Args:
        path (str): Output file path for the indirect calls list
    """
    from xrefer.backend import get_indirect_calls

    indirect_calls = get_indirect_calls()

    if indirect_calls:
        with open(path, "w") as outfile:
            outfile.write("\n".join(indirect_calls))
        log(f"Dumped indirect calls to: {path}")


def handle_entrypoint_selection(plugin_instance: Any, custom_ep: int) -> bool:
    """
    Handle selection of a custom entry point for analysis.

    Validates the selected entry point and initiates either primary or secondary
    analysis based on current plugin state.

    Args:
        plugin_instance: Instance of XReferPlugin
        custom_ep (int): Address of selected entry point function

    Returns:
        bool: True if entry point was valid and analysis started, False otherwise
    """
    if custom_ep != idc.BADADDR:
        ep_name: str = idc.get_func_name(ida_idaapi.ea_t(custom_ep))
        if plugin_instance.xrefer_view and plugin_instance.xrefer_view.xrefer_obj.lang:
            log(f"Custom entrypoint selected for secondary analysis: 0x{custom_ep:x} ({ep_name})")
            plugin_instance.xrefer_view.xrefer_obj.current_analysis_ep = custom_ep
            plugin_instance.xrefer_view.xrefer_obj.run_standalone_secondary_analysis()
            plugin_instance.xrefer_view.update(True, ea=custom_ep)
        else:
            log(f"Custom entrypoint selected for primary analysis: 0x{custom_ep:x} ({ep_name})")
            if plugin_instance.xrefer_view:
                plugin_instance.xrefer_view.xrefer_obj.load_analysis()
                if plugin_instance.xrefer_view.xrefer_obj.lang:
                    plugin_instance.xrefer_view.create()
            else:
                plugin_instance.start(custom_ep)
        return True
    else:
        log("No valid function selected as entrypoint")
        return False


def colorize_api_call(input_string: str) -> str:
    """
    Apply IDA color codes to API call string.

    Parses and colorizes different components of API call string:
    - Arguments in parentheses
    - String values in quotes
    - Numeric values
    - Equal signs and operators

    Args:
        input_string (str): Raw API call string to colorize

    Returns:
        str: API call string with IDA color codes inserted

    Note:
        Handles nested structures and maintains proper color code nesting.
        Uses different colors for:
        - String values (SCOLOR_DSTR)
        - Numeric values (SCOLOR_CREFTAIL)
        - API names (SCOLOR_DEMNAME)
    """
    result = []
    length = len(input_string)
    i = 0
    in_value = False
    in_quotes = False
    quote_char = None
    param_count = 0
    equal_sign_present = False
    paren_depth = 0

    quoted_color_start = f"{ida_lines.SCOLOR_ON}{ida_lines.SCOLOR_DSTR}"
    quoted_color_end = f"{ida_lines.SCOLOR_OFF}{ida_lines.SCOLOR_DSTR}"
    non_quoted_color_start = f"{ida_lines.SCOLOR_ON}{ida_lines.SCOLOR_CREFTAIL}"
    non_quoted_color_end = f"{ida_lines.SCOLOR_OFF}{ida_lines.SCOLOR_CREFTAIL}"

    while i < length:
        char = input_string[i]

        if char == "(":
            paren_depth += 1
            result.append(char)
            i += 1
            continue
        elif char == ")":
            paren_depth -= 1
            if paren_depth == 0:
                # This is the final closing parenthesis
                if in_value:
                    result.append(quoted_color_end if in_quotes else non_quoted_color_end)
                    in_value = False
                result.append(char)
                break
            result.append(char)
            i += 1
            continue

        if not equal_sign_present and char == "=":
            equal_sign_present = True

        if equal_sign_present:
            if not in_value and char == "=":
                in_value = True
                result.append(char)
                i += 1
                if i < length and input_string[i] in ('"', "'"):
                    result.append(quoted_color_start)
                    in_quotes = True
                    quote_char = input_string[i]
                else:
                    result.append(non_quoted_color_start)
                continue

            if in_value:
                if in_quotes:
                    result.append(char)
                    if char == quote_char:
                        j = i + 1
                        while j < length and input_string[j] in (" ", "\t", "\n"):
                            j += 1
                        if j < length and input_string[j] in (",", ")"):
                            result.append(quoted_color_end)
                            in_quotes = False
                            in_value = False
                            i = j - 1
                else:
                    if char == ",":
                        result.append(non_quoted_color_end)
                        in_value = False
                    else:
                        result.append(char)
            else:
                result.append(char)
        else:
            if char == ",":
                if in_value:
                    result.append(non_quoted_color_end)
                    in_value = False
                param_count += 1
            elif param_count % 2 == 1 and char not in (" ", "\t", "\n", ","):
                if not in_value:
                    in_value = True
                    result.append(non_quoted_color_start)
                result.append(char)
            else:
                result.append(char)

        i += 1

    return ida_lines.COLSTR("".join(result), ida_lines.SCOLOR_DEMNAME)


def format_api_call_for_ida(rec: ApiCall) -> str:
    """Render an ApiCall record for the IDA custom-viewer panel with full color decoration."""
    addr = ida_lines.COLSTR(f"0x{rec.call_addr:x}", ida_lines.SCOLOR_LIBNAME)
    name = ida_lines.COLSTR(rec.api_name.split(".")[-1], ida_lines.SCOLOR_IMPNAME)
    return f"{addr}: {name}{colorize_api_call(rec.call_str)} x {rec.count}"


def _collect_library_cluster_ids(clusters: List["FunctionalCluster"]) -> Set[int]:
    """Walk a cluster forest and return the IDs of every cluster (or
    subcluster, recursively) marked ``is_library``. Used by the cluster
    rendering helpers to skip library nodes when the user has them
    hidden via the ``L`` toggle.
    """
    ids: Set[int] = set()

    def walk(c: "FunctionalCluster") -> None:
        if getattr(c, "is_library", False):
            ids.add(c.id)
        for sub in c.subclusters:
            walk(sub)

    for c in clusters:
        walk(c)
    return ids


def _lifted_descendants(
    cluster_or_list: Any,
    trimmed_ids: Set[int],
) -> List["FunctionalCluster"]:
    """Return the effective list of clusters to render under (or in
    place of) the given parent / list, lifting non-trimmed descendants
    out of trimmed ancestors.

    Given a top-level list or a single cluster's ``subclusters``, walk
    the children: keep each non-trimmed child as-is, and replace each
    trimmed child with the recursive lift of its own ``subclusters``.
    The recursion preserves any non-trimmed cluster whose only
    structural parent chain runs through trimmed library clusters —
    without it those user-code clusters would silently disappear when
    their library parent is hidden by either the L toggle or the
    boot-prefix trim.

    ``cluster_refs`` are deliberately NOT walked here: they point to
    sibling clusters that already appear elsewhere in the forest, so
    lifting through them would risk double-rendering.
    """
    out: List["FunctionalCluster"] = []
    if isinstance(cluster_or_list, list):
        roots = cluster_or_list
    else:
        roots = cluster_or_list.subclusters

    for child in roots:
        if child.id not in trimmed_ids:
            out.append(child)
        else:
            out.extend(_lifted_descendants(child.subclusters, trimmed_ids))
    return out


def _collect_boot_prefix_cluster_ids(
    clusters: List["FunctionalCluster"],
    paths: Optional[Dict[int, Any]],
) -> Set[int]:
    """Find the leading non-user (library) cluster prefix at each entry
    point.

    Rationale: the first few clusters reached from any analyzed EP are
    almost always boot/CRT/runtime plumbing — initialization, argv
    setup, runtime bootstrap — and add noise to the cluster relationship
    graph without telling the analyst anything actionable. This helper
    identifies those clusters so the renderer can hide them, regardless
    of whether the user has the L (hide-library) toggle on.

    The walk:

    1. Index every cluster by id (recursing through ``subclusters`` so
       nested clusters are reachable by id).
    2. For each EP in ``paths``, find the top-level cluster that
       contains the EP function in its ``nodes``. That is this EP's
       root cluster.
    3. BFS downstream from each root cluster following BOTH
       ``subclusters`` and ``cluster_refs``. While the current cluster
       is library, add it to the trimmed set and keep traversing. The
       moment we hit a non-library cluster on a branch, stop traversing
       that branch — anything past it (even later library clusters in
       the middle / tail) is preserved.

    Returns:
        Set of cluster IDs that should be hidden as boot prefix.
        Always a subset of all library cluster IDs.
    """
    if not clusters or not paths:
        return set()

    cluster_by_id: Dict[int, "FunctionalCluster"] = {}

    def index(cluster: "FunctionalCluster") -> None:
        cluster_by_id[cluster.id] = cluster
        for sub in cluster.subclusters:
            index(sub)

    for cluster in clusters:
        index(cluster)

    ep_set = set(paths.keys())
    root_ids: List[int] = []
    for cluster in clusters:
        if any(ep in cluster.nodes for ep in ep_set):
            root_ids.append(cluster.id)

    trimmed: Set[int] = set()
    for root_id in root_ids:
        queue: List[int] = [root_id]
        seen: Set[int] = set()
        while queue:
            cid = queue.pop(0)
            if cid in seen:
                continue
            seen.add(cid)

            cluster = cluster_by_id.get(cid)
            if cluster is None:
                continue
            if not getattr(cluster, "is_library", False):
                # First user-code cluster on this branch — stop.
                continue

            trimmed.add(cid)
            # Continue downstream along both decomposition (subclusters)
            # and call-flow (cluster_refs) edges.
            for sub in cluster.subclusters:
                queue.append(sub.id)
            for ref_id in cluster.cluster_refs.values():
                queue.append(ref_id)

    return trimmed


def create_cluster_relationship_graph(
    clusters: List["FunctionalCluster"],
    analysis: Dict,
    paths: Optional[Dict[int, Any]] = None,
    hide_library: bool = False,
) -> Optional[nx.DiGraph]:
    """Create graph respecting merge hierarchy and hiding merged nodes.

    When ``hide_library`` is True, every cluster (and its subclusters /
    references) marked ``is_library`` is omitted from the graph. When
    ``hide_library`` is False, only the *boot prefix* — the leading
    library clusters at each EP, up to the first user-code cluster — is
    omitted. Either way, the EP-rooted boot/CRT noise is suppressed and
    the graph starts at the first meaningful user cluster.
    """
    if not clusters:
        return None

    if hide_library:
        library_ids = _collect_library_cluster_ids(clusters)
    else:
        library_ids = _collect_boot_prefix_cluster_ids(clusters, paths)

    try:
        graph = nx.DiGraph()

        # Track nodes and merged states
        added_nodes = set()
        merged_nodes = {}  # Maps merged_id -> parent_id

        def add_valid_node(node_id: str, label: str = "") -> bool:
            """Add node with validation of merge state."""
            if not isinstance(node_id, str) or not node_id.strip():
                return False

            # Check if this is a merged node
            try:
                cluster_id = int(node_id.split(".")[-1])
                if cluster_id in merged_nodes:
                    # Don't add individual merged nodes
                    return False
            except (ValueError, IndexError):
                pass

            node_text = f"{node_id}\n{label}" if label else node_id
            if len(node_text) > 500:  # Reasonable limit
                node_text = node_text[:497] + "..."

            if node_text not in added_nodes:
                graph.add_node(node_text)
                added_nodes.add(node_text)
            return True

        def add_valid_edge(source: str, target: str) -> bool:
            """Add edge respecting merge hierarchy."""
            if source not in added_nodes or target not in added_nodes:
                return False
            if source == target:
                return False

            # Extract cluster IDs
            try:
                source_id = int(source.split(".")[-1])
                target_id = int(target.split(".")[-1])

                # If either node is merged, remap to parent
                if source_id in merged_nodes:
                    source_text = f"cluster.id.{merged_nodes[source_id]}"
                    if source_text not in added_nodes:
                        return False
                    source = source_text
                if target_id in merged_nodes:
                    target_text = f"cluster.id.{merged_nodes[target_id]}"
                    if target_text not in added_nodes:
                        return False
                    target = target_text
            except (ValueError, IndexError):
                pass

            graph.add_edge(source, target)
            return True

        # Process multiple clusters case — iterate the lifted top-level
        # set so user clusters orphaned by trimmed library ancestors
        # are still rendered as roots.
        for cluster in _lifted_descendants(clusters, library_ids):
            cluster_id = f"cluster.id.{cluster.id:04d}"
            if cluster.id in merged_nodes:
                continue  # Skip merged nodes

            # Get cluster data
            cluster_data = find_cluster_analysis(analysis, cluster.id)
            if not cluster_data:
                continue

            label = cluster_data.get("label", "").strip()
            if not add_valid_node(cluster_id, label):
                continue

            node_text = f"{cluster_id}\n{label}" if label else cluster_id

            # Process relationships respecting merges
            if cluster.parent_cluster_id and cluster.parent_cluster_id not in library_ids:
                parent_data = find_cluster_analysis(analysis, cluster.parent_cluster_id)
                if parent_data:
                    parent_id = f"cluster.id.{cluster.parent_cluster_id:04d}"
                    parent_label = parent_data.get("label", "").strip()
                    if add_valid_node(parent_id, parent_label):
                        parent_text = f"{parent_id}\n{parent_label}" if parent_label else parent_id
                        add_valid_edge(parent_text, node_text)

            # Handle subclusters — same lift so a deeper user cluster
            # nested under a trimmed library subcluster surfaces as a
            # direct child here (with a parent edge from this cluster
            # rather than the trimmed intermediate).
            for subcluster in _lifted_descendants(cluster.subclusters, library_ids):
                sub_data = find_cluster_analysis(analysis, subcluster.id)
                if sub_data and subcluster.id not in merged_nodes:
                    sub_id = f"cluster.id.{subcluster.id:04d}"
                    sub_label = sub_data.get("label", "").strip()
                    if add_valid_node(sub_id, sub_label):
                        sub_text = f"{sub_id}\n{sub_label}" if sub_label else sub_id
                        add_valid_edge(node_text, sub_text)

            # Handle cluster references
            for _, ref_id in cluster.cluster_refs.items():
                if ref_id in library_ids:
                    continue
                if ref_id not in merged_nodes:  # Skip refs to merged nodes
                    ref_data = find_cluster_analysis(analysis, ref_id)
                    if ref_data:
                        ref_id_str = f"cluster.id.{ref_id:04d}"
                        ref_label = ref_data.get("label", "").strip()
                        if add_valid_node(ref_id_str, ref_label):
                            ref_text = f"{ref_id_str}\n{ref_label}" if ref_label else ref_id_str
                            add_valid_edge(node_text, ref_text)

        return graph

    except Exception as e:
        log(f"[-] Error creating relationship graph: {str(e)}")
        return None


def create_cluster_table(headings: List[str], rows: List[List[Any]], color: int) -> List[str]:
    """
    Create formatted table for clusters with consistent alignment,
    accounting for IDA color codes when measuring column widths.
    """
    # Calculate max widths for each column
    col_widths = [len(h) for h in headings]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], get_visible_width(cell))

    # Add padding
    col_widths = [w + 2 for w in col_widths]

    # Format header
    formatted_rows = []
    header_row = []
    for i, heading in enumerate(headings):
        padding = " " * (col_widths[i] - len(heading))
        header_row.append(f"{heading}{padding}")
    formatted_rows.append(ida_lines.COLSTR("".join(header_row), color))

    # Add separator
    separator = []
    for width in col_widths:
        separator.append("-" * (width - 1) + " ")
    formatted_rows.append(ida_lines.COLSTR("".join(separator), color))
    formatted_rows.append("")  # Empty line after header

    # Format data rows with proper alignment
    for row in rows:
        formatted_row = []
        for i, cell in enumerate(row):
            if cell:  # Only add padding if cell has content
                # Color cluster IDs consistently
                cell = re.sub(r"(cluster\.id\.\d{4})", lambda m: f"\x01{ida_lines.SCOLOR_DATNAME}{m.group(1)}\x02{ida_lines.SCOLOR_DATNAME}", cell)
                visible_length = get_visible_width(cell)
                padding = " " * (col_widths[i] - visible_length)
                formatted_row.append(f"{cell}{padding}")
        formatted_rows.append("".join(formatted_row))

    return formatted_rows


def calculate_first_column_width(clusters, analysis_data):
    """Calculate required width for first column based on longest cluster label."""
    max_width = 0

    def check_cluster(cluster):
        nonlocal max_width
        # Get cluster label from analysis data
        cluster_label = ""
        cluster_analysis_data = find_cluster_analysis(analysis_data, cluster.id)
        if cluster_analysis_data:
            cluster_label = cluster_analysis_data.get("label", "")

        cluster_str = f"[{cluster.id}] {cluster_label}"
        max_width = max(max_width, len(cluster_str))
        for subcluster in cluster.subclusters:
            check_cluster(subcluster)

    if isinstance(clusters, list):
        for cluster in clusters:
            check_cluster(cluster)
    else:
        check_cluster(clusters)

    # Add some padding for arrow head and corner
    return max_width + 15  # minimum space for arrow


def create_cluster_rows(cluster, analysis, column_width, paths, library_ids: Optional[Set[int]] = None, match_ids: Optional[Set[int]] = None):
    """
    Create properly aligned rows for a cluster with visual indicators for entry points.
    Dynamically arranges description and function list in parallel, with properly colored separator.

    Args:
        cluster: FunctionalCluster object
        analysis: Dictionary containing analysis for this cluster
        column_width: Width for consistent alignment
        paths: Dictionary of paths to check for entry points
        library_ids: Optional set of cluster IDs to skip during subcluster
            recursion (used by ``draw_cluster_hierarchy`` to hide library
            clusters). ``None`` is equivalent to no filtering.
        match_ids: When not None, subcluster blocks render only when
            their subtree contains a matched id (per-view filter).

    Returns:
        List[List[str]]: Formatted rows for display
    """
    if library_ids is None:
        library_ids = set()
    rows = []

    # Get cluster info
    cluster_id = cluster.id_str
    cluster_label = ""
    description = ""
    relationships = ""

    # Extract data from analysis if available
    cluster_analysis_data = find_cluster_analysis(analysis, cluster.id)
    if cluster_analysis_data:
        cluster_label = cluster_analysis_data.get("label", "")
        description = cluster_analysis_data.get("description", "")
        relationships = cluster_analysis_data.get("relationships", "")

    # Add entry point indicator if applicable
    entry_point_indicator = ""
    if any(ep in cluster.nodes for ep in paths):
        entry_point_indicator = " ★"  # Star indicator for entry point clusters

    # Format cluster identifier with colors
    cluster_str = f"] {cluster_label}{entry_point_indicator}"
    cluster_id_str = f"{cluster_id}"
    cluster_colored = f"\x01{ida_lines.SCOLOR_DEMNAME}[\x01\x18{cluster_id_str}\x02\x18{cluster_str}\x02{ida_lines.SCOLOR_DEMNAME}"

    # Calculate arrow components
    base_padding = 2
    remaining_space = column_width - len(cluster_str + cluster_id_str) - base_padding - 1
    arrow_line = "─" * (remaining_space - 2)
    arrow_str = f"{' ' * base_padding}◄{arrow_line}┐"
    arrow = f"\x01{ida_lines.SCOLOR_LIBNAME}{arrow_str}\x02{ida_lines.SCOLOR_LIBNAME}"

    # Calculate vertical line position
    vert_line_pos = column_width - 1

    # Process nodes and description
    nodes = sorted(cluster.nodes)
    if nodes:
        # First row with cluster info and first node.
        # cluster.nodes contains xrefer.backend.base.Address instances (an int
        # subclass from the gsoc_2025 backend abstraction). IDA 9.3's SWIG
        # bindings strict-typecheck `ea_t` and reject int subclasses, so we
        # explicitly cast to plain int when crossing into IDA's C API.
        first_node = nodes[0]
        func_name = idc.get_func_name(int(first_node))
        if len(func_name) > 13:
            func_name = f"{func_name[:11]}.."
        func_name = ida_lines.COLSTR(func_name, ida_lines.SCOLOR_CODNAME)
        node_str = f"0x{first_node:x} \x01\x18->\x02\x18 {func_name}"
        node_colored = f"\x01{ida_lines.SCOLOR_CREFTAIL}{node_str}\x02{ida_lines.SCOLOR_CREFTAIL}"

        # Add first row
        rows.append([f"{cluster_colored}{arrow}", node_colored])

        # Get the remaining nodes
        remaining_nodes = nodes[1:]

        # Add separator line if we have a description
        if description:
            separator = "─" * (column_width - 2) + " "  # -2 for space and vertical line
            vert_line = f"\x01{ida_lines.SCOLOR_LIBNAME}│\x02{ida_lines.SCOLOR_LIBNAME}"

            # If we have more nodes, show the next node with the separator line
            if remaining_nodes:
                node = remaining_nodes[0]
                func_name = idc.get_func_name(int(node))
                if len(func_name) > 13:
                    func_name = f"{func_name[:11]}.."
                func_name = ida_lines.COLSTR(func_name, ida_lines.SCOLOR_CODNAME)
                node_str = f"0x{node:x} \x01\x18->\x02\x18 {func_name}"
                node_colored = f"\x01{ida_lines.SCOLOR_CREFTAIL}{node_str}\x02{ida_lines.SCOLOR_CREFTAIL}"
                remaining_nodes = remaining_nodes[1:]  # Remove the used node
            else:
                node_colored = ""

            rows.append([f"\x01{ida_lines.SCOLOR_DEMNAME}{separator}\x02{ida_lines.SCOLOR_DEMNAME}{vert_line}", node_colored])

        # Prepare description lines
        desc_lines = []
        if description or relationships:
            full_desc = f"{description} {relationships}"
            desc_width = column_width - 2
            desc_lines = word_wrap_text(full_desc, desc_width)

        # Create rows combining description and nodes
        max_rows = max(len(desc_lines), len(remaining_nodes))
        for i in range(max_rows):
            # Determine if this is the last content line
            is_last_line = i == max_rows - 1

            # Prepare left column (description)
            if i < len(desc_lines):
                desc_line = desc_lines[i]
                desc_colored = f"\x01{ida_lines.SCOLOR_DSTR}{desc_line}\x02{ida_lines.SCOLOR_DSTR}"
                padding_needed = column_width - len(desc_line)
                padding = " " * (padding_needed - 1)
                connector = "└" if is_last_line else "│"
                vert_line = f"\x01{ida_lines.SCOLOR_LIBNAME}{connector}\x02{ida_lines.SCOLOR_LIBNAME}"
                left_col = f"{desc_colored}{padding}{vert_line}"
            else:
                # Just the vertical line with proper spacing if no more description
                connector = "└" if is_last_line else "│"
                left_col = f"{' ' * (vert_line_pos)}\x01{ida_lines.SCOLOR_LIBNAME}{connector}\x02{ida_lines.SCOLOR_LIBNAME}"

            # Prepare right column (function)
            right_col = ""
            if i < len(remaining_nodes):
                node = remaining_nodes[i]
                func_name = idc.get_func_name(int(node))
                if len(func_name) > 13:
                    func_name = f"{func_name[:11]}.."
                func_name = ida_lines.COLSTR(func_name, ida_lines.SCOLOR_CODNAME)
                node_str = f"0x{node:x} \x01\x18->\x02\x18 {func_name}"
                right_col = f"\x01{ida_lines.SCOLOR_CREFTAIL}{node_str}\x02{ida_lines.SCOLOR_CREFTAIL}"

            rows.append([left_col, right_col])

    # Add subclusters — lift non-trimmed grandchildren out of any
    # trimmed direct subclusters so user-code nested under library
    # ancestors still surfaces.
    for subcluster in _lifted_descendants(cluster.subclusters, library_ids):
        if match_ids is not None and not cluster_subtree_matches(subcluster, match_ids):
            continue
        # Add exactly one empty row before each subcluster
        rows.append(["", ""])

        sub_rows = create_cluster_rows(subcluster, analysis, column_width, paths, library_ids=library_ids, match_ids=match_ids)
        # Remove the trailing empty row that comes with sub_rows to avoid accumulation
        if sub_rows and not sub_rows[-1][0] and not sub_rows[-1][1]:
            sub_rows.pop()
        rows.extend(sub_rows)

    # Always add exactly one empty row after the cluster
    rows.append(["", ""])
    return rows


def draw_cluster_hierarchy(clusters, analysis, paths, hide_library: bool = False, match_ids: Optional[Set[int]] = None):
    """
    Draw all clusters in a hierarchical table format with proper sorting.

    Args:
        clusters: List of clusters to display
        analysis: Dictionary containing analysis data for clusters
        paths: Dictionary of paths to check for entry points
        hide_library: When True, every cluster (and subcluster,
            recursively) marked ``is_library`` is omitted. When False,
            only the leading boot/CRT prefix at each EP is omitted —
            middle/tail library clusters are kept.
        match_ids: When not None, the per-view filter is live: only
            cluster blocks whose subtree contains a matched id render
            (ancestors of matches stay so the tree remains rooted).

    Returns:
        List[str]: Formatted lines ready for display
    """
    if not clusters:
        return ["    NO CLUSTERS TO DISPLAY"]

    if hide_library:
        library_ids = _collect_library_cluster_ids(clusters)
    else:
        library_ids = _collect_boot_prefix_cluster_ids(clusters, paths)

    # Lift non-trimmed user-code clusters out of trimmed ancestors so
    # they aren't accidentally hidden when their only parent is being
    # filtered (e.g. user code nested inside a CRT library cluster).
    visible_clusters = _lifted_descendants(clusters, library_ids)
    if not visible_clusters:
        return ["    NO NON-LIBRARY CLUSTERS — press L to show library clusters"]

    # Sort clusters
    sorted_clusters = sort_clusters(visible_clusters, paths)

    if match_ids is not None:
        sorted_clusters = [c for c in sorted_clusters if cluster_subtree_matches(c, match_ids)]
        if not sorted_clusters:
            return ["    NO CLUSTERS MATCH — backspace edits, ESC clears the filter"]

    # Calculate required column width based on all clusters
    column_width = calculate_first_column_width(sorted_clusters, analysis)

    # Prepare all rows including subclusters
    all_rows = []
    first_non_ep_cluster = True

    # Process each cluster
    for cluster in sorted_clusters:
        # Add separator before first non-entry point cluster
        if first_non_ep_cluster and cluster.parent_cluster_id is None and not any(ep in cluster.nodes for ep in paths):
            first_non_ep_cluster = False

        cluster_rows = create_cluster_rows(cluster, analysis, column_width, paths, library_ids=library_ids, match_ids=match_ids)
        all_rows.extend(cluster_rows)

        # Add spacing between primary clusters
        if cluster.parent_cluster_id is None:
            all_rows.append(["", ""])

    if not all_rows:
        return ["    NO CLUSTERS TO DISPLAY"]

    # Create table
    headings = ["Cluster", "Node"]
    table = create_cluster_table(headings, all_rows, ida_lines.SCOLOR_DATNAME)

    # Format lines with proper indentation
    formatted_lines = []
    for line in table:
        if line.strip():
            formatted_lines.append(f"    {line}")
        else:
            formatted_lines.append("")

    return formatted_lines


def is_call_insn(addr: int) -> bool:
    """
    Check if the instruction at the given address is a call instruction.

    Args:
        addr (int): The address to check.

    Returns:
        bool: True if the instruction is a call, False otherwise.
    """
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, addr) and ida_idp.is_call_insn(insn):
        return True
    return False


def set_focus_to_code(pseudo: bool = True) -> None:
    """
    Set focus to the code or pseudocode window in IDA.

    Args:
        pseudo (bool): If True, focus on pseudocode, otherwise on disassembly.
    """
    widget_prefix = "Pseudocode-" if pseudo else "IDA View-"

    for i in range(ord("A"), ord("Z") + 1):
        disassembly_title = f"{widget_prefix}{chr(i)}"
        widget = ida_kernwin.find_widget(disassembly_title)
        if widget:
            ida_kernwin.activate_widget(widget, True)
            break


def navigate_back() -> None:
    """
    Navigate back in IDA's navigation history.
    """
    action_name = "JumpPrev"
    ida_kernwin.process_ui_action(action_name)


def register_menu_action(menu_path: str, menu_id: str, label: str, handler: idaapi.action_handler_t) -> None:
    """
    Register a menu action in IDA.

    Creates and registers an action in IDA's menu system with given handler.

    Args:
        menu_path (str): Path in menu where action should appear
        menu_id (str): Unique identifier for the action
        label (str): Display label for the menu item
        handler (idaapi.action_handler_t): Handler class for the action
    """
    action_desc = idaapi.action_desc_t(menu_id, label, handler, None, label)
    idaapi.register_action(action_desc)
    idaapi.attach_action_to_menu(menu_path, menu_id, idaapi.SETMENU_APP)


def register_popup_action(form: Any, popup: Any, menu_path: str, menu_id: str, label: str, handler: idaapi.action_handler_t, tooltip: str) -> None:
    """
    Register a popup menu action in IDA.

    Creates and registers an action in IDA's popup menu system.

    Args:
        form: Form widget containing popup menu
        popup: Popup menu instance
        menu_path (str): Path in menu where action should appear
        menu_id (str): Unique identifier for the action
        label (str): Display label for the menu item
        handler (idaapi.action_handler_t): Handler class for the action
        tooltip (str): Tooltip text for the menu item
    """
    action = idaapi.action_desc_t(menu_id, label, handler, None, tooltip, -1)
    idaapi.register_action(action)
    idaapi.attach_action_to_popup(form, popup, menu_id, menu_path)


def make_string(ea: int, size: int, undefine_first: bool = True) -> bool:
    """
    Create a string at specified address.

    Optionally undefines existing data before creating string.

    Args:
        ea (int): Address to create string at
        size (int): Size of string in bytes
        undefine_first (bool): Whether to undefine existing data first

    Returns:
        bool: True if string was created successfully
    """
    if undefine_first:
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
    return ida_bytes.create_strlit(ea, size, ida_nalt.STRTYPE_TERMCHR)


def patch_asciinet() -> None:
    """No-op retained for backwards compatibility.

    This previously wrapped asciinet's JVM-backed ``graph_to_ascii`` to
    normalise its bytes/str output for IDA's text display. ASCII rendering now
    uses the pure-Python ``ascii_graphs.graph_to_ascii``, which already returns
    a ``str``, so no monkey-patching is required.
    """
    return None


def help_text() -> List[str]:
    """
    Generate complete help text for XRefer.

    Creates formatted help text explaining all available commands,
    keyboard shortcuts, and features of XRefer.

    Returns:
        List[str]: List of lines containing formatted help text
    """
    help_text = r"""
 ------------------------------------------------------------------------------------------
  /$$   /$$ /$$$$$$$             /$$$$$$
 | $$  / $$| $$__  $$           /$$__  $$
 |  $$/ $$/| $$  \ $$  /$$$$$$ | $$  \__//$$$$$$   /$$$$$$
  \  $$$$/ | $$$$$$$/ /$$__  $$| $$$$   /$$__  $$ /$$__  $$
   >$$  $$ | $$__  $$| $$$$$$$$| $$_/  | $$$$$$$$| $$  \__/
  /$$/\  $$| $$  \ $$| $$_____/| $$    | $$_____/| $$
 | $$  \ $$| $$  | $$|  $$$$$$$| $$    |  $$$$$$$| $$
 |__/  |__/|__/  |__/ \_______/|__/     \_______/|__/

                The Binary Navigator (XRefer) - Help
 ------------------------------------------------------------------------------------------

 GLOBAL KEYS (available in every view):
 [ESC]      Go back one view, or (at home) switch focus back to IDA
 [ENTER]    Return to the home view (per-function tables)
 [H]        Show / hide this help (except while typing a search filter,
            where 'h' goes into the filter text)
 [N]        Rename the function / reference under the cursor
 (MOUSE)    Click = expand row / open cluster / show call details;
            Double-click = select artifact or jump to address; Hover = tooltip

 ----------------------------------------

 HOME VIEW (initial state — per-function cross-reference tables):
 [S]    Search / filter the current view (then type to filter)
 [T]    Trace API calls; press again to cycle function -> path -> full scope
 [C]    Cluster relationship graph
 [K]    ATT&CK matrix (kill-chain coverage of the clusters)
 [O]    Show orphan artifacts (no path to an entry point)
 [X]    Cross-reference listing for the artifact under the cursor
 [G]    Artifact path graph for the artifact under the cursor
 [P]    Call focus (when the cursor is on a 0x... call address)
 [V]    Neighborhood: clusters reachable from the cursor function
 [M]    Intermediate paths through the cursor function (when it links a cluster)
 [J]    Jump to the cluster containing this function
 [B]    Boundary scan: find functions containing all selected artifacts
 [L]    Show the last boundary scan results
 [D]    Add selected artifacts (APIs/libs/strings/CAPA) to exclusions
 [U]    Toggle exclusions on / off
 [E]    Expand / collapse table sections

 ----------------------------------------

 SEARCH MODE ([S] from home):
 Type to filter the current content
 [X]    Cross-references for the artifact under the cursor
 [G]    Artifact path graph for the artifact under the cursor
 [ESC/ENTER] Exit search and return home

 ----------------------------------------

 TRACE SCOPES (after pressing [T] in home view):
 [T]    Cycle scope: function -> path -> full -> function
          - function: API calls in the current function
          - path:     calls along paths reaching this function
          - full:     all recorded calls in the trace
 [U]    Toggle exclusions on / off
 [ESC/ENTER] Return to home view

 ----------------------------------------

 CLUSTERS & CLUSTER GRAPHS (after pressing [C] in home view):
 [C]    Toggle between cluster table and cluster relationship graph
 [L]    Show / hide library clusters
 [R]    Toggle cluster description / full report view
 [J]    Toggle cluster sync (follow the IDA cursor across clusters)
 [G]    Pin / unpin the cluster graph
 [M]    Intermediate paths through the cursor function
 [A]    While in intermediate-paths view: scope this cluster <-> all clusters
 [K]    ATT&CK matrix for these clusters (scoped to the current cluster)
 [V]    Neighborhood: clusters reachable from the cursor function
 [ESC]  Step back through visited clusters;  [ENTER] returns home

 ----------------------------------------

 ATT&CK MATRIX (after pressing [K] from the home or a cluster view):
 Kill-chain coverage built from the clusters' MITRE ATT&CK mappings:
 a per-tactic coverage strip, then techniques grouped by tactic, each
 with a rationale and the cluster(s) that ground it.
 [K]    Exit the matrix
 [G]    Open the ATT&CK heat-grid popup (Navigator-style, cells shaded by coverage)
 [L]    Show / hide library clusters (binary-wide view)
 (MOUSE) Click a cluster.id.xxxx to open that cluster;
            click a T#### id to open its attack.mitre.org page
 [ESC/ENTER] Return to the previous view / home

 ----------------------------------------

 ARTIFACT PATH GRAPH (after pressing [G] on an artifact):
 [G]    Pin / unpin the graph
 [S]    Toggle simplified / normal graph representation
 [D]    Node detail: show / hide each node's direct artifacts in the box
 [V]    Neighborhood: clusters reachable from the cursor function
 (MOUSE) Hover / click / double-click nodes for details or navigation
 [ESC/ENTER] Return to home view

 ----------------------------------------

 NEIGHBORHOOD VIEW (after pressing [V]):
 Shows the cursor function centered, with adjacent clusters around it
 [V]    Exit the neighborhood view
 [M]    Intermediate paths through the cursor function
 [ESC/ENTER] Return to the previous view / home

 ----------------------------------------

 ORPHAN ARTIFACTS (after pressing [O] in home view):
 [E]    Expand / collapse table sections
 [O]    Exit the orphans view
 [ESC/ENTER] Return to home view

 ----------------------------------------

 CALL FOCUS (after pressing [P] on a 0x... call in home view):
 Shows context specific to the selected call instruction
 [ESC/ENTER] Return to home view

 ----------------------------------------

 XREF LISTING (after pressing [X] on an artifact):
 Detailed cross-reference listing for the selected artifact
 [ESC/ENTER] Return to home view

 ----------------------------------------

 BOUNDARY SCANS (after pressing [B] with artifacts selected in home view):
 Double-click artifacts to select them, then press [B]
 [L]    Re-show the last boundary scan results (from home)
 [ESC/ENTER] Return to home view

 ----------------------------------------

 MOUSE INTERACTIONS:
  - Click: expand/collapse a section (click the ▸/▾ header row), open a cluster id, or expand call details (→)
  - Double-click: select / deselect an artifact, or jump to an address
  - Hover: tooltip with details
  - Right-click: copy / export actions (e.g. copy strings)

 ----------------------------------------

 TIPS & NOTES:
  - Selection is by double-click; selected artifacts stay selected until
    double-clicked again. [B] (boundary) and [D] (exclude) act on the selection.
  - Pressing [ESC] repeatedly steps back through your view history to home
  - Keys like [T], [C], [G] cycle or toggle related modes each press
  - Refine what is shown with exclusions: [D] adds the selection, [U] toggles all
  - Experiment with cluster graphs, neighborhoods, traces, and paths for insight

 ----------------------------------------

 Press [H] to hide this help.
 """
    return help_text.splitlines()
